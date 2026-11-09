defmodule Tspex.Verify do
  @moduledoc false
  # Every decision of trust, in a fixed order (RFC 3161, 2.4.2 and 4; see
  # `Tspex.verify/3`). The result exists only after the last check.
  #
  # The signature is checked twice by `Cmsex.verify/2`: first without
  # `:trust`, to know which certificate signed and to apply the rules for a
  # TSA certificate to it, then with the roots, once the genTime that the
  # validity of the path depends on is read. That way a certificate that
  # breaks a rule of a TSA is reported as such and not as the failure of the
  # OTP that the same defect would also cause.

  alias Tspex.{
    Certificate,
    Codec,
    DER,
    Error,
    Imprint,
    Name,
    Options,
    PathValidation,
    Request,
    Response,
    TSA,
    TSTInfo,
    Verified
  }

  @options [
    :trust,
    :certificates,
    :input,
    :policies,
    :tsa_name,
    :tsa_eku,
    :critical_extensions,
    :granted_with_mods,
    :max_skew,
    :now,
    :revocation,
    :allow_sha1,
    :min_rsa_bits,
    :path_validation,
    :max_size,
    :max_depth,
    :max_nodes,
    :max_signers,
    :max_certificates,
    :max_attributes
  ]

  @signing_certificate [:signing_certificate, :signing_certificate_v2]
  @nonce_width 40

  @typep option ::
           :trust
           | :certificates
           | :input
           | :policies
           | :tsa_name
           | :tsa_eku
           | :critical_extensions
           | :granted_with_mods
           | :max_skew
           | :now
           | :revocation
           | :allow_sha1
           | :min_rsa_bits
           | :path_validation
           | :max_size
           | :max_depth
           | :max_nodes
           | :max_signers
           | :max_certificates
           | :max_attributes

  @doc false
  @spec options() :: [option(), ...]
  def options, do: @options

  @doc false
  # Checks the options of `verify/3` without verifying anything, for the
  # functions that verify tokens later.
  @spec check_options!(keyword()) :: :ok
  def check_options!(opts) do
    Options.take!(opts, @options, [:trust])
    :ok
  end

  @spec verify(binary(), term(), keyword()) :: {:ok, Verified.t()} | {:error, Error.t()}
  def verify(input, expected, opts) do
    opts = Options.take!(opts, @options, [:trust])
    expected = expected!(expected)
    check_arguments!(input, opts)

    with :ok <- check_size(input, opts),
         {:ok, mode} <- input_mode(input, opts),
         {:ok, token, status, response_deviations} <- token_of(mode, input, opts),
         {:ok, signed_data, content} <- TSTInfo.read_signed_data(token, opts),
         :ok <- one_signer(signed_data),
         {:ok, info} <- TSTInfo.parse(content, opts),
         {:ok, signer} <- signature(token, opts),
         :ok <- signing_certificate_present(signer),
         :ok <- TSA.check(signer.certificate, info.gen_time, opts.tsa_eku),
         {:ok, signer, trust} <- trust(token, info, signer, opts),
         :ok <- imprint(info, expected, opts),
         :ok <- nonce(info, expected),
         :ok <- policy(info, expected, opts),
         :ok <- tsa_name(info, signer.certificate, opts),
         :ok <- critical_extensions(info, opts),
         :ok <- clock(info, opts),
         {:ok, revocation} <- revocation(signer.path, info.gen_time, opts) do
      deviations =
        response_deviations ++
          info.deviations ++
          signed_data.deviations ++
          signer.deviations ++ certificate_deviations(expected, signed_data, signer, opts)

      {:ok,
       %Verified{
         info: info,
         token: token,
         status: status,
         signer: %{
           certificate: signer.certificate,
           path: signer.path,
           signer_info: signer.signer_info
         },
         certificates: signed_data.certificates,
         trust: trust,
         revocation: revocation,
         deviations: Enum.uniq(deviations)
       }}
    end
  end

  ## Arguments

  defp expected!(%Request{} = request), do: request
  defp expected!({:data, data}) when is_binary(data), do: data

  defp expected!(expected) do
    if Options.content?(expected) and not is_binary(expected) do
      expected
    else
      raise ArgumentError,
            "expected the second argument to be a Tspex.Request or {:data, binary}, " <>
              "{:stream, enumerable} or {:digest, hash, digest}, got #{Options.kind(expected)}"
    end
  end

  defp check_arguments!(input, opts) do
    unless is_binary(input),
      do: raise(ArgumentError, "expected the response or the token as a binary")

    if opts.trust == :none and opts.revocation != nil,
      do:
        raise(
          ArgumentError,
          ":revocation needs a certificate path, and trust: :none has none"
        )
  end

  ## The input

  defp check_size(input, opts) do
    cond do
      byte_size(input) > opts.max_size -> {:error, Error.new(:limit_exceeded, :max_size)}
      match?(<<0x30, _::binary>>, input) -> :ok
      true -> {:error, Error.new(:malformed)}
    end
  end

  defp input_mode(_input, %{input: mode}) when mode in [:response, :token], do: {:ok, mode}

  # A response starts with the PKIStatusInfo, a SEQUENCE; a token is a
  # ContentInfo, which starts with an OID (RFC 3161, 2.4.2).
  defp input_mode(input, opts) do
    with {:ok, root} <- Codec.decode(input, opts) do
      case DER.children(root) do
        [{0x30, _, _} | _] -> {:ok, :response}
        [{0x06, _, _} | _] -> {:ok, :token}
        _ -> {:error, Error.new(:malformed)}
      end
    end
  end

  defp token_of(:token, input, _opts), do: {:ok, input, nil, []}

  defp token_of(:response, input, opts) do
    limits = Map.to_list(Map.take(opts, [:max_size, :max_depth, :max_nodes]))

    with {:ok, response} <- Response.decode(input, limits), do: granted(response, opts)
  end

  defp granted(%Response{status: status, token: token} = response, opts)
       when status in [:granted, :granted_with_mods] do
    unknown = for {:unknown_bit, bit} <- response.fail_info, do: bit

    cond do
      token == nil ->
        {:error, Error.new(:token_missing)}

      unknown != [] ->
        {:error, Error.new(:unknown_fail_info, unknown)}

      status == :granted_with_mods and opts.granted_with_mods == :reject ->
        {:error, Error.new(:granted_with_mods)}

      true ->
        {:ok, token, status, response.deviations}
    end
  end

  defp granted(%Response{token: token}, _opts) when is_binary(token),
    do: {:error, Error.new(:unexpected_token)}

  defp granted(%Response{status: :rejection} = response, _opts),
    do:
      {:error,
       Error.new(:rejection, %{fail_info: response.fail_info, text: response.status_text})}

  defp granted(%Response{status: status}, _opts), do: {:error, Error.new(status)}

  defp one_signer(%Cmsex.SignedData{signer_infos: [_]}), do: :ok

  defp one_signer(%Cmsex.SignedData{signer_infos: signers}),
    do: {:error, Error.new(:signer_count, length(signers))}

  ## The signature and the certificate path

  defp cms_options(opts) do
    [
      certificates: opts.certificates,
      allow_sha1: opts.allow_sha1,
      min_rsa_bits: opts.min_rsa_bits,
      max_depth: opts.max_depth,
      max_elements: opts.max_nodes,
      max_signers: opts.max_signers,
      max_certificates: opts.max_certificates,
      max_attributes: opts.max_attributes
    ]
  end

  # Without the roots: which certificate signed, and is the signature good.
  defp signature(token, opts) do
    case Cmsex.verify(token, cms_options(opts)) do
      {:ok, %Cmsex.Verified{signers: [signer]}} -> {:ok, signer}
      {:error, %Cmsex.Error{} = cause} -> {:error, Error.from_cms(:token_invalid, cause)}
    end
  end

  # RFC 3161, 2.4.2 and RFC 5816: the signing certificate attribute is
  # required. `Cmsex.verify/2` has checked that it names the signer, when it
  # is there.
  defp signing_certificate_present(signer) do
    attributes = signer.signer_info.signed_attributes || []

    if Enum.any?(attributes, &(&1.type in @signing_certificate)),
      do: :ok,
      else: {:error, Error.new(:signing_certificate_missing)}
  end

  defp trust(_token, _info, signer, %{trust: :none}), do: {:ok, signer, :none}

  defp trust(token, info, signer, opts) do
    cms_opts =
      cms_options(opts) ++
        [
          trust: opts.trust,
          path_validation: Tspex.path_validation_at(info.gen_time, opts.path_validation)
        ]

    with {:ok, signer2} <- trusted_signer(token, cms_opts),
         :ok <- same_certificate(signer, signer2, info, opts),
         :ok <- whole_path(signer2.path, info.gen_time) do
      {:ok, signer2, :validated}
    end
  end

  defp trusted_signer(token, cms_opts) do
    case Cmsex.verify(token, cms_opts) do
      {:ok, %Cmsex.Verified{signers: [signer]}} ->
        {:ok, signer}

      {:error, %Cmsex.Error{reason: :untrusted} = cause} ->
        {:error, Error.from_cms(:untrusted, cause)}

      {:error, %Cmsex.Error{} = cause} ->
        {:error, Error.from_cms(:token_invalid, cause)}
    end
  end

  # Two certificates with the same identifier can both carry the signature;
  # the one that the roots vouch for is the one that counts, and it gets the
  # rules for a TSA too.
  defp same_certificate(%{certificate: der}, %{certificate: der}, _info, _opts), do: :ok

  defp same_certificate(_first, %{certificate: der}, info, opts),
    do: TSA.check(der, info.gen_time, opts.tsa_eku)

  defp whole_path(path, gen_time) do
    case PathValidation.check_path(path, gen_time) do
      :ok -> :ok
      {:error, reason} -> {:error, Error.new(:untrusted, reason)}
    end
  end

  ## What the token says

  defp imprint(info, expected, opts) do
    with :ok <- strong(info.hash, opts),
         {:ok, digest} <- expected_digest(expected, info.hash) do
      compare_imprint(info, digest)
    end
  end

  defp strong(:md5, _opts), do: {:error, Error.new(:weak_algorithm, :md5)}

  defp strong(:sha1, %{allow_sha1: false}), do: {:error, Error.new(:weak_algorithm, :sha1)}
  defp strong(_hash, _opts), do: :ok

  # The digest the token has to carry: the one of the request, or the one of
  # the data hashed with the algorithm the token itself declares.
  defp expected_digest(%Request{hash: hash, digest: digest}, hash), do: {:ok, digest}

  defp expected_digest(%Request{}, _other),
    do: {:error, Error.new(:imprint_mismatch, :hash_algorithm)}

  defp expected_digest(_data, hash) when not is_atom(hash),
    do: {:error, Error.new(:imprint_mismatch, :hash_algorithm)}

  defp expected_digest(data, hash) do
    case Imprint.digest(data, hash) do
      {:ok, digest} -> {:ok, digest}
      {:error, :hash_mismatch} -> {:error, Error.new(:imprint_mismatch, :hash_algorithm)}
    end
  end

  defp compare_imprint(info, digest) do
    cond do
      byte_size(info.digest) != Imprint.digest_size(info.hash) ->
        {:error, Error.new(:imprint_mismatch, :length)}

      not Imprint.equal?(info.digest, digest) ->
        {:error, Error.new(:imprint_mismatch, :digest)}

      true ->
        :ok
    end
  end

  # Only a response to a request has a nonce to compare (RFC 3161, 2.4.2).
  defp nonce(info, %Request{nonce: requested}) when is_integer(requested) do
    case info.nonce do
      nil ->
        {:error, Error.new(:nonce_missing)}

      received ->
        if same_nonce?(received, requested), do: :ok, else: {:error, Error.new(:nonce_mismatch)}
    end
  end

  defp nonce(_info, _expected), do: :ok

  defp same_nonce?(a, b) when a >= 0 and b >= 0,
    do: Imprint.equal?(pad(a), pad(b))

  defp same_nonce?(_a, _b), do: false

  # The bytes of a nonce are not text: String functions must not touch them.
  defp pad(n) do
    bytes = :binary.encode_unsigned(n)
    <<0::size(max(@nonce_width - byte_size(bytes), 0) * 8), bytes::binary>>
  end

  defp policy(info, expected, opts) do
    accepted = Enum.map(opts.policies, &Options.oid!(&1, ":policies"))

    cond do
      match?(%Request{policy: p} when p != nil, expected) and info.policy != expected.policy ->
        {:error, Error.new(:policy_mismatch, info.policy)}

      accepted != [] and info.policy not in accepted ->
        {:error, Error.new(:policy_mismatch, info.policy)}

      true ->
        :ok
    end
  end

  defp tsa_name(%{tsa: nil}, _certificate, _opts), do: :ok
  defp tsa_name(_info, _certificate, %{tsa_name: :ignore}), do: :ok

  defp tsa_name(info, certificate, _opts) do
    with {:ok, parsed} <- Certificate.parse(certificate),
         true <- Name.matches?(info.tsa, parsed) do
      :ok
    else
      _ -> {:error, Error.new(:tsa_name_mismatch)}
    end
  end

  defp critical_extensions(_info, %{critical_extensions: :ignore}), do: :ok

  defp critical_extensions(info, _opts) do
    case Enum.find(info.extensions, & &1.critical) do
      nil -> :ok
      extension -> {:error, Error.new(:critical_extension, extension.oid)}
    end
  end

  defp clock(_info, %{max_skew: nil}), do: :ok

  defp clock(info, opts) do
    now = opts.now || DateTime.utc_now()
    difference = abs(DateTime.diff(info.gen_time, now, :microsecond))
    allowed = opts.max_skew * 1_000_000 + accuracy_micros(info.accuracy)

    if difference <= allowed,
      do: :ok,
      else: {:error, Error.new(:gen_time_skew, div(difference, 1_000_000))}
  end

  defp accuracy_micros(nil), do: 0

  defp accuracy_micros(%{seconds: s, millis: ms, micros: us}),
    do: s * 1_000_000 + ms * 1_000 + us

  @doc false
  @spec revocation([binary()] | nil, DateTime.t(), map()) ::
          {:ok, :checked | :not_checked} | {:error, Error.t()}
  def revocation(_path, _gen_time, %{revocation: nil}), do: {:ok, :not_checked}

  def revocation(path, gen_time, %{revocation: check}) do
    case check.(path, gen_time) do
      :ok -> {:ok, :checked}
      {:error, reason} -> {:error, Error.new(:untrusted, {:revocation, reason})}
      _other -> {:error, Error.new(:untrusted, {:revocation, :bad_result})}
    end
  end

  ## Deviations

  defp certificate_deviations(%Request{cert_req: false}, %{certificates: [_ | _]}, _, _),
    do: [:unrequested_certificates]

  defp certificate_deviations(%Request{cert_req: true}, signed_data, signer, _opts),
    do: if(signer.certificate in signed_data.certificates, do: [], else: [:cert_req_not_honored])

  defp certificate_deviations(_expected, _signed_data, _signer, _opts), do: []
end
