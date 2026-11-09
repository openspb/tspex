defmodule Tspex.Stamps do
  @moduledoc false
  # Time-stamps that travel inside a CMS message: the signature time-stamp
  # (an unsigned attribute of a signer, RFC 3161 appendix A) and the content
  # time-stamp (a signed attribute, RFC 5126, 5.11.4). Positions are those
  # of `Cmsex`: an integer for a signer, a list for a countersignature.

  alias Cmsex.{Attribute, SignerInfo}
  alias Tspex.{Error, Imprint, Options, PathValidation, TSTInfo, Verified, Verify}

  @content_time_stamp {1, 2, 840, 113_549, 1, 9, 16, 2, 20}
  @hashes [:sha224, :sha256, :sha384, :sha512]

  @cms_options [:content, :certificates, :allow_sha1, :min_rsa_bits, :path_validation]
  @limit_options [
    :max_size,
    :max_depth,
    :max_nodes,
    :max_signers,
    :max_certificates,
    :max_attributes
  ]
  @token_options [:policies, :tsa_name, :tsa_eku, :critical_extensions]
  @at_stamp_options [:trust, :tsa_trust, :stamps, :revocation] ++
                      @cms_options ++ @limit_options ++ @token_options

  ## The signature to stamp

  @spec signature_imprint(binary(), Cmsex.position(), atom()) ::
          {:ok, {:digest, Tspex.hash(), binary()}} | {:error, Error.t()}
  def signature_imprint(cms, position, hash) do
    position!(position)

    unless hash in @hashes,
      do: raise(ArgumentError, "the hash must be one of #{inspect(@hashes)}")

    with {:ok, signer_info} <- signer_info(cms, position) do
      {:ok, digest} = Imprint.digest(SignerInfo.signature(signer_info), hash)
      {:ok, {:digest, hash, digest}}
    end
  end

  @spec add_signature_time_stamp(binary(), Cmsex.position(), Verified.t() | binary(), keyword()) ::
          {:ok, binary()} | {:error, Error.t()}
  def add_signature_time_stamp(cms, position, stamp, opts) do
    position!(position)
    Options.unique!(opts)
    if is_binary(stamp), do: Verify.check_options!(opts)

    with {:ok, signer_info} <- signer_info(cms, position),
         {:ok, token} <- bound(stamp, SignerInfo.signature(signer_info), opts) do
      case Cmsex.add_unsigned_attribute(cms, position, Attribute.new(:time_stamp_token, [token])) do
        {:ok, stamped} -> {:ok, stamped}
        {:error, %Cmsex.Error{} = cause} -> {:error, Error.from_cms(:cms_invalid, cause)}
      end
    end
  end

  # A token that was verified already only has to be about this signature.
  defp bound(%Verified{token: token, info: info}, signature, _opts) do
    cond do
      info.hash not in Imprint.hashes() ->
        {:error, Error.new(:imprint_mismatch, :hash_algorithm)}

      Imprint.equal?(info.digest, :crypto.hash(Imprint.crypto_name(info.hash), signature)) ->
        {:ok, token}

      true ->
        {:error, Error.new(:imprint_mismatch, :digest)}
    end
  end

  defp bound(token, signature, opts) when is_binary(token) do
    with {:ok, verified} <- Verify.verify(token, {:data, signature}, opts),
         do: {:ok, verified.token}
  end

  defp bound(_other, _signature, _opts),
    do: raise(ArgumentError, "expected a Tspex.Verified or a token in DER as the time-stamp")

  ## Reading and verifying the stamps of a signature

  @spec signature_time_stamps(binary(), Cmsex.position(), keyword()) ::
          {:ok, [TSTInfo.t()]} | {:error, Error.t()}
  def signature_time_stamps(cms, position, opts) do
    position!(position)
    TSTInfo.check_options!(opts)

    with {:ok, signer_info} <- signer_info(cms, position),
         do: each_ok(tokens(signer_info), &read_info(&1, opts))
  end

  defp read_info(token, opts) do
    with {:ok, _signed_data, info} <- TSTInfo.read_token(token, opts), do: {:ok, info}
  end

  # The values of `fun` for each item, or the first error.
  defp each_ok(items, fun), do: each_ok(items, fun, [])
  defp each_ok([], _fun, values), do: {:ok, Enum.reverse(values)}

  defp each_ok([item | rest], fun, values) do
    case fun.(item) do
      {:ok, value} -> each_ok(rest, fun, [value | values])
      {:error, _} = error -> error
    end
  end

  @spec verify_signature_time_stamps(binary(), Cmsex.position(), keyword()) ::
          {:ok, [Verified.t()]} | {:error, Error.t()}
  def verify_signature_time_stamps(cms, position, opts) do
    position!(position)
    Options.unique!(opts)
    {mode, opts} = stamps_mode(opts)
    Verify.check_options!(opts)

    with {:ok, signer_info} <- signer_info(cms, position) do
      verify_tokens(tokens(signer_info), {:data, SignerInfo.signature(signer_info)}, mode, opts)
    end
  end

  defp tokens(%SignerInfo{unsigned_attributes: attributes}) do
    for %Attribute{type: :time_stamp_token, values: values} <- attributes || [],
        token <- values,
        do: token
  end

  defp verify_tokens([], _expected, _mode, _opts), do: {:error, Error.new(:no_time_stamp)}

  defp verify_tokens(tokens, expected, mode, opts),
    do: tokens |> Enum.map(&Verify.verify(&1, expected, opts)) |> collect(mode)

  # `:all` fails with the first stamp that does not verify; `:any` returns
  # those that did, and fails with the first error only when none did.
  defp collect(results, :all) do
    case Enum.find(results, &match?({:error, _}, &1)) do
      nil -> {:ok, Enum.map(results, fn {:ok, verified} -> verified end)}
      error -> error
    end
  end

  defp collect([first | _] = results, :any) do
    case for({:ok, verified} <- results, do: verified) do
      [] -> first
      verified -> {:ok, verified}
    end
  end

  defp stamps_mode(opts) do
    {mode, rest} = Keyword.pop(opts, :stamps, :all)

    unless mode in [:all, :any],
      do: raise(ArgumentError, ":stamps must be :all or :any, got #{Options.kind(mode)}")

    {mode, rest}
  end

  ## The content time-stamp

  @spec content_time_stamp_attribute(Verified.t()) :: Attribute.t()
  def content_time_stamp_attribute(%Verified{token: token}),
    do: Attribute.new(@content_time_stamp, [token])

  def content_time_stamp_attribute(_other),
    do: raise(ArgumentError, "expected a Tspex.Verified")

  @spec verify_content_time_stamp(Cmsex.Verified.t(), non_neg_integer(), keyword()) ::
          {:ok, [Verified.t()]} | {:error, Error.t()}
  def verify_content_time_stamp(%Cmsex.Verified{} = verified, index, opts)
      when is_integer(index) and index >= 0 do
    Options.unique!(opts)
    {mode, opts} = stamps_mode(opts)
    {content, opts} = Keyword.pop(opts, :content)
    Verify.check_options!(opts)
    expected = content_expected!(verified, content)

    case Enum.find(verified.signers, &(&1.index == index)) do
      nil ->
        {:error, Error.new(:signer_not_found, index)}

      signer ->
        verify_tokens(content_tokens(signer.signer_info), expected, mode, opts)
    end
  end

  def verify_content_time_stamp(_verified, _index, _opts),
    do: raise(ArgumentError, "expected a Cmsex.Verified and the index of a signer")

  defp content_expected!(%Cmsex.Verified{content: nil}, nil),
    do: raise(ArgumentError, "the content is detached: give it in the :content option")

  defp content_expected!(%Cmsex.Verified{content: nil}, content) do
    if Options.content?(content),
      do: if(is_binary(content), do: {:data, content}, else: content),
      else: raise(ArgumentError, ":content must be data, got #{Options.kind(content)}")
  end

  defp content_expected!(%Cmsex.Verified{content: content}, nil), do: {:data, content}

  defp content_expected!(%Cmsex.Verified{}, _content),
    do: raise(ArgumentError, "the message carries its content: do not give :content")

  defp content_tokens(%SignerInfo{signed_attributes: attributes}) do
    for %Attribute{type: @content_time_stamp, values: values} <- attributes || [],
        token <- values,
        do: token
  end

  ## A signature as it was at the time of its time-stamp

  @spec verify_at_stamp(binary(), keyword()) :: {:ok, [map()]} | {:error, Error.t()}
  def verify_at_stamp(cms, opts) do
    Options.take!(opts, @at_stamp_options, [:trust])
    {trust, tsa_trust, mode, revocation, rest} = at_stamp_options!(opts)

    context = %{
      trust: trust,
      revocation: revocation,
      cms: cms_options(rest),
      path_validation: Keyword.get(rest, :path_validation, []),
      stamp: [trust: tsa_trust, stamps: mode] ++ Keyword.take(rest, stamp_keys())
    }

    with {:ok, count} <- signer_count(cms),
         do: each_ok(Enum.to_list(0..(count - 1)), &at_stamp(cms, &1, context))
  end

  defp at_stamp_options!(opts) do
    trust = Keyword.fetch!(opts, :trust)

    unless is_list(trust),
      do: raise(ArgumentError, ":trust must be a list of DER certificates here")

    {mode, rest} = stamps_mode(opts)
    {revocation, rest} = Keyword.pop(rest, :revocation)
    {tsa_trust, rest} = Keyword.pop(rest, :tsa_trust, trust)
    {trust, tsa_trust, mode, revocation, Keyword.delete(rest, :trust)}
  end

  defp stamp_keys, do: [:allow_sha1, :min_rsa_bits] ++ @limit_options ++ @token_options

  # The options for Cmsex: the limits of Tspex under the names of Cmsex.
  defp cms_options(opts) do
    limits = [
      max_size: opts[:max_size],
      max_depth: opts[:max_depth],
      max_elements: opts[:max_nodes],
      max_signers: opts[:max_signers],
      max_certificates: opts[:max_certificates],
      max_attributes: opts[:max_attributes]
    ]

    Keyword.take(opts, [:content, :certificates, :allow_sha1, :min_rsa_bits]) ++
      Enum.reject(limits, fn {_key, value} -> value == nil end)
  end

  defp at_stamp(cms, index, context) do
    with {:ok, stamps} <- verify_signature_time_stamps(cms, index, context.stamp),
         time = earliest(stamps),
         {:ok, signer} <- signer_at(cms, index, time, context),
         {:ok, _} <- Verify.revocation(signer.path, time, %{revocation: context.revocation}) do
      {:ok, %{signer: signer, stamps: stamps, time: time}}
    end
  end

  defp earliest(stamps), do: stamps |> Enum.map(& &1.info.gen_time) |> Enum.min(DateTime)

  # The signer is verified with the path validated at `time`. A message
  # with several signers verifies all of them for each, which costs more
  # than it needs to and keeps the result of one signer from depending on
  # the others.
  defp signer_at(cms, index, time, context) do
    path_validation = PathValidation.options_at(time, context.path_validation, :signer)
    options = context.cms ++ [trust: context.trust, path_validation: path_validation]

    case Cmsex.verify_each(cms, options) do
      {:ok, _signed_data, results} ->
        case Enum.at(results, index) do
          {_info, {:ok, signer}} -> whole_path(signer, time)
          {_info, {:error, cause}} -> {:error, cms_error(cause)}
        end

      {:error, cause} ->
        {:error, cms_error(cause)}
    end
  end

  defp whole_path(signer, time) do
    case PathValidation.check_path(signer.path, time, :signer) do
      :ok -> {:ok, signer}
      {:error, reason} -> {:error, Error.new(:untrusted, reason)}
    end
  end

  defp cms_error(%Cmsex.Error{reason: :untrusted} = cause), do: Error.from_cms(:untrusted, cause)
  defp cms_error(%Cmsex.Error{} = cause), do: Error.from_cms(:cms_invalid, cause)

  ## Finding a signer

  defp signer_count(cms) do
    with {:ok, infos} <- signer_infos(cms) do
      case infos do
        [] -> {:error, Error.new(:signer_count, 0)}
        _ -> {:ok, length(infos)}
      end
    end
  end

  defp signer_infos(cms) do
    case Cmsex.decode(cms) do
      {:ok, %Cmsex.SignedData{signer_infos: infos}} -> {:ok, infos}
      {:ok, _other} -> {:error, Error.new(:cms_invalid, :not_signed_data)}
      {:error, %Cmsex.Error{} = cause} -> {:error, Error.from_cms(:cms_invalid, cause)}
    end
  end

  defp signer_info(cms, position) do
    with {:ok, infos} <- signer_infos(cms), do: walk(infos, List.wrap(position), position)
  end

  defp walk(infos, [index | rest], position) do
    case Enum.fetch(infos, index) do
      {:ok, info} when rest == [] -> {:ok, info}
      {:ok, info} -> countersignatures(info, rest, position)
      :error -> {:error, Error.new(:signer_not_found, position)}
    end
  end

  defp countersignatures(info, rest, position) do
    case SignerInfo.countersignatures(info) do
      {:ok, list} -> walk(list, rest, position)
      {:error, %Cmsex.Error{} = cause} -> {:error, Error.from_cms(:cms_invalid, cause)}
    end
  end

  defp position!(position) when is_integer(position) and position >= 0, do: :ok

  defp position!([_ | _] = position) do
    if Enum.all?(position, &(is_integer(&1) and &1 >= 0)),
      do: :ok,
      else: bad_position!()
  end

  defp position!(_position), do: bad_position!()

  @spec bad_position!() :: no_return()
  defp bad_position!,
    do: raise(ArgumentError, "the position must be an index or a non-empty list of indexes")
end
