defmodule Tspex.TestTSA do
  @moduledoc false
  # A time-stamping authority in memory for the tests: it builds a PKI
  # (root, an optional intermediate, the certificate of the TSA) and issues
  # responses, tokens and TSTInfo with any field made wrong on purpose. The
  # token is a real SignedData signed with `Cmsex.sign/3`, so a token that
  # is wrong in the CMS layer is wrong the way a real one would be.

  alias Cmsex.Attribute
  alias Tspex.{Certificate, DER, Imprint, TestPKI}

  @time_stamping TestPKI.time_stamping()
  @md5 {1, 2, 840, 113_549, 2, 5}
  @data {1, 2, 840, 113_549, 1, 7, 1}
  @signed_data {1, 2, 840, 113_549, 1, 7, 2}
  @tst_info {1, 2, 840, 113_549, 1, 9, 16, 1, 4}

  ## The authority

  @doc """
  Builds the PKI of a TSA. Options:

    * `:key` - the kind of key of the TSA: `:p256` (the default), `:p384`,
      `:rsa2048`, `:rsa3072`, `:ed25519`.
    * `:tag` - another TSA of the same kind of key (`:tsa`).
    * `:root_tag` - another root (`:root`).
    * `:intermediate` - a CA between the root and the TSA (`false`).
    * `:root`, `:ca`, `:cert` - options for `Tspex.TestPKI.cert/2` for the
      root, the intermediate and the certificate of the TSA. The TSA has a
      critical extKeyUsage with timeStamping alone unless `:cert` says
      otherwise.
  """
  def new(opts \\ []) do
    kind = Keyword.get(opts, :key, :p256)
    tag = Keyword.get(opts, :tag, :tsa)
    root_tag = Keyword.get(opts, :root_tag, :root)
    root_key = {:p256, root_tag}

    root =
      TestPKI.cert(
        root_key,
        Keyword.merge([ca: true, subject: "Tspex Root #{root_tag}"], Keyword.get(opts, :root, []))
      )

    {intermediate, issuer} =
      if Keyword.get(opts, :intermediate, false) do
        ca_key = {:p256, :"ca_#{root_tag}"}

        ca =
          TestPKI.cert(
            ca_key,
            Keyword.merge(
              [ca: true, subject: "Tspex Intermediate #{root_tag}", issuer: {root, root_key}],
              Keyword.get(opts, :ca, [])
            )
          )

        {ca, {ca, ca_key}}
      else
        {nil, {root, root_key}}
      end

    key_name = {kind, tag}

    cert =
      TestPKI.cert(
        key_name,
        Keyword.merge(
          [eku: [@time_stamping], subject: "Tspex TSA #{tag}", issuer: issuer],
          Keyword.get(opts, :cert, [])
        )
      )

    %{
      root: root,
      root_key: root_key,
      intermediate: intermediate,
      cert: cert,
      key_name: key_name,
      key: TestPKI.key(key_name),
      chain: List.wrap(intermediate)
    }
  end

  @doc "The roots to trust for this TSA."
  def trust(tsa), do: [tsa.root]

  ## Responses

  @doc """
  A `TimeStampResp` in DER. Options of the response:

    * `:status` - 0 to 5, or another integer (0).
    * `:status_text` - a list of strings (none).
    * `:fail_info` - a list of bit positions (none).
    * `:token` - `:include` (the default for status 0 and 1), `:omit` (the
      default for the others) or the bytes of a token.

  and those of `token/3`.
  """
  def response(tsa, request, opts \\ []) do
    status = Keyword.get(opts, :status, 0)
    token = response_token(tsa, request, status, opts)

    info =
      {:seq,
       [{:int, status}] ++
         status_text(Keyword.get(opts, :status_text, [])) ++
         fail_info(Keyword.get(opts, :fail_info))}

    DER.encode({:seq, [info] ++ if(token, do: [{:raw, token}], else: [])})
  end

  defp response_token(tsa, request, status, opts) do
    default = if status in [0, 1], do: :include, else: :omit

    case Keyword.get(opts, :token, default) do
      :include -> token(tsa, request, opts)
      :omit -> nil
      bytes when is_binary(bytes) -> bytes
    end
  end

  defp status_text([]), do: []
  defp status_text(texts), do: [{:seq, Enum.map(texts, &{:utf8, &1})}]

  defp fail_info(nil), do: []
  defp fail_info(bits), do: [{:named_bits, bits}]

  ## Tokens

  @doc """
  A time-stamp token (a `ContentInfo` with a `SignedData`). Options:

    * `:signer` - another TSA to sign with (the certificate and the key of
      `tsa`).
    * `:ess` - `:both` (the default: ESSCertID and ESSCertIDv2), `:v1`,
      `:v2`, `:none`, `:other` (both for another certificate), `:disagree`
      (v1 for the signer, v2 for another certificate).
    * `:ess_issuer_serial` - `false` leaves the issuerSerial out (`true`).
    * `:certs` - `:auto` (the default: the certificates of the signer if the
      request asked for them), `:include`, `:omit`, `:signer_only`,
      `:duplicate_signer`, `{:list, ders}`, `{:also, ders}`.
    * `:digest`, `:rsa_padding` - for the signature.
    * `:extra_signers` - more signers, each `%{tsa: tsa}`, for a token with
      several.
    * `:content_type` - the `eContentType` (`:tst_info`).
    * `:no_signer` - a SignedData with no SignerInfo.
    * `:not_signed_data` - a `ContentInfo` of id-data.
    * `:tst_info` - the DER of the TSTInfo to sign, instead of one made from
      `tst_info/3`.

  and those of `tst_info/3`.
  """
  def token(tsa, request, opts \\ []) do
    content = Keyword.get_lazy(opts, :tst_info, fn -> tst_info(tsa, request, opts) end)

    cond do
      Keyword.get(opts, :not_signed_data) ->
        DER.encode({:seq, [{:oid, @data}, {:explicit, 0, {:octets, content}}]})

      Keyword.get(opts, :no_signer) ->
        unsigned(content)

      true ->
        sign(tsa, request, content, opts)
    end
  end

  defp sign(tsa, request, content, opts) do
    signer_tsa = Keyword.get(opts, :signer, tsa)
    others = Keyword.get(opts, :extra_signers, [])

    signers =
      Enum.map([%{tsa: signer_tsa} | others], fn %{tsa: t} -> signer(t, opts) end)

    sign_options = [
      content_type: Keyword.get(opts, :content_type, :tst_info),
      certificates: certificates(signer_tsa, request, opts)
    ]

    {:ok, token} = Cmsex.sign(content, signers, sign_options)
    token
  end

  defp signer(tsa, opts) do
    base = %{
      certificate: tsa.cert,
      key: tsa.key,
      chain: tsa.chain,
      signed_attributes: ess(tsa, Keyword.get(opts, :ess, :both), opts)
    }

    base
    |> put_new(:digest, Keyword.get(opts, :digest))
    |> put_new(:rsa_padding, Keyword.get(opts, :rsa_padding))
  end

  defp put_new(map, _key, nil), do: map
  defp put_new(map, key, value), do: Map.put(map, key, value)

  defp certificates(tsa, request, opts) do
    case Keyword.get(opts, :certs, :auto) do
      :auto -> if(cert_req?(request), do: :signers, else: :none)
      :include -> :signers
      :omit -> :none
      :signer_only -> [tsa.cert]
      :duplicate_signer -> [tsa.cert, tsa.cert | tsa.chain]
      {:list, ders} -> ders
      {:also, ders} -> [tsa.cert | tsa.chain] ++ ders
    end
  end

  defp cert_req?(%{cert_req: cert_req}), do: cert_req
  defp cert_req?(_), do: true

  ## ESSCertID

  defp ess(_tsa, :none, _opts), do: []

  defp ess(tsa, mode, opts) do
    issuer_serial? = Keyword.get(opts, :ess_issuer_serial, true)
    other = Keyword.get_lazy(opts, :other_cert, fn -> TestPKI.cert({:p256, :ess_other}) end)

    case mode do
      :both -> [ess_v1(tsa.cert, issuer_serial?), ess_v2(tsa.cert, issuer_serial?)]
      :v1 -> [ess_v1(tsa.cert, issuer_serial?)]
      :v2 -> [ess_v2(tsa.cert, issuer_serial?)]
      :other -> [ess_v1(other, issuer_serial?), ess_v2(other, issuer_serial?)]
      :disagree -> [ess_v1(tsa.cert, issuer_serial?), ess_v2(other, issuer_serial?)]
    end
  end

  defp ess_v1(cert_der, issuer_serial?) do
    {:ok, cert} = Certificate.parse(cert_der)

    issuer_serial =
      if issuer_serial?,
        do: [{:seq, [{:seq, [{:explicit, 4, {:raw, cert.issuer}}]}, {:int, cert.serial}]}],
        else: []

    id = {:seq, [{:octets, :crypto.hash(:sha, cert_der)}] ++ issuer_serial}
    Attribute.new(:signing_certificate, [DER.encode({:seq, [{:seq, [id]}]})])
  end

  defp ess_v2(cert_der, issuer_serial?),
    do: Attribute.signing_certificate_v2(cert_der, issuer_serial: issuer_serial?)

  # A SignedData that is well formed and has no SignerInfo.
  defp unsigned(content) do
    sha256 = {:seq, [{:oid, Imprint.oid(:sha256)}, :null]}

    signed_data =
      {:seq,
       [
         {:int, 3},
         {:set, [sha256]},
         {:seq, [{:oid, @tst_info}, {:explicit, 0, {:octets, content}}]},
         {:set, []}
       ]}

    DER.encode({:seq, [{:oid, @signed_data}, {:explicit, 0, signed_data}]})
  end

  ## TSTInfo

  @doc """
  The `TSTInfo` in DER. `request` gives the imprint, the policy and the
  nonce (any map with `:hash`, `:digest`, `:policy`, `:nonce`). Options:

    * `:version` (1), `:policy`, `:serial`.
    * `:imprint` - `{hash, digest}` in place of the one of the request; the
      hash is a name, `:md5` or an OID tuple. `:imprint_params` is `:null`
      (the default) or `:absent`.
    * `:gen_time` - a `DateTime` (now, in seconds); `:gen_time_raw` - the
      text of the GeneralizedTime as it is to be written.
    * `:accuracy` - `nil` or a map with `:seconds`, `:millis`, `:micros`,
      written when present.
    * `:ordering` - `nil`, `true` or `false`.
    * `:nonce` - `:echo` (the default), `:omit` or an integer.
    * `:tsa_name` - `nil`, `{:dns, text}`, `{:uri, text}`, `{:ip, octets}`,
      `{:email, text}`, `{:directory, name_term}`, `:subject` (the subject
      of the certificate of the TSA), `:issuer`.
    * `:extensions` - `[%{oid:, critical:, value:}]`.
  """
  def tst_info(tsa, request, opts \\ []) do
    {hash, digest} = Keyword.get(opts, :imprint, {request.hash, request.digest})
    policy = Keyword.get(opts, :policy) || Map.get(request, :policy) || {1, 2, 3, 4, 5}

    gen_time =
      case Keyword.fetch(opts, :gen_time_raw) do
        {:ok, text} ->
          {:generalized_time, text}

        :error ->
          {:generalized_time, Keyword.get_lazy(opts, :gen_time, &now/0)}
      end

    fields =
      [
        {:int, Keyword.get(opts, :version, 1)},
        {:oid, policy},
        {:seq, [algorithm(hash, Keyword.get(opts, :imprint_params, :null)), {:octets, digest}]},
        {:int, Keyword.get_lazy(opts, :serial, fn -> :rand.uniform(1_000_000_000) end)},
        gen_time
      ] ++
        accuracy(Keyword.get(opts, :accuracy)) ++
        ordering(Keyword.get(opts, :ordering)) ++
        nonce(Keyword.get(opts, :nonce, :echo), request) ++
        tsa_name(Keyword.get(opts, :tsa_name), tsa) ++
        extensions(Keyword.get(opts, :extensions, []))

    DER.encode({:seq, fields})
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  @doc "The AlgorithmIdentifier of a hash, with NULL or no parameters."
  def algorithm(hash, params) do
    oid =
      cond do
        hash == :md5 -> @md5
        is_tuple(hash) -> hash
        true -> Imprint.oid(hash)
      end

    {:seq, [{:oid, oid}] ++ if(params == :null, do: [:null], else: [])}
  end

  defp accuracy(nil), do: []

  defp accuracy(map) do
    parts =
      [
        Map.has_key?(map, :seconds) && {:int, map.seconds},
        Map.has_key?(map, :millis) && {:implicit, 0, {:int, map.millis}},
        Map.has_key?(map, :micros) && {:implicit, 1, {:int, map.micros}}
      ]
      |> Enum.filter(& &1)

    [{:seq, parts}]
  end

  defp ordering(nil), do: []
  defp ordering(flag), do: [{:bool, flag}]

  defp nonce(:omit, _request), do: []
  defp nonce(:echo, request), do: nonce(Map.get(request, :nonce), request)
  defp nonce(nil, _request), do: []
  defp nonce(n, _request) when is_integer(n), do: [{:int, n}]

  defp tsa_name(nil, _tsa), do: []
  defp tsa_name(:subject, tsa), do: tsa_name({:directory_of, tsa.cert}, tsa)
  defp tsa_name(:issuer, tsa), do: tsa_name({:issuer_of, tsa.cert}, tsa)

  defp tsa_name({:directory_of, cert_der}, _tsa) do
    {:ok, cert} = Certificate.parse(cert_der)
    [{:explicit, 0, {:explicit, 4, {:raw, cert.subject}}}]
  end

  defp tsa_name({:issuer_of, cert_der}, _tsa) do
    {:ok, cert} = Certificate.parse(cert_der)
    [{:explicit, 0, {:explicit, 4, {:raw, cert.issuer}}}]
  end

  defp tsa_name({:dns, text}, _tsa), do: [{:explicit, 0, {:primitive, 2, text}}]
  defp tsa_name({:uri, text}, _tsa), do: [{:explicit, 0, {:primitive, 6, text}}]
  defp tsa_name({:ip, octets}, _tsa), do: [{:explicit, 0, {:primitive, 7, octets}}]
  defp tsa_name({:email, text}, _tsa), do: [{:explicit, 0, {:primitive, 1, text}}]
  defp tsa_name({:directory, term}, _tsa), do: [{:explicit, 0, {:explicit, 4, term}}]

  defp extensions([]), do: []

  defp extensions(list) do
    exts =
      Enum.map(list, fn %{oid: oid, critical: critical, value: value} ->
        {:seq, [{:oid, oid}] ++ if(critical, do: [{:bool, true}], else: []) ++ [{:octets, value}]}
      end)

    [{:implicit, 1, {:seq, exts}}]
  end

  ## Tampering with a token

  @doc "Flips the last bit of the token, which is in the signature."
  def flip_signature(token) do
    size = byte_size(token)
    <<head::binary-size(size - 1), last>> = token
    <<head::binary, Bitwise.bxor(last, 1)>>
  end

  @doc """
  Replaces the `tst_info` bytes inside `token` with `fun.(tst_info)`, which
  must have the same size. The signature then no longer matches.
  """
  def replace_tst_info(token, tst_info, fun) do
    new = fun.(tst_info)
    true = byte_size(new) == byte_size(tst_info)
    [before, after_] = :binary.split(token, tst_info)
    <<before::binary, new::binary, after_::binary>>
  end
end
