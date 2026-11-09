defmodule Tspex.TestPKI do
  @moduledoc false
  # Keys and certificates made on the fly for the tests, written with the
  # DER writer of the library so that any field can be made wrong on
  # purpose. Keys are cached for the whole run, since RSA key generation is
  # slow. Adapted from the helper of cmsex.

  import Bitwise

  alias Tspex.DER

  @time_stamping {1, 3, 6, 1, 5, 5, 7, 3, 8}
  @any_eku {2, 5, 29, 37, 0}
  @server_auth {1, 3, 6, 1, 5, 5, 7, 3, 1}
  @client_auth {1, 3, 6, 1, 5, 5, 7, 3, 2}
  @code_signing {1, 3, 6, 1, 5, 5, 7, 3, 3}

  def time_stamping, do: @time_stamping
  def any_eku, do: @any_eku
  def server_auth, do: @server_auth
  def client_auth, do: @client_auth
  def code_signing, do: @code_signing

  ## Keys

  @doc """
  A private key as a `:public_key` record, cached by name: `:rsa2048`,
  `:rsa3072`, `:p256`, `:p384`, `:ed25519`, and any of them as `{name, tag}`
  for another key of the same kind.
  """
  def key(name) do
    case :persistent_term.get({__MODULE__, name}, nil) do
      nil -> :global.trans({{__MODULE__, name}, self()}, fn -> generate_once(name) end)
      key -> key
    end
  end

  defp generate_once(name) do
    case :persistent_term.get({__MODULE__, name}, nil) do
      nil ->
        key = generate(kind(name))
        :persistent_term.put({__MODULE__, name}, key)
        key

      key ->
        key
    end
  end

  defp kind({name, _tag}), do: name
  defp kind(name), do: name

  defp generate(:rsa2048), do: :public_key.generate_key({:rsa, 2048, 65_537})
  defp generate(:rsa3072), do: :public_key.generate_key({:rsa, 3072, 65_537})
  defp generate(:p256), do: :public_key.generate_key({:namedCurve, :secp256r1})
  defp generate(:p384), do: :public_key.generate_key({:namedCurve, :secp384r1})
  defp generate(:ed25519), do: :public_key.generate_key({:namedCurve, :ed25519})

  ## Certificates

  @doc """
  A certificate in DER for the key `name`. Options:

    * `:issuer` - `{issuer_certificate_der, issuer_key_name}`; self-signed
      if absent.
    * `:subject` - the common name (default: the key name).
    * `:serial` - default: random.
    * `:not_before`, `:not_after` - `DateTime`s (a day ago, ten years).
    * `:ca` - adds basicConstraints cA and, unless `:key_usage` is given,
      keyCertSign and cRLSign. `:path_len` limits the path below it.
    * `:key_usage` - a list of bit positions (0 digitalSignature, 1
      nonRepudiation, 2 keyEncipherment, 5 keyCertSign), or `nil` for no
      extension. Default: `[0, 1]` (`[5, 6]` for a CA).
    * `:eku` - a list of OIDs for extKeyUsage, or `nil` (the default) for
      no extension; `:eku_critical` (true); `:eku_twice` writes two
      instances of the extension.
    * `:san` - a list of terms for subjectAltName: `{:dns, text}`,
      `{:uri, text}`, `{:ip, octets}`, `{:email, text}`.
    * `:subject_name` - the whole subject as a DER term, in place of the
      common name; `:empty_subject` makes an empty subject.
    * `:extensions` - extra extensions as DER terms.
  """
  def cert(name, opts \\ []) do
    key = key(name)

    subject =
      cond do
        Keyword.get(opts, :empty_subject) -> {:seq, []}
        Keyword.has_key?(opts, :subject_name) -> Keyword.fetch!(opts, :subject_name)
        true -> name_term(Keyword.get(opts, :subject, label(name)))
      end

    {issuer_name, issuer_key, issuer_ski} =
      case Keyword.get(opts, :issuer) do
        nil ->
          {subject, key, nil}

        {issuer_der, issuer_key_name} ->
          {:ok, root} = DER.decode(issuer_der)
          [tbs | _] = DER.children(root)
          fields = tbs_fields(tbs)
          {{:raw, fields.issuer_raw_subject}, key(issuer_key_name), fields.ski}
      end

    spki = spki(key)
    ski = :crypto.hash(:sha, public_bits(key))

    serial =
      Keyword.get_lazy(opts, :serial, fn ->
        :binary.decode_unsigned(:crypto.strong_rand_bytes(16)) >>> 1
      end)

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    not_before = Keyword.get(opts, :not_before, DateTime.add(now, -86_400))
    not_after = Keyword.get(opts, :not_after, DateTime.add(now, 3650 * 86_400))
    {sig_alg, sign_fun} = cert_signature(issuer_key)

    extensions =
      ([
         ext({2, 5, 29, 14}, {:octets, ski}),
         issuer_ski && ext({2, 5, 29, 35}, {:seq, [{:primitive, 0, issuer_ski}]}),
         key_usage_ext(opts),
         Keyword.get(opts, :ca) && basic_constraints(opts),
         san_ext(opts)
       ] ++ eku_exts(opts))
      |> Enum.reject(&(&1 in [nil, false]))
      |> Kernel.++(Keyword.get(opts, :extensions, []))

    tbs =
      DER.encode(
        {:seq,
         [
           {:explicit, 0, {:int, 2}},
           {:int, serial},
           sig_alg,
           issuer_name,
           {:seq, [{:time, not_before}, {:time, not_after}]},
           subject,
           {:raw, spki},
           {:explicit, 3, {:seq, extensions}}
         ]}
      )

    DER.encode({:seq, [{:raw, tbs}, sig_alg, {:bits, sign_fun.(tbs)}]})
  end

  defp label({name, tag}), do: "Test #{name} #{tag}"
  defp label(name), do: "Test #{name}"

  @doc """
  A CRL in DER, issued by the certificate `issuer_der` and signed with its key
  `issuer_key_name`. Options:

    * `:revoked` - a list of `{serial, revoked_at}` or `{serial, revoked_at,
      reason}`, with the reason as the number of CRLReason (1 keyCompromise,
      4 superseded, 5 cessationOfOperation); no reason writes no extension.
    * `:this_update` - a day ago; `:next_update` - in a week, `nil` for none.
  """
  def crl(issuer_der, issuer_key_name, opts \\ []) do
    {:ok, root} = DER.decode(issuer_der)
    [tbs | _] = DER.children(root)
    issuer = tbs_fields(tbs).issuer_raw_subject
    {sig_alg, sign_fun} = cert_signature(key(issuer_key_name))

    now = DateTime.utc_now() |> DateTime.truncate(:second)
    this_update = Keyword.get(opts, :this_update, DateTime.add(now, -86_400))
    next_update = Keyword.get(opts, :next_update, DateTime.add(now, 7 * 86_400))

    revoked =
      for entry <- Keyword.get(opts, :revoked, []) do
        {serial, at, reason} =
          if tuple_size(entry) == 2, do: Tuple.insert_at(entry, 2, nil), else: entry

        extensions =
          if reason,
            do: [{:seq, [ext({2, 5, 29, 21}, {:raw, <<0x0A, 1, reason>>})]}],
            else: []

        {:seq, [{:int, serial}, {:time, at}] ++ extensions}
      end

    tbs =
      DER.encode(
        {:seq,
         [{:int, 1}, sig_alg, {:raw, issuer}, {:time, this_update}] ++
           if(next_update, do: [{:time, next_update}], else: []) ++
           if(revoked == [], do: [], else: [{:seq, revoked}])}
      )

    DER.encode({:seq, [{:raw, tbs}, sig_alg, {:bits, sign_fun.(tbs)}]})
  end

  @doc "A Name with the country, the organization and the common name."
  def name_term(cn, type \\ :utf8) do
    {:seq,
     [
       {:set, [{:seq, [{:oid, {2, 5, 4, 6}}, {:printable, "BR"}]}]},
       {:set, [{:seq, [{:oid, {2, 5, 4, 10}}, {type, "tspex tests"}]}]},
       {:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {type, cn}]}]}
     ]}
  end

  defp spki({:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}) do
    DER.encode(
      {:seq,
       [
         {:seq, [{:oid, {1, 2, 840, 113_549, 1, 1, 1}}, :null]},
         {:bits, DER.encode({:seq, [{:int, n}, {:int, e}]})}
       ]}
    )
  end

  defp spki({:ECPrivateKey, _, _priv, {:namedCurve, curve}, point, _}) do
    algorithm =
      if curve == {1, 3, 101, 112},
        do: {:seq, [{:oid, curve}]},
        else: {:seq, [{:oid, {1, 2, 840, 10_045, 2, 1}}, {:oid, curve}]}

    DER.encode({:seq, [algorithm, {:bits, point}]})
  end

  defp public_bits(key) do
    {:ok, el} = DER.decode(spki(key))
    [_, {0x03, <<0, bits::binary>>, _}] = DER.children(el)
    bits
  end

  defp cert_signature({:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key) do
    {{:seq, [{:oid, {1, 2, 840, 113_549, 1, 1, 11}}, :null]},
     fn tbs -> :public_key.sign(tbs, :sha256, key) end}
  end

  defp cert_signature({:ECPrivateKey, _, _, {:namedCurve, {1, 3, 101, 112}}, _, _} = key) do
    {{:seq, [{:oid, {1, 3, 101, 112}}]}, fn tbs -> :public_key.sign(tbs, :none, key) end}
  end

  defp cert_signature({:ECPrivateKey, _, _, _, _, _} = key) do
    {{:seq, [{:oid, {1, 2, 840, 10_045, 4, 3, 2}}]},
     fn tbs -> :public_key.sign(tbs, :sha256, key) end}
  end

  defp key_usage_ext(opts) do
    usage =
      cond do
        Keyword.has_key?(opts, :key_usage) -> Keyword.get(opts, :key_usage)
        Keyword.get(opts, :ca) -> [5, 6]
        true -> [0, 1]
      end

    usage && ext({2, 5, 29, 15}, {:named_bits, usage}, true)
  end

  defp basic_constraints(opts) do
    path_len = if len = Keyword.get(opts, :path_len), do: [{:int, len}], else: []
    ext({2, 5, 29, 19}, {:seq, [{:bool, true}] ++ path_len}, true)
  end

  defp eku_exts(opts) do
    case Keyword.get(opts, :eku) do
      nil ->
        []

      oids ->
        critical = Keyword.get(opts, :eku_critical, true)
        one = ext({2, 5, 29, 37}, {:seq, Enum.map(oids, &{:oid, &1})}, critical)
        if Keyword.get(opts, :eku_twice), do: [one, one], else: [one]
    end
  end

  defp san_ext(opts) do
    case Keyword.get(opts, :san) do
      nil -> nil
      names -> ext({2, 5, 29, 17}, {:seq, Enum.map(names, &general_name/1)})
    end
  end

  defp general_name({:dns, text}), do: {:primitive, 2, text}
  defp general_name({:uri, text}), do: {:primitive, 6, text}
  defp general_name({:ip, octets}), do: {:primitive, 7, octets}
  defp general_name({:email, text}), do: {:primitive, 1, text}

  @doc "An extension as a DER term."
  def ext(oid, value, critical \\ false) do
    {:seq,
     [{:oid, oid}] ++
       if(critical, do: [{:bool, true}], else: []) ++ [{:octets, DER.encode(value)}]}
  end

  # The pieces of a certificate that the helper itself needs.
  defp tbs_fields(tbs) do
    children = DER.children(tbs)
    children = if match?({0xA0, _, _}, hd(children)), do: tl(children), else: children
    [_serial, _alg, _issuer, _validity, {0x30, _, subject_raw} | rest] = children
    {0xA3, _, _} = extensions = Enum.find(rest, &match?({0xA3, _, _}, &1))
    [seq] = DER.children(extensions)

    ski =
      Enum.find_value(DER.children(seq), fn extension ->
        [{0x06, _, _} = oid_el | tail] = DER.children(extension)
        {:ok, oid} = DER.oid(oid_el)
        {0x04, value, _} = List.last(tail)

        if oid == {2, 5, 29, 14} do
          {:ok, el} = DER.decode(value)
          {:ok, id} = DER.octets(el)
          id
        end
      end)

    %{issuer_raw_subject: subject_raw, ski: ski}
  end
end
