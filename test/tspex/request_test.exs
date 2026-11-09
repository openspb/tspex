defmodule Tspex.RequestTest do
  use ExUnit.Case, async: true

  alias Tspex.{Error, Fixtures}

  @data Fixtures.data()
  @digest :crypto.hash(:sha256, @data)

  describe "against the openssl tool" do
    test "the default request, with the nonce the tool chose, is the same bytes" do
      der = Fixtures.read("q_sha256.tsq")
      assert byte_size(der) == 69
      assert {:ok, parsed} = Tspex.decode_request(der)
      assert parsed.nonce
      assert {:ok, ours} = Tspex.request(@data, nonce: parsed.nonce, cert_req: true)
      assert ours.der == der
    end

    for {file, opts} <- [
          {"q_no_nonce", [nonce: false, cert_req: true]},
          {"q_policy", [nonce: false, cert_req: true, policy: "1.2.3.4.5.6"]},
          {"q_no_cert", [nonce: false, cert_req: false]},
          {"q_sha224", [hash: :sha224, cert_req: true]},
          {"q_sha384", [hash: :sha384, cert_req: true]},
          {"q_sha512", [hash: :sha512, cert_req: true]},
          {"q_sha1", [hash: :sha1, allow_sha1: true, cert_req: true]}
        ] do
      test "#{file} is the same bytes" do
        der = Fixtures.read(unquote(file) <> ".tsq")
        opts = unquote(opts)
        {:ok, parsed} = Tspex.decode_request(der)
        opts = if parsed.nonce, do: Keyword.put(opts, :nonce, parsed.nonce), else: opts
        assert {:ok, ours} = Tspex.request(@data, opts)
        assert ours.der == der
      end
    end

    test "every request of the tool is read back to what we ask for" do
      for name <- ~w(q_sha256 q_no_nonce q_policy q_no_cert q_sha224 q_sha384 q_sha512 q_sha1) do
        der = Fixtures.read(name <> ".tsq")
        assert {:ok, req} = Tspex.decode_request(der)
        assert req.der == der
        assert req.version == 1
        assert is_atom(req.hash)
        assert req.digest == :crypto.hash(Tspex.Imprint.crypto_name(req.hash), @data)
      end
    end

    test "the fields of a read request" do
      {:ok, req} = Tspex.decode_request(Fixtures.read("q_policy.tsq"))
      assert req.hash == :sha256
      assert req.digest == @digest
      assert req.policy == {1, 2, 3, 4, 5, 6}
      assert req.nonce == nil
      assert req.cert_req == true
      assert req.extensions == []

      {:ok, req} = Tspex.decode_request(Fixtures.read("q_no_cert.tsq"))
      assert req.cert_req == false
    end

    test "a request for MD5 is read as the OID, since the library does not know it" do
      # N23 for the algorithm the tool can still write
      {:ok, req} = Tspex.decode_request(Fixtures.read("q_md5.tsq"))
      assert req.hash == :md5
    end
  end

  describe "building" do
    test "the defaults: SHA-256, a random nonce, the certificate asked for" do
      {:ok, a} = Tspex.request(@data)
      {:ok, b} = Tspex.request(@data)
      assert a.hash == :sha256
      assert a.digest == @digest
      assert is_integer(a.nonce) and a.nonce > 0 and a.nonce < Bitwise.bsl(1, 63)
      assert a.nonce != b.nonce
      assert a.cert_req == true
      assert a.version == 1
      assert {:ok, ^a} = Tspex.decode_request(a.der)
    end

    test "a stream and a ready digest give the same request as the data" do
      {:ok, a} = Tspex.request(@data, nonce: 7)
      {:ok, b} = Tspex.request({:stream, [@data]}, nonce: 7)
      {:ok, c} = Tspex.request({:digest, :sha256, @digest}, nonce: 7)
      assert a.der == b.der
      assert a.der == c.der
    end

    test "extensions are written and read back" do
      ext = %{oid: {1, 2, 3, 4}, critical: true, value: <<0x05, 0x00>>}
      other = %{oid: {1, 2, 3, 5}, critical: false, value: <<0x04, 0x01, 0xFF>>}
      {:ok, req} = Tspex.request(@data, nonce: 7, extensions: [ext, other])
      assert {:ok, back} = Tspex.decode_request(req.der)
      assert back.extensions == [ext, other]
    end

    test "text and tuples are both taken as a policy" do
      {:ok, a} = Tspex.request(@data, nonce: 7, policy: "1.2.3.4")
      {:ok, b} = Tspex.request(@data, nonce: 7, policy: {1, 2, 3, 4})
      assert a.der == b.der
      assert a.policy == {1, 2, 3, 4}
    end

    test "request!/2 returns the struct" do
      assert %Tspex.Request{} = Tspex.request!(@data)
    end

    test "inspect shows no digest" do
      {:ok, req} = Tspex.request(@data, nonce: 7)
      text = inspect(req)
      assert text =~ "#Tspex.Request<"
      assert text =~ "69 bytes" or text =~ "bytes"
      refute text =~ Base.encode16(@digest, case: :lower)
      refute text =~ inspect(@digest)
    end
  end

  describe "bad arguments (N24 to N26)" do
    test "N24: a nonce that is zero, negative or not a number" do
      assert_raise ArgumentError, fn -> Tspex.request(@data, nonce: 0) end
      assert_raise ArgumentError, fn -> Tspex.request(@data, nonce: -5) end
      assert_raise ArgumentError, fn -> Tspex.request(@data, nonce: "7") end
      assert_raise ArgumentError, fn -> Tspex.request(@data, nonce: Bitwise.bsl(1, 255)) end
    end

    test "N25: a digest of the wrong size" do
      assert_raise ArgumentError, fn ->
        Tspex.request({:digest, :sha256, :binary.copy(<<1>>, 31)})
      end
    end

    test "N26: SHA-1 without allow_sha1" do
      assert_raise ArgumentError, ~r/allow_sha1/, fn -> Tspex.request(@data, hash: :sha1) end

      assert_raise ArgumentError, ~r/allow_sha1/, fn ->
        Tspex.request({:digest, :sha1, :binary.copy(<<1>>, 20)})
      end

      assert {:ok, _} = Tspex.request(@data, hash: :sha1, allow_sha1: true)
    end

    test "an algorithm that is not known, or a :hash that disagrees with the digest" do
      assert_raise ArgumentError, fn -> Tspex.request(@data, hash: :md5) end
      assert_raise ArgumentError, fn -> Tspex.request(@data, hash: :sha3) end

      assert_raise ArgumentError, fn ->
        Tspex.request({:digest, :sha256, @digest}, hash: :sha384)
      end
    end

    test "data that is not data, an option that does not exist, an option twice" do
      assert_raise ArgumentError, fn -> Tspex.request(:atom) end
      assert_raise ArgumentError, fn -> Tspex.request(@data, bogus: 1) end
      assert_raise ArgumentError, fn -> Tspex.request(@data, nonce: 1, nonce: 2) end
    end

    test "an extension whose value is not DER, a policy that is not an OID" do
      bad = %{oid: {1, 2, 3}, critical: false, value: <<1, 2, 3>>}
      assert_raise ArgumentError, fn -> Tspex.request(@data, extensions: [bad]) end
      assert_raise ArgumentError, fn -> Tspex.request(@data, policy: "not an oid") end
    end

    test "the message of an error never shows the data" do
      secret = "secret-data-0123456789"
      error = assert_raise ArgumentError, fn -> Tspex.request({:digest, :sha256, secret}) end
      refute error.message =~ secret
    end
  end

  describe "reading (N4, N10, N20 to N23)" do
    defp good, do: Fixtures.read("q_sha256.tsq")

    test "N4: it does not begin with a SEQUENCE" do
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request(<<0x31, 0x00>>)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request(<<0x02, 0x01, 0x01>>)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request(<<>>)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request("not DER")
    end

    test "N10: a nonce of more than 32 octets" do
      nonce = <<0x02, 0x21, 0x01, :binary.copy(<<0xFF>>, 32)::binary>>
      der = rebuild(good(), fn [v, i | _] -> [v, i, nonce] end)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request(der)
    end

    test "N20: version 2" do
      der = rebuild(good(), fn [_ | rest] -> [<<2, 1, 2>> | rest] end)
      assert {:error, %Error{reason: :unsupported_version, detail: 2}} = Tspex.decode_request(der)
    end

    test "N21: no messageImprint" do
      der = rebuild(good(), fn [v | _] -> [v] end)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request(der)
    end

    test "N22: SHA-256 with a digest of 31 octets" do
      imprint =
        <<0x30, 0x2F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
          0x01, 0x05, 0x00, 0x04, 0x1F, :binary.copy(<<7>>, 31)::binary>>

      der = rebuild(good(), fn [v, _ | rest] -> [v, imprint | rest] end)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request(der)
    end

    test "N23: an algorithm the library does not know is read as its OID" do
      imprint =
        <<0x30, 0x27, 0x30, 0x0B, 0x06, 0x07, 0x2A, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x05,
          0x00, 0x04, 0x18, :binary.copy(<<7>>, 24)::binary>>

      der = rebuild(good(), fn [v, _ | rest] -> [v, imprint | rest] end)
      assert {:ok, req} = Tspex.decode_request(der)
      assert req.hash == {1, 2, 3, 4, 5, 6, 7, 8}
      assert req.digest == :binary.copy(<<7>>, 24)
    end

    test "optional fields out of order, trailing or repeated are malformed" do
      [v, i, nonce, cert] = children(good())
      assert {:error, %Error{reason: :malformed}} = decode_children([v, i, cert, nonce])
      assert {:error, %Error{reason: :malformed}} = decode_children([v, i, nonce, nonce])
      assert {:error, %Error{reason: :malformed}} = decode_children([v, i, nonce, cert, <<5, 0>>])
      assert {:ok, _} = decode_children([v, i, nonce, cert])
    end

    test "trailing bytes after the request, and the limits" do
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_request(good() <> <<0>>)

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_size}} =
               Tspex.decode_request(good(), max_size: 10)
    end

    test "decode_request!/2 raises Tspex.Error" do
      assert_raise Error, fn -> Tspex.decode_request!(<<0x31, 0>>) end
      assert %Tspex.Request{} = Tspex.decode_request!(good())
    end

    test "any prefix or single-byte change of a request is read or refused, never raised" do
      der = good()

      for n <- 0..(byte_size(der) - 1) do
        prefix = binary_part(der, 0, n)
        assert {:error, %Error{}} = Tspex.decode_request(prefix)
      end

      for n <- 0..(byte_size(der) - 1), byte <- [0x00, 0xFF, 0x30] do
        <<a::binary-size(n), _, b::binary>> = der

        assert match?({:ok, _}, Tspex.decode_request(<<a::binary, byte, b::binary>>)) or
                 match?({:error, %Error{}}, Tspex.decode_request(<<a::binary, byte, b::binary>>))
      end
    end

    defp seq(parts), do: Tspex.DER.encode({:seq, Enum.map(parts, &{:raw, &1})})

    defp children(der) do
      {:ok, root} = Tspex.DER.decode(der)

      for {_id, _content, raw} <- Tspex.DER.children(root), do: raw
    end

    defp decode_children(parts) do
      Tspex.decode_request(seq(parts))
    end

    defp rebuild(der, fun), do: seq(fun.(children(der)))
  end
end
