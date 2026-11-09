defmodule Tspex.TSTInfoTest do
  use ExUnit.Case, async: true

  alias Tspex.{DER, Error, Fixtures, TSTInfo}

  @digest :crypto.hash(:sha256, Fixtures.data())
  @sha256 {2, 16, 840, 1, 101, 3, 4, 2, 1}
  @signed_data_oid {1, 2, 840, 113_549, 1, 7, 2}
  @tst_info_oid {1, 2, 840, 113_549, 1, 9, 16, 1, 4}

  defp imprint(hash_oid \\ @sha256, digest \\ @digest),
    do: {:seq, [{:seq, [{:oid, hash_oid}, :null]}, {:octets, digest}]}

  defp gen_time(text), do: {:raw, <<0x18, byte_size(text), text::binary>>}

  defp base(extra \\ []) do
    [
      {:int, 1},
      {:oid, {1, 2, 3, 4, 1}},
      imprint(),
      {:int, 5},
      gen_time("20261107212746Z")
    ] ++ extra
  end

  defp der(terms), do: DER.encode({:seq, terms})
  defp parse(terms, opts \\ []), do: TSTInfo.parse(der(terms), opts)

  defp token(content_type, econtent) do
    encap =
      {:seq,
       [{:oid, content_type}] ++
         if(econtent, do: [{:explicit, 0, {:octets, econtent}}], else: [])}

    signed = {:seq, [{:int, 3}, {:set, []}, encap, {:set, []}]}
    DER.encode({:seq, [{:oid, @signed_data_oid}, {:explicit, 0, signed}]})
  end

  describe "the tokens of the openssl tool" do
    test "an RSA token, field by field" do
      {:ok, info} = Tspex.decode_token(Fixtures.read("r_rsa.tst"))
      {:ok, request} = Tspex.decode_request(Fixtures.read("q_sha256.tsq"))

      assert info.version == 1
      assert info.policy == {1, 2, 3, 4, 1}
      assert info.hash == :sha256
      assert info.digest == @digest
      assert is_integer(info.serial) and info.serial > 0
      assert %DateTime{year: 2026, time_zone: "Etc/UTC"} = info.gen_time
      assert info.accuracy == %{seconds: 1, millis: 500, micros: 100}
      assert info.ordering == true
      assert info.nonce == request.nonce
      assert {:directory_name, <<0x30, _::binary>> = name} = info.tsa
      assert name =~ "tspex test TSA rsa"
      assert {:ok, _} = DER.decode(name)
      assert info.extensions == []
      assert info.deviations == []
    end

    test "the token inside a response is the same kind of thing" do
      {:ok, response} = Tspex.decode_response(Fixtures.read("r_ec.tsr"))
      {:ok, info} = Tspex.decode_token(response.token)
      assert info.hash == :sha256
      assert {:directory_name, name} = info.tsa
      assert name =~ "tspex test TSA ec"
    end

    test "every hash and the policy and the nonce the request asked for" do
      for {name, hash} <- [
            {"r_rsa_sha224", :sha224},
            {"r_rsa_sha384", :sha384},
            {"r_rsa_sha512", :sha512},
            {"r_rsa_sha1", :sha1}
          ] do
        {:ok, response} = Tspex.decode_response(Fixtures.read(name <> ".tsr"))
        {:ok, info} = Tspex.decode_token(response.token)
        assert info.hash == hash
        assert info.digest == :crypto.hash(Tspex.Imprint.crypto_name(hash), Fixtures.data())
      end

      {:ok, response} = Tspex.decode_response(Fixtures.read("r_rsa_policy.tsr"))
      {:ok, info} = Tspex.decode_token(response.token)
      assert info.policy == {1, 2, 3, 4, 5, 6}

      {:ok, response} = Tspex.decode_response(Fixtures.read("r_rsa_no_nonce.tsr"))
      {:ok, info} = Tspex.decode_token(response.token)
      assert info.nonce == nil
    end

    test "bounds/1 is the time plus and minus the accuracy" do
      {:ok, info} = Tspex.decode_token(Fixtures.read("r_rsa.tst"))
      {low, high} = TSTInfo.bounds(info)
      assert DateTime.diff(info.gen_time, low, :microsecond) == 1_500_100
      assert DateTime.diff(high, info.gen_time, :microsecond) == 1_500_100
    end
  end

  describe "the TSTInfo" do
    test "the fields that are required, and the defaults of those that are not" do
      assert {:ok, info} = parse(base())
      assert info.version == 1
      assert info.policy == {1, 2, 3, 4, 1}
      assert info.serial == 5
      assert info.gen_time == ~U[2026-11-07 21:27:46Z]
      assert info.accuracy == nil
      assert info.ordering == false
      assert info.nonce == nil
      assert info.tsa == nil
      assert info.extensions == []
      assert info.deviations == []
    end

    test "all the optional fields together" do
      terms =
        base([
          {:seq, [{:int, 2}, {:primitive, 0, <<0x03, 0xE7>>}, {:primitive, 1, <<7>>}]},
          {:bool, true},
          {:int, 99},
          {:explicit, 0, {:primitive, 2, "tsa.example.org"}},
          {:implicit, 1,
           {:seq, [{:seq, [{:oid, {1, 2, 3}}, {:bool, true}, {:octets, <<5, 0>>}]}]}}
        ])

      assert {:ok, info} = parse(terms)
      assert info.accuracy == %{seconds: 2, millis: 999, micros: 7}
      assert info.ordering == true
      assert info.nonce == 99
      assert info.tsa == {:dns_name, "tsa.example.org"}
      assert info.extensions == [%{oid: {1, 2, 3}, critical: true, value: <<5, 0>>}]
    end

    test "N10: a serial number of more than 32 octets" do
      big = {:raw, <<2, 33, 1, :binary.copy(<<255>>, 32)::binary>>}
      assert {:error, %Error{reason: :malformed}} = parse(List.replace_at(base(), 3, big))
    end

    test "N31: version 2 (and 0)" do
      assert {:error, %Error{reason: :unsupported_version, detail: 2}} =
               parse(List.replace_at(base(), 0, {:int, 2}))

      assert {:error, %Error{reason: :unsupported_version, detail: 0}} =
               parse(List.replace_at(base(), 0, {:int, 0}))
    end

    test "N19: genTime with the tag of UTCTime" do
      utc = {:raw, <<0x17, 13, "261107212746Z">>}
      assert {:error, %Error{reason: :malformed}} = parse(List.replace_at(base(), 4, utc))
    end

    test "N17: a fraction that is not DER is read with the deviation" do
      terms = List.replace_at(base(), 4, gen_time("20261107212746.500Z"))
      assert {:ok, info} = parse(terms)
      assert info.deviations == [:gen_time_encoding]
      assert info.gen_time == ~U[2026-11-07 21:27:46.500000Z]

      terms = List.replace_at(base(), 4, gen_time("20261107212746.5Z"))
      assert {:ok, %{deviations: []}} = parse(terms)
    end

    test "N11 to N16, N18: a genTime that is not valid" do
      for bad <- [
            "20261107212746",
            "202611072127Z",
            "20261107212760Z",
            "20261307212746Z",
            "20261132212746Z",
            "20261107242746Z",
            "20261107212746,5Z",
            "20261107212746.Z",
            "20261107212746+0300"
          ] do
        assert {:error, %Error{reason: :malformed}} =
                 parse(List.replace_at(base(), 4, gen_time(bad))),
               bad
      end
    end

    test "a genTime that is not a time, a policy that is not an OID, and so on" do
      assert {:error, %Error{reason: :malformed}} = parse(List.replace_at(base(), 4, {:int, 5}))
      assert {:error, %Error{reason: :malformed}} = parse(List.replace_at(base(), 1, {:int, 5}))

      assert {:error, %Error{reason: :malformed}} =
               parse(List.replace_at(base(), 3, {:oid, {1, 2}}))

      assert {:error, %Error{reason: :malformed}} =
               parse(List.replace_at(base(), 2, {:octets, "x"}))
    end

    test "too few elements, or an unknown one at the end, is malformed" do
      assert {:error, %Error{reason: :malformed}} = parse(Enum.take(base(), 4))
      assert {:error, %Error{reason: :malformed}} = parse([])
      assert {:error, %Error{reason: :malformed}} = parse(base([{:octets, "x"}]))
      assert {:error, %Error{reason: :malformed}} = parse(base([{:int, 1}, {:int, 2}]))
    end

    test "optional fields out of order or twice are malformed" do
      assert {:error, %Error{reason: :malformed}} = parse(base([{:int, 1}, {:bool, true}]))
      assert {:error, %Error{reason: :malformed}} = parse(base([{:bool, true}, {:bool, true}]))

      assert {:error, %Error{reason: :malformed}} =
               parse(base([{:seq, []}, {:seq, []}]))
    end

    test "the message imprint: unknown hash, MD5, wrong size" do
      assert {:ok, info} = parse(List.replace_at(base(), 2, imprint({1, 2, 3, 4}, "any size")))
      assert info.hash == {1, 2, 3, 4}
      assert info.digest == "any size"

      md5 = imprint({1, 2, 840, 113_549, 2, 5}, :binary.copy(<<1>>, 16))
      assert {:ok, %{hash: :md5}} = parse(List.replace_at(base(), 2, md5))

      assert {:error, %Error{reason: :malformed}} =
               parse(List.replace_at(base(), 2, imprint(@sha256, :binary.copy(<<1>>, 31))))
    end

    test "an imprint without NULL parameters is read the same" do
      bare = {:seq, [{:seq, [{:oid, @sha256}]}, {:octets, @digest}]}
      assert {:ok, a} = parse(List.replace_at(base(), 2, bare))
      assert {:ok, b} = parse(base())
      assert a == b
    end

    test "it is not a SEQUENCE" do
      assert {:error, %Error{reason: :malformed}} = TSTInfo.parse(<<2, 1, 1>>, [])
      assert {:error, %Error{reason: :malformed}} = TSTInfo.parse(<<>>, [])
      assert {:error, %Error{reason: :malformed}} = TSTInfo.parse(der(base()) <> <<0>>, [])
    end
  end

  describe "accuracy" do
    defp accuracy(parts), do: parse(base([{:seq, parts}]))

    test "an empty accuracy is zero, and an absent field is zero" do
      assert {:ok, %{accuracy: %{seconds: 0, millis: 0, micros: 0}}} = accuracy([])
      assert {:ok, %{accuracy: %{seconds: 3, millis: 0, micros: 0}}} = accuracy([{:int, 3}])

      assert {:ok, %{accuracy: %{seconds: 0, millis: 0, micros: 9}}} =
               accuracy([{:primitive, 1, <<9>>}])
    end

    test "N32: millis 1000 and micros 1000 are malformed" do
      assert {:error, %Error{reason: :malformed}} =
               accuracy([{:primitive, 0, <<0x03, 0xE8>>}])

      assert {:error, %Error{reason: :malformed}} =
               accuracy([{:primitive, 1, <<0x03, 0xE8>>}])
    end

    test "N33: millis 0 is read" do
      assert {:ok, %{accuracy: %{millis: 0}}} = accuracy([{:int, 1}, {:primitive, 0, <<0>>}])
    end

    test "a negative value, a huge seconds, a wrong order, a repeated field" do
      assert {:error, %Error{reason: :malformed}} = accuracy([{:int, -1}])
      assert {:error, %Error{reason: :malformed}} = accuracy([{:int, 2_147_483_648}])
      assert {:error, %Error{reason: :malformed}} = accuracy([{:primitive, 0, <<1>>}, {:int, 1}])
      assert {:error, %Error{reason: :malformed}} = accuracy([{:int, 1}, {:int, 1}])
      assert {:error, %Error{reason: :malformed}} = accuracy([{:primitive, 1, <<>>}])
      assert {:error, %Error{reason: :malformed}} = accuracy([{:octets, "x"}])
    end

    test "bounds/1 without accuracy, and near the ends of the calendar" do
      {:ok, info} = parse(base())
      assert TSTInfo.bounds(info) == {info.gen_time, info.gen_time}

      {:ok, info} =
        parse(
          List.replace_at(base([{:seq, [{:int, 2_147_483_647}]}]), 4, gen_time("99991231235959Z"))
        )

      {low, high} = TSTInfo.bounds(info)
      assert high == ~U[9999-12-31 23:59:59.999999Z]
      assert DateTime.compare(low, info.gen_time) == :lt

      {:ok, info} =
        parse(
          List.replace_at(base([{:seq, [{:int, 2_147_483_647}]}]), 4, gen_time("00010101000000Z"))
        )

      {low, _high} = TSTInfo.bounds(info)
      assert low == ~U[0001-01-01 00:00:00.000000Z]
    end
  end

  describe "the name of the TSA" do
    defp tsa(inner), do: parse(base([{:explicit, 0, inner}]))

    test "the kinds of name" do
      assert {:ok, %{tsa: {:dns_name, "a.example"}}} = tsa({:primitive, 2, "a.example"})

      assert {:ok, %{tsa: {:uri, "https://a.example/tsa"}}} =
               tsa({:primitive, 6, "https://a.example/tsa"})

      assert {:ok, %{tsa: {:rfc822_name, "a@example.org"}}} =
               tsa({:primitive, 1, "a@example.org"})

      assert {:ok, %{tsa: {:ip_address, <<192, 0, 2, 1>>}}} =
               tsa({:primitive, 7, <<192, 0, 2, 1>>})

      ip6 = :binary.copy(<<1>>, 16)
      assert {:ok, %{tsa: {:ip_address, ^ip6}}} = tsa({:primitive, 7, ip6})

      name = DER.encode({:seq, [{:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {:utf8, "TSA"}]}]}]})
      assert {:ok, %{tsa: {:directory_name, ^name}}} = tsa({:explicit, 4, {:raw, name}})

      other =
        DER.encode({:explicit, 0, {:seq, [{:oid, {1, 2, 3}}, {:explicit, 0, {:utf8, "x"}}]}})

      assert {:ok, %{tsa: {:other, ^other}}} = tsa({:raw, other})
    end

    test "a malformed name" do
      assert {:error, %Error{reason: :malformed}} = tsa({:primitive, 7, <<1, 2, 3, 4, 5>>})
      assert {:error, %Error{reason: :malformed}} = tsa({:primitive, 2, <<"caf", 0xC3, 0xA9>>})
      assert {:error, %Error{reason: :malformed}} = tsa({:explicit, 4, {:octets, "x"}})

      assert {:error, %Error{reason: :malformed}} =
               parse(
                 base([
                   {:explicit, 0, {:primitive, 2, "a"}},
                   {:explicit, 0, {:primitive, 2, "b"}}
                 ])
               )

      two = {:raw, DER.encode({:primitive, 2, "a"}) <> DER.encode({:primitive, 2, "b"})}
      assert {:error, %Error{reason: :malformed}} = tsa(two)
    end
  end

  describe "extensions" do
    test "an extension that is not well formed" do
      bad = {:implicit, 1, {:seq, [{:int, 1}]}}
      assert {:error, %Error{reason: :malformed}} = parse(base([bad]))

      bad = {:implicit, 1, {:seq, [{:seq, [{:oid, {1, 2}}]}]}}
      assert {:error, %Error{reason: :malformed}} = parse(base([bad]))
    end

    test "extensions are kept in order, with the value as bytes" do
      ext = fn oid, critical ->
        flag = if critical, do: [{:bool, true}], else: []
        {:seq, [{:oid, oid}] ++ flag ++ [{:octets, <<5, 0>>}]}
      end

      assert {:ok, info} =
               parse(
                 base([{:implicit, 1, {:seq, [ext.({1, 2, 3}, false), ext.({1, 2, 4}, true)]}}])
               )

      assert info.extensions == [
               %{oid: {1, 2, 3}, critical: false, value: <<5, 0>>},
               %{oid: {1, 2, 4}, critical: true, value: <<5, 0>>}
             ]
    end
  end

  describe "reading a token" do
    test "a token with a TSTInfo inside" do
      assert {:ok, info} = Tspex.decode_token(token(@tst_info_oid, der(base())))
      assert info.serial == 5
    end

    test "a ContentInfo that is not a SignedData is not a time-stamp token" do
      data =
        DER.encode(
          {:seq, [{:oid, {1, 2, 840, 113_549, 1, 7, 1}}, {:explicit, 0, {:octets, "x"}}]}
        )

      assert {:error, %Error{reason: :not_a_time_stamp_token}} = Tspex.decode_token(data)
    end

    test "a SignedData of another content type, or detached" do
      assert {:error, %Error{reason: :not_a_time_stamp_token, detail: {:content_type, :data}}} =
               Tspex.decode_token(token({1, 2, 840, 113_549, 1, 7, 1}, der(base())))

      assert {:error, %Error{reason: :not_a_time_stamp_token, detail: :detached}} =
               Tspex.decode_token(token(@tst_info_oid, nil))
    end

    test "a TSTInfo that is not valid inside a good token" do
      assert {:error, %Error{reason: :unsupported_version, detail: 2}} =
               Tspex.decode_token(
                 token(@tst_info_oid, der(List.replace_at(base(), 0, {:int, 2})))
               )

      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_token(token(@tst_info_oid, <<1, 2, 3>>))
    end

    test "not DER, not a SEQUENCE, PEM, empty" do
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_token(<<>>)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_token(<<2, 1, 1>>)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_token(<<0x30, 0x80>>)

      pem =
        "-----BEGIN PKCS7-----\n" <>
          Base.encode64(Fixtures.read("r_rsa.tst")) <> "\n-----END PKCS7-----\n"

      assert {:error, %Error{reason: :malformed}} = Tspex.decode_token(pem)
    end

    test "the limits" do
      der = Fixtures.read("r_rsa.tst")

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_size}} =
               Tspex.decode_token(der, max_size: 100)

      assert {:error, %Error{reason: :limit_exceeded}} = Tspex.decode_token(der, max_depth: 3)
      assert {:error, %Error{reason: :limit_exceeded}} = Tspex.decode_token(der, max_nodes: 20)

      assert {:error, %Error{reason: :limit_exceeded}} =
               Tspex.decode_token(der, max_certificates: 0 + 1, max_nodes: 50)
    end

    test "bad arguments raise" do
      assert_raise ArgumentError, fn -> Tspex.decode_token(:token) end
      assert_raise ArgumentError, fn -> Tspex.decode_token(<<>>, bogus: 1) end
      assert_raise ArgumentError, fn -> Tspex.decode_token(<<>>, max_signers: 0) end
    end

    test "decode_token!/2 raises Tspex.Error" do
      assert_raise Error, fn -> Tspex.decode_token!(<<>>) end
      assert %TSTInfo{} = Tspex.decode_token!(Fixtures.read("r_rsa.tst"))
    end
  end
end
