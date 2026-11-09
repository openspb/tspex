defmodule Tspex.TimeStampedDataTest do
  use Tspex.VerifyCase, async: true
  use ExUnitProperties

  alias Tspex.{DER, Error, TestFuzz, TestHTTPServer, TimeStampedData, Verified}

  @content "the contract, as bytes"
  @oid {1, 2, 840, 113_549, 1, 9, 16, 1, 31}

  setup_all do
    %{tsa: TestTSA.new(), other: TestTSA.new(tag: :other_tsa, root_tag: :other_root)}
  end

  # A token of `tsa` over an imprint, in DER.
  defp token(tsa, imprint, opts \\ []),
    do: TestTSA.token(tsa, Tspex.request!(imprint), opts)

  defp trust(tsa), do: [trust: TestTSA.trust(tsa)]

  # A structure with `count` tokens, each over the one before it.
  defp chain(tsa, count, opts \\ []) do
    {:ok, imprint} = TimeStampedData.imprint(@content, opts)
    {:ok, tsd} = TimeStampedData.new(@content, token(tsa, imprint), opts ++ trust(tsa))

    Enum.reduce(2..count//1, tsd, fn _, acc ->
      {:ok, next} = TimeStampedData.extension_imprint(acc)
      {:ok, acc} = TimeStampedData.extend(acc, token(tsa, next), trust(tsa))
      acc
    end)
  end

  defp meta_opts,
    do: [file_name: "contract.pdf", media_type: "application/pdf", hash_protected: true]

  describe "imprint/2" do
    test "is the hash of the content" do
      assert {:ok, {:digest, :sha256, digest}} = TimeStampedData.imprint(@content)
      assert digest == :crypto.hash(:sha256, @content)

      assert {:ok, {:digest, :sha512, digest}} = TimeStampedData.imprint(@content, hash: :sha512)
      assert digest == :crypto.hash(:sha512, @content)
    end

    test "metadata that is not protected does not change it" do
      {:ok, plain} = TimeStampedData.imprint(@content)
      {:ok, with_meta} = TimeStampedData.imprint(@content, file_name: "a.pdf")
      assert plain == with_meta
    end

    test "the metadata is hashed in DER, in front of the content, when it is protected" do
      {:ok, {:digest, :sha256, digest}} =
        TimeStampedData.imprint(@content, file_name: "a.pdf", hash_protected: true)

      # SEQUENCE { BOOLEAN TRUE, UTF8String "a.pdf" }, written by hand
      meta = <<0x30, 10, 0x01, 1, 0xFF, 0x0C, 5, "a.pdf">>
      assert digest == :crypto.hash(:sha256, meta <> @content)
    end

    test "all the fields of the metadata, as DER" do
      {:ok, {:digest, :sha256, digest}} =
        TimeStampedData.imprint(@content,
          file_name: "a.pdf",
          media_type: "application/pdf",
          other_meta_data: [%{oid: {1, 2, 3}, values: [<<0x04, 1, 9>>]}],
          hash_protected: true
        )

      attribute_body = <<0x06, 2, 0x2A, 0x03, 0x31, 3, 0x04, 1, 9>>
      attribute = <<0x30, byte_size(attribute_body)>> <> attribute_body
      attributes = <<0x31, byte_size(attribute)>> <> attribute
      fields = <<0x01, 1, 0xFF, 0x0C, 5, "a.pdf", 0x16, 15, "application/pdf">> <> attributes
      meta = <<0x30, byte_size(fields)>> <> fields
      assert digest == :crypto.hash(:sha256, meta <> @content)
    end

    test "a stream gives the same imprint as the binary" do
      {:ok, from_binary} = TimeStampedData.imprint(@content, meta_opts())

      {:ok, from_stream} =
        TimeStampedData.imprint({:stream, ["the contract", ", as bytes"]}, meta_opts())

      assert from_binary == from_stream
    end

    test "arguments that cannot be right" do
      for opts <- [
            [hash_protected: true],
            [hash: :sha1],
            [hash: :md5],
            [file_name: ""],
            [file_name: <<0xFF>>],
            [media_type: "tëxt"],
            [other_meta_data: [%{oid: {1, 2, 3}, values: ["not der"]}]],
            [other_meta_data: [:nope]],
            [hash_protected: :yes, file_name: "a"],
            [unknown: 1]
          ] do
        assert_raise ArgumentError, fn -> TimeStampedData.imprint(@content, opts) end
      end

      assert_raise ArgumentError, fn -> TimeStampedData.imprint(:atom) end
      assert {:ok, _} = TimeStampedData.imprint(@content, hash: :sha1, allow_sha1: true)
    end
  end

  describe "new/3, encode/1, decode/2 and verify/2" do
    test "the cycle, with a content inside", %{tsa: tsa} do
      tsd = chain(tsa, 1)

      assert %TimeStampedData{version: 1, content: @content, meta_data: nil, data_uri: nil} = tsd
      assert {:tst, [%{crl: nil}]} = tsd.evidence

      der = TimeStampedData.encode(tsd)
      assert {:ok, ^tsd} = TimeStampedData.decode(der)
      assert ^tsd = TimeStampedData.decode!(der)

      assert {:ok, result} = TimeStampedData.verify(der, trust(tsa))
      assert [%Verified{trust: :validated}] = result.stamps
      assert result.time == hd(result.stamps).info.gen_time
      assert result.crls == [nil]
      assert result.meta_data == nil
      assert {:ok, _} = TimeStampedData.verify(tsd, trust(tsa))
    end

    test "it is a ContentInfo of the right type", %{tsa: tsa} do
      assert {0x30, _, _} = root = elem(DER.decode(TimeStampedData.encode(chain(tsa, 1))), 1)
      assert [oid, {0xA0, _, _}] = DER.children(root)
      assert {:ok, @oid} = DER.oid(oid)
    end

    test "the metadata, protected, travels and is checked", %{tsa: tsa} do
      tsd = chain(tsa, 1, meta_opts())

      assert tsd.meta_data == %{
               hash_protected: true,
               file_name: "contract.pdf",
               media_type: "application/pdf",
               other: []
             }

      der = TimeStampedData.encode(tsd)
      assert {:ok, ^tsd} = TimeStampedData.decode(der)
      assert {:ok, result} = TimeStampedData.verify(der, trust(tsa))
      assert result.meta_data == tsd.meta_data
    end

    test "other metadata is read back", %{tsa: tsa} do
      attributes = [
        %{oid: {1, 2, 3, 4}, values: [<<0x0C, 2, "hi">>]},
        %{oid: {1, 2, 3, 5}, values: [<<0x02, 1, 7>>, <<0x02, 1, 8>>]}
      ]

      tsd = chain(tsa, 1, other_meta_data: attributes, hash_protected: true)
      assert {:ok, back} = tsd |> TimeStampedData.encode() |> TimeStampedData.decode()
      assert Enum.sort_by(back.meta_data.other, & &1.oid) == attributes
      assert {:ok, _} = TimeStampedData.verify(back, trust(tsa))
    end

    test "a content outside, with a dataUri that is never used", %{tsa: tsa} do
      {:ok, imprint} = TimeStampedData.imprint(@content)

      {:ok, tsd} =
        TimeStampedData.new(@content, token(tsa, imprint),
          detached: true,
          data_uri: "http://127.0.0.1:9/contract.pdf",
          trust: TestTSA.trust(tsa)
        )

      assert tsd.content == nil
      assert tsd.data_uri == "http://127.0.0.1:9/contract.pdf"

      der = TimeStampedData.encode(tsd)
      assert {:ok, ^tsd} = TimeStampedData.decode(der)

      assert {:ok, _} = TimeStampedData.verify(der, [content: @content] ++ trust(tsa))

      assert {:ok, _} =
               TimeStampedData.verify(der, [content: {:stream, [@content]}] ++ trust(tsa))

      assert reason(TimeStampedData.verify(der, trust(tsa))) == :content_missing

      assert reason(TimeStampedData.verify(der, [content: "other"] ++ trust(tsa))) ==
               :imprint_mismatch
    end

    test "dataUri is never fetched" do
      port = TestHTTPServer.start(fn %{send: send} -> send.(TestHTTPServer.ok("x")) end)
      tsa = TestTSA.new()
      {:ok, imprint} = TimeStampedData.imprint(@content)

      {:ok, tsd} =
        TimeStampedData.new(@content, token(tsa, imprint),
          detached: true,
          data_uri: "http://127.0.0.1:#{port}/doc",
          trust: TestTSA.trust(tsa)
        )

      assert reason(TimeStampedData.verify(tsd, trust(tsa))) == :content_missing
      assert {:ok, _} = TimeStampedData.verify(tsd, [content: @content] ++ trust(tsa))
      refute_receive {:request, _}, 200

      # the same port does report a request that is made to it
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
      :ok = :gen_tcp.send(socket, "GET /doc HTTP/1.1\r\nHost: x\r\n\r\n")
      assert_receive {:request, _}, 2_000
      :gen_tcp.close(socket)
    end

    test "a stream is always detached and needs a dataUri", %{tsa: tsa} do
      {:ok, imprint} = TimeStampedData.imprint({:stream, [@content]})
      token = token(tsa, imprint)

      assert_raise ArgumentError, fn ->
        TimeStampedData.new({:stream, [@content]}, token, trust(tsa))
      end

      assert {:ok, %{content: nil}} =
               TimeStampedData.new(
                 {:stream, [@content]},
                 token,
                 [data_uri: "urn:x"] ++ trust(tsa)
               )

      assert_raise ArgumentError, fn ->
        TimeStampedData.new(@content, token, [detached: true] ++ trust(tsa))
      end
    end

    test "a content inside and one given are two contents", %{tsa: tsa} do
      der = tsa |> chain(1) |> TimeStampedData.encode()

      assert reason(TimeStampedData.verify(der, [content: @content] ++ trust(tsa))) ==
               :unexpected_content
    end

    test "a Verified is accepted as the first stamp, a token of other data is not", %{tsa: tsa} do
      {:ok, imprint} = TimeStampedData.imprint(@content)
      request = Tspex.request!(imprint)
      response = TestTSA.response(tsa, request)
      verified = Tspex.verify!(response, request, trust(tsa))

      assert {:ok, %TimeStampedData{}} = TimeStampedData.new(@content, verified)
      assert reason(TimeStampedData.new("other data", verified)) == :imprint_mismatch

      assert reason(TimeStampedData.new("other data", token(tsa, imprint), trust(tsa))) ==
               :imprint_mismatch
    end

    test "a token that does not chain to the roots is refused", %{tsa: tsa, other: other} do
      {:ok, imprint} = TimeStampedData.imprint(@content)

      assert reason(TimeStampedData.new(@content, token(other, imprint), trust(tsa))) ==
               :untrusted
    end

    test "a DER token needs :trust", %{tsa: tsa} do
      {:ok, imprint} = TimeStampedData.imprint(@content)

      assert_raise ArgumentError, ~r/:trust/, fn ->
        TimeStampedData.new(@content, token(tsa, imprint))
      end
    end
  end

  describe "the chain" do
    test "each token covers the element before it", %{tsa: tsa} do
      tsd = chain(tsa, 3)
      {:tst, elements} = tsd.evidence
      assert length(elements) == 3

      der = TimeStampedData.encode(tsd)
      assert {:ok, ^tsd} = TimeStampedData.decode(der)
      assert {:ok, result} = TimeStampedData.verify(der, trust(tsa))
      assert length(result.stamps) == 3

      [first, second, third] = result.stamps
      assert first.info.digest == :crypto.hash(:sha256, @content)
      assert second.info.digest == :crypto.hash(:sha256, Enum.at(elements, 0).raw)
      assert third.info.digest == :crypto.hash(:sha256, Enum.at(elements, 1).raw)
    end

    test "the elements are DER SEQUENCEs of the token and the CRL", %{tsa: tsa} do
      {:tst, [element]} = chain(tsa, 1).evidence
      assert element.raw == DER.encode({:seq, [{:raw, element.token}]})
    end

    test "the crl goes in the element the next token covers", %{tsa: tsa} do
      crl = DER.encode({:seq, [{:seq, []}, {:seq, []}, {:bits, <<0>>}]})
      tsd = chain(tsa, 1)

      {:ok, imprint} = TimeStampedData.extension_imprint(tsd, crl: crl)
      {:ok, plain} = TimeStampedData.extension_imprint(tsd)
      assert imprint != plain

      assert {:ok, tsd} =
               TimeStampedData.extend(tsd, token(tsa, imprint), [crl: crl] ++ trust(tsa))

      {:tst, [first, _second]} = tsd.evidence
      assert first.crl == crl
      assert first.raw == DER.encode({:seq, [{:raw, first.token}, {:raw, crl}]})

      der = TimeStampedData.encode(tsd)
      assert {:ok, ^tsd} = TimeStampedData.decode(der)
      assert {:ok, result} = TimeStampedData.verify(der, trust(tsa))
      assert result.crls == [crl, nil]
    end

    test "a token over the element without the crl does not pass with the crl", %{tsa: tsa} do
      crl = DER.encode({:seq, [{:seq, []}, {:seq, []}, {:bits, <<0>>}]})
      tsd = chain(tsa, 1)
      {:ok, plain} = TimeStampedData.extension_imprint(tsd)

      assert reason(TimeStampedData.extend(tsd, token(tsa, plain), [crl: crl] ++ trust(tsa))) ==
               :imprint_mismatch
    end

    test "a token over the content, as the second one, is refused", %{tsa: tsa} do
      tsd = chain(tsa, 1)
      {:ok, imprint} = TimeStampedData.imprint(@content)

      assert reason(TimeStampedData.extend(tsd, token(tsa, imprint), trust(tsa))) ==
               :imprint_mismatch
    end

    test "a second token over the wrong element fails the verification", %{tsa: tsa} do
      {:tst, [first]} = chain(tsa, 1).evidence
      wrong = first.raw <> <<0>>

      {:ok, imprint} =
        Tspex.Imprint.digest(wrong, :sha256)
        |> then(fn {:ok, d} -> {:ok, {:digest, :sha256, d}} end)

      bad =
        struct(TimeStampedData,
          content: @content,
          evidence: {:tst, [first, fake_element(token(tsa, imprint))]}
        )

      assert reason(TimeStampedData.verify(bad, trust(tsa))) == :imprint_mismatch
    end

    test "changing the content breaks the first token", %{tsa: tsa} do
      tsd = %{chain(tsa, 2) | content: @content <> "!"}
      assert reason(TimeStampedData.verify(tsd, trust(tsa))) == :imprint_mismatch
    end

    test "changing a token breaks the one after it", %{tsa: tsa} do
      tsd = chain(tsa, 2)
      {:tst, [first, second]} = tsd.evidence

      # a stamp of the first element that is not the one the second covers
      other = TestTSA.token(tsa, Tspex.request!(@content <> "x"), [])
      changed = fake_element(other)
      bad = %{tsd | evidence: {:tst, [changed, second]}}
      assert reason(TimeStampedData.verify(bad, trust(tsa))) == :imprint_mismatch

      assert {:ok, _} =
               TimeStampedData.verify(%{tsd | evidence: {:tst, [first, second]}}, trust(tsa))
    end

    test "the metadata, when protected, is under the first token", %{tsa: tsa} do
      tsd = chain(tsa, 1, meta_opts())
      altered = %{tsd | meta_data: %{tsd.meta_data | file_name: "other.pdf"}}
      assert reason(TimeStampedData.verify(altered, trust(tsa))) == :imprint_mismatch
    end

    test "the metadata, when not protected, is only a label", %{tsa: tsa} do
      tsd = chain(tsa, 1, file_name: "a.pdf")
      altered = %{tsd | meta_data: %{tsd.meta_data | file_name: "other.pdf"}}
      assert {:ok, _} = TimeStampedData.verify(altered, trust(tsa))
    end

    test "a hash that is not the first one", %{tsa: tsa} do
      {:ok, imprint} = TimeStampedData.imprint(@content, hash: :sha512)
      {:ok, tsd} = TimeStampedData.new(@content, token(tsa, imprint), trust(tsa))
      {:ok, next} = TimeStampedData.extension_imprint(tsd, hash: :sha384)
      assert {:digest, :sha384, _} = next
      {:ok, tsd} = TimeStampedData.extend(tsd, token(tsa, next), trust(tsa))

      assert {:ok, result} = TimeStampedData.verify(tsd, trust(tsa))
      assert Enum.map(result.stamps, & &1.info.hash) == [:sha512, :sha384]
    end

    test "the certificate of each TSA is judged at the time of its own token" do
      tsa =
        TestTSA.new(
          cert: [not_before: ~U[2020-01-01 00:00:00Z], not_after: ~U[2021-01-01 00:00:00Z]],
          root: old_root()
        )

      {:ok, imprint} = TimeStampedData.imprint(@content)

      {:ok, tsd} =
        TimeStampedData.new(
          @content,
          token(tsa, imprint, gen_time: ~U[2020-06-01 00:00:00Z]),
          trust(tsa)
        )

      {:ok, next} = TimeStampedData.extension_imprint(tsd)
      late = token(tsa, next, gen_time: ~U[2022-06-01 00:00:00Z])

      assert failure(TimeStampedData.extend(tsd, late, trust(tsa))) ==
               {:bad_tsa_certificate, :not_valid_at_time}

      early = token(tsa, next, gen_time: ~U[2020-09-01 00:00:00Z])
      assert {:ok, tsd} = TimeStampedData.extend(tsd, early, trust(tsa))
      assert {:ok, result} = TimeStampedData.verify(tsd, trust(tsa))
      assert result.time == ~U[2020-06-01 00:00:00Z]
    end

    test "two TSAs in one chain", %{tsa: tsa, other: other} do
      tsd = chain(tsa, 1)
      {:ok, next} = TimeStampedData.extension_imprint(tsd)
      {:ok, tsd} = TimeStampedData.extend(tsd, token(other, next), trust(other))

      assert reason(TimeStampedData.verify(tsd, trust(tsa))) == :untrusted
      roots = TestTSA.trust(tsa) ++ TestTSA.trust(other)
      assert {:ok, %{stamps: [_, _]}} = TimeStampedData.verify(tsd, trust: roots)
    end

    test "the options of verify/3 apply to each token", %{tsa: tsa} do
      tsd = chain(tsa, 2)

      assert reason(TimeStampedData.verify(tsd, [policies: ["1.2.9.9"]] ++ trust(tsa))) ==
               :policy_mismatch

      assert {:ok, %{stamps: [%{revocation: :checked}, %{revocation: :checked}]}} =
               TimeStampedData.verify(tsd, [revocation: fn _path, _time -> :ok end] ++ trust(tsa))

      assert failure(
               TimeStampedData.verify(
                 tsd,
                 [revocation: fn _, _ -> {:error, :revoked} end] ++ trust(tsa)
               )
             ) ==
               {:untrusted, {:revocation, :revoked}}
    end

    test "time_stamps/2 reads the TSTInfo of each token", %{tsa: tsa} do
      tsd = chain(tsa, 3)
      assert {:ok, [first, _, _]} = TimeStampedData.time_stamps(tsd)
      assert first.digest == :crypto.hash(:sha256, @content)
      assert {:ok, [_, _, _]} = tsd |> TimeStampedData.encode() |> TimeStampedData.time_stamps()
    end

    test ":max_stamps bounds the chain", %{tsa: tsa} do
      tsd = chain(tsa, 3)
      der = TimeStampedData.encode(tsd)

      assert {:error, %{reason: :limit_exceeded, detail: :max_stamps}} =
               TimeStampedData.decode(der, max_stamps: 2)

      assert {:error, %{reason: :limit_exceeded, detail: :max_stamps}} =
               TimeStampedData.verify(tsd, [max_stamps: 2] ++ trust(tsa))

      assert {:ok, _} = TimeStampedData.decode(der, max_stamps: 3)
      assert_raise ArgumentError, fn -> TimeStampedData.decode(der, max_stamps: 0) end
    end
  end

  describe "what is read" do
    # The structure with the pieces replaced, for the cases the builders
    # refuse to make.
    defp build(tsa, fields \\ []) do
      {:tst, [element]} = chain(tsa, 1).evidence
      version = Keyword.get(fields, :version, 1)
      evidence = Keyword.get(fields, :evidence, {:implicit, 0, {:seq, [{:raw, element.raw}]}})
      middle = Keyword.get(fields, :middle, [{:octets, @content}])

      DER.encode(
        {:seq, [{:oid, @oid}, {:explicit, 0, {:seq, [{:int, version}] ++ middle ++ [evidence]}}]}
      )
    end

    test "a structure that is right", %{tsa: tsa} do
      assert {:ok, %TimeStampedData{content: @content}} = TimeStampedData.decode(build(tsa))
    end

    test "a version that is not 1", %{tsa: tsa} do
      for version <- [0, 2, 5] do
        assert failure(TimeStampedData.decode(build(tsa, version: version))) ==
                 {:unsupported_version, version}
      end
    end

    test "evidence with a tag that is not defined", %{tsa: tsa} do
      for tag <- [3, 4] do
        evidence = {:implicit, tag, {:seq, []}}
        assert reason(TimeStampedData.decode(build(tsa, evidence: evidence))) == :malformed
      end

      assert reason(TimeStampedData.decode(build(tsa, evidence: {:seq, []}))) == :malformed
    end

    test "evidence with no element", %{tsa: tsa} do
      evidence = {:implicit, 0, {:seq, []}}
      assert reason(TimeStampedData.decode(build(tsa, evidence: evidence))) == :malformed
    end

    test "an element that is not a token and a crl", %{tsa: tsa} do
      for items <- [
            [],
            [{:int, 1}],
            [{:seq, []}, {:int, 1}],
            [{:seq, []}, {:seq, []}, {:seq, []}]
          ] do
        evidence = {:implicit, 0, {:seq, [{:seq, items}]}}

        assert reason(TimeStampedData.decode(build(tsa, evidence: evidence))) == :malformed,
               inspect(items)
      end
    end

    test "no content and no dataUri", %{tsa: tsa} do
      assert reason(TimeStampedData.decode(build(tsa, middle: []))) == :malformed
    end

    test "a dataUri alone is enough", %{tsa: tsa} do
      assert {:ok, %{content: nil, data_uri: "urn:x"}} =
               TimeStampedData.decode(build(tsa, middle: [{:ia5, "urn:x"}]))
    end

    test "a MetaData with nothing in it, or out of order", %{tsa: tsa} do
      empty = {:seq, [{:bool, true}]}

      assert reason(TimeStampedData.decode(build(tsa, middle: [empty, {:octets, @content}]))) ==
               :malformed

      misplaced = {:seq, [{:bool, false}, {:ia5, "text/plain"}, {:utf8, "name"}]}

      assert reason(TimeStampedData.decode(build(tsa, middle: [misplaced, {:octets, @content}]))) ==
               :malformed

      empty_set = {:seq, [{:bool, false}, {:set, []}]}

      assert reason(TimeStampedData.decode(build(tsa, middle: [empty_set, {:octets, @content}]))) ==
               :malformed
    end

    test "other evidence and the evidence record are read, written and not verified", %{tsa: tsa} do
      ers = {:implicit, 1, {:seq, [{:int, 1}]}}
      other = {:implicit, 2, {:seq, [{:oid, {1, 2, 3}}, {:octets, "x"}]}}

      for evidence <- [ers, other] do
        der = build(tsa, evidence: evidence)
        assert {:ok, tsd} = TimeStampedData.decode(der)
        assert TimeStampedData.encode(tsd) == der
        assert reason(TimeStampedData.verify(tsd, trust(tsa))) == :unsupported_evidence
        assert reason(TimeStampedData.verify(der, trust(tsa))) == :unsupported_evidence
        assert reason(TimeStampedData.time_stamps(tsd)) == :unsupported_evidence
        assert reason(TimeStampedData.extension_imprint(tsd)) == :unsupported_evidence
      end

      assert {:ers, _} = elem(TimeStampedData.decode(build(tsa, evidence: ers)), 1).evidence

      assert {:other, {1, 2, 3}, _} =
               elem(TimeStampedData.decode(build(tsa, evidence: other)), 1).evidence
    end

    test "something else", %{tsa: tsa} do
      assert reason(TimeStampedData.decode("")) == :malformed
      assert reason(TimeStampedData.decode(<<0x30, 0>>)) == :malformed

      assert reason(
               TimeStampedData.decode(
                 DER.encode({:seq, [{:oid, {1, 2, 3}}, {:explicit, 0, {:seq, []}}]})
               )
             ) == :malformed

      assert reason(TimeStampedData.decode(build(tsa) <> <<0>>)) == :malformed

      assert {:error, %{reason: :limit_exceeded}} =
               TimeStampedData.decode(build(tsa), max_size: 10)
    end

    test "BER: indefinite lengths and a constructed content", %{tsa: tsa} do
      tsd = chain(tsa, 1)
      {:tst, [element]} = tsd.evidence

      indefinite = fn tag, inner -> <<tag, 0x80>> <> inner <> <<0, 0>> end

      content =
        indefinite.(
          0x24,
          DER.encode({:octets, "the contract, "}) <> DER.encode({:octets, "as bytes"})
        )

      body =
        DER.encode({:int, 1}) <>
          content <> indefinite.(0xA0, element.raw)

      der =
        indefinite.(
          0x30,
          DER.encode({:oid, @oid}) <> indefinite.(0xA0, indefinite.(0x30, body))
        )

      assert {:ok, ber} = TimeStampedData.decode(der)
      assert ber.content == @content
      assert ber.evidence == tsd.evidence
      assert {:ok, _} = TimeStampedData.verify(der, trust(tsa))
    end

    test "arguments that cannot be right", %{tsa: tsa} do
      assert_raise ArgumentError, fn -> TimeStampedData.decode(:atom) end
      assert_raise ArgumentError, fn -> TimeStampedData.verify(:atom, trust(tsa)) end
      assert_raise ArgumentError, fn -> TimeStampedData.verify(chain(tsa, 1), []) end

      assert_raise ArgumentError, fn ->
        TimeStampedData.verify(chain(tsa, 1), trust: :none, bogus: 1)
      end
    end
  end

  describe "any input" do
    # A structure with metadata, three tokens and a CRL in the first element.
    defp rich(tsa) do
      crl = DER.encode({:seq, [{:seq, []}, {:seq, []}, {:bits, <<0>>}]})
      tsd = chain(tsa, 1, meta_opts())
      {:ok, next} = TimeStampedData.extension_imprint(tsd, crl: crl)
      {:ok, tsd} = TimeStampedData.extend(tsd, token(tsa, next), [crl: crl] ++ trust(tsa))
      {:ok, next} = TimeStampedData.extension_imprint(tsd)
      {:ok, tsd} = TimeStampedData.extend(tsd, token(tsa, next), trust(tsa))
      tsd
    end

    defp ok_or_error?({:ok, _}), do: true
    defp ok_or_error?({:error, %Error{}}), do: true
    defp ok_or_error?(_), do: false

    property "a structure with edits is read or refused, never raised on", %{tsa: tsa} do
      base = tsa |> rich() |> TimeStampedData.encode()
      options = [max_stamps: 8] ++ trust(tsa)

      check all input <- TestFuzz.mutated(base), max_runs: TestFuzz.rounds(100) do
        assert ok_or_error?(TimeStampedData.decode(input, max_stamps: 8))
        assert ok_or_error?(TimeStampedData.time_stamps(input, max_stamps: 8))
        assert ok_or_error?(TimeStampedData.verify(input, options))
      end
    end

    property "random bytes are refused, never raised on", %{tsa: tsa} do
      check all input <- TestFuzz.random(), max_runs: TestFuzz.rounds(100) do
        assert {:error, %Error{}} = TimeStampedData.decode(input)
        assert {:error, %Error{}} = TimeStampedData.verify(input, trust(tsa))
      end
    end

    property "what decodes encodes to the same structure again", %{tsa: tsa} do
      base = tsa |> rich() |> TimeStampedData.encode()

      check all input <- TestFuzz.mutated(base), max_runs: TestFuzz.rounds(100) do
        case TimeStampedData.decode(input) do
          {:ok, tsd} ->
            assert {:ok, ^tsd} = tsd |> TimeStampedData.encode() |> TimeStampedData.decode()

          {:error, %Error{}} ->
            :ok
        end
      end
    end
  end

  # An element made of a token only.
  defp fake_element(token) do
    raw = DER.encode({:seq, [{:raw, token}]})
    %{token: token, crl: nil, raw: raw}
  end
end
