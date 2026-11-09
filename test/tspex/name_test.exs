defmodule Tspex.NameTest do
  use ExUnit.Case, async: true

  alias Tspex.{Certificate, DER, Name, TestPKI}

  defp cert(opts) do
    {:ok, cert} = Certificate.parse(TestPKI.cert(:p256, opts))
    cert
  end

  defp name(cn, type, org \\ "tspex tests") do
    DER.encode(
      {:seq,
       [
         {:set, [{:seq, [{:oid, {2, 5, 4, 6}}, {:printable, "BR"}]}]},
         {:set, [{:seq, [{:oid, {2, 5, 4, 10}}, {type, org}]}]},
         {:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {type, cn}]}]}
       ]}
    )
  end

  describe "directoryName" do
    test "N114: PrintableString against UTF8String, other case, repeated spaces" do
      cert = cert(subject_name: TestPKI.name_term("tsa example", :utf8))
      tsa = {:directory_name, name("  TSA    EXAMPLE ", :printable, "TSPEX  Tests")}
      assert Name.matches?(tsa, cert)
    end

    test "a different value, a different attribute, a different order of RDNs" do
      cert = cert(subject_name: TestPKI.name_term("tsa one"))
      refute Name.matches?({:directory_name, name("tsa two", :utf8)}, cert)

      other_attribute =
        DER.encode(
          {:seq,
           [
             {:set, [{:seq, [{:oid, {2, 5, 4, 6}}, {:printable, "BR"}]}]},
             {:set, [{:seq, [{:oid, {2, 5, 4, 10}}, {:utf8, "tspex tests"}]}]},
             {:set, [{:seq, [{:oid, {2, 5, 4, 11}}, {:utf8, "tsa one"}]}]}
           ]}
        )

      refute Name.matches?({:directory_name, other_attribute}, cert)

      reversed =
        DER.encode(
          {:seq,
           [
             {:set, [{:seq, [{:oid, {2, 5, 4, 3}}, {:utf8, "tsa one"}]}]},
             {:set, [{:seq, [{:oid, {2, 5, 4, 10}}, {:utf8, "tspex tests"}]}]},
             {:set, [{:seq, [{:oid, {2, 5, 4, 6}}, {:printable, "BR"}]}]}
           ]}
        )

      refute Name.matches?({:directory_name, reversed}, cert)
    end

    test "the members of one RDN are a set" do
      ab =
        DER.encode(
          {:seq,
           [
             {:set,
              [
                {:seq, [{:oid, {2, 5, 4, 3}}, {:utf8, "x"}]},
                {:seq, [{:oid, {2, 5, 4, 5}}, {:printable, "42"}]}
              ]}
           ]}
        )

      ba =
        DER.encode(
          {:seq,
           [
             {:raw,
              <<0x31, 0x0F, 0x30, 0x06, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x02, 0x34, 0x32,
                0x30, 0x03, 0x06, 0x03, 0x55>>}
           ]}
        )

      assert Name.same?({:directory_name, ab}, {:directory_name, ab})
      refute Name.same?({:directory_name, ab}, {:directory_name, ba})
    end

    test "N118: the name of the issuer is not a name of the certificate" do
      ca = TestPKI.cert(:rsa2048, ca: true, subject: "The CA")
      leaf = cert(issuer: {ca, :rsa2048}, subject: "The TSA")
      {:ok, parsed_ca} = Certificate.parse(ca)
      refute Name.matches?({:directory_name, parsed_ca.subject}, leaf)
      assert Name.matches?({:directory_name, leaf.subject}, leaf)
    end

    test "text that is not UTF-8 is compared as bytes" do
      raw = fn bytes ->
        DER.encode(
          {:seq,
           [
             {:set,
              [{:seq, [{:oid, {2, 5, 4, 3}}, {:raw, <<0x0C, byte_size(bytes), bytes::binary>>}]}]}
           ]}
        )
      end

      assert Name.same?(
               {:directory_name, raw.(<<0xFF, 0xFE>>)},
               {:directory_name, raw.(<<0xFF, 0xFE>>)}
             )

      refute Name.same?(
               {:directory_name, raw.(<<0xFF, 0xFE>>)},
               {:directory_name, raw.(<<0xFF, 0xFD>>)}
             )
    end

    test "names that are not names are compared as bytes" do
      assert Name.same?({:directory_name, <<1, 2>>}, {:directory_name, <<1, 2>>})
      refute Name.same?({:directory_name, <<1, 2>>}, {:directory_name, <<1, 3>>})
    end
  end

  describe "the other kinds" do
    test "N115: a dNSName, whatever the case" do
      cert = cert(san: [{:dns, "tsa.example.org"}])
      assert Name.matches?({:dns_name, "TSA.Example.ORG"}, cert)
      refute Name.matches?({:dns_name, "other.example.org"}, cert)
      refute Name.matches?({:dns_name, "*.example.org"}, cert)
    end

    test "N116: a URI when the certificate has only a dNSName" do
      cert = cert(san: [{:dns, "tsa.example.org"}])
      refute Name.matches?({:uri, "https://tsa.example.org/"}, cert)
    end

    test "a URI: scheme and host without case, the rest exact" do
      cert = cert(san: [{:uri, "https://tsa.example.org/tsp?x=1"}])
      assert Name.matches?({:uri, "HTTPS://TSA.Example.org/tsp?x=1"}, cert)
      refute Name.matches?({:uri, "https://tsa.example.org/TSP?x=1"}, cert)
      refute Name.matches?({:uri, "https://tsa.example.org/tsp?x=2"}, cert)
      refute Name.matches?({:uri, "http://tsa.example.org/tsp?x=1"}, cert)
    end

    test "a URI that has no host is compared exactly" do
      assert Name.same?({:uri, "urn:example:a"}, {:uri, "urn:example:a"})
      refute Name.same?({:uri, "urn:example:a"}, {:uri, "URN:example:a"})
    end

    test "N117: an iPAddress that is not the one of the certificate" do
      cert = cert(san: [{:ip, <<192, 0, 2, 1>>}])
      assert Name.matches?({:ip_address, <<192, 0, 2, 1>>}, cert)
      refute Name.matches?({:ip_address, <<192, 0, 2, 2>>}, cert)
      refute Name.matches?({:ip_address, :binary.copy(<<0>>, 16)}, cert)
    end

    test "an e-mail name: the domain without case, the local part exact" do
      cert = cert(san: [{:email, "Ops@Example.org"}])
      assert Name.matches?({:rfc822_name, "Ops@EXAMPLE.ORG"}, cert)
      refute Name.matches?({:rfc822_name, "ops@example.org"}, cert)
      refute Name.matches?({:rfc822_name, "nobody"}, cert)
      assert Name.same?({:rfc822_name, "nobody"}, {:rfc822_name, "nobody"})
    end

    test "other names are equal when their DER is" do
      assert Name.same?({:other, <<1>>}, {:other, <<1>>})
      refute Name.same?({:other, <<1>>}, {:other, <<2>>})
    end

    test "a name of one type never matches another type" do
      cert = cert(san: [{:dns, "tsa.example.org"}])
      refute Name.matches?({:uri, "tsa.example.org"}, cert)
      refute Name.matches?({:rfc822_name, "tsa.example.org"}, cert)
    end
  end
end
