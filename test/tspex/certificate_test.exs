defmodule Tspex.CertificateTest do
  use ExUnit.Case, async: true

  alias Tspex.{Certificate, Fixtures, TestPKI}

  test "the certificate of the openssl TSA, field by field" do
    {:ok, cert} = Certificate.parse(Fixtures.read("tsa_rsa.der"))
    assert cert.not_before.year >= 2026
    assert cert.not_after.year >= 2040
    assert [%{critical: true} = eku] = Certificate.extensions(cert, {2, 5, 29, 37})
    assert Certificate.eku_list(eku) == {:ok, [TestPKI.time_stamping()]}
    assert Certificate.key_usage(cert) == [0]
    assert [{:directory_name, subject}] = Certificate.names(cert)
    assert subject =~ "tspex test TSA rsa"
    assert cert.issuer =~ "tspex test CA"
  end

  test "an EC certificate and a root" do
    assert {:ok, _} = Certificate.parse(Fixtures.read("tsa_ec.der"))
    assert {:ok, ca} = Certificate.parse(Fixtures.read("ca.der"))
    assert Certificate.key_usage(ca) == [5, 6]
  end

  test "names: the subject first, then each subjectAltName" do
    der =
      TestPKI.cert(:p256,
        san: [
          {:dns, "tsa.example.org"},
          {:uri, "https://tsa.example.org/tsp"},
          {:ip, <<10, 0, 0, 1>>}
        ]
      )

    {:ok, cert} = Certificate.parse(der)

    assert [
             {:directory_name, _},
             {:dns_name, "tsa.example.org"},
             {:uri, "https://tsa.example.org/tsp"},
             {:ip_address, <<10, 0, 0, 1>>}
           ] = Certificate.names(cert)
  end

  test "an empty subject is not a name" do
    {:ok, cert} =
      Certificate.parse(TestPKI.cert(:p256, empty_subject: true, san: [{:dns, "a.example"}]))

    assert Certificate.names(cert) == [{:dns_name, "a.example"}]
  end

  test "an extension that is written twice is seen twice" do
    {:ok, cert} =
      Certificate.parse(TestPKI.cert(:p256, eku: [TestPKI.time_stamping()], eku_twice: true))

    assert [_, _] = Certificate.extensions(cert, {2, 5, 29, 37})
  end

  test "UTCTime and GeneralizedTime" do
    early =
      TestPKI.cert(:p256,
        not_before: ~U[1999-01-01 00:00:00Z],
        not_after: ~U[2049-12-31 23:59:59Z]
      )

    late =
      TestPKI.cert(:p256,
        not_before: ~U[2050-01-01 00:00:00Z],
        not_after: ~U[2080-01-01 00:00:00Z]
      )

    {:ok, a} = Certificate.parse(early)
    {:ok, b} = Certificate.parse(late)
    assert a.not_before == ~U[1999-01-01 00:00:00Z]
    assert a.not_after == ~U[2049-12-31 23:59:59Z]
    assert b.not_before == ~U[2050-01-01 00:00:00Z]
  end

  test "a validity time with bytes that are not digits, or not text, is unreadable" do
    der = TestPKI.cert(:p256, not_before: ~U[2024-01-01 00:00:00Z])
    assert {:ok, _} = Certificate.parse(der)

    # The first UTCTime is notBefore, written as 13 octets.
    [head, tail] = :binary.split(der, <<0x17, 0x0D>>)

    for bad <- [<<0xFF, 0xFE>>, <<0xC3, 0x28>>, <<0x80, 0x80>>, "ab", "9a", "1 ", "\0\0"] do
      <<_::binary-size(2), rest::binary>> = tail
      assert Certificate.parse(head <> <<0x17, 0x0D>> <> bad <> rest) == :error, inspect(bad)
    end

    # The same in the middle of the text, and in a GeneralizedTime.
    <<year::binary-size(2), _::binary-size(2), rest::binary>> = tail
    assert Certificate.parse(head <> <<0x17, 0x0D>> <> year <> <<0xFF, 0xFE>> <> rest) == :error

    late = TestPKI.cert(:p256, not_before: ~U[2051-01-01 00:00:00Z])
    [head, tail] = :binary.split(late, <<0x18, 0x0F>>)
    <<_::binary-size(4), rest::binary>> = tail

    assert Certificate.parse(head <> <<0x18, 0x0F>> <> <<0xFF, 0xFE, 0xC3, 0x28>> <> rest) ==
             :error
  end

  test "the pathLenConstraint of basicConstraints" do
    parse = fn opts ->
      {:ok, cert} = Certificate.parse(TestPKI.cert(:p256, opts))
      cert
    end

    assert Certificate.path_len(parse.(ca: true, path_len: 0)) == 0
    assert Certificate.path_len(parse.(ca: true, path_len: 3)) == 3
    assert Certificate.path_len(parse.(ca: true)) == nil
    assert Certificate.path_len(parse.([])) == nil
  end

  test "garbage is not a certificate" do
    assert Certificate.parse(<<>>) == :error
    assert Certificate.parse(<<0x30, 0>>) == :error
    assert Certificate.parse("not a certificate") == :error
    assert Certificate.parse(:atom) == :error
    der = Fixtures.read("tsa_rsa.der")

    for n <- 0..(byte_size(der) - 1) do
      assert Certificate.parse(binary_part(der, 0, n)) == :error
    end
  end
end
