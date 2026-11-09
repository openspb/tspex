defmodule Tspex.TSATest do
  use ExUnit.Case, async: true

  alias Tspex.{Error, Fixtures, TestPKI, TSA}

  @ts TestPKI.time_stamping()
  @now ~U[2026-11-08 12:00:00.000000Z]

  defp cert(opts), do: TestPKI.cert(:p256, opts)
  defp bad(detail), do: {:error, %Error{reason: :bad_tsa_certificate, detail: detail}}

  describe "extKeyUsage" do
    test "the certificate of a TSA: critical, only timeStamping" do
      assert TSA.check(cert(eku: [@ts]), @now, :strict) == :ok
      assert TSA.check(Fixtures.read("tsa_rsa.der"), DateTime.utc_now(), :strict) == :ok
      assert TSA.check(Fixtures.read("tsa_ec.der"), DateTime.utc_now(), :strict) == :ok
    end

    test "N34: no extKeyUsage" do
      assert TSA.check(cert([]), @now, :strict) == bad(:eku_missing)
      assert TSA.check(cert([]), @now, :extra_purposes) == bad(:eku_missing)
    end

    test "N35: not critical" do
      assert TSA.check(cert(eku: [@ts], eku_critical: false), @now, :strict) ==
               bad(:eku_not_critical)
    end

    test "N36: timeStamping and clientAuth, which the default refuses" do
      der = cert(eku: [@ts, TestPKI.client_auth()])
      assert TSA.check(der, @now, :strict) == bad(:eku_extra_purposes)
    end

    test "N121: the same certificate with tsa_eku: :extra_purposes" do
      der = cert(eku: [@ts, TestPKI.client_auth()])
      assert TSA.check(der, @now, :extra_purposes) == :ok
    end

    test "N37, N122: critical, without timeStamping" do
      der = cert(eku: [TestPKI.code_signing()])
      assert TSA.check(der, @now, :strict) == bad(:eku_missing)
      assert TSA.check(der, @now, :extra_purposes) == bad(:eku_missing)
      der = cert(eku: [TestPKI.any_eku()])
      assert TSA.check(der, @now, :strict) == bad(:eku_missing)
    end

    test "N38: two instances of the extension" do
      assert TSA.check(cert(eku: [@ts], eku_twice: true), @now, :strict) == bad(:eku_repeated)
    end
  end

  describe "keyUsage" do
    test "N39: neither digitalSignature nor nonRepudiation" do
      assert TSA.check(cert(eku: [@ts], key_usage: [2]), @now, :strict) == bad(:key_usage)
      assert TSA.check(cert(eku: [@ts], key_usage: [5]), @now, :strict) == bad(:key_usage)
    end

    test "N129, N130: keyEncipherment alone fails, nonRepudiation alone passes" do
      assert TSA.check(cert(eku: [@ts], key_usage: [2]), @now, :strict) == bad(:key_usage)
      assert TSA.check(cert(eku: [@ts], key_usage: [1]), @now, :strict) == :ok
      assert TSA.check(cert(eku: [@ts], key_usage: [0]), @now, :strict) == :ok
      assert TSA.check(cert(eku: [@ts], key_usage: nil), @now, :strict) == :ok
    end
  end

  describe "validity at the time of the token (N40 to N43)" do
    @from ~U[2026-01-01 00:00:00Z]
    @to ~U[2026-12-31 23:59:59Z]
    defp dated, do: cert(eku: [@ts], not_before: @from, not_after: @to)

    test "inside, and on both ends" do
      assert TSA.check(dated(), ~U[2026-06-01 00:00:00.5Z], :strict) == :ok
      assert TSA.check(dated(), @from, :strict) == :ok
      assert TSA.check(dated(), @to, :strict) == :ok
      assert TSA.check(dated(), ~U[2026-12-31 23:59:59.900000Z], :strict) == :ok
    end

    test "after the end, before the start" do
      assert TSA.check(dated(), ~U[2027-01-01 00:00:00Z], :strict) == bad(:not_valid_at_time)
      assert TSA.check(dated(), ~U[2025-12-31 23:59:59Z], :strict) == bad(:not_valid_at_time)
    end

    test "a certificate that has expired today, valid when the token was made" do
      der =
        cert(
          eku: [@ts],
          not_before: ~U[2020-01-01 00:00:00Z],
          not_after: ~U[2021-01-01 00:00:00Z]
        )

      assert TSA.check(der, ~U[2020-06-01 00:00:00Z], :strict) == :ok
      assert TSA.check(der, ~U[2022-06-01 00:00:00Z], :strict) == bad(:not_valid_at_time)
    end
  end

  test "bytes that are not a certificate" do
    assert TSA.check("nope", @now, :strict) == bad(:unreadable)
  end
end
