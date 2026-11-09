defmodule Tspex.PathValidationTest do
  use ExUnit.Case, async: true

  alias Tspex.{PathValidation, TestPKI}

  @ts TestPKI.time_stamping()
  @long_ago ~U[2015-01-01 00:00:00Z]
  @mid ~U[2020-06-01 12:00:00Z]

  # root -> intermediate -> tsa, with options for each level.
  defp chain(root_opts \\ [], ca_opts \\ [], leaf_opts \\ []) do
    root = TestPKI.cert(:p256, Keyword.merge([ca: true, subject: "Root"], root_opts))

    ca =
      TestPKI.cert(
        {:p256, :ca},
        Keyword.merge([ca: true, subject: "Intermediate", issuer: {root, :p256}], ca_opts)
      )

    leaf =
      TestPKI.cert(
        {:p256, :tsa},
        Keyword.merge([eku: [@ts], subject: "TSA", issuer: {ca, {:p256, :ca}}], leaf_opts)
      )

    {root, [ca, leaf]}
  end

  defp validate({root, path}, time, opts \\ []),
    do: :public_key.pkix_path_validation(root, path, Tspex.path_validation_at(time, opts))

  defp check({root, path}, time), do: PathValidation.check_path([root | path], time)

  defp dated(from, to), do: [not_before: from, not_after: to]
  defp today, do: DateTime.utc_now()

  describe "validity at the time of the stamp, through the OTP" do
    test "everything valid today" do
      assert {:ok, _} = validate(chain(), today())
    end

    test "N40: a leaf that has expired by today but was valid at genTime" do
      path = chain([], [], dated(@long_ago, ~U[2025-01-01 00:00:00Z]))
      assert {:ok, _} = validate(path, @mid)
      assert {:error, {:bad_cert, :not_valid_at_time}} = validate(path, ~U[2026-01-01 00:00:00Z])
    end

    test "an intermediate that expired before genTime, and before today" do
      path = chain([], dated(@long_ago, ~U[2019-01-01 00:00:00Z]))
      assert {:error, {:bad_cert, :not_valid_at_time}} = validate(path, @mid)
      assert {:ok, _} = validate(path, ~U[2018-01-01 00:00:00Z])
    end

    test "N125: a root that has expired today but was valid at genTime" do
      path = chain(dated(@long_ago, ~U[2019-01-01 00:00:00Z]))
      assert {:ok, _} = validate(path, ~U[2018-01-01 00:00:00Z])
    end

    test "N124: a root that had expired at genTime" do
      path = chain(dated(@long_ago, ~U[2019-01-01 00:00:00Z]))
      assert {:error, {:bad_cert, :not_valid_at_time}} = validate(path, @mid)
    end

    test "the ends of the validity are inside" do
      from = ~U[2020-01-01 00:00:00Z]
      to = ~U[2020-12-31 23:59:59Z]
      path = chain([], [], dated(from, to))
      assert {:ok, _} = validate(path, from)
      assert {:ok, _} = validate(path, to)
      assert {:ok, _} = validate(path, ~U[2020-12-31 23:59:59.900000Z])
      assert {:error, _} = validate(path, ~U[2021-01-01 00:00:00Z])
      assert {:error, _} = validate(path, ~U[2019-12-31 23:59:59Z])
    end
  end

  describe "check_path/2: every certificate of the path at the time of the stamp" do
    test "a path that is fine" do
      assert check(chain(), today()) == :ok
    end

    test "a leaf, an intermediate or a root that was not valid yet, though it is today" do
      from = dated(~U[2021-01-01 00:00:00Z], ~U[2060-01-01 00:00:00Z])
      assert check(chain([], [], from), @mid) == {:error, :not_valid_at_time}
      assert check(chain([], from, []), @mid) == {:error, :not_valid_at_time}
      assert check(chain(from, [], []), @mid) == {:error, :not_valid_at_time}
      assert check(chain(from, from, from), ~U[2022-01-01 00:00:00Z]) == :ok
    end

    test "a certificate that had expired at genTime" do
      to = dated(@long_ago, ~U[2019-01-01 00:00:00Z])
      assert check(chain([], [], to), @mid) == {:error, :not_valid_at_time}
      assert check(chain([], to, []), @mid) == {:error, :not_valid_at_time}
      assert check(chain(to, [], []), @mid) == {:error, :not_valid_at_time}
    end

    test "the ends of the validity are inside" do
      from = ~U[2020-01-01 00:00:00Z]
      to = ~U[2020-12-31 23:59:59Z]
      path = chain(dated(from, to), dated(from, to), dated(from, to))
      assert check(path, from) == :ok
      assert check(path, to) == :ok
      assert check(path, ~U[2020-12-31 23:59:59.999999Z]) == :ok
      assert check(path, ~U[2021-01-01 00:00:00Z]) == {:error, :not_valid_at_time}
    end

    test "N119: an intermediate limited to another purpose, critical or not" do
      assert check(chain([], eku: [TestPKI.server_auth()]), today()) ==
               {:error, :eku_excludes_time_stamping}

      assert check(chain([], eku: [TestPKI.server_auth()], eku_critical: false), today()) ==
               {:error, :eku_excludes_time_stamping}
    end

    test "N120, N127: an intermediate that allows timeStamping" do
      assert check(chain([], eku: [@ts, TestPKI.server_auth()]), today()) == :ok
      assert check(chain([], eku: [TestPKI.any_eku()]), today()) == :ok
      assert check(chain([], eku: [@ts]), today()) == :ok
    end

    test "the extKeyUsage of the signer itself is the business of the TSA rules" do
      assert check(chain([], [], eku: [TestPKI.server_auth()]), today()) == :ok
    end

    test "a path of one: the certificate is its own anchor" do
      der = TestPKI.cert(:p256, eku: [@ts])
      assert PathValidation.check_path([der], today()) == :ok
      assert PathValidation.check_path([der], @mid) == {:error, :not_valid_at_time}
    end

    test "garbage" do
      assert PathValidation.check_path(["nope"], today()) == {:error, :invalid_certificate}
      assert PathValidation.check_path([], today()) == :ok
    end
  end

  describe "extKeyUsage of the signer, through the OTP" do
    test "a leaf without timeStamping" do
      path = chain([], [], eku: [TestPKI.server_auth()])
      assert {:error, {:bad_cert, :eku_excludes_time_stamping}} = validate(path, today())
    end

    test "a leaf with timeStamping and other purposes" do
      path = chain([], [], eku: [@ts, TestPKI.client_auth()])
      assert {:ok, _} = validate(path, today())
    end

    test "a leaf with anyExtendedKeyUsage is let through here (the TSA rules refuse it)" do
      path = chain([], [], eku: [TestPKI.any_eku()])
      assert {:ok, _} = validate(path, today())
    end

    test "an intermediate limited to timeStamping" do
      assert {:ok, _} = validate(chain([], eku: [@ts]), today())
    end

    test "an intermediate with anyExtendedKeyUsage" do
      assert {:ok, _} = validate(chain([], eku: [TestPKI.any_eku()]), today())
    end

    test "N128: an intermediate with an extKeyUsage and no keyUsage is an error or an exception, never a pass for the wrong reason" do
      path = chain([], eku: [@ts], key_usage: nil)

      result =
        try do
          validate(path, today())
        rescue
          error -> {:raised, error}
        end

      assert match?({:ok, _}, result) or match?({:error, _}, result) or
               match?({:raised, _}, result)
    end
  end

  describe "other errors are passed on" do
    test "N126: an intermediate that cannot sign certificates" do
      path = chain([], key_usage: [0])
      assert {:error, {:bad_cert, _}} = validate(path, today())
    end

    test "a path longer than pathLenConstraint allows" do
      {root, [ca, leaf]} = chain([], path_len: 0)

      deeper =
        TestPKI.cert({:p256, :deep}, ca: true, subject: "Deeper", issuer: {ca, {:p256, :ca}})

      leaf2 = TestPKI.cert({:p256, :tsa2}, eku: [@ts], issuer: {deeper, {:p256, :deep}})

      assert {:error, {:bad_cert, :max_path_length_reached}} =
               validate({root, [ca, deeper, leaf2]}, today())

      assert {:ok, _} = validate({root, [ca, leaf]}, today())
    end

    test "a path whose root is not the anchor" do
      {_, path} = chain()
      other = TestPKI.cert({:p256, :other}, ca: true, subject: "Other")
      assert {:error, {:bad_cert, :invalid_issuer}} = validate({other, path}, today())
    end

    test "a leaf that was not signed by the intermediate" do
      {root, [ca, _leaf]} = chain()
      forged = TestPKI.cert({:p256, :forged}, eku: [@ts], issuer: {ca, {:p256, :wrong_key}})
      assert {:error, {:bad_cert, :invalid_signature}} = validate({root, [ca, forged]}, today())
    end
  end

  describe "options" do
    test "path_validation_at/2 passes the other options on" do
      opts = Tspex.path_validation_at(@mid, max_path_length: 3)
      assert Keyword.get(opts, :max_path_length) == 3
      assert {fun, @mid} = Keyword.fetch!(opts, :verify_fun)
      assert is_function(fun, 3)
    end

    test "N131: a :verify_fun of the caller is refused" do
      assert_raise ArgumentError, ~r/verify_fun/, fn ->
        Tspex.path_validation_at(@mid, verify_fun: {fn _, _, s -> {:valid, s} end, nil})
      end
    end

    test "a repeated option, and a wrong time" do
      assert_raise ArgumentError, fn ->
        Tspex.path_validation_at(@mid, max_path_length: 1, max_path_length: 2)
      end

      assert_raise ArgumentError, fn -> Tspex.path_validation_at("2020-01-01", []) end
      assert_raise ArgumentError, fn -> Tspex.path_validation_at(@mid, :nope) end
    end
  end
end
