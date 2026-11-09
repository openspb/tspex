defmodule Tspex.ResponseTest do
  use ExUnit.Case, async: true

  alias Tspex.{DER, Error, Fixtures}

  defp resp(parts), do: DER.encode({:seq, parts})
  defp info(parts), do: {:seq, parts}
  @token_stub {:seq, [{:oid, {1, 2, 840, 113_549, 1, 7, 2}}]}

  describe "the responses of the openssl tool" do
    test "a rejection for the algorithm (bit 0)" do
      {:ok, r} = Tspex.decode_response(Fixtures.read("r_alg_reject.tsr"))
      assert r.status == :rejection
      assert r.fail_info == [:bad_alg]
      assert r.status_text == ["Message digest algorithm is not supported."]
      assert r.token == nil
      assert r.deviations == []
    end

    test "a rejection for the policy (bit 15)" do
      {:ok, r} = Tspex.decode_response(Fixtures.read("r_policy_reject.tsr"))
      assert r.status == :rejection
      assert r.fail_info == [:unaccepted_policy]
      assert r.status_text == ["Requested policy is not supported."]
      assert r.token == nil
    end

    test "granted responses carry the token, as the bytes received" do
      for name <- ~w(r_rsa r_ec r_rsa_no_nonce r_rsa_policy r_rsa_no_cert r_rsa_sha224
                     r_rsa_sha384 r_rsa_sha512 r_rsa_sha1) do
        der = Fixtures.read(name <> ".tsr")
        {:ok, r} = Tspex.decode_response(der)
        assert r.status == :granted, name
        assert r.fail_info == []
        assert r.status_text == []
        assert <<0x30, _::binary>> = r.token
        # the token is the tail of the response, and it is not copied
        assert binary_part(der, byte_size(der) - byte_size(r.token), byte_size(r.token)) ==
                 r.token
      end
    end
  end

  describe "status (N27, N28)" do
    test "the six statuses" do
      names = [:granted, :granted_with_mods, :rejection, :waiting, :revocation_warning]

      for {name, n} <- Enum.with_index(names) do
        assert {:ok, %{status: ^name}} = Tspex.decode_response(resp([info([{:int, n}])]))
      end

      assert {:ok, %{status: :revocation_notification}} =
               Tspex.decode_response(resp([info([{:int, 5}])]))
    end

    test "N27: status 6 is unknown" do
      assert {:error, %Error{reason: :unknown_status, detail: 6}} =
               Tspex.decode_response(resp([info([{:int, 6}])]))
    end

    test "N28: a negative status is unknown" do
      assert {:error, %Error{reason: :unknown_status, detail: -1}} =
               Tspex.decode_response(resp([info([{:int, -1}])]))
    end

    test "a status that is not an INTEGER is malformed" do
      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:bool, true}])]))
    end
  end

  describe "failInfo and statusString" do
    test "N29: an unknown bit is read, not judged" do
      der = resp([info([{:int, 2}, {:named_bits, [0, 30]}])])
      assert {:ok, r} = Tspex.decode_response(der)
      assert r.fail_info == [:bad_alg, {:unknown_bit, 30}]
    end

    test "all the eight defined bits have a name" do
      bits = [0, 2, 5, 14, 15, 16, 17, 25]
      {:ok, r} = Tspex.decode_response(resp([info([{:int, 2}, {:named_bits, bits}])]))

      assert r.fail_info ==
               [
                 :bad_alg,
                 :bad_request,
                 :bad_data_format,
                 :time_not_available,
                 :unaccepted_policy,
                 :unaccepted_extension,
                 :add_info_not_available,
                 :system_failure
               ]
    end

    test "failInfo without a statusString, and both" do
      {:ok, r} = Tspex.decode_response(resp([info([{:int, 2}, {:named_bits, [5]}])]))
      assert r.fail_info == [:bad_data_format]
      assert r.status_text == []

      text = {:seq, [{:utf8, "one"}, {:utf8, "dois: ação"}]}
      {:ok, r} = Tspex.decode_response(resp([info([{:int, 2}, text, {:named_bits, [0]}])]))
      assert r.status_text == ["one", "dois: ação"]
      assert r.fail_info == [:bad_alg]
    end

    test "N30: an empty statusString is malformed" do
      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:int, 2}, {:seq, []}])]))
    end

    test "a statusString of something that is not a UTF8String, or not UTF-8" do
      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:int, 2}, {:seq, [{:int, 1}]}])]))

      bad = <<0x30, 0x03, 0x0C, 0x01, 0xFF>>

      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:int, 2}, {:raw, bad}])]))
    end

    test "failInfo twice, or before the statusString, is malformed" do
      f = {:named_bits, [0]}
      t = {:seq, [{:utf8, "x"}]}

      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:int, 2}, f, f])]))

      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:int, 2}, f, t])]))
    end
  end

  describe "the token, which is not judged on reading" do
    test "a rejection with a token is read, and so is a grant without one" do
      assert {:ok, %{status: :rejection, token: <<0x30, _::binary>>}} =
               Tspex.decode_response(resp([info([{:int, 2}]), @token_stub]))

      assert {:ok, %{status: :granted, token: nil}} =
               Tspex.decode_response(resp([info([{:int, 0}])]))
    end

    test "something after the token, or a token that is not a SEQUENCE, is malformed" do
      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:int, 0}]), @token_stub, @token_stub]))

      assert {:error, %Error{reason: :malformed}} =
               Tspex.decode_response(resp([info([{:int, 0}]), {:octets, "x"}]))
    end
  end

  describe "malformed input and limits" do
    test "not a SEQUENCE, empty, with a status info that is not a SEQUENCE" do
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_response(<<>>)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_response(<<0x02, 0x01, 0x00>>)
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_response(resp([]))
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_response(resp([{:int, 0}]))
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_response(resp([info([])]))
    end

    test "bytes after the response" do
      der = Fixtures.read("r_alg_reject.tsr")
      assert {:error, %Error{reason: :malformed}} = Tspex.decode_response(der <> <<0>>)
    end

    test "the limits" do
      der = Fixtures.read("r_rsa.tsr")

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_size}} =
               Tspex.decode_response(der, max_size: 100)

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_nodes}} =
               Tspex.decode_response(der, max_nodes: 5)

      assert {:error, %Error{reason: :limit_exceeded, detail: :max_depth}} =
               Tspex.decode_response(der, max_depth: 2)
    end

    test "a bad option or a non-binary raises ArgumentError" do
      assert_raise ArgumentError, fn -> Tspex.decode_response(<<>>, max_size: -1) end
      assert_raise ArgumentError, fn -> Tspex.decode_response(:not_a_binary) end
      assert_raise ArgumentError, fn -> Tspex.decode_response(<<>>, nonce: true) end
    end

    test "decode_response!/2 raises Tspex.Error" do
      assert_raise Error, fn -> Tspex.decode_response!(<<>>) end
      assert %Tspex.Response{} = Tspex.decode_response!(Fixtures.read("r_rsa.tsr"))
    end

    test "no prefix or one-byte change of a response raises" do
      der = Fixtures.read("r_alg_reject.tsr")

      for n <- 0..(byte_size(der) - 1) do
        assert {:error, %Error{}} = Tspex.decode_response(binary_part(der, 0, n))
      end

      for n <- 0..(byte_size(der) - 1), byte <- [0x00, 0xFF, 0x30, 0x02] do
        <<a::binary-size(n), _, b::binary>> = der
        result = Tspex.decode_response(<<a::binary, byte, b::binary>>)
        assert match?({:ok, _}, result) or match?({:error, %Error{}}, result)
      end
    end
  end
end
