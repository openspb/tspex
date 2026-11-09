defmodule Tspex.VerifyTest do
  use Tspex.VerifyCase, async: true

  alias Tspex.Verified

  setup_all do
    %{tsa: TestTSA.new()}
  end

  describe "a granted response to a request (fresh)" do
    test "is verified, and says what it proves", %{tsa: tsa} do
      {request, response} = issue(tsa)
      assert {:ok, %Verified{} = verified} = verify(tsa, response, request)

      assert verified.status == :granted
      assert verified.info.hash == :sha256
      assert verified.info.digest == request.digest
      assert verified.info.nonce == request.nonce
      assert verified.signer.certificate == tsa.cert
      assert verified.signer.path == [tsa.root, tsa.cert]
      assert %Cmsex.SignerInfo{} = verified.signer.signer_info
      assert verified.token == token_of(response)
      assert verified.certificates == [tsa.cert]
      assert verified.trust == :validated
      assert verified.revocation == :not_checked
      assert verified.deviations == []
    end

    test "every kind of key of the TSA" do
      for opts <- [
            [key: :p256],
            [key: :p384],
            [key: :ed25519],
            [key: :rsa2048],
            [key: :rsa2048, tag: :pss]
          ] do
        tsa = TestTSA.new(opts)
        padding = if opts[:tag] == :pss, do: :pss, else: :pkcs1
        {request, response} = issue(tsa, [], rsa_padding: padding)
        assert {:ok, _} = verify(tsa, response, request), inspect(opts)
      end
    end

    test "every hash" do
      tsa = TestTSA.new()

      for hash <- [:sha224, :sha256, :sha384, :sha512] do
        {request, response} = issue(tsa, hash: hash)
        assert {:ok, %{info: %{hash: ^hash}}} = verify(tsa, response, request)
      end
    end

    test "through an intermediate CA, whose path comes back whole" do
      tsa = TestTSA.new(intermediate: true)
      {request, response} = issue(tsa)
      assert {:ok, verified} = verify(tsa, response, request)
      assert verified.signer.path == [tsa.root, tsa.intermediate, tsa.cert]
    end

    test "the fields the TSA writes reach the result" do
      tsa = TestTSA.new()
      now = DateTime.utc_now()

      {request, response} =
        issue(tsa, [], gen_time: now, accuracy: %{seconds: 1, millis: 500}, ordering: true)

      assert {:ok, %{info: info}} = verify(tsa, response, request)
      assert info.gen_time == now
      assert info.accuracy == %{seconds: 1, millis: 500, micros: 0}
      assert info.ordering
    end

    test "inspect shows the size of the token, not its bytes", %{tsa: tsa} do
      {request, response} = issue(tsa)
      {:ok, verified} = verify(tsa, response, request)
      text = inspect(verified)
      assert text =~ "bytes"
      assert text =~ "trust: :validated"
      refute text =~ "<<48"
    end

    test "verify!/3 returns the result or raises", %{tsa: tsa} do
      {request, response} = issue(tsa)
      assert %Verified{} = Tspex.verify!(response, request, trust: tsa.root |> List.wrap())

      assert_raise Error, fn ->
        Tspex.verify!(response, Tspex.request!("other"), trust: [tsa.root])
      end
    end
  end

  describe "a stored token" do
    test "checked against the data in three forms", %{tsa: tsa} do
      {_, response} = issue(tsa)
      token = token_of(response)

      assert {:ok, %{status: nil}} = verify(tsa, token, {:data, "contract"})
      assert {:ok, _} = verify(tsa, token, {:stream, ["con", "tr", "act"]})
      digest = :crypto.hash(:sha256, "contract")
      assert {:ok, _} = verify(tsa, token, {:digest, :sha256, digest})
    end

    test "the data is hashed with the algorithm the token declares", %{tsa: tsa} do
      for hash <- [:sha384, :sha512] do
        {_, response} = issue(tsa, hash: hash)

        assert {:ok, %{info: %{hash: ^hash}}} =
                 verify(tsa, token_of(response), {:data, "contract"})
      end
    end

    test "other data, a stream of other data, a digest of another algorithm", %{tsa: tsa} do
      {_, response} = issue(tsa)
      token = token_of(response)

      assert failure(verify(tsa, token, {:data, "Contract"})) == {:imprint_mismatch, :digest}
      assert failure(verify(tsa, token, {:stream, ["x"]})) == {:imprint_mismatch, :digest}

      other = :crypto.hash(:sha512, "contract")

      assert failure(verify(tsa, token, {:digest, :sha512, other})) ==
               {:imprint_mismatch, :hash_algorithm}
    end

    test "a whole response with the data: the status is checked and the nonce ignored", %{
      tsa: tsa
    } do
      {_, response} = issue(tsa, [], nonce: 4242)
      assert {:ok, %{status: :granted}} = verify(tsa, response, {:data, "contract"})
    end

    test "a token of another query, as if it were fresh, is a nonce mismatch", %{tsa: tsa} do
      {_, response} = issue(tsa)
      other = Tspex.request!("contract")
      assert reason(verify(tsa, token_of(response), other)) == :nonce_mismatch
    end

    test "a fresh token alone is checked like a response", %{tsa: tsa} do
      {request, response} = issue(tsa)
      assert {:ok, %{status: nil}} = verify(tsa, token_of(response), request)
    end
  end

  describe "the input" do
    test "forced to the wrong form", %{tsa: tsa} do
      {request, response} = issue(tsa)
      token = token_of(response)
      assert reason(verify(tsa, token, request, input: :response)) == :malformed
      assert {:error, %Error{}} = verify(tsa, response, request, input: :token)
      assert {:ok, _} = verify(tsa, response, request, input: :response)
      assert {:ok, _} = verify(tsa, token, request, input: :token)
    end

    test "garbage and limits", %{tsa: tsa} do
      {request, response} = issue(tsa)

      for bad <- [<<>>, <<0x30>>, <<0x30, 0>>, <<0x04, 1, 1>>, "not DER", <<0x30, 0x80>>] do
        assert reason(verify(tsa, bad, request)) == :malformed
      end

      assert failure(verify(tsa, response, request, max_size: 100)) ==
               {:limit_exceeded, :max_size}

      assert reason(verify(tsa, response, request, max_depth: 2)) == :limit_exceeded
      assert reason(verify(tsa, response, request, max_nodes: 5)) == :limit_exceeded
    end

    test "every truncation of a response is an error and never a crash", %{tsa: tsa} do
      {request, response} = issue(tsa)

      for n <- 0..(byte_size(response) - 1)//7 do
        assert {:error, %Error{}} = verify(tsa, binary_part(response, 0, n), request)
      end
    end
  end

  describe "arguments" do
    test "trust is required, and not empty", %{tsa: tsa} do
      {request, response} = issue(tsa)
      assert_raise ArgumentError, ~r/trust/, fn -> Tspex.verify(response, request, []) end
      assert_raise ArgumentError, ~r/trust/, fn -> Tspex.verify(response, request, trust: []) end

      assert_raise ArgumentError, ~r/trust/, fn ->
        Tspex.verify(response, request, trust: [:nope])
      end
    end

    test "other mistakes raise without showing the data", %{tsa: tsa} do
      {request, response} = issue(tsa)
      trust = [trust: [tsa.root]]

      assert_raise ArgumentError, fn -> Tspex.verify(:atom, request, trust) end
      assert_raise ArgumentError, fn -> Tspex.verify(response, "contract", trust) end
      assert_raise ArgumentError, fn -> Tspex.verify(response, {:data, :x}, trust) end
      assert_raise ArgumentError, fn -> Tspex.verify(response, request, trust ++ [nope: 1]) end

      assert_raise ArgumentError, ~r/more than once/, fn ->
        Tspex.verify(response, request, trust ++ [max_skew: 1, max_skew: 2])
      end

      assert_raise ArgumentError, ~r/revocation/, fn ->
        Tspex.verify(response, request, trust: :none, revocation: fn _, _ -> :ok end)
      end

      assert_raise ArgumentError, ~r/verify_fun/, fn ->
        Tspex.verify(
          response,
          request,
          trust ++ [path_validation: [verify_fun: {fn _, _, s -> {:valid, s} end, nil}]]
        )
      end

      error =
        assert_raise ArgumentError, fn -> Tspex.verify(response, {:data, :secret_atom}, trust) end

      refute error.message =~ "secret_atom"
    end

    test "trust: :none verifies the signature and says it did not check the chain", %{
      tsa: tsa
    } do
      {request, response} = issue(tsa)
      assert {:ok, verified} = Tspex.verify(response, request, trust: :none)
      assert verified.trust == :none
      assert verified.signer.path == nil
      assert inspect(verified) =~ "trust: :none"
    end
  end

  describe "responses that are not granted" do
    test "a rejection says why", %{tsa: tsa} do
      {request, response} =
        issue(tsa, [], status: 2, status_text: ["not supported"], fail_info: [0])

      assert {:error, %Error{reason: :rejection, detail: detail}} = verify(tsa, response, request)
      assert detail == %{fail_info: [:bad_alg], text: ["not supported"]}
    end

    test "waiting, and the revocation statuses", %{tsa: tsa} do
      for {status, reason} <- [
            {3, :waiting},
            {4, :revocation_warning},
            {5, :revocation_notification}
          ] do
        {request, response} = issue(tsa, [], status: status)
        assert reason(verify(tsa, response, request)) == reason
      end
    end

    test "granted with modifications, accepted unless refused", %{tsa: tsa} do
      {request, response} = issue(tsa, [], status: 1)
      assert {:ok, %{status: :granted_with_mods}} = verify(tsa, response, request)

      assert reason(verify(tsa, response, request, granted_with_mods: :reject)) ==
               :granted_with_mods
    end

    test "granted and no token", %{tsa: tsa} do
      {request, response} = issue(tsa, [], token: :omit)
      assert reason(verify(tsa, response, request)) == :token_missing
    end

    test "a token with a status that is not granted", %{tsa: tsa} do
      {request, good} = issue(tsa)
      token = token_of(good)
      response = TestTSA.response(tsa, request, status: 2, token: token)
      assert reason(verify(tsa, response, request)) == :unexpected_token
    end

    test "granted with a failInfo bit that is not defined", %{tsa: tsa} do
      {request, response} = issue(tsa, [], fail_info: [30])
      assert failure(verify(tsa, response, request)) == {:unknown_fail_info, [30]}
    end

    test "the same bit in a rejection is read", %{tsa: tsa} do
      {request, response} = issue(tsa, [], status: 2, fail_info: [30])
      assert {:error, %Error{reason: :rejection, detail: detail}} = verify(tsa, response, request)
      assert detail.fail_info == [{:unknown_bit, 30}]
    end

    test "a status outside 0 to 5", %{tsa: tsa} do
      {request, response} = issue(tsa, [], status: 6, token: :omit)
      assert reason(verify(tsa, response, request)) == :unknown_status
    end
  end
end
