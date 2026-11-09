defmodule Tspex.VerifyRobustnessTest do
  # `Tspex.verify/3` returns `{:ok, _}` or `{:error, %Tspex.Error{}}` for any
  # token, and never raises. The token is the input of an adversary that can
  # sign with its own key and bring its own certificates, so every field the
  # verification reads is hit: here one byte at a time is replaced by values
  # that are not valid in text (0x80, 0xC3, 0xFF), in a number, or in DER.
  use Tspex.VerifyCase, async: true
  use ExUnitProperties

  alias Tspex.TestFuzz

  defp sample(kind) do
    tsa = TestTSA.new(key: kind, intermediate: true)
    request = Tspex.request!("contract", cert_req: true, nonce: 123_456_789)

    response =
      TestTSA.response(tsa, request,
        status_text: ["granted"],
        accuracy: %{seconds: 1, millis: 500, micros: 7},
        ordering: true,
        tsa_name: :subject,
        extensions: [%{oid: {1, 2, 3, 4}, critical: false, value: <<5, 0>>}]
      )

    {tsa, request, response}
  end

  for kind <- [:p256, :rsa2048] do
    test "a response with one byte changed, #{kind}, trusted" do
      {tsa, request, response} = sample(unquote(kind))
      assert {:ok, _} = verify(tsa, response, request)

      assert TestFuzz.sweep(response, &verify(tsa, &1, request)) == []
    end
  end

  test "a bare token with one byte changed, without roots" do
    {tsa, request, response} = sample(:p256)
    token = token_of(response)
    opts = [trust: :none]
    assert {:ok, _} = Tspex.verify(token, request, opts)

    assert TestFuzz.sweep(token, &Tspex.verify(&1, request, opts)) == []
    _ = tsa
  end

  # The signature covers the TSTInfo and the ESSCertID covers the signer
  # certificate, so a change in either is stopped by the signature before the
  # code that reads those fields runs. An adversary signs after the change,
  # and so does this: the token is made again around each changed copy.
  test "a TSTInfo with one byte changed and signed again" do
    {tsa, request, _response} = sample(:p256)

    info =
      TestTSA.tst_info(tsa, request,
        accuracy: %{seconds: 1, millis: 500, micros: 7},
        ordering: true,
        tsa_name: :subject,
        extensions: [%{oid: {1, 2, 3, 4}, critical: false, value: <<5, 0>>}]
      )

    opts = []
    assert {:ok, _} = verify(tsa, TestTSA.token(tsa, request, tst_info: info), request, opts)

    check = fn changed ->
      verify(tsa, TestTSA.token(tsa, request, tst_info: changed), request, opts)
    end

    assert TestFuzz.sweep(info, check) == []
  end

  test "a signer certificate with one byte changed and signed again" do
    {tsa, request, _response} = sample(:p256)
    opts = [tsa_eku: :strict]

    check = fn changed ->
      other = %{tsa | cert: changed}

      token =
        try do
          TestTSA.token(other, request, ess: :v2, ess_issuer_serial: false)
        rescue
          _ -> nil
        end

      if token,
        do: verify(tsa, token, request, opts),
        else: {:error, %Tspex.Error{reason: :token_invalid}}
    end

    assert TestFuzz.sweep(tsa.cert, check) == []
  end

  property "a response with a few edits, trusted" do
    {tsa, request, response} = sample(:p256)

    check all input <- TestFuzz.mutated(response), max_runs: TestFuzz.rounds() do
      assert TestFuzz.check(fn -> verify(tsa, input, request) end) == :ok
    end
  end
end
