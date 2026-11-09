defmodule Tspex.VerifyInfoTest do
  use Tspex.VerifyCase, async: true

  alias Tspex.DER

  setup_all do
    %{tsa: TestTSA.new()}
  end

  describe "the imprint" do
    test "a digest that is not the one requested", %{tsa: tsa} do
      request = Tspex.request!("contract")
      other = :crypto.hash(:sha256, "something else")
      response = TestTSA.response(tsa, request, imprint: {:sha256, other})
      assert failure(verify(tsa, response, request)) == {:imprint_mismatch, :digest}
    end

    test "another algorithm than the one requested", %{tsa: tsa} do
      request = Tspex.request!("contract")
      digest = :crypto.hash(:sha512, "contract")
      response = TestTSA.response(tsa, request, imprint: {:sha512, digest})
      assert failure(verify(tsa, response, request)) == {:imprint_mismatch, :hash_algorithm}
    end

    test "a digest of the wrong length for its algorithm", %{tsa: tsa} do
      request = Tspex.request!("contract")
      response = TestTSA.response(tsa, request, imprint: {:sha256, <<0::160>>})
      assert failure(verify(tsa, response, request)) == {:imprint_mismatch, :length}
    end

    test "MD5 is never accepted, SHA-1 only when allowed", %{tsa: tsa} do
      request = Tspex.request!("contract")
      md5 = :crypto.hash(:md5, "contract")
      response = TestTSA.response(tsa, request, imprint: {:md5, md5})
      assert failure(verify(tsa, response, request)) == {:weak_algorithm, :md5}

      assert failure(verify(tsa, response, request, allow_sha1: true)) ==
               {:weak_algorithm, :md5}

      sha1 = :crypto.hash(:sha, "contract")
      response = TestTSA.response(tsa, request, imprint: {:sha1, sha1})

      assert failure(verify(tsa, token_of(response), {:data, "contract"})) ==
               {:weak_algorithm, :sha1}

      assert {:ok, %{info: %{hash: :sha1}}} =
               verify(tsa, token_of(response), {:data, "contract"}, allow_sha1: true)
    end

    test "an algorithm that tspex does not know", %{tsa: tsa} do
      request = Tspex.request!("contract")
      response = TestTSA.response(tsa, request, imprint: {{1, 2, 3, 4}, <<0::256>>})
      assert {:error, %Error{}} = verify(tsa, response, request)
    end

    test "no NULL in the AlgorithmIdentifier of the imprint is read all the same", %{
      tsa: tsa
    } do
      {request, response} = issue(tsa, [], imprint_params: :absent)
      assert {:ok, _} = verify(tsa, response, request)
    end

    test "the imprint of the data hashed with the algorithm of the token", %{tsa: tsa} do
      request = Tspex.request!("contract", hash: :sha384)
      response = TestTSA.response(tsa, request)
      assert {:ok, _} = verify(tsa, token_of(response), {:data, "contract"})

      assert failure(verify(tsa, token_of(response), {:data, "other"})) ==
               {:imprint_mismatch, :digest}
    end
  end

  describe "the nonce" do
    test "the TSA left it out", %{tsa: tsa} do
      {request, response} = issue(tsa, [], nonce: :omit)
      assert reason(verify(tsa, response, request)) == :nonce_missing
    end

    test "the TSA answered another one", %{tsa: tsa} do
      request = Tspex.request!("contract")
      response = TestTSA.response(tsa, request, nonce: request.nonce + 1)
      assert reason(verify(tsa, response, request)) == :nonce_mismatch
    end

    test "a request without a nonce checks none", %{tsa: tsa} do
      request = Tspex.request!("contract", nonce: false)
      assert request.nonce == nil
      response = TestTSA.response(tsa, request)
      assert {:ok, %{info: %{nonce: nil}}} = verify(tsa, response, request)

      response = TestTSA.response(tsa, request, nonce: 99)
      assert {:ok, %{info: %{nonce: 99}}} = verify(tsa, response, request)
    end

    test "the largest nonce, and a nonce that is negative", %{tsa: tsa} do
      largest = Bitwise.bsl(1, 255) - 1
      request = Tspex.request!("contract", nonce: largest)
      assert {:ok, _} = verify(tsa, TestTSA.response(tsa, request), request)

      response = TestTSA.response(tsa, request, nonce: -largest)
      assert reason(verify(tsa, response, request)) == :nonce_mismatch
    end

    test "a nonce with leading zeros in the answer is the same number", %{tsa: tsa} do
      request = Tspex.request!("contract", nonce: 7)
      response = TestTSA.response(tsa, request, nonce: 7)
      assert {:ok, _} = verify(tsa, response, request)
    end
  end

  describe "the policy" do
    test "the policy requested comes back", %{tsa: tsa} do
      request = Tspex.request!("contract", policy: {1, 2, 3, 99})
      response = TestTSA.response(tsa, request)
      assert {:ok, %{info: %{policy: {1, 2, 3, 99}}}} = verify(tsa, response, request)
    end

    test "another policy than the one requested", %{tsa: tsa} do
      request = Tspex.request!("contract", policy: {1, 2, 3, 99})
      response = TestTSA.response(tsa, request, policy: {1, 2, 3, 100})
      assert failure(verify(tsa, response, request)) == {:policy_mismatch, {1, 2, 3, 100}}
    end

    test "no policy requested, the TSA picks its own, and :policies limits it", %{tsa: tsa} do
      {request, response} = issue(tsa, [], policy: {1, 2, 3, 7})
      assert {:ok, %{info: %{policy: {1, 2, 3, 7}}}} = verify(tsa, response, request)

      assert {:ok, _} = verify(tsa, response, request, policies: [{1, 2, 3, 7}])
      assert {:ok, _} = verify(tsa, response, request, policies: ["1.2.3.8", "1.2.3.7"])

      assert failure(verify(tsa, response, request, policies: [{1, 2, 3, 8}])) ==
               {:policy_mismatch, {1, 2, 3, 7}}
    end

    test ":policies must be OIDs", %{tsa: tsa} do
      {request, response} = issue(tsa)

      assert_raise ArgumentError, ~r/policies/, fn ->
        Tspex.verify(response, request, trust: [tsa.root], policies: [:nope])
      end
    end
  end

  describe "the name of the TSA" do
    test "no name in the token", %{tsa: tsa} do
      {request, response} = issue(tsa)
      assert {:ok, %{info: %{tsa: nil}}} = verify(tsa, response, request)
    end

    test "the directory name is the subject of the certificate", %{tsa: tsa} do
      {request, response} = issue(tsa, [], tsa_name: :subject)
      assert {:ok, _} = verify(tsa, response, request)
    end

    test "a name that is not in the certificate", %{tsa: tsa} do
      for name <- [{:dns, "tsa.example"}, {:uri, "http://tsa.example/"}, {:email, "a@b.example"}] do
        {request, response} = issue(tsa, [], tsa_name: name)
        assert reason(verify(tsa, response, request)) == :tsa_name_mismatch, inspect(name)
        assert {:ok, _} = verify(tsa, response, request, tsa_name: :ignore)
      end
    end

    test "the name of the issuer is not the name of the TSA", %{tsa: tsa} do
      {request, response} = issue(tsa, [], tsa_name: :issuer)
      assert reason(verify(tsa, response, request)) == :tsa_name_mismatch
    end

    test "the directory name may differ in string type, case and spaces" do
      tsa = TestTSA.new(cert: [subject_name: TestPKI.name_term("Time  Stamp Unit", :printable)])
      folded = TestPKI.name_term(" time stamp unit ", :utf8)
      {request, response} = issue(tsa, [], tsa_name: {:directory, folded})
      assert {:ok, _} = verify(tsa, response, request)
    end

    test "a name in the subjectAltName" do
      tsa = TestTSA.new(cert: [san: [{:dns, "tsa.example"}, {:uri, "http://tsa.example/"}]])

      for name <- [{:dns, "tsa.example"}, {:uri, "http://tsa.example/"}] do
        {request, response} = issue(tsa, [], tsa_name: name)
        assert {:ok, _} = verify(tsa, response, request), inspect(name)
      end

      {request, response} = issue(tsa, [], tsa_name: {:dns, "other.example"})
      assert reason(verify(tsa, response, request)) == :tsa_name_mismatch
    end

    test "a certificate with an empty subject has only its subjectAltName" do
      tsa =
        TestTSA.new(cert: [empty_subject: true, san: [{:dns, "tsa.example"}]])

      {request, response} = issue(tsa, [], tsa_name: {:dns, "tsa.example"})
      assert {:ok, _} = verify(tsa, response, request)
    end
  end

  describe "extensions" do
    test "a critical extension that nobody knows", %{tsa: tsa} do
      extension = %{oid: {1, 2, 3, 4, 5}, critical: true, value: DER.encode(:null)}
      {request, response} = issue(tsa, [], extensions: [extension])
      assert failure(verify(tsa, response, request)) == {:critical_extension, {1, 2, 3, 4, 5}}
      assert {:ok, _} = verify(tsa, response, request, critical_extensions: :ignore)
    end

    test "one that is not critical", %{tsa: tsa} do
      extension = %{oid: {1, 2, 3, 4, 5}, critical: false, value: DER.encode(:null)}
      {request, response} = issue(tsa, [], extensions: [extension])

      assert {:ok, %{info: %{extensions: [%{oid: {1, 2, 3, 4, 5}, critical: false}]}}} =
               verify(tsa, response, request)
    end
  end

  describe "the time" do
    test "genTime in the future, past, or close", %{tsa: tsa} do
      now = DateTime.utc_now()
      {request, response} = issue(tsa, [], gen_time: DateTime.add(now, 3600))

      assert {:ok, _} = verify(tsa, response, request)

      assert reason(verify(tsa, response, request, max_skew: 60)) == :gen_time_skew
      assert {:ok, _} = verify(tsa, response, request, max_skew: 3700)

      {request, response} = issue(tsa, [], gen_time: DateTime.add(now, -3600))
      assert reason(verify(tsa, response, request, max_skew: 60)) == :gen_time_skew
    end

    test ":now moves the clock, and the accuracy widens the window", %{tsa: tsa} do
      time = DateTime.utc_now() |> DateTime.truncate(:second)
      {request, response} = issue(tsa, [], gen_time: time, accuracy: %{seconds: 30})

      assert {:ok, _} = verify(tsa, response, request, max_skew: 10, now: DateTime.add(time, 35))

      assert failure(verify(tsa, response, request, max_skew: 10, now: DateTime.add(time, 41))) ==
               {:gen_time_skew, 41}
    end

    test "fractional seconds are read, and noted when the encoding is not DER", %{tsa: tsa} do
      stamp = Calendar.strftime(DateTime.utc_now(), "%Y%m%d%H%M%S")

      {request, response} = issue(tsa, [], gen_time_raw: stamp <> ".25Z")
      assert {:ok, %{info: info, deviations: []}} = verify(tsa, response, request)
      assert info.gen_time.microsecond == {250_000, 6}

      {request, response} = issue(tsa, [], gen_time_raw: stamp <> ".250Z")
      assert {:ok, %{deviations: deviations}} = verify(tsa, response, request)
      assert :gen_time_encoding in deviations
    end

    test "an invalid genTime", %{tsa: tsa} do
      for raw <- ["20261302030405Z", "20260102030405", "2026010203Z", "20260230030405Z"] do
        {request, response} = issue(tsa, [], gen_time_raw: raw)
        assert reason(verify(tsa, response, request)) == :malformed, raw
      end
    end

    test "a TSTInfo of version 2", %{tsa: tsa} do
      {request, response} = issue(tsa, [], version: 2)
      assert failure(verify(tsa, response, request)) == {:unsupported_version, 2}
    end
  end

  describe "the accuracy and ordering" do
    test "are read as written", %{tsa: tsa} do
      {request, response} =
        issue(tsa, [], accuracy: %{seconds: 2, millis: 3, micros: 4}, ordering: true)

      assert {:ok, %{info: info}} = verify(tsa, response, request)
      assert info.accuracy == %{seconds: 2, millis: 3, micros: 4}
      assert info.ordering == true
    end

    test "an accuracy out of range is malformed", %{tsa: tsa} do
      {request, response} = issue(tsa, [], accuracy: %{millis: 1000})
      assert reason(verify(tsa, response, request)) == :malformed
    end
  end
end
