defmodule Tspex.VerifyCertificatesTest do
  use Tspex.VerifyCase, async: true

  @ts TestPKI.time_stamping()

  # A PKI dated around `time`, so that a token generated then verifies today
  # although the certificates are long expired.
  defp dated(from, to, extra \\ []) do
    window = [not_before: from, not_after: to]

    TestTSA.new(
      Keyword.merge(
        [root: window, ca: window, cert: window, intermediate: true],
        extra
      )
    )
  end

  describe "the certificate that signed" do
    test "no extKeyUsage" do
      tsa = TestTSA.new(cert: [eku: nil])
      {request, response} = issue(tsa)
      assert failure(verify(tsa, response, request)) == {:bad_tsa_certificate, :eku_missing}
    end

    test "extKeyUsage that is not critical" do
      tsa = TestTSA.new(cert: [eku: [@ts], eku_critical: false])
      {request, response} = issue(tsa)
      assert failure(verify(tsa, response, request)) == {:bad_tsa_certificate, :eku_not_critical}
    end

    test "timeStamping with another purpose, refused unless asked" do
      tsa = TestTSA.new(cert: [eku: [@ts, TestPKI.client_auth()]])
      {request, response} = issue(tsa)

      assert failure(verify(tsa, response, request)) ==
               {:bad_tsa_certificate, :eku_extra_purposes}

      assert {:ok, _} = verify(tsa, response, request, tsa_eku: :extra_purposes)
    end

    test "critical extKeyUsage without timeStamping" do
      for oids <- [[TestPKI.code_signing()], [TestPKI.any_eku()], [TestPKI.server_auth()]] do
        tsa = TestTSA.new(cert: [eku: oids])
        {request, response} = issue(tsa)

        assert failure(verify(tsa, response, request)) == {:bad_tsa_certificate, :eku_missing}

        assert failure(verify(tsa, response, request, tsa_eku: :extra_purposes)) ==
                 {:bad_tsa_certificate, :eku_missing}
      end
    end

    test "two extKeyUsage extensions" do
      tsa = TestTSA.new(cert: [eku: [@ts], eku_twice: true])
      {request, response} = issue(tsa)
      assert failure(verify(tsa, response, request)) == {:bad_tsa_certificate, :eku_repeated}
    end

    test "keyUsage has to allow signing" do
      for {usage, expected} <- [
            {[2], {:bad_tsa_certificate, :key_usage}},
            {[5], {:bad_tsa_certificate, :key_usage}},
            {[1], :ok},
            {[0], :ok},
            {nil, :ok}
          ] do
        tsa = TestTSA.new(cert: [key_usage: usage])
        {request, response} = issue(tsa)

        result =
          case failure(verify(tsa, response, request)) do
            :ok -> :ok
            other -> other
          end

        assert result == expected, "key usage #{inspect(usage)}"
      end
    end

    test "expired at the time of the token" do
      tsa =
        TestTSA.new(
          cert: [not_before: ~U[2020-01-01 00:00:00Z], not_after: ~U[2021-01-01 00:00:00Z]]
        )

      {request, response} = issue(tsa)
      assert failure(verify(tsa, response, request)) == {:bad_tsa_certificate, :not_valid_at_time}
    end

    test "a token made while the certificates were valid still verifies today" do
      tsa = dated(~U[2020-01-01 00:00:00Z], ~U[2021-01-01 00:00:00Z])
      request = Tspex.request!("old")
      response = TestTSA.response(tsa, request, gen_time: ~U[2020-06-01 12:00:00Z])

      assert {:ok, verified} = verify(tsa, response, request)
      assert verified.info.gen_time == ~U[2020-06-01 12:00:00Z]
      assert verified.trust == :validated
    end

    test "the validity is closed at both ends, to the second" do
      from = ~U[2020-01-01 00:00:00Z]
      to = ~U[2021-01-01 00:00:00Z]
      tsa = dated(from, to)
      request = Tspex.request!("edge")

      for {time, ok?} <- [
            {from, true},
            {to, true},
            {DateTime.add(from, -1), false},
            {DateTime.add(to, 1), false}
          ] do
        response = TestTSA.response(tsa, request, gen_time: time)

        assert reason(verify(tsa, response, request)) ==
                 if(ok?, do: :ok, else: :bad_tsa_certificate)
      end
    end

    test "the certificate pinned as the root is judged as a TSA anyway" do
      tsa = TestTSA.new(cert: [eku: [TestPKI.server_auth()]])
      {request, response} = issue(tsa)
      result = Tspex.verify(response, request, trust: [tsa.cert])
      assert {:error, %Error{reason: :bad_tsa_certificate}} = result
    end

    test "the certificate pinned as the root works when it is a good TSA certificate" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa)
      assert {:ok, %{trust: :validated}} = Tspex.verify(response, request, trust: [tsa.cert])
    end
  end

  describe "the certificate path" do
    test "another root" do
      tsa = TestTSA.new()
      other = TestTSA.new(root_tag: :other_root, tag: :other_tsa)
      {request, response} = issue(tsa)

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify(response, request, trust: TestTSA.trust(other))
    end

    test "an intermediate that is missing from the token" do
      tsa = TestTSA.new(intermediate: true)
      {request, response} = issue(tsa, [], certs: :signer_only)
      assert {:error, %Error{reason: :untrusted}} = verify(tsa, response, request)

      assert {:ok, %{signer: %{path: path}}} =
               verify(tsa, response, request, certificates: [tsa.intermediate])

      assert length(path) == 3
    end

    test "an intermediate expired at the time of the token" do
      tsa =
        TestTSA.new(
          intermediate: true,
          ca: [not_before: ~U[2020-01-01 00:00:00Z], not_after: ~U[2021-01-01 00:00:00Z]]
        )

      {request, response} = issue(tsa)
      assert {:error, %Error{reason: :untrusted}} = verify(tsa, response, request)
    end

    test "a root that is expired at the time of the token" do
      tsa =
        TestTSA.new(
          intermediate: true,
          root: [not_before: ~U[2010-01-01 00:00:00Z], not_after: ~U[2022-01-01 00:00:00Z]]
        )

      {request, response} = issue(tsa)
      assert {:error, %Error{reason: :untrusted}} = verify(tsa, response, request)
    end

    test "a CA that is not yet valid at the time of the token" do
      tsa =
        dated(~U[2020-01-01 00:00:00Z], ~U[2060-01-01 00:00:00Z],
          ca: [not_before: ~U[2022-01-01 00:00:00Z], not_after: ~U[2060-01-01 00:00:00Z]]
        )

      request = Tspex.request!("early")
      response = TestTSA.response(tsa, request, gen_time: ~U[2021-06-01 00:00:00Z])
      assert {:error, %Error{reason: :untrusted}} = verify(tsa, response, request)
    end

    test "a CA that restricts the extKeyUsage to another purpose" do
      for critical <- [true, false] do
        tsa =
          TestTSA.new(
            intermediate: true,
            ca: [eku: [TestPKI.server_auth()], eku_critical: critical]
          )

        {request, response} = issue(tsa)

        assert {:error, %Error{reason: :untrusted}} = verify(tsa, response, request),
               "critical: #{critical}"
      end
    end

    test "a CA that allows timeStamping in its extKeyUsage" do
      tsa = TestTSA.new(intermediate: true, ca: [eku: [@ts, TestPKI.server_auth()]])
      {request, response} = issue(tsa)
      assert {:ok, _} = verify(tsa, response, request)
    end

    test "a CA with an extKeyUsage and no keyUsage is untrusted, not a crash" do
      tsa = TestTSA.new(intermediate: true, ca: [eku: [@ts], key_usage: nil])
      {request, response} = issue(tsa)
      assert {:error, %Error{reason: :untrusted}} = verify(tsa, response, request)
    end

    test "a path longer than the root allows" do
      tsa = TestTSA.new(intermediate: true, root: [path_len: 0])
      {request, response} = issue(tsa)
      assert {:error, %Error{reason: :untrusted}} = verify(tsa, response, request)
    end

    test "the revocation callback sees the whole path and the time of the token" do
      tsa = TestTSA.new(intermediate: true)
      {request, response} = issue(tsa)
      test = self()

      check = fn path, time ->
        send(test, {:checked, path, time})
        :ok
      end

      assert {:ok, %{revocation: :checked, info: info}} =
               verify(tsa, response, request, revocation: check)

      assert_received {:checked, [_root, _ca, _leaf], time}
      assert time == info.gen_time
    end

    test "a revocation callback that refuses, and one that answers badly" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa)

      result = verify(tsa, response, request, revocation: fn _, _ -> {:error, :revoked} end)
      assert failure(result) == {:untrusted, {:revocation, :revoked}}

      result = verify(tsa, response, request, revocation: fn _, _ -> :maybe end)
      assert failure(result) == {:untrusted, {:revocation, :bad_result}}
    end

    test "the path validation options reach the OTP" do
      tsa = TestTSA.new(intermediate: true)
      {request, response} = issue(tsa)
      result = verify(tsa, response, request, path_validation: [max_path_length: 0])
      assert {:error, %Error{reason: :untrusted}} = result
    end
  end

  describe "the certificates in the token" do
    test "cert_req false and no certificate at all" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, cert_req: false)
      assert reason(verify(tsa, response, request)) == :token_invalid
    end

    test "the certificate given by the caller instead" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, cert_req: false)
      assert {:ok, _} = verify(tsa, response, request, certificates: [tsa.cert])
    end

    test "a TSA that sends the certificate nobody asked for" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, [cert_req: false], certs: :include)
      assert {:ok, verified} = verify(tsa, response, request)
      assert :unrequested_certificates in verified.deviations
    end

    test "a TSA that does not send the certificate that was asked for" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, [cert_req: true], certs: :omit)
      assert reason(verify(tsa, response, request)) == :token_invalid
      assert {:ok, v} = verify(tsa, response, request, certificates: [tsa.cert])
      assert :cert_req_not_honored in v.deviations
    end

    test "the signer certificate twice" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, [], certs: :duplicate_signer)
      assert {:ok, _} = verify(tsa, response, request)
    end

    test "extra certificates that are not part of any path do no harm" do
      tsa = TestTSA.new()
      stranger = TestPKI.cert({:p256, :stranger}, subject: "Stranger")
      {request, response} = issue(tsa, [], certs: {:also, [stranger]})
      assert {:ok, _} = verify(tsa, response, request)
    end
  end

  describe "a certificate the signer wrote" do
    # The signer is its own judge of the certificate it brings: it signs a
    # certificate whose validity is not text, and names it in the ESSCertID.
    test "a validity time that is not text is an unreadable certificate" do
      tsa = TestTSA.new()
      [head, tail] = :binary.split(tsa.cert, <<0x17, 0x0D>>)
      <<_::binary-size(2), rest::binary>> = tail

      for bad <- [<<0xFF, 0xFE>>, <<0xC3, 0x28>>, "ab"] do
        forged = %{tsa | cert: head <> <<0x17, 0x0D>> <> bad <> rest}
        {request, response} = issue(forged, [], ess: :v2, ess_issuer_serial: false)

        assert failure(verify(tsa, response, request)) ==
                 {:bad_tsa_certificate, :unreadable},
               inspect(bad)
      end
    end
  end

  describe "the signing certificate attribute" do
    test "neither ESSCertID nor ESSCertIDv2" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, [], ess: :none)
      assert reason(verify(tsa, response, request)) == :signing_certificate_missing
    end

    test "either version alone is enough, with or without issuerSerial" do
      tsa = TestTSA.new()

      for ess <- [:v1, :v2, :both], issuer_serial <- [true, false] do
        {request, response} = issue(tsa, [], ess: ess, ess_issuer_serial: issuer_serial)
        assert {:ok, _} = verify(tsa, response, request), inspect({ess, issuer_serial})
      end
    end

    test "the attribute names another certificate, or the two versions disagree" do
      tsa = TestTSA.new()

      for ess <- [:other, :disagree] do
        {request, response} = issue(tsa, [], ess: ess)
        assert reason(verify(tsa, response, request)) == :token_invalid, inspect(ess)
      end
    end
  end

  describe "the signature" do
    test "a flipped bit in the signature" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa)
      token = TestTSA.flip_signature(token_of(response))
      assert reason(verify(tsa, token, request)) == :token_invalid
    end

    test "a changed TSTInfo under the same signature" do
      tsa = TestTSA.new()
      request = Tspex.request!("contract")
      info = TestTSA.tst_info(tsa, request, serial: 123_456)
      token = TestTSA.token(tsa, request, tst_info: info)

      changed =
        TestTSA.replace_tst_info(token, info, fn der ->
          size = byte_size(der) - 1
          <<head::binary-size(size), byte>> = der
          <<head::binary, Bitwise.bxor(byte, 1)>>
        end)

      assert reason(verify(tsa, changed, request)) in [:token_invalid, :malformed]
    end

    test "a signer that is not the TSA of the certificates in the token" do
      tsa = TestTSA.new()
      other = TestTSA.new(tag: :other_tsa)
      request = Tspex.request!("contract")
      token = TestTSA.token(tsa, request, signer: other, certs: {:list, [tsa.cert]})
      assert reason(verify(tsa, token, request)) == :token_invalid
    end

    test "more than one signer" do
      tsa = TestTSA.new()
      other = TestTSA.new(tag: :second)
      {request, response} = issue(tsa, [], extra_signers: [%{tsa: other}])
      assert failure(verify(tsa, response, request)) == {:signer_count, 2}
    end

    test "no signer at all" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, [], no_signer: true)
      assert failure(verify(tsa, response, request)) == {:signer_count, 0}
    end

    test "a ContentInfo that is not SignedData" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, [], not_signed_data: true)

      assert failure(verify(tsa, response, request)) ==
               {:not_a_time_stamp_token, {1, 2, 840, 113_549, 1, 7, 1}}
    end

    test "the content is not a TSTInfo" do
      tsa = TestTSA.new()
      {request, response} = issue(tsa, [], content_type: {1, 2, 840, 113_549, 1, 7, 1})

      assert failure(verify(tsa, response, request)) ==
               {:not_a_time_stamp_token, {:content_type, :data}}
    end
  end

  describe "tokens made by OpenSSL" do
    setup do
      %{
        ca: Fixtures.read("ca.der"),
        request: Tspex.decode_request!(Fixtures.read("q_sha256.tsq"))
      }
    end

    test "RSA and EC, as response and as token", %{ca: ca, request: request} do
      for name <- ["r_rsa", "r_ec"] do
        response = Fixtures.read(name <> ".tsr")
        token = Fixtures.read(name <> ".tst")

        assert {:ok, %{status: :granted, trust: :validated}} =
                 Tspex.verify(response, request, trust: [ca])

        assert {:ok, %{status: nil}} = Tspex.verify(token, request, trust: [ca])
        assert {:ok, _} = Tspex.verify(token, {:data, Fixtures.data()}, trust: [ca])
      end
    end

    test "other data, and another root", %{ca: ca, request: request} do
      response = Fixtures.read("r_rsa.tsr")

      assert failure(Tspex.verify(response, {:data, "other"}, trust: [ca])) ==
               {:imprint_mismatch, :digest}

      other = TestTSA.new()

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify(response, request, trust: TestTSA.trust(other))
    end

    test "the digests it was asked for", %{ca: ca} do
      for {name, hash} <- [
            {"r_rsa_sha224", :sha224},
            {"r_rsa_sha384", :sha384},
            {"r_rsa_sha512", :sha512}
          ] do
        response = Fixtures.read(name <> ".tsr")

        assert {:ok, %{info: %{hash: ^hash}}} =
                 Tspex.verify(response, {:data, Fixtures.data()}, trust: [ca])
      end
    end

    test "SHA-1 is refused unless allowed", %{ca: ca} do
      response = Fixtures.read("r_rsa_sha1.tsr")

      assert failure(Tspex.verify(response, {:data, Fixtures.data()}, trust: [ca])) ==
               {:weak_algorithm, :sha1}

      assert {:ok, _} =
               Tspex.verify(response, {:data, Fixtures.data()}, trust: [ca], allow_sha1: true)
    end

    test "a response without the certificate needs the caller to give it", %{ca: ca} do
      response = Fixtures.read("r_rsa_no_cert.tsr")
      data = {:data, Fixtures.data()}
      assert reason(Tspex.verify(response, data, trust: [ca])) == :token_invalid

      assert {:ok, _} =
               Tspex.verify(response, data,
                 trust: [ca],
                 certificates: [Fixtures.read("tsa_rsa.der")]
               )
    end

    test "a response without nonce, to a request that had none", %{ca: ca} do
      response = Fixtures.read("r_rsa_no_nonce.tsr")
      request = Tspex.decode_request!(Fixtures.read("q_no_nonce.tsq"))
      assert {:ok, %{info: %{nonce: nil}}} = Tspex.verify(response, request, trust: [ca])
    end

    test "the rejections", %{ca: ca, request: request} do
      for name <- ["r_alg_reject", "r_policy_reject"] do
        assert {:error, %Error{reason: :rejection}} =
                 Tspex.verify(Fixtures.read(name <> ".tsr"), request, trust: [ca])
      end
    end
  end
end
