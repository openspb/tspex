defmodule Tspex.StampTest do
  use Tspex.VerifyCase, async: true

  # The OTP logs the alerts of the TLS refusals below.
  @moduletag :capture_log

  alias Tspex.{TestHTTPServer, Verified}

  setup_all do
    %{tsa: TestTSA.new()}
  end

  # A TSA behind a local port: it answers the request it gets with a token
  # of `tsa`, shaped by `opts` (see `TestTSA.response/3`).
  defp tsa_server(tsa, opts \\ [], headers \\ [{"content-type", "application/timestamp-reply"}]) do
    TestHTTPServer.start(fn %{request: request, send: send} ->
      asked = Tspex.decode_request!(TestHTTPServer.body(request))
      send.(TestHTTPServer.ok(TestTSA.response(tsa, asked, opts), headers))
    end)
  end

  defp url(port), do: "http://127.0.0.1:#{port}/tsp"

  defp stamp(tsa, data, port, opts \\ []),
    do: Tspex.stamp(data, Keyword.merge([url: url(port), trust: TestTSA.trust(tsa)], opts))

  describe "stamp/2 over HTTP" do
    test "asks, reads and verifies in one call", %{tsa: tsa} do
      port = tsa_server(tsa)

      assert {:ok, %Verified{} = verified} = stamp(tsa, "contract", port)

      assert verified.status == :granted
      assert verified.trust == :validated
      assert verified.info.hash == :sha256
      assert verified.info.digest == :crypto.hash(:sha256, "contract")
      assert verified.signer.certificate == tsa.cert

      assert_receive {:request, raw}
      headers = TestHTTPServer.headers(raw)
      assert headers["content-type"] == "application/timestamp-query"
      assert headers["accept"] == "application/timestamp-reply"
      sent = Tspex.decode_request!(TestHTTPServer.body(raw))
      assert sent.digest == :crypto.hash(:sha256, "contract")
      assert sent.nonce != nil
      assert sent.cert_req
      assert verified.info.nonce == sent.nonce

      # the token alone verifies later, without the request
      assert {:ok, %Verified{}} =
               Tspex.verify(verified.token, {:data, "contract"}, trust: TestTSA.trust(tsa))
    end

    test "takes the options of the request", %{tsa: tsa} do
      port = tsa_server(tsa)

      assert {:ok, _} =
               stamp(tsa, "contract", port,
                 hash: :sha384,
                 policy: "1.2.3.4.5",
                 nonce: 12_345,
                 cert_req: false,
                 certificates: [tsa.cert]
               )

      assert_receive {:request, raw}
      sent = Tspex.decode_request!(TestHTTPServer.body(raw))
      assert sent.hash == :sha384
      assert sent.policy == {1, 2, 3, 4, 5}
      assert sent.nonce == 12_345
      refute sent.cert_req
    end

    test "takes every form of data", %{tsa: tsa} do
      port = tsa_server(tsa)
      digest = :crypto.hash(:sha256, "abc")

      for data <- ["abc", {:digest, :sha256, digest}, {:stream, ["a", "b", "c"]}] do
        assert {:ok, verified} = stamp(tsa, data, port)
        assert verified.info.digest == digest
      end
    end

    test "SHA-1 needs allow_sha1, for the request and for the answer", %{tsa: tsa} do
      port = tsa_server(tsa)

      assert_raise ArgumentError, ~r/allow_sha1/, fn -> stamp(tsa, "x", port, hash: :sha1) end
      assert {:ok, verified} = stamp(tsa, "x", port, hash: :sha1, allow_sha1: true)
      assert verified.info.hash == :sha1
    end

    test "takes the options of the verification", %{tsa: tsa} do
      port = tsa_server(tsa)

      assert {:error, %Error{reason: :policy_mismatch}} =
               stamp(tsa, "x", port, policies: ["1.2.9.9"])

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.stamp("x", url: url(port), trust: [TestTSA.new(root_tag: :other).root])

      assert {:error, %Error{reason: :gen_time_skew}} =
               stamp(tsa, "x", port, max_skew: 60, now: ~U[2030-01-01 00:00:00Z])
    end

    test "does not need the type of the body", %{tsa: tsa} do
      for headers <- [
            [],
            [{"content-type", "text/plain"}],
            [{"content-type", "application/octet-stream"}]
          ] do
        port = tsa_server(tsa, [], headers)
        assert {:ok, _} = stamp(tsa, "x", port)
      end
    end

    test "sends the extra headers", %{tsa: tsa} do
      port = tsa_server(tsa)
      assert {:ok, _} = stamp(tsa, "x", port, headers: [{"authorization", "Bearer t0k3n"}])

      assert_receive {:request, raw}
      assert TestHTTPServer.headers(raw)["authorization"] == "Bearer t0k3n"
    end
  end

  describe "what the TSA says" do
    test "a rejection says why", %{tsa: tsa} do
      port = tsa_server(tsa, status: 2, fail_info: [0], status_text: ["no such algorithm"])

      assert {:error, %Error{reason: :rejection, detail: detail}} = stamp(tsa, "x", port)
      assert detail.fail_info == [:bad_alg]
      assert detail.text == ["no such algorithm"]
    end

    test "other statuses are not a time-stamp", %{tsa: tsa} do
      for {status, reason} <- [
            {3, :waiting},
            {4, :revocation_warning},
            {5, :revocation_notification}
          ] do
        port = tsa_server(tsa, status: status)
        assert {:error, %Error{reason: ^reason}} = stamp(tsa, "x", port)
      end
    end

    test "granted with modifications is accepted unless refused", %{tsa: tsa} do
      port = tsa_server(tsa, status: 1)
      assert {:ok, %Verified{status: :granted_with_mods}} = stamp(tsa, "x", port)

      assert {:error, %Error{reason: :granted_with_mods}} =
               stamp(tsa, "x", port, granted_with_mods: :reject)
    end

    test "an answer for another request is refused", %{tsa: tsa} do
      other = Tspex.request!("another contract", nonce: 777)

      port =
        TestHTTPServer.start(fn %{send: send} ->
          send.(TestHTTPServer.ok(TestTSA.response(tsa, other)))
        end)

      assert {:error, %Error{reason: reason}} = stamp(tsa, "contract", port)
      assert reason in [:imprint_mismatch, :nonce_mismatch]

      port =
        TestHTTPServer.start(fn %{request: request, send: send} ->
          asked = Tspex.decode_request!(TestHTTPServer.body(request))
          send.(TestHTTPServer.ok(TestTSA.response(tsa, %{asked | nonce: asked.nonce + 1})))
        end)

      assert {:error, %Error{reason: :nonce_mismatch}} = stamp(tsa, "contract", port)
    end

    test "bytes that are not a response", %{tsa: tsa} do
      port =
        TestHTTPServer.start(fn %{send: send} -> send.(TestHTTPServer.ok("not DER at all")) end)

      assert {:error, %Error{reason: :malformed}} = stamp(tsa, "x", port)

      port = TestHTTPServer.start(fn %{send: send} -> send.(TestHTTPServer.ok("")) end)
      assert {:error, %Error{reason: :malformed}} = stamp(tsa, "x", port)
    end

    test "a bare token is not what a TSA answers, unless you say so", %{tsa: tsa} do
      token = fn %{request: request, send: send} ->
        asked = Tspex.decode_request!(TestHTTPServer.body(request))
        send.(TestHTTPServer.ok(TestTSA.token(tsa, asked)))
      end

      port = TestHTTPServer.start(token)
      assert {:error, %Error{}} = stamp(tsa, "x", port)

      port = TestHTTPServer.start(token)
      assert {:ok, _} = stamp(tsa, "x", port, input: :token)
    end
  end

  describe "the network" do
    test "an error status", %{tsa: tsa} do
      port =
        TestHTTPServer.start(fn %{send: send} ->
          send.("HTTP/1.1 503 Busy\r\ncontent-length: 0\r\n\r\n")
        end)

      assert {:error, %Error{reason: :transport, detail: {:http_status, 503}} = error} =
               stamp(tsa, "x", port)

      assert Exception.message(error) =~ "503"
    end

    test "a refused connection", %{tsa: tsa} do
      assert {:error, %Error{reason: :transport, detail: {:connect, :econnrefused}}} =
               stamp(tsa, "x", TestHTTPServer.closed_port())
    end

    test "a server that does not answer in time", %{tsa: tsa} do
      port = TestHTTPServer.start(fn _conn -> Process.sleep(30_000) end)

      assert {:error, %Error{reason: :transport, detail: :timeout}} =
               stamp(tsa, "x", port, timeout: 300)
    end

    test "a body above the limit", %{tsa: tsa} do
      port = tsa_server(tsa)

      assert {:error, %Error{reason: :transport, detail: :too_large}} =
               stamp(tsa, "x", port, max_response_bytes: 100)
    end

    test "https, with a CA it trusts and with one it does not", %{tsa: tsa} do
      ca = TestPKI.cert({:p256, :stamp_ca}, ca: true, subject: "Stamp test CA")

      cert =
        TestPKI.cert({:p256, :stamp_server},
          issuer: {ca, {:p256, :stamp_ca}},
          key_usage: [0],
          eku: [TestPKI.server_auth()],
          eku_critical: false,
          san: [{:dns, "localhost"}]
        )

      server = fn ->
        TestHTTPServer.start(
          fn %{request: request, send: send} ->
            asked = Tspex.decode_request!(TestHTTPServer.body(request))
            send.(TestHTTPServer.ok(TestTSA.response(tsa, asked)))
          end,
          tls: {cert, TestPKI.key({:p256, :stamp_server})}
        )
      end

      port = server.()

      secure = fn opts ->
        Tspex.stamp("x", [url: "https://localhost:#{port}/", trust: TestTSA.trust(tsa)] ++ opts)
      end

      assert {:ok, _} = secure.(ssl: [cacerts: [ca]])
      assert {:error, %Error{reason: :transport, detail: {:tls, _}}} = secure.([])
    end
  end

  describe "a transport of your own" do
    test "gets the URL, the request and the options, and needs no URL to be given", %{tsa: tsa} do
      me = self()

      transport = fn url, der, options ->
        send(me, {:transport, url, der, options})
        {:ok, TestTSA.response(tsa, Tspex.decode_request!(der))}
      end

      assert {:ok, %Verified{}} =
               Tspex.stamp("x", transport: transport, trust: TestTSA.trust(tsa))

      assert_receive {:transport, nil, der, options}
      assert %Tspex.Request{} = Tspex.decode_request!(der)

      assert Enum.sort(options) ==
               [
                 headers: [],
                 max_redirects: 0,
                 max_response_bytes: 1_048_576,
                 ssl: [],
                 timeout: 30_000
               ]

      assert {:ok, _} =
               Tspex.stamp("x",
                 url: "https://tsa.example.test/",
                 transport: transport,
                 trust: TestTSA.trust(tsa),
                 headers: [{"x-key", "1"}],
                 timeout: 5_000
               )

      assert_receive {:transport, "https://tsa.example.test/", _der, options}
      assert options[:headers] == [{"x-key", "1"}]
      assert options[:timeout] == 5_000
    end

    test "its errors become transport errors", %{tsa: tsa} do
      stamp = fn transport ->
        Tspex.stamp("x", transport: transport, trust: TestTSA.trust(tsa))
      end

      assert {:error, %Error{reason: :transport, detail: :boom}} =
               stamp.(fn _url, _der, _options -> {:error, :boom} end)

      assert {:error, %Error{reason: :transport, detail: {:http_status, 429}}} =
               stamp.(fn _url, _der, _options -> {:error, {:http_status, 429}} end)

      original = Error.new(:transport, :mine)
      assert {:error, ^original} = stamp.(fn _url, _der, _options -> {:error, original} end)
    end

    test "must answer as a transport does", %{tsa: tsa} do
      for bad <- [:ok, {:ok, :not_a_binary}, nil, {:error}] do
        assert_raise ArgumentError, ~r/:transport function must return/, fn ->
          Tspex.stamp("x",
            transport: fn _url, _der, _options -> bad end,
            trust: TestTSA.trust(tsa)
          )
        end
      end
    end
  end

  describe "arguments" do
    test "stamp!/2 raises the error", %{tsa: tsa} do
      port = tsa_server(tsa, status: 2)
      assert_raise Error, fn -> Tspex.stamp!("x", url: url(port), trust: TestTSA.trust(tsa)) end

      port = tsa_server(tsa)
      assert %Verified{} = Tspex.stamp!("x", url: url(port), trust: TestTSA.trust(tsa))
    end

    test "needs :trust, and :url unless there is a :transport", %{tsa: tsa} do
      assert_raise ArgumentError, ~r/:trust.*required/, fn ->
        Tspex.stamp("x", url: "http://x/")
      end

      assert_raise ArgumentError, ~r/:url is required/, fn ->
        Tspex.stamp("x", trust: TestTSA.trust(tsa))
      end

      assert {:ok, _} =
               Tspex.stamp("x",
                 trust: TestTSA.trust(tsa),
                 transport: fn _url, der, _options ->
                   {:ok, TestTSA.response(tsa, Tspex.decode_request!(der))}
                 end
               )
    end

    test "refuses what it does not know, or twice, or of the wrong kind", %{tsa: tsa} do
      trust = TestTSA.trust(tsa)

      assert_raise ArgumentError, ~r/unknown option/, fn ->
        Tspex.stamp("x", url: "http://x/", trust: trust, nope: 1)
      end

      assert_raise ArgumentError, fn ->
        Tspex.stamp("x", url: "http://x/", trust: trust, timeout: "30")
      end

      assert_raise ArgumentError, fn ->
        Tspex.stamp("x", url: "http://x/", trust: trust, transport: :http)
      end

      assert_raise ArgumentError, fn ->
        Tspex.stamp("x", url: "http://x/", trust: trust, hash: :md5)
      end

      assert_raise ArgumentError, fn ->
        Tspex.stamp("x", url: "http://x/", url: "http://y/", trust: trust)
      end

      assert_raise ArgumentError, fn -> Tspex.stamp(:not_data, url: "http://x/", trust: trust) end
    end

    test "a URL that is not http or https is an argument error", %{tsa: tsa} do
      assert_raise ArgumentError, ~r/URL must be http or https/, fn ->
        Tspex.stamp("x", url: "ftp://tsa.example.test/", trust: TestTSA.trust(tsa))
      end
    end
  end
end
