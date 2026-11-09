defmodule Tspex.HTTPTest do
  use ExUnit.Case, async: true

  # The OTP logs every TLS alert that the refusals below cause.
  @moduletag :capture_log

  alias Tspex.{HTTP, TestHTTPServer, TestPKI}

  import Tspex.TestHTTPServer, only: [ok: 1, ok: 2]

  defp url(port, path \\ "/tsp"), do: "http://127.0.0.1:#{port}#{path}"

  defp reply(data), do: TestHTTPServer.start(fn %{send: send} -> send.(data) end)

  defp chunked(chunks, extra \\ "") do
    [
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
      Enum.map(chunks, fn chunk ->
        [Integer.to_string(byte_size(chunk), 16), "\r\n", chunk, "\r\n"]
      end),
      "0\r\n",
      extra,
      "\r\n"
    ]
  end

  # Sends `piece` over and over until the client goes away.
  defp flood(head, piece) do
    TestHTTPServer.start(fn %{send: send} ->
      send.(head)
      Stream.repeatedly(fn -> send.(piece) end) |> Enum.take_while(&(&1 == :ok))
    end)
  end

  describe "the request" do
    test "is a POST with the headers of the protocol, and the body is returned" do
      port = reply(ok("the-response", [{"content-type", "text/plain"}]))

      assert {:ok, "the-response"} = HTTP.post(url(port), "the-request")

      assert_receive {:request, request}
      assert TestHTTPServer.request_line(request) == "POST /tsp HTTP/1.1"
      headers = TestHTTPServer.headers(request)
      assert headers["content-type"] == "application/timestamp-query"
      assert headers["accept"] == "application/timestamp-reply"
      assert headers["user-agent"] =~ ~r{\Atspex/}
      assert headers["content-length"] == "11"
      assert headers["connection"] == "close"
      assert headers["host"] == "127.0.0.1:#{port}"
      assert TestHTTPServer.body(request) == "the-request"
    end

    test "keeps the query and writes / for an empty path" do
      port = reply(ok("x"))
      assert {:ok, "x"} = HTTP.post("http://127.0.0.1:#{port}", "q")
      assert_receive {:request, request}
      assert TestHTTPServer.request_line(request) == "POST / HTTP/1.1"

      port = reply(ok("x"))
      assert {:ok, "x"} = HTTP.post("http://127.0.0.1:#{port}/tsa?a=b&c=d#frag", "q")
      assert_receive {:request, request}
      assert TestHTTPServer.request_line(request) == "POST /tsa?a=b&c=d HTTP/1.1"
    end

    test "sends the extra headers and lets them replace the ones it sets" do
      port = reply(ok("x"))

      assert {:ok, "x"} =
               HTTP.post(url(port), "q",
                 headers: [{"Authorization", "Bearer abc"}, {"accept", "*/*"}]
               )

      assert_receive {:request, request}
      headers = TestHTTPServer.headers(request)
      assert headers["authorization"] == "Bearer abc"
      assert headers["accept"] == "*/*"
      assert headers["content-type"] == "application/timestamp-query"
    end

    test "carries every byte of a binary body and of the answer" do
      all = :binary.list_to_bin(Enum.to_list(0..255))
      port = reply(ok(all))

      assert {:ok, ^all} = HTTP.post(url(port), all)
      assert_receive {:request, request}
      assert TestHTTPServer.body(request) == all
    end

    test "names an IPv6 host in brackets" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {0, 0, 0, 0, 0, 0, 0, 1}])
      {:ok, port} = :inet.port(listener)
      me = self()

      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, data} = :gen_tcp.recv(socket, 0, 5_000)
        send(me, {:seen, data})
        :gen_tcp.send(socket, ok("v6"))
        :gen_tcp.close(socket)
      end)

      assert {:ok, "v6"} = HTTP.post("http://[::1]:#{port}/", "q")
      assert_receive {:seen, data}
      assert TestHTTPServer.headers(data <> "\r\n\r\n")["host"] == "[::1]:#{port}"
    rescue
      MatchError -> :ok
    end
  end

  describe "the answer" do
    test "does not need a content type" do
      for type <- [
            [],
            [{"content-type", "text/plain"}],
            [{"content-type", "application/timestamp-reply"}]
          ] do
        port = reply(ok("body", type))
        assert {:ok, "body"} = HTTP.post(url(port), "q")
      end
    end

    test "an empty body is an empty body" do
      assert {:ok, ""} = HTTP.post(url(reply(ok(""))), "q")
    end

    test "reads a chunked body, with extensions and a trailer" do
      port = reply(chunked(["ab", "cde", String.duplicate("f", 300)], "x-trailer: 1\r\n"))
      assert {:ok, "abcde" <> rest} = HTTP.post(url(port), "q")
      assert rest == String.duplicate("f", 300)

      port =
        reply([
          "HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n",
          "3;name=value\r\nabc\r\n0\r\n\r\n"
        ])

      assert {:ok, "abc"} = HTTP.post(url(port), "q")
    end

    test "reads a body that ends when the connection does" do
      port = reply("HTTP/1.0 200 OK\r\n\r\nuntil the end")
      assert {:ok, "until the end"} = HTTP.post(url(port), "q")
    end

    test "reads a body that comes in pieces" do
      port =
        TestHTTPServer.start(fn %{send: send} ->
          send.("HTTP/1.1 200 OK\r\ncon")
          Process.sleep(20)
          send.("tent-length: 6\r\n\r\nab")
          Process.sleep(20)
          send.("c")
          Process.sleep(20)
          send.("def")
        end)

      assert {:ok, "abcdef"} = HTTP.post(url(port), "q")
    end

    test "skips an interim 100 answer" do
      port = reply(["HTTP/1.1 100 Continue\r\n\r\n", ok("after")])
      assert {:ok, "after"} = HTTP.post(url(port), "q")
    end

    test "ignores bytes after the announced length" do
      port = reply("HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabcXYZ")
      assert {:ok, "abc"} = HTTP.post(url(port), "q")
    end
  end

  describe "statuses" do
    test "only 200 is a success" do
      for status <- [201, 202, 204, 400, 401, 403, 404, 429, 500, 503] do
        port = reply("HTTP/1.1 #{status} Whatever\r\ncontent-length: 2\r\n\r\nhi")
        assert {:error, {:http_status, ^status}} = HTTP.post(url(port), "q")
      end
    end

    test "does not read the body of an error, however large it says it is" do
      port =
        flood("HTTP/1.1 500 Oops\r\ncontent-length: 314572800\r\n\r\n", :binary.copy("A", 65_536))

      {time, result} = :timer.tc(fn -> HTTP.post(url(port), "q") end)

      assert result == {:error, {:http_status, 500}}
      assert time < 2_000_000
    end
  end

  describe "redirects" do
    test "are not followed by default" do
      other = reply(ok("elsewhere"))
      port = reply("HTTP/1.1 302 Found\r\nlocation: #{url(other)}\r\ncontent-length: 0\r\n\r\n")

      assert {:error, {:http_status, 302}} = HTTP.post(url(port), "q")
      assert_receive {:request, _first}
      refute_receive {:request, _second}, 100
    end

    test "307 and 308 are followed when allowed, with the method and the body" do
      for status <- [307, 308] do
        final = reply(ok("final"))

        port =
          reply(
            "HTTP/1.1 #{status} R\r\nlocation: #{url(final, "/new")}\r\ncontent-length: 0\r\n\r\n"
          )

        assert {:ok, "final"} = HTTP.post(url(port), "again", max_redirects: 1)
        assert_receive {:request, first}
        assert_receive {:request, second}
        assert TestHTTPServer.request_line(first) == "POST /tsp HTTP/1.1"
        assert TestHTTPServer.request_line(second) == "POST /new HTTP/1.1"
        assert TestHTTPServer.body(second) == "again"
      end
    end

    test "301, 302 and 303 are not followed even when allowed" do
      for status <- [301, 302, 303] do
        final = reply(ok("final"))

        port =
          reply("HTTP/1.1 #{status} R\r\nlocation: #{url(final)}\r\ncontent-length: 0\r\n\r\n")

        assert {:error, {:http_status, ^status}} = HTTP.post(url(port), "q", max_redirects: 3)
      end
    end

    test "a relative location is resolved against the URL" do
      port =
        TestHTTPServer.start(fn %{request: request, send: send} ->
          if TestHTTPServer.request_line(request) =~ "/other",
            do: send.(ok("relative")),
            else: send.("HTTP/1.1 307 R\r\nlocation: /other\r\ncontent-length: 0\r\n\r\n")
        end)

      assert {:ok, "relative"} = HTTP.post(url(port), "q", max_redirects: 1)
    end

    test "stops at the limit" do
      port = reply("HTTP/1.1 307 R\r\nlocation: /again\r\ncontent-length: 0\r\n\r\n")
      assert {:error, {:http_status, 307}} = HTTP.post(url(port), "q", max_redirects: 2)
    end

    test "does not follow a redirect without a location, or to another scheme" do
      port = reply("HTTP/1.1 307 R\r\ncontent-length: 0\r\n\r\n")
      assert {:error, {:http_status, 307}} = HTTP.post(url(port), "q", max_redirects: 1)

      port = reply("HTTP/1.1 307 R\r\nlocation: ftp://example.com/x\r\ncontent-length: 0\r\n\r\n")
      assert {:error, {:http_status, 307}} = HTTP.post(url(port), "q", max_redirects: 1)
    end

    test "does not send the headers to another host" do
      final = reply(ok("final"))
      other_host = "http://localhost:#{final}/x"
      port = reply("HTTP/1.1 307 R\r\nlocation: #{other_host}\r\ncontent-length: 0\r\n\r\n")

      assert {:ok, "final"} =
               HTTP.post(url(port), "q", max_redirects: 1, headers: [{"authorization", "secret"}])

      assert_receive {:request, first}
      assert_receive {:request, second}
      assert TestHTTPServer.headers(first)["authorization"] == "secret"
      refute Map.has_key?(TestHTTPServer.headers(second), "authorization")
    end
  end

  describe "limits" do
    test "a Content-Length above the limit is refused without reading the body" do
      port =
        flood("HTTP/1.1 200 OK\r\ncontent-length: 314572800\r\n\r\n", :binary.copy("A", 65_536))

      {time, result} = :timer.tc(fn -> HTTP.post(url(port), "q") end)

      assert result == {:error, :too_large}
      assert time < 2_000_000
    end

    test "a body of exactly the limit passes and one byte more does not" do
      port = reply(ok(String.duplicate("a", 1000)))
      assert {:ok, body} = HTTP.post(url(port), "q", max_response_bytes: 1000)
      assert byte_size(body) == 1000

      port = reply(ok(String.duplicate("a", 1001)))
      assert {:error, :too_large} = HTTP.post(url(port), "q", max_response_bytes: 1000)
    end

    test "a chunked body is cut at the limit" do
      port = reply(chunked([String.duplicate("a", 600), String.duplicate("b", 400)]))
      assert {:ok, body} = HTTP.post(url(port), "q", max_response_bytes: 1000)
      assert byte_size(body) == 1000

      port = reply(chunked([String.duplicate("a", 600), String.duplicate("b", 401)]))
      assert {:error, :too_large} = HTTP.post(url(port), "q", max_response_bytes: 1000)

      port =
        flood(
          "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
          "10000\r\n" <> :binary.copy("A", 65_536) <> "\r\n"
        )

      assert {:error, :too_large} = HTTP.post(url(port), "q")
    end

    test "a body that ends with the connection is cut at the limit" do
      port = flood("HTTP/1.0 200 OK\r\n\r\n", :binary.copy("A", 65_536))
      {time, result} = :timer.tc(fn -> HTTP.post(url(port), "q") end)

      assert result == {:error, :too_large}
      assert time < 2_000_000
    end
  end

  describe "time" do
    test "is one budget for the whole exchange, against a slow body" do
      port =
        TestHTTPServer.start(fn %{send: send} ->
          send.("HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n")

          for _ <- 1..60 do
            send.("x")
            Process.sleep(100)
          end
        end)

      {time, result} = :timer.tc(fn -> HTTP.post(url(port), "q", timeout: 600) end)

      assert result == {:error, :timeout}
      assert div(time, 1000) in 550..1500
    end

    test "ends against a server that never answers" do
      port = TestHTTPServer.start(fn _conn -> Process.sleep(30_000) end)
      {time, result} = :timer.tc(fn -> HTTP.post(url(port), "q", timeout: 400) end)

      assert result == {:error, :timeout}
      assert div(time, 1000) in 350..1500
    end

    test "ends against a server that sends headers forever" do
      port =
        TestHTTPServer.start(fn %{send: send} ->
          send.("HTTP/1.1 200 OK\r\n")

          for n <- 1..60 do
            send.("x-#{n}: 1\r\n")
            Process.sleep(100)
          end
        end)

      assert {:error, :timeout} = HTTP.post(url(port), "q", timeout: 500)
    end
  end

  describe "connection" do
    test "refused" do
      port = TestHTTPServer.closed_port()
      assert {:error, {:connect, :econnrefused}} = HTTP.post(url(port), "q")
    end

    test "closed before the end of the body" do
      port = reply("HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort")
      assert {:error, {:other, :closed}} = HTTP.post(url(port), "q")

      port = reply("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nab")
      assert {:error, {:other, :closed}} = HTTP.post(url(port), "q")
    end

    test "closed before any answer" do
      port = reply("")
      assert {:error, {:other, :closed}} = HTTP.post(url(port), "q")
    end
  end

  describe "answers that are not valid" do
    test "bytes that are not HTTP" do
      for junk <- ["garbage\r\n\r\n", "HTTP/2 200\r\n\r\n", "HTTP/1.1 abc OK\r\n\r\n", "\r\n\r\n"] do
        port = reply(junk)
        assert {:error, {:other, :bad_response}} = HTTP.post(url(port), "q")
      end
    end

    test "a header block that is too large, or has too many headers" do
      port = reply(["HTTP/1.1 200 OK\r\nx: ", String.duplicate("a", 70_000), "\r\n\r\n"])
      assert {:error, {:other, reason}} = HTTP.post(url(port), "q")
      assert reason in [:header_too_large, :bad_response]

      headers = Enum.map(1..150, fn n -> "x-#{n}: 1\r\n" end)
      port = reply(["HTTP/1.1 200 OK\r\n", headers, "content-length: 1\r\n\r\na"])
      assert {:error, {:other, :bad_response}} = HTTP.post(url(port), "q")
    end

    test "a bad Content-Length" do
      for value <- ["12x", "-1", "", "99999999999999999999", "1, 2"] do
        port = reply("HTTP/1.1 200 OK\r\ncontent-length: #{value}\r\n\r\nabc")
        assert {:error, {:other, :bad_content_length}} = HTTP.post(url(port), "q")
      end

      port = reply("HTTP/1.1 200 OK\r\ncontent-length: 3\r\ncontent-length: 4\r\n\r\nabc")
      assert {:error, {:other, :bad_content_length}} = HTTP.post(url(port), "q")
    end

    test "a repeated Content-Length with the same value is one length" do
      port = reply("HTTP/1.1 200 OK\r\ncontent-length: 3\r\ncontent-length: 3\r\n\r\nabc")
      assert {:ok, "abc"} = HTTP.post(url(port), "q")
    end

    test "a transfer coding that is not chunked" do
      port = reply("HTTP/1.1 200 OK\r\ntransfer-encoding: gzip\r\n\r\nabc")
      assert {:error, {:other, :unsupported_transfer_encoding}} = HTTP.post(url(port), "q")
    end

    test "chunks that are broken" do
      for body <- ["zz\r\nab\r\n0\r\n\r\n", "2\r\nabXX0\r\n\r\n", "\r\nab", "-1\r\n"] do
        port = reply(["HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n", body])
        assert {:error, {:other, :bad_chunk}} = HTTP.post(url(port), "q")
      end
    end
  end

  describe "arguments" do
    test "a URL that is not http or https with a host" do
      for bad <- [
            "ftp://example.com/",
            "example.com",
            "http://",
            "/path",
            "http://user:pw@example.com/"
          ] do
        assert_raise ArgumentError, ~r/URL must be http or https/, fn -> HTTP.post(bad, "q") end
      end

      assert_raise ArgumentError, fn -> HTTP.post(:not_a_url, "q") end
      assert_raise ArgumentError, fn -> HTTP.post("http://example.com/", :not_a_body) end
    end

    test "bad options" do
      assert_raise ArgumentError, ~r/unknown option/, fn ->
        HTTP.post("http://x/", "q", other: 1)
      end

      assert_raise ArgumentError, fn -> HTTP.post("http://x/", "q", timeout: 0) end
      assert_raise ArgumentError, fn -> HTTP.post("http://x/", "q", max_redirects: -1) end
      assert_raise ArgumentError, fn -> HTTP.post("http://x/", "q", max_response_bytes: 0) end
      assert_raise ArgumentError, fn -> HTTP.post("http://x/", "q", ssl: :verify_none) end
      assert_raise ArgumentError, fn -> HTTP.post("http://x/", "q", timeout: 5, timeout: 6) end
    end

    test "headers that could write another header are refused without showing the value" do
      for headers <- [
            [{"x-a", "1\r\nx-b: 2"}],
            [{"x-a", "1\nx-b: 2"}],
            [{"x-a", <<0>>}],
            [{"x a", "1"}],
            [{"x:a", "1"}],
            [{"", "1"}],
            [{"x-a", 1}],
            ["x-a: 1"]
          ] do
        assert_raise ArgumentError, ~r/headers must be/, fn ->
          HTTP.post("http://x/", "q", headers: headers)
        end
      end

      for name <- ["Host", "content-length", "Connection", "Transfer-Encoding"] do
        error =
          assert_raise ArgumentError, fn ->
            HTTP.post("http://x/", "q", headers: [{name, "secret-value"}])
          end

        refute error.message =~ "secret-value"
      end
    end
  end

  describe "https" do
    setup do
      ca = TestPKI.cert({:p256, :http_ca}, ca: true, subject: "HTTP test CA")
      {:ok, ca: ca}
    end

    defp server_cert(ca, tag, opts \\ []) do
      name = {:p256, tag}

      cert =
        TestPKI.cert(
          name,
          Keyword.merge(
            [
              issuer: {ca, {:p256, :http_ca}},
              key_usage: [0],
              eku: [TestPKI.server_auth()],
              eku_critical: false,
              san: [{:dns, "localhost"}, {:ip, <<127, 0, 0, 1>>}]
            ],
            opts
          )
        )

      {cert, TestPKI.key(name)}
    end

    defp tls_url(port, host \\ "localhost"), do: "https://#{host}:#{port}/tsp"

    test "talks to a server whose certificate it trusts, by name and by address", %{ca: ca} do
      port =
        TestHTTPServer.start(fn %{send: send} -> send.(ok("secure")) end,
          tls: server_cert(ca, :ok)
        )

      assert {:ok, "secure"} = HTTP.post(tls_url(port), "q", ssl: [cacerts: [ca]])
      assert {:ok, "secure"} = HTTP.post(tls_url(port, "127.0.0.1"), "q", ssl: [cacerts: [ca]])
      assert_receive {:request, request}
      assert TestHTTPServer.headers(request)["host"] == "localhost:#{port}"
    end

    test "refuses a certificate of a CA it does not trust", %{ca: ca} do
      port =
        TestHTTPServer.start(fn %{send: send} -> send.(ok("secure")) end,
          tls: server_cert(ca, :unknown)
        )

      assert {:error, {:tls, _reason}} = HTTP.post(tls_url(port), "q")

      other = TestPKI.cert({:p256, :other_ca}, ca: true)
      assert {:error, {:tls, _reason}} = HTTP.post(tls_url(port), "q", ssl: [cacerts: [other]])
    end

    test "refuses a certificate for another name", %{ca: ca} do
      cert = server_cert(ca, :wrong_name, san: [{:dns, "other.example.test"}])
      port = TestHTTPServer.start(fn %{send: send} -> send.(ok("secure")) end, tls: cert)

      assert {:error, {:tls, _reason}} = HTTP.post(tls_url(port), "q", ssl: [cacerts: [ca]])
    end

    test "refuses a certificate that has expired", %{ca: ca} do
      cert =
        server_cert(ca, :expired,
          not_before: ~U[2015-01-01 00:00:00Z],
          not_after: ~U[2016-01-01 00:00:00Z]
        )

      port = TestHTTPServer.start(fn %{send: send} -> send.(ok("secure")) end, tls: cert)

      assert {:error, {:tls, _reason}} = HTTP.post(tls_url(port), "q", ssl: [cacerts: [ca]])
    end

    test "refuses an address that the certificate does not name", %{ca: ca} do
      cert = server_cert(ca, :only_name, san: [{:dns, "localhost"}])
      port = TestHTTPServer.start(fn %{send: send} -> send.(ok("secure")) end, tls: cert)

      assert {:error, {:tls, _reason}} =
               HTTP.post(tls_url(port, "127.0.0.1"), "q", ssl: [cacerts: [ca]])
    end

    test "a server that does not speak TLS is a TLS error" do
      port =
        TestHTTPServer.start(fn %{send: send} -> send.("HTTP/1.1 400 Bad Request\r\n\r\n") end,
          request: false
        )

      assert {:error, {:tls, _reason}} = HTTP.post(tls_url(port), "q", timeout: 2_000)
    end

    test "does not follow a redirect from https to http", %{ca: ca} do
      plain = reply(ok("plain"))

      port =
        TestHTTPServer.start(
          fn %{send: send} ->
            send.("HTTP/1.1 307 R\r\nlocation: #{url(plain)}\r\ncontent-length: 0\r\n\r\n")
          end,
          tls: server_cert(ca, :downgrade)
        )

      assert {:error, {:http_status, 307}} =
               HTTP.post(tls_url(port), "q", ssl: [cacerts: [ca]], max_redirects: 1)
    end
  end
end
