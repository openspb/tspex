defmodule Tspex.InteropJarTest do
  # jarsigner asks a TSA for the time-stamp of its signature, and verifies a
  # stamp that Tspex adds. The TSA is a test TSA behind a local port.
  use ExUnit.Case, async: true

  alias Tspex.{Interop, TestHTTPServer, TestTSA}

  @moduletag :interop
  @moduletag :tmp_dir
  @moduletag timeout: 300_000

  found = Interop.find(:jarsigner)

  describe "jarsigner" do
    cond do
      found ->
        test "time-stamps its signature with a TSA, and Tspex reads the request and the stamp",
             %{tmp_dir: dir} do
          {jarsigner, _version} = unquote(Macro.escape(found))
          tsa = TestTSA.new()
          port = tsa_server(tsa)
          jar = make_jar(jarsigner, dir)

          assert {output, 0} =
                   Interop.run(jarsigner, [
                     "-keystore",
                     keystore(dir),
                     "-storepass",
                     "changeit",
                     "-tsa",
                     "http://127.0.0.1:#{port}/",
                     "-tsadigestalg",
                     "SHA-256",
                     jar,
                     "signer"
                   ])

          assert output =~ "jar signed"

          # the request it made
          assert_receive {:request, raw}
          headers = TestHTTPServer.headers(raw)
          assert headers["content-type"] == "application/timestamp-query"
          assert TestHTTPServer.request_line(raw) =~ ~r{^POST / HTTP/1\.[01]$}
          asked = Tspex.decode_request!(TestHTTPServer.body(raw))
          assert asked.hash == :sha256
          assert asked.cert_req
          assert asked.policy == nil
          assert asked.nonce != nil and asked.nonce < Bitwise.bsl(1, 64)

          # the stamp it keeps in the signature block
          block = block_of(jar)

          assert {:ok, [verified]} =
                   Tspex.verify_signature_time_stamps(block, 0, trust: TestTSA.trust(tsa))

          assert verified.info.digest == asked.digest
          assert verified.signer.certificate == tsa.cert

          # and jarsigner itself sees the stamp
          assert {out, 0} = Interop.run(jarsigner, ~w(-verify -verbose -certs) ++ [jar])
          assert out =~ "Timestamped by"
          assert out =~ "jar verified"
        end

        test "verifies a jar whose signature Tspex time-stamped", %{tmp_dir: dir} do
          {jarsigner, _version} = unquote(Macro.escape(found))
          tsa = TestTSA.new()
          jar = make_jar(jarsigner, dir)

          assert {_, 0} =
                   Interop.run(jarsigner, [
                     "-keystore",
                     keystore(dir),
                     "-storepass",
                     "changeit",
                     jar,
                     "signer"
                   ])

          block = block_of(jar)

          assert {:error, %Tspex.Error{reason: :no_time_stamp}} =
                   Tspex.verify_signature_time_stamps(block, 0, trust: TestTSA.trust(tsa))

          {:ok, imprint} = Tspex.signature_imprint(block, 0)
          request = Tspex.request!(imprint)
          response = TestTSA.response(tsa, request)
          {:ok, verified} = Tspex.verify(response, request, trust: TestTSA.trust(tsa))
          {:ok, stamped} = Tspex.add_signature_time_stamp(block, 0, verified)

          stamped_jar = Path.join(dir, "stamped.jar")
          File.write!(stamped_jar, replace_block(jar, stamped))

          assert {out, 0} = Interop.run(jarsigner, ~w(-verify -verbose -certs) ++ [stamped_jar])
          assert out =~ "Timestamped by"
          assert out =~ "jar verified"
          assert out =~ "SHA-256"

          assert {:ok, [_]} =
                   Tspex.verify_signature_time_stamps(block_of(stamped_jar), 0,
                     trust: TestTSA.trust(tsa)
                   )
        end

      Interop.required?(:jarsigner) ->
        test "is found" do
          flunk("jarsigner was not found; see test/support/interop.ex")
        end

      true ->
        @tag skip: "jarsigner was not found"
        test "was not found", do: :ok
    end
  end

  defp tsa_server(tsa) do
    TestHTTPServer.start(fn %{request: request, send: send} ->
      asked = Tspex.decode_request!(TestHTTPServer.body(request))

      send.(
        TestHTTPServer.ok(TestTSA.response(tsa, asked), [
          {"content-type", "application/timestamp-reply"}
        ])
      )
    end)
  end

  defp keystore(dir), do: Path.join(dir, "ks.p12")

  # A jar with one file and a key for jarsigner in a new keystore.
  defp make_jar(jarsigner, dir) do
    File.mkdir_p!(Path.join(dir, "content"))
    File.write!(Path.join([dir, "content", "a.txt"]), "hello\n")
    jar = Path.join(dir, "t.jar")

    {_, 0} =
      Interop.run(Interop.jdk_tool(jarsigner, "jar"), [
        "cf",
        jar,
        "-C",
        Path.join(dir, "content"),
        "a.txt"
      ])

    {_, 0} =
      Interop.run(Interop.jdk_tool(jarsigner, "keytool"), [
        "-genkeypair",
        "-alias",
        "signer",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-dname",
        "CN=Test signer",
        "-validity",
        "365",
        "-storetype",
        "PKCS12",
        "-keystore",
        keystore(dir),
        "-storepass",
        "changeit"
      ])

    jar
  end

  defp entries(jar) do
    {:ok, files} = :zip.unzip(File.read!(jar), [:memory])
    files
  end

  # The signature block of the jar: META-INF/SIGNER.RSA.
  defp block_of(jar) do
    {_name, block} =
      Enum.find(entries(jar), fn {name, _} -> List.to_string(name) =~ ~r{^META-INF/.*\.RSA$} end)

    block
  end

  defp replace_block(jar, new_block) do
    files =
      for {name, bytes} <- entries(jar) do
        if List.to_string(name) =~ ~r{^META-INF/.*\.RSA$},
          do: {name, new_block},
          else: {name, bytes}
      end

    {:ok, {_name, zip}} = :zip.zip(~c"stamped.jar", files, [:memory])
    zip
  end
end
