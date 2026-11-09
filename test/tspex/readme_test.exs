defmodule Tspex.ReadmeTest do
  # The examples of the README run here, in order, as one program, in a
  # directory with the files they read: the root of a TSA, a signer and its
  # root, and a document. The TSA is a test TSA behind a local port, and the
  # address of the README is replaced by the one of that port.
  #
  # Not async: the examples read files by relative paths, so the test
  # changes the working directory, which is the same for the whole VM.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Tspex.{TestHTTPServer, TestPKI, TestTSA}

  @moduletag :tmp_dir

  @readme Path.expand("../../README.md", __DIR__)
  @url "https://tsa.example.com/tsp"

  # The blocks of Elixir code with the line where each starts, but the one
  # of the installation, which is not a program.
  defp examples do
    readme = File.read!(@readme)

    ~r/^```elixir\n(.*?)^```$/ms
    |> Regex.scan(readme, return: :index, capture: :all_but_first)
    |> Enum.map(fn [{start, size}] ->
      line = readme |> binary_part(0, start) |> String.split("\n") |> length()
      {binary_part(readme, start, size), line}
    end)
    |> Enum.reject(fn {code, _line} -> code =~ "def deps" end)
  end

  defp stage(dir) do
    write = fn name, bytes -> File.write!(Path.join(dir, name), bytes) end

    tsa = TestTSA.new()

    signer_root_key = {:p256, :readme_root}
    signer_root = TestPKI.cert(signer_root_key, ca: true, subject: "Readme root")

    signer_key = {:p256, :readme_signer}

    signer =
      TestPKI.cert(signer_key,
        subject: "Readme signer",
        issuer: {signer_root, signer_root_key},
        key_usage: [0]
      )

    {:PrivateKeyInfo, key_der, :not_encrypted} =
      :public_key.pem_entry_encode(:PrivateKeyInfo, TestPKI.key(signer_key))

    write.("tsa-root.crt", tsa.root)
    write.("signer.crt", signer)
    write.("signer.key", key_der)
    write.("signer-root.crt", signer_root)
    write.("contract.pdf", "%PDF-1.7\n" <> :crypto.strong_rand_bytes(20_000))

    port =
      TestHTTPServer.start(fn %{request: request, send: send} ->
        asked = Tspex.decode_request!(TestHTTPServer.body(request))
        reply = TestTSA.response(tsa, asked)
        send.(TestHTTPServer.ok(reply, [{"content-type", "application/timestamp-reply"}]))
      end)

    "http://127.0.0.1:#{port}/tsp"
  end

  test "the examples call the main functions" do
    code = Enum.map_join(examples(), "\n", &elem(&1, 0))

    for function <-
          ~w(stamp verify request! decode_token signature_imprint add_signature_time_stamp
             verify_at_stamp content_time_stamp_attribute verify_content_time_stamp) do
      assert code =~ "Tspex.#{function}(", "no example of Tspex.#{function}"
    end

    for function <- ~w(imprint new extension_imprint extend encode verify) do
      assert code =~ "TimeStampedData.#{function}(",
             "no example of TimeStampedData.#{function}"
    end
  end

  test "the examples of the README run, in order, without warnings", %{tmp_dir: dir} do
    url = stage(dir)

    warnings =
      capture_io(:stderr, fn ->
        File.cd!(dir, fn ->
          Enum.reduce(examples(), [], fn {code, line}, binding ->
            code = String.replace(code, @url, url)
            {_result, binding} = Code.eval_string(code, binding, file: @readme, line: line)
            binding
          end)
        end)
      end)

    assert warnings == ""
  end
end
