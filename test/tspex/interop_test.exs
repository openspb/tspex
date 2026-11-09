defmodule Tspex.InteropTest do
  # Other implementations read what Tspex writes and write what Tspex reads.
  # The tools are those found on this system; see test/support/interop.ex.
  use ExUnit.Case, async: true

  alias Tspex.{Interop, TestTSA}

  @moduletag :interop
  @moduletag :tmp_dir
  @moduletag timeout: 300_000

  @data "the contract of the interop tests\n"

  for tool <- [:openssl, :libressl] do
    found = Interop.find(tool)

    # The LibreSSL of macOS signs its tokens with SHA-1 whatever its
    # configuration says (signer_digest), so they are read only with
    # allow_sha1: true.
    extra = if tool == :libressl, do: [allow_sha1: true], else: []

    describe "#{tool}" do
      cond do
        found ->
          test "reads the request that Tspex writes", %{tmp_dir: dir} do
            found = unquote(Macro.escape(found))
            {path, _version} = found

            for opts <- [[], [hash: :sha384], [hash: :sha512, nonce: false], [cert_req: false]] do
              request = Tspex.request!(@data, opts)
              file = Path.join(dir, "q.tsq")
              File.write!(file, request.der)

              {text, 0} = Interop.run(path, ~w(ts -query -in #{file} -text))

              hash = Keyword.get(opts, :hash, :sha256)
              assert text =~ "Hash Algorithm: #{hash}"
              assert hex_dump(text) == request.digest
              assert text =~ if(request.cert_req, do: "required: yes", else: "required: no")

              if request.nonce do
                [_, hex] = Regex.run(~r/Nonce: 0x([0-9A-F]+)/, text)
                assert String.to_integer(hex, 16) == request.nonce
              else
                assert text =~ "Nonce: unspecified"
              end
            end
          end

          # No tool reads RFC 5544 itself; what it can say is that the
          # structure is DER all the way down, with the tokens inside.
          test "parses the TimeStampedData that Tspex writes", %{tmp_dir: dir} do
            {path, _version} = unquote(Macro.escape(found))
            tsa = TestTSA.new()
            token = fn imprint -> TestTSA.token(tsa, Tspex.request!(imprint)) end

            options = [
              file_name: "contract.pdf",
              media_type: "application/pdf",
              hash_protected: true
            ]

            {:ok, imprint} = Tspex.TimeStampedData.imprint(@data, options)

            {:ok, tsd} =
              Tspex.TimeStampedData.new(@data, token.(imprint), options ++ [trust: [tsa.root]])

            {:ok, next} = Tspex.TimeStampedData.extension_imprint(tsd)
            {:ok, tsd} = Tspex.TimeStampedData.extend(tsd, token.(next), trust: [tsa.root])

            file = Path.join(dir, "tsd.der")
            File.write!(file, Tspex.TimeStampedData.encode(tsd))

            {text, 0} = Interop.run(path, ~w(asn1parse -inform DER -in #{file}))

            assert text =~ "1.2.840.113549.1.9.16.1.31"
            assert text =~ "contract.pdf"
            assert length(Regex.scan(~r/pkcs7-signedData/, text)) == 2
            # In each token: the eContentType and the content-type attribute.
            assert length(Regex.scan(~r/id-smime-ct-TSTInfo/, text)) == 4
          end

          for kind <- [:rsa, :ec] do
            test "answers a Tspex request with a #{kind} TSA, and Tspex verifies the answer", %{
              tmp_dir: dir
            } do
              found = unquote(Macro.escape(found))
              tsa = Interop.make_tsa(found, dir, unquote(kind))

              for opts <- [
                    [],
                    [hash: :sha384],
                    [hash: :sha512, policy: "1.2.3.4.5.6"],
                    [hash: :sha1, allow_sha1: true],
                    [nonce: false],
                    [hash: :sha224]
                  ] do
                request = Tspex.request!(@data, opts)
                response = Interop.reply(found, dir, request.der)
                verify_opts = Keyword.merge(Keyword.take(opts, [:allow_sha1]), unquote(extra))

                assert {:ok, verified} =
                         Tspex.verify(response, request, [trust: [tsa.root]] ++ verify_opts),
                       inspect(opts)

                assert verified.info.digest == request.digest
                assert verified.signer.certificate == tsa.cert
                assert verified.trust == :validated
                assert verified.info.policy == Keyword.get(opts, :policy, "1.2.3.4.1") |> oid()
              end

              # kept for later, and as a bare token
              request = Tspex.request!(@data)
              token = Interop.reply(found, dir, request.der, true)

              assert {:ok, _} =
                       Tspex.verify(
                         token,
                         {:data, @data},
                         [trust: [tsa.root], input: :token] ++ unquote(extra)
                       )
            end
          end

          if tool == :libressl do
            test "a token signed with SHA-1 is refused unless allowed", %{tmp_dir: dir} do
              found = unquote(Macro.escape(found))
              tsa = Interop.make_tsa(found, dir, :rsa)
              request = Tspex.request!(@data)
              response = Interop.reply(found, dir, request.der)

              assert {:error, %Tspex.Error{reason: :weak_algorithm, detail: :sha1, cause: cause}} =
                       Tspex.verify(response, request, trust: [tsa.root])

              assert %Cmsex.Error{reason: :weak_algorithm} = cause

              assert {:error, %Tspex.Error{reason: :weak_algorithm}} =
                       Tspex.verify(response, request, trust: :none)

              assert {:ok, %{trust: :validated}} =
                       Tspex.verify(response, request, trust: [tsa.root], allow_sha1: true)
            end
          end

          test "a policy it does not offer is a rejection that Tspex reads", %{tmp_dir: dir} do
            found = unquote(Macro.escape(found))
            tsa = Interop.make_tsa(found, dir, :rsa)
            request = Tspex.request!(@data, policy: "1.9.9")
            response = Interop.reply(found, dir, request.der)

            assert {:error, %Tspex.Error{reason: :rejection, detail: detail}} =
                     Tspex.verify(response, request, [trust: [tsa.root]] ++ unquote(extra))

            assert :unaccepted_policy in detail.fail_info
          end

          test "an answer for other data, or from another CA, is refused", %{tmp_dir: dir} do
            found = unquote(Macro.escape(found))
            tsa = Interop.make_tsa(found, dir, :ec)
            request = Tspex.request!(@data)
            response = Interop.reply(found, dir, request.der)

            assert {:error, %Tspex.Error{reason: :nonce_mismatch}} =
                     Tspex.verify(
                       response,
                       Tspex.request!(@data),
                       [trust: [tsa.root]] ++ unquote(extra)
                     )

            assert {:error, %Tspex.Error{reason: :imprint_mismatch}} =
                     Tspex.verify(
                       response,
                       {:data, "other data"},
                       [trust: [tsa.root], input: :response] ++ unquote(extra)
                     )

            other = TestTSA.new(root_tag: :interop_other)

            assert {:error, %Tspex.Error{reason: :untrusted}} =
                     Tspex.verify(response, request, [trust: [other.root]] ++ unquote(extra))
          end

          for {name, opts} <- [
                {"a P-256 TSA", [key: :p256]},
                {"an RSA TSA", [key: :rsa2048]}
              ] do
            test "verifies what a test TSA issues: #{name}", %{tmp_dir: dir} do
              found = unquote(Macro.escape(found))
              {path, _version} = found
              tsa = TestTSA.new(unquote(opts))
              request = Tspex.request!(@data)
              response = TestTSA.response(tsa, request)

              File.write!(Path.join(dir, "q.tsq"), request.der)
              File.write!(Path.join(dir, "r.tsr"), response)
              File.write!(Path.join(dir, "data.txt"), @data)
              File.write!(Path.join(dir, "root.pem"), Interop.pem(tsa.root))

              verify = fn args -> Interop.run(path, ~w(ts -verify) ++ args, cd: dir) end

              assert {out, 0} =
                       verify.(~w(-queryfile q.tsq -in r.tsr -CAfile root.pem))

              assert out =~ "Verification: OK"
              assert {_, 0} = verify.(~w(-data data.txt -in r.tsr -CAfile root.pem))

              # and refuses what is wrong
              File.write!(Path.join(dir, "other.txt"), "other data")
              assert {_, status} = verify.(~w(-data other.txt -in r.tsr -CAfile root.pem))
              assert status != 0

              File.write!(Path.join(dir, "bad.tsr"), TestTSA.flip_signature(response))
              assert {_, status} = verify.(~w(-queryfile q.tsq -in bad.tsr -CAfile root.pem))
              assert status != 0

              other = TestTSA.new(root_tag: :interop_other)
              File.write!(Path.join(dir, "other.pem"), Interop.pem(other.root))
              assert {_, status} = verify.(~w(-queryfile q.tsq -in r.tsr -CAfile other.pem))
              assert status != 0
            end
          end

        Interop.required?(tool) ->
          test "is found" do
            flunk("#{unquote(tool)} was not found; see test/support/interop.ex")
          end

        true ->
          @tag skip: "#{tool} was not found"
          test "was not found", do: :ok
      end
    end
  end

  defp oid(text),
    do: text |> String.split(".") |> Enum.map(&String.to_integer/1) |> List.to_tuple()

  # The bytes of the "Message data:" dump of `openssl ts -query -text`.
  defp hex_dump(text) do
    text
    |> String.split("\n")
    |> Enum.flat_map(fn line ->
      case Regex.run(~r/^\s+[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -]){15}[0-9a-f]{2})/, line) do
        [_, bytes] -> [String.replace(bytes, ~r/[^0-9a-f]/, "")]
        nil -> []
      end
    end)
    |> Enum.join()
    |> Base.decode16!(case: :lower)
  end
end
