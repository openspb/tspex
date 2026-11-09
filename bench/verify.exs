# Time of Tspex.verify/3 and of reading the same answers without verifying.
#
#     MIX_ENV=test mix run bench/verify.exs
#
# Each case runs for about a second; the median and the 99th percentile of
# the calls are shown, in milliseconds.

Code.require_file("helper.exs", __DIR__)
alias Tspex.TestTSA
alias TspexBench, as: B

B.header("Tspex.verify/3")
data = :crypto.strong_rand_bytes(1024)

for {label, opts} <- [
      {"P-256 TSA", [key: :p256]},
      {"RSA-2048 TSA", [key: :rsa2048]},
      {"P-256 TSA, with an intermediate CA", [key: :p256, intermediate: true]}
    ] do
  tsa = TestTSA.new(opts)
  trust = TestTSA.trust(tsa)
  request = Tspex.request!(data)
  response = TestTSA.response(tsa, request)
  token = Tspex.decode_response!(response).token

  B.measure(label <> ": decode_response", fn -> {:ok, _} = Tspex.decode_response(response) end)
  B.measure(label <> ": decode_token", fn -> {:ok, _} = Tspex.decode_token(token) end)

  B.measure(label <> ": verify, fresh", fn ->
    {:ok, _} = Tspex.verify(response, request, trust: trust)
  end)

  B.measure(label <> ": verify, stored", fn ->
    {:ok, _} = Tspex.verify(token, {:data, data}, trust: trust)
  end)

  B.measure(label <> ": verify, trust: :none", fn ->
    {:ok, _} = Tspex.verify(token, {:data, data}, trust: :none)
  end)

  # the TSA certificate given, not read from the token
  bare_request = Tspex.request!(data, cert_req: false)
  bare = TestTSA.response(tsa, bare_request, certs: :omit)

  B.measure(label <> ": verify, certificates: given", fn ->
    {:ok, _} =
      Tspex.verify(bare, bare_request,
        trust: trust,
        certificates: [tsa.cert | List.wrap(tsa.intermediate)]
      )
  end)

  IO.puts("")
end

# Many stored tokens in a row, as an archive is checked.
tsa = TestTSA.new()
trust = TestTSA.trust(tsa)

tokens =
  for n <- 1..200 do
    request = Tspex.request!("document #{n}")
    {"document #{n}", Tspex.decode_response!(TestTSA.response(tsa, request)).token}
  end

{us, :ok} =
  :timer.tc(fn ->
    for {doc, token} <- tokens, do: {:ok, _} = Tspex.verify(token, {:data, doc}, trust: trust)
    :ok
  end)

IO.puts(
  "200 stored tokens of one TSA in a row: #{B.ms(us / 1000)} ms in all, #{B.ms(us / 1000 / 200)} ms each"
)
