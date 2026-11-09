# Time of Tspex.verify_signature_time_stamps/3 for a signer with N stamps.
#
#     MIX_ENV=test mix run bench/stamps.exs

Code.require_file("helper.exs", __DIR__)
alias Tspex.{TestPKI, TestTSA}
alias TspexBench, as: B

B.header("Tspex.verify_signature_time_stamps/3")

tsa = TestTSA.new()
trust = TestTSA.trust(tsa)
root_key = {:p256, :bench_root}
root = TestPKI.cert(root_key, ca: true, subject: "Bench root")

cert =
  TestPKI.cert({:p256, :bench_signer},
    issuer: {root, root_key},
    key_usage: [0],
    subject: "Bench signer"
  )

signer = %{certificate: cert, key: TestPKI.key({:p256, :bench_signer}), chain: []}
{:ok, cms} = Cmsex.sign(:crypto.strong_rand_bytes(1024), signer)

stamped = fn count ->
  Enum.reduce(1..count, cms, fn _, acc ->
    {:ok, imprint} = Tspex.signature_imprint(cms, 0)
    request = Tspex.request!(imprint)
    {:ok, verified} = Tspex.verify(TestTSA.response(tsa, request), request, trust: trust)
    {:ok, with_stamp} = Tspex.add_signature_time_stamp(acc, 0, verified, max_attributes: 256)
    with_stamp
  end)
end

for count <- [1, 10, 100] do
  message = stamped.(count)

  B.measure("#{count} stamp(s): verify_signature_time_stamps", fn ->
    {:ok, verified} =
      Tspex.verify_signature_time_stamps(message, 0, trust: trust, max_attributes: 256)

    ^count = length(verified)
  end)

  B.measure("#{count} stamp(s): signature_time_stamps (reading)", fn ->
    {:ok, read} = Tspex.signature_time_stamps(message, 0, max_attributes: 256)
    ^count = length(read)
  end)
end
