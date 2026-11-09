# What the benchmarks share: a measure of the time of a call. The scripts
# use the test TSA of test/support, so they run in the test environment:
#
#     MIX_ENV=test mix run bench/verify.exs

defmodule TspexBench do
  @doc "The versions, to head the output."
  def header(title) do
    [{_, _, openssl}] = :crypto.info_lib()
    IO.puts("#{title}: OTP #{System.otp_release()}, Elixir #{System.version()}, #{openssl}\n")
    row("", "median", "p99")
  end

  @doc """
  Calls `fun` for about `seconds`, after a few calls to warm up, and
  prints the median and the 99th percentile, in milliseconds. Returns the
  median.
  """
  def measure(label, fun, seconds \\ 1) do
    for _ <- 1..3, do: fun.()
    deadline = System.monotonic_time(:millisecond) + round(seconds * 1000)
    times = times(fun, deadline, []) |> Enum.sort()
    at = fn q -> Enum.at(times, min(length(times) - 1, trunc(q * length(times)))) / 1000 end
    row(label, ms(at.(0.5)), ms(at.(0.99)))
    at.(0.5)
  end

  defp times(fun, deadline, acc) do
    {us, _} = :timer.tc(fun)
    acc = [us | acc]
    if System.monotonic_time(:millisecond) < deadline, do: times(fun, deadline, acc), else: acc
  end

  def row(label, a, b),
    do:
      IO.puts(
        String.pad_trailing(label, 52) <> String.pad_leading(a, 10) <> String.pad_leading(b, 10)
      )

  def ms(value) when value >= 100, do: :erlang.float_to_binary(value, decimals: 0)
  def ms(value) when value >= 10, do: :erlang.float_to_binary(value, decimals: 1)
  def ms(value), do: :erlang.float_to_binary(value, decimals: 3)
end
