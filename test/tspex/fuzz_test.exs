defmodule Tspex.FuzzTest do
  # Every reader returns {:ok, _} or {:error, %Tspex.Error{}} for any input,
  # a valid message with a few edits or random bytes, and never raises.
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Tspex.{Error, Fixtures, TestFuzz}

  defp ok_or_error?({:ok, _}), do: true
  defp ok_or_error?({:error, %Error{}}), do: true
  defp ok_or_error?(_), do: false

  for {reader, fixture} <- [
        {:decode_request, "q_policy.tsq"},
        {:decode_request, "q_sha512.tsq"},
        {:decode_response, "r_alg_reject.tsr"},
        {:decode_response, "r_rsa.tsr"},
        {:decode_response, "r_ec.tsr"},
        {:decode_token, "r_rsa.tst"},
        {:decode_token, "r_ec.tst"}
      ] do
    property "#{reader} of #{fixture} with edits" do
      base = Fixtures.read(unquote(fixture))

      check all input <- TestFuzz.mutated(base), max_runs: TestFuzz.rounds() do
        assert ok_or_error?(apply(Tspex, unquote(reader), [input]))
      end
    end
  end

  for reader <- [:decode_request, :decode_response, :decode_token] do
    property "#{reader} of random bytes" do
      check all input <- TestFuzz.random(), max_runs: TestFuzz.rounds() do
        assert ok_or_error?(apply(Tspex, unquote(reader), [input]))
      end
    end
  end
end
