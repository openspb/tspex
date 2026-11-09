defmodule Tspex.Time do
  @moduledoc false
  # GeneralizedTime as RFC 3161 uses it (genTime): YYYYMMDDhhmmss[.d+]Z.
  # The reader is stricter than X.690 in what it refuses (no time zone
  # offsets, no minutes-only forms, no leap seconds) and more tolerant in
  # one thing: a fraction that is not in DER is read and reported as a
  # deviation.

  @doc """
  Reads the content octets of a GeneralizedTime. Returns the DateTime (the
  fraction truncated to microseconds) and the deviations from DER found.
  """
  @spec parse(binary()) :: {:ok, DateTime.t(), [:gen_time_encoding]} | :error
  def parse(<<digits::binary-size(14), rest::binary>>) do
    with {:ok, fraction, deviations} <- fraction(rest),
         <<y::binary-size(4), mo::binary-size(2), d::binary-size(2), h::binary-size(2),
           mi::binary-size(2), s::binary-size(2)>> <- digits,
         true <- all_digits?(digits) and y != "0000",
         {:ok, date} <-
           Date.new(String.to_integer(y), String.to_integer(mo), String.to_integer(d)),
         {:ok, time} <-
           Time.new(String.to_integer(h), String.to_integer(mi), String.to_integer(s), fraction),
         {:ok, dt} <- DateTime.new(date, time, "Etc/UTC") do
      {:ok, dt, deviations}
    else
      _ -> :error
    end
  end

  def parse(_), do: :error

  # "Z" alone is DER. ".d+Z" is allowed by the RFC; a trailing zero or ".0"
  # is not DER (X.690 11.7) and is read with the deviation.
  defp fraction("Z"), do: {:ok, {0, 0}, []}

  defp fraction(<<".", rest::binary>>) do
    with true <- byte_size(rest) >= 2 and binary_part(rest, byte_size(rest) - 1, 1) == "Z",
         digits = binary_part(rest, 0, byte_size(rest) - 1),
         true <- all_digits?(digits) do
      micro = digits |> String.slice(0, 6) |> String.pad_trailing(6, "0") |> String.to_integer()
      der? = not String.ends_with?(digits, "0")
      {:ok, {micro, 6}, if(der?, do: [], else: [:gen_time_encoding])}
    else
      _ -> :error
    end
  end

  defp fraction(_), do: :error

  defp all_digits?(bin),
    do: bin != "" and for(<<c <- bin>>, reduce: true, do: (ok -> ok and c in ?0..?9))
end
