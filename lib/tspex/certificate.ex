defmodule Tspex.Certificate do
  @moduledoc false
  # What the verification needs from an X.509 certificate (RFC 5280, 4.1),
  # read with the DER reader of the library: the names, the validity and
  # the extensions as they are written, so that a repeated extension is seen
  # as repeated.

  alias Tspex.{Codec, DER}

  @eku {2, 5, 29, 37}
  @key_usage {2, 5, 29, 15}
  @san {2, 5, 29, 17}

  @type t :: %{
          der: binary(),
          serial: integer(),
          issuer: binary(),
          subject: binary(),
          not_before: DateTime.t(),
          not_after: DateTime.t(),
          extensions: [Codec.extension()]
        }

  @spec parse(binary()) :: {:ok, t()} | :error
  def parse(der) when is_binary(der) do
    with {:ok, {0x30, _, _} = root} <- DER.decode(der),
         [{0x30, _, _} = tbs, {0x30, _, _}, {0x03, _, _}] <- DER.children(root),
         {:ok, fields} <- tbs_fields(DER.children(tbs)) do
      {:ok, Map.put(fields, :der, der)}
    else
      _ -> :error
    end
  end

  def parse(_), do: :error

  defp tbs_fields([{0xA0, _, _} | rest]), do: tbs_fields(rest)

  defp tbs_fields([
         serial,
         {0x30, _, _},
         {0x30, _, issuer},
         {0x30, _, _} = validity,
         {0x30, _, subject},
         {0x30, _, _} | rest
       ]) do
    with {:ok, serial} <- DER.integer(serial),
         [not_before, not_after] <- DER.children(validity),
         {:ok, not_before} <- time(not_before),
         {:ok, not_after} <- time(not_after),
         {:ok, extensions} <- extensions(rest) do
      {:ok,
       %{
         serial: serial,
         issuer: issuer,
         subject: subject,
         not_before: not_before,
         not_after: not_after,
         extensions: extensions
       }}
    else
      _ -> :error
    end
  end

  defp tbs_fields(_), do: :error

  # Time ::= CHOICE { utcTime, generalTime } (RFC 5280, 4.1.2.5): the
  # seconds are always written, and the time is UTC.
  defp time({0x17, <<yy::binary-size(2), rest::binary-size(11)>>, _}) do
    if all_digits?(yy) do
      year = String.to_integer(yy)
      datetime(if(year >= 50, do: 1900 + year, else: 2000 + year), rest)
    else
      :error
    end
  end

  defp time({0x18, <<year::binary-size(4), rest::binary-size(11)>>, _}) do
    with true <- all_digits?(year), do: datetime(String.to_integer(year), rest)
  end

  defp time(_), do: :error

  defp datetime(
         year,
         <<mo::binary-size(2), d::binary-size(2), h::binary-size(2), mi::binary-size(2),
           s::binary-size(2), "Z">>
       ) do
    with true <- all_digits?(mo <> d <> h <> mi <> s),
         {:ok, date} <- Date.new(year, String.to_integer(mo), String.to_integer(d)),
         {:ok, time} <-
           Time.new(String.to_integer(h), String.to_integer(mi), String.to_integer(s)),
         do: DateTime.new(date, time, "Etc/UTC")
  end

  defp datetime(_year, _rest), do: :error

  defp all_digits?(text), do: text != "" and Enum.all?(String.to_charlist(text), &(&1 in ?0..?9))

  defp extensions([]), do: {:ok, []}
  defp extensions([{0xA1, _, _}, {0xA2, _, _}, {0xA3, _, _} = tagged]), do: extensions([tagged])
  defp extensions([{0xA1, _, _}, {0xA3, _, _} = tagged]), do: extensions([tagged])
  defp extensions([{0xA2, _, _}, {0xA3, _, _} = tagged]), do: extensions([tagged])

  defp extensions([{0xA3, _, _} = tagged]) do
    case DER.children(tagged) do
      [{0x30, _, _} = seq] -> Codec.extensions(seq)
      _ -> :error
    end
  end

  defp extensions(_), do: :error

  ## What the rules look at

  @doc "The instances of the extension `oid`, in the order they are written."
  @spec extensions(t(), tuple()) :: [Codec.extension()]
  def extensions(%{extensions: extensions}, oid), do: Enum.filter(extensions, &(&1.oid == oid))

  @doc "The OIDs of one extKeyUsage extension."
  @spec eku_list(Codec.extension()) :: {:ok, [tuple()]} | :error
  def eku_list(%{oid: @eku, value: value}) do
    case DER.decode(value) do
      {:ok, {0x30, _, _} = seq} ->
        seq |> DER.children() |> Enum.reduce_while({:ok, []}, &add_oid/2) |> reverse()

      _ ->
        :error
    end
  end

  defp add_oid(element, {:ok, acc}) do
    case DER.oid(element) do
      {:ok, oid} -> {:cont, {:ok, [oid | acc]}}
      :error -> {:halt, :error}
    end
  end

  defp reverse({:ok, list}), do: {:ok, Enum.reverse(list)}
  defp reverse(:error), do: :error

  @doc "The bit positions of the keyUsage extension, `nil` when there is none, `:error` when it is not valid."
  @spec key_usage(t()) :: [non_neg_integer()] | nil | :error
  def key_usage(cert) do
    case extensions(cert, @key_usage) do
      [] ->
        nil

      [%{value: value}] ->
        with {:ok, {0x03, _, _} = bits} <- DER.decode(value),
             {:ok, positions} <- DER.named_bits(bits) do
          positions
        else
          _ -> :error
        end

      _ ->
        :error
    end
  end

  @doc """
  The names of the certificate for the match with the `tsa` field: the
  subject when it is not empty, then each subjectAltName.
  """
  @spec names(t()) :: [Codec.name()]
  def names(cert) do
    subject = if cert.subject == <<0x30, 0>>, do: [], else: [{:directory_name, cert.subject}]
    subject ++ alt_names(cert)
  end

  defp alt_names(cert) do
    for %{value: value} <- extensions(cert, @san),
        {:ok, {0x30, _, _} = seq} <- [DER.decode(value)],
        element <- DER.children(seq),
        {:ok, name} <- [Codec.general_name(element)],
        do: name
  end
end
