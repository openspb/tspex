defmodule Tspex.Codec do
  @moduledoc false
  # The pieces of ASN.1 that the request, the response and the TSTInfo share:
  # the message imprint, the extensions, integers of bounded size, and the
  # conversion of the errors of the DER reader.

  alias Tspex.{DER, Error, Imprint}

  @max_integer_octets 32

  @type hash :: Imprint.hash() | :md5 | tuple()
  @type extension :: %{oid: tuple(), critical: boolean(), value: binary()}

  @doc "Reads the root element of `der`, with the limits in `opts` (a map)."
  @spec decode(binary(), map()) :: {:ok, DER.element()} | {:error, Error.t()}
  def decode(der, opts) do
    limits = opts |> Map.take([:max_size, :max_depth, :max_nodes]) |> Map.to_list()

    case DER.decode(der, limits) do
      {:ok, element} -> {:ok, element}
      {:error, :malformed} -> {:error, Error.new(:malformed)}
      {:error, {:limit_exceeded, limit}} -> {:error, Error.new(:limit_exceeded, limit)}
    end
  end

  @doc "The limits of the options, as the keyword list `DER.decode/2` takes."
  @spec limits(map()) :: keyword()
  def limits(opts), do: opts |> Map.take([:max_size, :max_depth, :max_nodes]) |> Map.to_list()

  ## Message imprint

  @doc """
  MessageImprint: the hash (a name, `:md5`, or the OID tuple of an algorithm
  this library does not know) and the digest, whose size is checked for a
  known hash. The parameters of the hash may be absent or NULL.
  """
  @spec message_imprint(DER.element()) :: {:ok, hash(), binary()} | :error
  def message_imprint({0x30, _, _} = element) do
    with [algorithm, {0x04, _, _} = digest_element] <- DER.children(element),
         {:ok, hash} <- hash_algorithm(algorithm),
         {:ok, digest} <- DER.octets(digest_element),
         true <- size_ok?(hash, digest) do
      {:ok, hash, digest}
    else
      _ -> :error
    end
  end

  def message_imprint(_element), do: :error

  defp hash_algorithm({0x30, _, _} = element) do
    case DER.children(element) do
      [oid_element | params] when length(params) <= 1 ->
        with {:ok, oid} <- DER.oid(oid_element), do: known_or_oid(oid, params)

      _ ->
        :error
    end
  end

  defp hash_algorithm(_element), do: :error

  defp known_or_oid(oid, params) do
    case Imprint.from_oid(oid) do
      {:ok, hash} -> if null_or_absent?(params), do: {:ok, hash}, else: :error
      {:weak, :md5} -> if null_or_absent?(params), do: {:ok, :md5}, else: :error
      :error -> {:ok, oid}
    end
  end

  defp null_or_absent?([]), do: true
  defp null_or_absent?([element]), do: DER.null?(element)

  defp size_ok?(hash, digest) when is_atom(hash),
    do: byte_size(digest) == Imprint.digest_size(hash)

  defp size_ok?(_oid, _digest), do: true

  @doc "The DER term of a MessageImprint, with NULL parameters (RFC 5754, 2; RFC 4055, 2.1)."
  @spec message_imprint_term(Imprint.hash(), binary()) :: DER.term_()
  def message_imprint_term(hash, digest) do
    {:seq, [{:seq, [{:oid, Imprint.oid(hash)}, :null]}, {:octets, digest}]}
  end

  ## Integers

  @doc "An INTEGER of at most 32 octets."
  @spec integer(DER.element()) :: {:ok, integer()} | :error
  def integer({0x02, content, _raw} = element) when byte_size(content) <= @max_integer_octets,
    do: DER.integer(element)

  def integer(_element), do: :error

  ## Extensions

  @doc """
  The Extensions of a request or a TSTInfo, `[0]` or `[1]` IMPLICIT in the
  caller: each one's OID, its critical flag (false when absent) and the DER
  of its value, as bytes.
  """
  @spec extensions(DER.element()) :: {:ok, [extension()]} | :error
  def extensions(element) do
    element |> DER.children() |> Enum.reduce_while({:ok, []}, &add_extension/2) |> reverse()
  end

  defp add_extension({0x30, _, _} = element, {:ok, acc}) do
    case DER.children(element) do
      [oid_element, {0x04, _, _} = value] ->
        extension(oid_element, false, value, acc)

      [oid_element, {0x01, _, _} = flag, {0x04, _, _} = value] ->
        extension(oid_element, flag, value, acc)

      _ ->
        {:halt, :error}
    end
  end

  defp add_extension(_element, _acc), do: {:halt, :error}

  defp extension(oid_element, flag, value, acc) do
    with {:ok, oid} <- DER.oid(oid_element),
         {:ok, critical} <- critical(flag),
         {:ok, bytes} <- DER.octets(value) do
      {:cont, {:ok, [%{oid: oid, critical: critical, value: bytes} | acc]}}
    else
      _ -> {:halt, :error}
    end
  end

  defp critical(false), do: {:ok, false}
  defp critical(flag), do: DER.boolean(flag)

  defp reverse({:ok, list}), do: {:ok, Enum.reverse(list)}
  defp reverse(:error), do: :error

  @doc "The DER terms of extensions, for the writer."
  @spec extensions_term([extension()]) :: [DER.term_()]
  def extensions_term(extensions) do
    for %{oid: oid, critical: critical, value: value} <- extensions do
      flag = if critical, do: [{:bool, true}], else: []
      {:seq, [{:oid, oid}] ++ flag ++ [{:octets, value}]}
    end
  end
end
