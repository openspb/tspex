defmodule Tspex.DER do
  @moduledoc false
  # A BER/DER reader and a DER writer, with what the Time-Stamp Protocol uses.
  #
  # An element is `{id, content, raw}`: `id` is the identifier octet (tag
  # numbers up to 30), `content` the content octets (for an indefinite length,
  # up to the end-of-contents octets) and `raw` the whole element. `content`
  # and `raw` are sub-binaries of the input, so reading copies nothing and the
  # bytes received stay as they were. `decode/2` checks the whole structure
  # once (lengths, nesting, number of elements); `children/1` then reads one
  # level on demand.

  import Bitwise

  @type element :: {byte(), binary(), binary()}

  @default_max_size 1_048_576
  @default_max_depth 32
  @default_max_nodes 100_000

  ## Reading

  @type error :: :malformed | {:limit_exceeded, :max_size | :max_depth | :max_nodes}

  @doc """
  Reads one element that spans the whole binary and checks its structure.
  Options: `:max_size` (1 MiB), `:max_depth` (32) and `:max_nodes` (100,000).
  """
  @spec decode(binary(), keyword()) :: {:ok, element()} | {:error, error()}
  def decode(bin, opts \\ []) when is_binary(bin) do
    limits = {
      Keyword.get(opts, :max_depth, @default_max_depth),
      Keyword.get(opts, :max_nodes, @default_max_nodes)
    }

    if byte_size(bin) > Keyword.get(opts, :max_size, @default_max_size) do
      {:error, {:limit_exceeded, :max_size}}
    else
      case scan(bin, 1, 0, limits) do
        {:ok, element, <<>>, _count} -> {:ok, element}
        {:ok, _element, _rest, _count} -> {:error, :malformed}
        {:error, _} = error -> error
      end
    end
  end

  @doc "The elements inside a constructed element, in order, or `[]`."
  @spec children(element()) :: [element()]
  def children({id, content, _raw}) do
    if constructed?(id), do: read_all(content, []), else: []
  end

  @doc "Whether an identifier octet is of the constructed form."
  @spec constructed?(byte()) :: boolean()
  def constructed?(id), do: (id &&& 0x20) != 0

  # The checks of `scan/4` already passed, so this only finds boundaries.
  defp read_all(<<>>, acc), do: Enum.reverse(acc)

  defp read_all(bin, acc) do
    {element, rest} = read(bin)
    read_all(rest, [element | acc])
  end

  defp read(<<id, after_id::binary>> = bin) do
    {:ok, length, after_length} = read_length(after_id)
    header_size = byte_size(bin) - byte_size(after_length)

    {content_size, trailer} =
      case length do
        {:definite, len} -> {len, 0}
        :indefinite -> {eoc_offset(after_length, 0), 2}
      end

    raw_size = header_size + content_size + trailer
    content = binary_part(after_length, 0, content_size)
    raw = binary_part(bin, 0, raw_size)
    {{id, content, raw}, binary_part(bin, raw_size, byte_size(bin) - raw_size)}
  end

  defp eoc_offset(<<0, 0, _::binary>>, offset), do: offset

  defp eoc_offset(bin, offset) do
    {{_, _, raw}, rest} = read(bin)
    eoc_offset(rest, offset + byte_size(raw))
  end

  defp scan(_bin, depth, _count, {max_depth, _}) when depth > max_depth,
    do: {:error, {:limit_exceeded, :max_depth}}

  defp scan(_bin, _depth, count, {_, max_nodes}) when count >= max_nodes,
    do: {:error, {:limit_exceeded, :max_nodes}}

  defp scan(<<id, after_id::binary>> = bin, depth, count, limits)
       when (id &&& 0xDF) != 0 and (id &&& 0x1F) != 0x1F do
    with {:ok, length, after_length} <- read_length(after_id) do
      header_size = byte_size(bin) - byte_size(after_length)
      scan_body(bin, id, length, after_length, header_size, depth, count + 1, limits)
    end
  end

  # Tag 0 of the universal class is the end-of-contents marker, and tag
  # numbers above 30 never occur in this protocol.
  defp scan(_bin, _depth, _count, _limits), do: {:error, :malformed}

  defp scan_body(bin, id, {:definite, len}, rest, header_size, depth, count, limits)
       when byte_size(rest) >= len do
    content = binary_part(rest, 0, len)
    after_element = binary_part(rest, len, byte_size(rest) - len)
    raw = binary_part(bin, 0, header_size + len)

    if constructed?(id) do
      with {:ok, count} <- scan_contents(content, depth + 1, count, limits),
           do: {:ok, {id, content, raw}, after_element, count}
    else
      {:ok, {id, content, raw}, after_element, count}
    end
  end

  defp scan_body(_bin, _id, {:definite, _len}, _rest, _header, _depth, _count, _limits),
    do: {:error, :malformed}

  defp scan_body(bin, id, :indefinite, rest, header_size, depth, count, limits) do
    if constructed?(id) do
      with {:ok, size, count} <- scan_until_eoc(rest, 0, depth + 1, count, limits) do
        content = binary_part(rest, 0, size)
        raw = binary_part(bin, 0, header_size + size + 2)
        after_element = binary_part(rest, size + 2, byte_size(rest) - size - 2)
        {:ok, {id, content, raw}, after_element, count}
      end
    else
      {:error, :malformed}
    end
  end

  defp scan_contents(<<>>, _depth, count, _limits), do: {:ok, count}

  defp scan_contents(bin, depth, count, limits) do
    with {:ok, _element, rest, count} <- scan(bin, depth, count, limits),
         do: scan_contents(rest, depth, count, limits)
  end

  defp scan_until_eoc(<<0, 0, _::binary>>, size, _depth, count, _limits), do: {:ok, size, count}

  defp scan_until_eoc(bin, size, depth, count, limits) when byte_size(bin) >= 2 do
    with {:ok, {_, _, raw}, rest, count} <- scan(bin, depth, count, limits),
         do: scan_until_eoc(rest, size + byte_size(raw), depth, count, limits)
  end

  defp scan_until_eoc(_bin, _size, _depth, _count, _limits), do: {:error, :malformed}

  defp read_length(<<0x80, rest::binary>>), do: {:ok, :indefinite, rest}
  defp read_length(<<len, rest::binary>>) when len < 0x80, do: {:ok, {:definite, len}, rest}

  defp read_length(<<n, rest::binary>>) when n in 0x81..0x84 and byte_size(rest) >= n - 0x80 do
    size = n - 0x80
    <<len::unsigned-size(^size)-unit(8), rest::binary>> = rest
    {:ok, {:definite, len}, rest}
  end

  defp read_length(_bin), do: {:error, :malformed}

  ## Values

  @doc "An OCTET STRING, primitive or, in BER, made of segments."
  @spec octets(element()) :: {:ok, binary()} | :error
  def octets({0x04, content, _raw}), do: {:ok, content}

  def octets({0x24, _content, _raw} = element) do
    with {:ok, parts} <- segments(children(element), []), do: {:ok, IO.iodata_to_binary(parts)}
  end

  def octets(_element), do: :error

  defp segments([], acc), do: {:ok, Enum.reverse(acc)}
  defp segments([{0x04, content, _} | rest], acc), do: segments(rest, [content | acc])

  defp segments([{0x24, _, _} = element | rest], acc) do
    with {:ok, parts} <- segments(children(element), []), do: segments(rest, [parts | acc])
  end

  defp segments(_elements, _acc), do: :error

  @doc "A UTF8String that is valid UTF-8."
  @spec utf8(element()) :: {:ok, String.t()} | :error
  def utf8({0x0C, content, _raw}),
    do: if(String.valid?(content), do: {:ok, content}, else: :error)

  def utf8(_element), do: :error

  @doc "An IA5String (ASCII)."
  @spec ia5(element()) :: {:ok, String.t()} | :error
  def ia5({0x16, content, _raw}), do: if(ascii?(content), do: {:ok, content}, else: :error)
  def ia5(_element), do: :error

  defp ascii?(bin), do: for(<<c <- bin>>, reduce: true, do: (ok -> ok and c < 128))

  @doc "An INTEGER, in two's complement (X.690 8.3)."
  @spec integer(element()) :: {:ok, integer()} | :error
  def integer({0x02, <<_, _::binary>> = bytes, _raw}) do
    size = bit_size(bytes)
    <<n::signed-size(^size)>> = bytes
    {:ok, n}
  end

  def integer(_element), do: :error

  @doc "A BOOLEAN; BER takes any octet other than 0 as true."
  @spec boolean(element()) :: {:ok, boolean()} | :error
  def boolean({0x01, <<0>>, _raw}), do: {:ok, false}
  def boolean({0x01, <<_>>, _raw}), do: {:ok, true}
  def boolean(_element), do: :error

  @doc "Whether an element is a NULL."
  @spec null?(element()) :: boolean()
  def null?({0x05, <<>>, _raw}), do: true
  def null?(_element), do: false

  @doc "An OBJECT IDENTIFIER, as a tuple of integers."
  @spec oid(element()) :: {:ok, tuple()} | :error
  def oid({0x06, content, _raw}) when content != <<>> do
    with {:ok, [first | arcs]} <- arcs(content, []) do
      {a, b} =
        cond do
          first < 40 -> {0, first}
          first < 80 -> {1, first - 40}
          true -> {2, first - 80}
        end

      {:ok, List.to_tuple([a, b | arcs])}
    end
  end

  def oid(_element), do: :error

  defp arcs(<<>>, acc), do: {:ok, Enum.reverse(acc)}
  defp arcs(<<0x80, _::binary>>, _acc), do: :error

  defp arcs(bin, acc) do
    with {:ok, n, rest} <- take_arc(bin, 0), do: arcs(rest, [n | acc])
  end

  defp take_arc(<<1::1, bits::7, rest::binary>>, n), do: take_arc(rest, n <<< 7 ||| bits)
  defp take_arc(<<0::1, bits::7, rest::binary>>, n), do: {:ok, n <<< 7 ||| bits, rest}
  defp take_arc(<<>>, _n), do: :error

  @doc """
  A BIT STRING as named bits: the positions of the bits that are set, from
  0, as in PKIFailureInfo.
  """
  @spec named_bits(element()) :: {:ok, [non_neg_integer()]} | :error
  def named_bits({0x03, <<unused, bytes::binary>>, _raw})
      when unused < 8 and (bytes != <<>> or unused == 0) do
    used = bit_size(bytes) - unused
    <<bits::bitstring-size(^used), _::bitstring>> = bytes
    {:ok, for({1, i} <- Enum.with_index(for(<<bit::1 <- bits>>, do: bit)), do: i)}
  end

  def named_bits(_element), do: :error

  ## Writing

  @type term_ ::
          {:seq, [term_()]}
          | {:set, [term_()]}
          | {:int, integer()}
          | {:oid, tuple()}
          | {:octets, iodata()}
          | :null
          | {:bool, boolean()}
          | {:utf8, String.t()}
          | {:printable, String.t()}
          | {:ia5, String.t()}
          | {:bits, binary()}
          | {:named_bits, [non_neg_integer()]}
          | {:generalized_time, DateTime.t() | binary()}
          | {:time, DateTime.t()}
          | {:explicit, 0..30, term_()}
          | {:implicit, 0..30, term_()}
          | {:primitive, 0..30, iodata()}
          | {:raw, iodata()}

  @doc "Encodes a term in DER."
  @spec encode(term_()) :: binary()
  def encode(term), do: term |> to_iodata() |> IO.iodata_to_binary()

  @spec to_iodata(term_()) :: iodata()
  def to_iodata({:seq, items}), do: tlv(0x30, Enum.map(items, &to_iodata/1))

  # A SET OF in DER is sorted by the encodings of its elements (X.690 11.6).
  def to_iodata({:set, items}),
    do: tlv(0x31, items |> Enum.map(&encode/1) |> Enum.sort())

  def to_iodata({:int, n}) when is_integer(n), do: tlv(0x02, integer_octets(n))
  def to_iodata({:oid, oid}) when is_tuple(oid), do: tlv(0x06, oid_octets(oid))
  def to_iodata({:octets, bytes}), do: tlv(0x04, bytes)
  def to_iodata(:null), do: <<0x05, 0>>
  def to_iodata({:bool, true}), do: <<0x01, 1, 0xFF>>
  def to_iodata({:bool, false}), do: <<0x01, 1, 0>>
  def to_iodata({:utf8, text}), do: tlv(0x0C, text)
  def to_iodata({:printable, text}), do: tlv(0x13, text)
  def to_iodata({:ia5, text}), do: tlv(0x16, text)
  def to_iodata({:bits, bytes}), do: tlv(0x03, [0, bytes])
  def to_iodata({:named_bits, positions}), do: named_bits_octets(positions)
  def to_iodata({:generalized_time, time}), do: tlv(0x18, generalized(time))

  def to_iodata({:time, %DateTime{year: year} = time}) when year in 1950..2049,
    do: tlv(0x17, utc(time))

  def to_iodata({:time, %DateTime{} = time}), do: tlv(0x18, generalized(time))
  def to_iodata({:explicit, n, term}) when n in 0..30, do: tlv(0xA0 + n, to_iodata(term))
  def to_iodata({:primitive, n, bytes}) when n in 0..30, do: tlv(0x80 + n, bytes)

  def to_iodata({:implicit, n, term}) when n in 0..30 do
    <<id, rest::binary>> = encode(term)
    [(id &&& 0x20) ||| 0x80 ||| n, rest]
  end

  def to_iodata({:raw, der}), do: der

  defp generalized(time) when is_binary(time), do: time

  defp generalized(%DateTime{} = time) do
    time = DateTime.shift_zone!(time, "Etc/UTC")
    {micro, _} = time.microsecond

    fraction =
      if micro == 0 do
        ""
      else
        "." <>
          (micro
           |> Integer.to_string()
           |> String.pad_leading(6, "0")
           |> String.trim_trailing("0"))
      end

    pad(time.year, 4) <>
      pad(time.month, 2) <>
      pad(time.day, 2) <>
      pad(time.hour, 2) <>
      pad(time.minute, 2) <> pad(time.second, 2) <> fraction <> "Z"
  end

  defp utc(%DateTime{} = time) do
    time = DateTime.shift_zone!(time, "Etc/UTC")

    pad(rem(time.year, 100), 2) <>
      pad(time.month, 2) <>
      pad(time.day, 2) <>
      pad(time.hour, 2) <>
      pad(time.minute, 2) <> pad(time.second, 2) <> "Z"
  end

  defp pad(n, width), do: n |> Integer.to_string() |> String.pad_leading(width, "0")

  # A BIT STRING of named bits: trailing zero bits are removed (X.690 11.2.2).
  defp named_bits_octets([]), do: tlv(0x03, [0])

  defp named_bits_octets(positions) do
    last = Enum.max(positions)
    size = div(last, 8) + 1
    bits = Enum.reduce(positions, 0, fn i, acc -> acc ||| 1 <<< (size * 8 - 1 - i) end)
    unused = size * 8 - 1 - last
    tlv(0x03, [unused, <<bits::size(size)-unit(8)>>])
  end

  defp tlv(id, content), do: [id, encode_length(IO.iodata_length(content)), content]

  defp encode_length(len) when len < 0x80, do: <<len>>

  defp encode_length(len) do
    bytes = :binary.encode_unsigned(len)
    <<0x80 + byte_size(bytes), bytes::binary>>
  end

  defp integer_octets(n) when n >= 0 do
    bytes = :binary.encode_unsigned(n)
    if :binary.first(bytes) >= 0x80, do: <<0, bytes::binary>>, else: bytes
  end

  defp integer_octets(n) do
    bytes = :binary.encode_unsigned(-n - 1)
    size = if :binary.first(bytes) >= 0x80, do: byte_size(bytes) + 1, else: byte_size(bytes)
    <<n::signed-size(size)-unit(8)>>
  end

  defp oid_octets(oid) when tuple_size(oid) >= 2 do
    [a, b | rest] = Tuple.to_list(oid)
    IO.iodata_to_binary(Enum.map([a * 40 + b | rest], &arc_octets/1))
  end

  defp arc_octets(n) when n < 0x80, do: <<n>>

  defp arc_octets(n) do
    {init, [last]} = n |> Integer.digits(128) |> Enum.split(-1)
    IO.iodata_to_binary([Enum.map(init, &(&1 ||| 0x80)), last])
  end
end
