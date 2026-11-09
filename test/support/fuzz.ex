defmodule Tspex.TestFuzz do
  @moduledoc false
  # Inputs for the robustness tests: a valid message changed by a few random
  # edits, and random bytes. Every public function that reads a message must
  # return `{:ok, _}` or `{:error, %Tspex.Error{}}` for any of them, and
  # never raise.

  use ExUnitProperties

  import Bitwise

  @doc "How many cases a fuzz test runs; `FUZZ_ROUNDS` sets it."
  @spec rounds(pos_integer()) :: pos_integer()
  def rounds(default \\ 200) do
    case System.get_env("FUZZ_ROUNDS") do
      nil -> default
      text -> String.to_integer(text)
    end
  end

  # Bytes that mean something in BER: lengths, tags, end-of-contents.
  @interesting [
    0x00,
    0x01,
    0x02,
    0x04,
    0x06,
    0x30,
    0x31,
    0x7F,
    0x80,
    0x81,
    0x82,
    0x84,
    0xA0,
    0xFF
  ]

  @doc "A copy of `bin` with one to eight edits."
  def mutated(bin) do
    gen all edits <- list_of(edit(), min_length: 1, max_length: 8) do
      apply_edits(bin, edits)
    end
  end

  @doc "Random bytes, up to 2 KiB."
  def random, do: binary(max_length: 2048)

  defp edit do
    position = integer(0..(1 <<< 32))
    byte = one_of([integer(0..255), member_of(@interesting)])

    one_of([
      tuple({constant(:flip), position, integer(1..255)}),
      tuple({constant(:set), position, byte}),
      tuple({constant(:truncate), position}),
      tuple({constant(:insert), position, binary(min_length: 1, max_length: 8)}),
      tuple({constant(:delete), position, integer(1..64)}),
      tuple({constant(:duplicate), position, integer(1..64)})
    ])
  end

  @doc "Applies the edits of `mutated/1` in order."
  def apply_edits(bin, edits), do: Enum.reduce(edits, bin, &edit/2)

  defp edit({:insert, position, bytes}, bin) do
    {head, tail} = split(bin, rem(position, byte_size(bin) + 1))
    head <> bytes <> tail
  end

  defp edit({:truncate, position}, bin),
    do: binary_part(bin, 0, rem(position, byte_size(bin) + 1))

  defp edit(_edit, <<>>), do: <<>>

  defp edit({:flip, position, mask}, bin) do
    {head, <<byte, tail::binary>>} = split(bin, rem(position, byte_size(bin)))
    <<head::binary, bxor(byte, mask), tail::binary>>
  end

  defp edit({:set, position, value}, bin) do
    {head, <<_byte, tail::binary>>} = split(bin, rem(position, byte_size(bin)))
    <<head::binary, value, tail::binary>>
  end

  defp edit({:delete, position, size}, bin) do
    {head, tail} = split(bin, rem(position, byte_size(bin)))
    size = min(size, byte_size(tail))
    head <> binary_part(tail, size, byte_size(tail) - size)
  end

  defp edit({:duplicate, position, size}, bin) do
    at = rem(position, byte_size(bin))
    slice = binary_part(bin, at, min(size, byte_size(bin) - at))
    {head, tail} = split(bin, at)

    head <>
      slice <> slice <> binary_part(tail, byte_size(slice), byte_size(tail) - byte_size(slice))
  end

  defp split(bin, at), do: {binary_part(bin, 0, at), binary_part(bin, at, byte_size(bin) - at)}

  @doc """
  Runs `fun` and returns `:ok` when it gave `{:ok, _}` or `{:error,
  %Tspex.Error{}}`, and otherwise what went wrong (a return value that is
  neither, or the exception).
  """
  @spec check((-> term())) :: :ok | {:returned, term()} | {:raised, Exception.t(), list()}
  def check(fun) do
    case fun.() do
      {:ok, _} -> :ok
      {:error, %Tspex.Error{}} -> :ok
      other -> {:returned, other}
    end
  rescue
    exception -> {:raised, exception, __STACKTRACE__}
  end
end
