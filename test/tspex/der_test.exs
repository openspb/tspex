defmodule Tspex.DERTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Tspex.{DER, TestFuzz}

  defp decode!(bin), do: elem(DER.decode(bin), 1)

  describe "OBJECT IDENTIFIER" do
    test "known encodings" do
      sha256 = {2, 16, 840, 1, 101, 3, 4, 2, 1}
      assert DER.encode({:oid, sha256}) == <<6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1>>
      assert DER.encode({:oid, {2, 5, 29, 37}}) == <<6, 3, 0x55, 0x1D, 0x25>>

      assert DER.encode({:oid, {1, 2, 840, 113_549, 1, 7, 2}}) ==
               <<6, 9, 42, 134, 72, 134, 247, 13, 1, 7, 2>>
    end

    test "round trip, including big arcs and the first arcs" do
      for oid <- [
            {2, 16, 840, 1, 101, 3, 4, 2, 1},
            {1, 2, 840, 113_549, 1, 9, 16, 1, 4},
            {2, 5, 29, 37},
            {2, 999, 3},
            {1, 3, 6, 1, 5, 5, 7, 3, 8},
            {0, 39},
            {1, 2, 2 ** 40}
          ] do
        assert {:ok, ^oid} = oid |> then(&DER.encode({:oid, &1})) |> decode!() |> DER.oid()
      end
    end

    test "invalid contents are refused" do
      assert DER.oid({6, <<0x80, 1>>, <<>>}) == :error
      assert DER.oid({6, <<0x2A, 0x86>>, <<>>}) == :error
      assert DER.oid({6, <<>>, <<>>}) == :error
      assert DER.oid({2, <<1>>, <<>>}) == :error
    end
  end

  describe "INTEGER" do
    test "round trip" do
      for n <- [0, 1, 127, 128, 255, 256, 65_535, -1, -128, -129, 2 ** 70, -(2 ** 70)] do
        assert {:ok, ^n} = n |> then(&DER.encode({:int, &1})) |> decode!() |> DER.integer()
      end
    end

    test "minimal two's complement" do
      assert DER.encode({:int, 0}) == <<2, 1, 0>>
      assert DER.encode({:int, 127}) == <<2, 1, 127>>
      assert DER.encode({:int, 128}) == <<2, 2, 0, 128>>
      assert DER.encode({:int, -128}) == <<2, 1, 128>>
      assert DER.encode({:int, -129}) == <<2, 2, 0xFF, 0x7F>>
    end

    test "N9: a length of zero is refused" do
      assert DER.integer({2, <<>>, <<>>}) == :error
    end
  end

  describe "other values" do
    test "BOOLEAN: DER true is ff, BER takes any non-zero octet" do
      assert DER.encode({:bool, true}) == <<1, 1, 0xFF>>
      assert DER.encode({:bool, false}) == <<1, 1, 0>>
      assert DER.boolean({1, <<0>>, <<>>}) == {:ok, false}
      assert DER.boolean({1, <<0x42>>, <<>>}) == {:ok, true}
      assert DER.boolean({1, <<0, 0>>, <<>>}) == :error
    end

    test "NULL" do
      assert DER.encode(:null) == <<5, 0>>
      assert DER.null?(decode!(<<5, 0>>))
      refute DER.null?(decode!(<<4, 0>>))
    end

    test "strings" do
      assert DER.encode({:utf8, "ação"}) == <<0x0C, 6, "ação">>
      assert DER.encode({:printable, "BR"}) == <<0x13, 2, "BR">>
      assert DER.encode({:ia5, "a@b"}) == <<0x16, 3, "a@b">>
      assert DER.utf8(decode!(DER.encode({:utf8, "ação"}))) == {:ok, "ação"}
      assert DER.utf8({0x0C, <<0xFF, 0xFE>>, <<>>}) == :error
      assert DER.utf8({0x13, "x", <<>>}) == :error
      assert DER.ia5(decode!(DER.encode({:ia5, "a@b"}))) == {:ok, "a@b"}
      assert DER.ia5({0x16, <<200>>, <<>>}) == :error
    end

    test "a SET OF is sorted by encoding (X.690 11.6)" do
      a = {:int, 5}
      b = {:int, 1}
      assert DER.encode({:set, [a, b]}) == <<0x31, 6, 2, 1, 1, 2, 1, 5>>
    end

    test "named bits drop trailing zeros, and read back as positions" do
      assert DER.encode({:named_bits, []}) == <<3, 1, 0>>
      assert DER.encode({:named_bits, [0]}) == <<3, 2, 7, 0x80>>
      assert DER.encode({:named_bits, [0, 1]}) == <<3, 2, 6, 0xC0>>
      assert DER.encode({:named_bits, [15]}) == <<3, 3, 0, 0, 1>>
      assert DER.encode({:named_bits, [5, 6]}) == <<3, 2, 1, 6>>

      for positions <- [[], [0], [0, 1], [15], [5, 6], [0, 8, 25]] do
        assert {:ok, ^positions} =
                 positions
                 |> then(&DER.encode({:named_bits, &1}))
                 |> decode!()
                 |> DER.named_bits()
      end

      assert DER.named_bits({3, <<8, 0>>, <<>>}) == :error
      assert DER.named_bits({3, <<>>, <<>>}) == :error
    end

    test "BIT STRING as bytes" do
      assert DER.encode({:bits, <<1, 2>>}) == <<3, 3, 0, 1, 2>>
    end

    test "times" do
      assert DER.encode({:generalized_time, ~U[1999-06-09 00:13:26.34352Z]}) ==
               <<0x18, 21, "19990609001326.34352Z">>

      assert DER.encode({:generalized_time, ~U[2026-11-07 21:27:46Z]}) ==
               <<0x18, 15, "20261107212746Z">>

      assert DER.encode({:generalized_time, "20261107212746.50Z"}) ==
               <<0x18, 18, "20261107212746.50Z">>

      assert DER.encode({:time, ~U[2026-11-07 21:27:46Z]}) == <<0x17, 13, "261107212746Z">>
      assert DER.encode({:time, ~U[2060-01-01 00:00:00Z]}) == <<0x18, 15, "20600101000000Z">>
    end

    test "explicit and implicit tags, and primitive context tags" do
      assert DER.encode({:explicit, 0, {:int, 5}}) == <<0xA0, 3, 2, 1, 5>>
      assert DER.encode({:implicit, 1, {:octets, "ab"}}) == <<0x81, 2, "ab">>
      assert DER.encode({:implicit, 1, {:seq, [{:int, 5}]}}) == <<0xA1, 3, 2, 1, 5>>
      assert DER.encode({:primitive, 1, <<7>>}) == <<0x81, 1, 7>>
    end

    test "long lengths" do
      body = :binary.copy(<<0>>, 300)
      assert DER.encode({:octets, body}) == <<4, 0x82, 1, 44>> <> body

      assert DER.encode({:octets, :binary.copy(<<0>>, 200)}) ==
               <<4, 0x81, 200>> <> :binary.copy(<<0>>, 200)
    end

    test "raw terms are written as they are" do
      assert DER.encode({:seq, [{:raw, <<2, 1, 5>>}, {:raw, [<<5>>, <<0>>]}]}) ==
               <<0x30, 5, 2, 1, 5, 5, 0>>
    end
  end

  describe "reading" do
    test "an element keeps the bytes it was read from" do
      der = DER.encode({:seq, [{:int, 1}, {:octets, "abc"}]})
      {:ok, {0x30, content, raw}} = DER.decode(der)
      assert raw == der
      assert content == binary_part(der, 2, byte_size(der) - 2)

      assert [{0x02, <<1>>, <<2, 1, 1>>}, {0x04, "abc", <<4, 3, "abc">>}] =
               DER.children(decode!(der))
    end

    test "children of a primitive element are none" do
      assert DER.children(decode!(<<2, 1, 5>>)) == []
    end

    test "indefinite length (BER) and segmented octet strings" do
      ber = <<0x30, 0x80, 0x24, 0x80, 0x04, 1, "a", 0x04, 1, "b", 0, 0, 0, 0>>
      {:ok, {0x30, _, raw} = root} = DER.decode(ber)
      assert raw == ber
      [octets] = DER.children(root)
      assert DER.octets(octets) == {:ok, "ab"}
      assert DER.octets({0x04, "xy", <<>>}) == {:ok, "xy"}
      assert DER.octets({0x02, "xy", <<>>}) == :error
    end

    test "nested segments of an octet string" do
      ber = <<0x24, 0x80, 0x24, 0x80, 0x04, 1, "a", 0, 0, 0x04, 1, "b", 0, 0>>
      assert DER.octets(decode!(ber)) == {:ok, "ab"}
      assert DER.octets(decode!(<<0x24, 3, 0x02, 1, 5>>)) == :error
    end
  end

  describe "malformed input is an error, never an exception" do
    test "N1: empty" do
      assert DER.decode(<<>>) == {:error, :malformed}
    end

    test "N2: a length greater than the rest" do
      assert DER.decode(<<0x30>>) == {:error, :malformed}
      assert DER.decode(<<0x30, 5, 1, 2>>) == {:error, :malformed}
      assert DER.decode(<<0x30, 0x82, 1>>) == {:error, :malformed}
    end

    test "N3: bytes after the root element" do
      assert DER.decode(<<5, 0, 0>>) == {:error, :malformed}
      assert DER.decode(<<0x30, 0, 5, 0>>) == {:error, :malformed}
    end

    test "N5: end-of-contents out of place" do
      assert DER.decode(<<0x30, 0, 0>>) == {:error, :malformed}
      assert DER.decode(<<0x00, 0>>) == {:error, :malformed}
      assert DER.decode(<<0x30, 2, 0, 0>>) == {:error, :malformed}
      assert DER.decode(<<0x02, 0x80, 0, 0>>) == {:error, :malformed}
    end

    test "lengths and tags this protocol never uses" do
      assert DER.decode(<<0x30, 0x85, 0, 0, 0, 0, 1, 0>>) == {:error, :malformed}
      assert DER.decode(<<0x1F, 0x1F, 0>>) == {:error, :malformed}
      assert DER.decode(<<0x30, 0xFF, 0>>) == {:error, :malformed}
    end

    test "an unterminated indefinite length" do
      assert DER.decode(<<0x30, 0x80, 5, 0>>) == {:error, :malformed}
    end
  end

  describe "limits" do
    test "N6: depth" do
      deep = Enum.reduce(1..40, <<5, 0>>, fn _, acc -> <<0x30, byte_size(acc)>> <> acc end)
      assert DER.decode(deep) == {:error, {:limit_exceeded, :max_depth}}
      assert {:ok, _} = DER.decode(deep, max_depth: 64)
    end

    test "N7: number of nodes" do
      flat = <<0x30, 20>> <> :binary.copy(<<5, 0>>, 10)
      assert DER.decode(flat, max_nodes: 5) == {:error, {:limit_exceeded, :max_nodes}}
      assert {:ok, _} = DER.decode(flat, max_nodes: 11)
    end

    test "N8: size" do
      big = <<4, 0x83, 0x10, 0, 0>> <> :binary.copy(<<0>>, 0x100000)
      assert DER.decode(big) == {:error, {:limit_exceeded, :max_size}}
      assert {:ok, _} = DER.decode(big, max_size: 0x200000)
      assert DER.decode(<<5, 0>>, max_size: 1) == {:error, {:limit_exceeded, :max_size}}
    end
  end

  describe "properties" do
    defp der_term do
      leaf =
        one_of([
          map(integer(), &{:int, &1}),
          map(binary(max_length: 40), &{:octets, &1}),
          map(boolean(), &{:bool, &1}),
          constant(:null),
          map(member_of([{1, 2, 3}, {2, 5, 29, 37}, {1, 3, 6, 1, 5, 5, 7, 3, 8}]), &{:oid, &1}),
          map(string(:alphanumeric, max_length: 20), &{:utf8, &1})
        ])

      tree(leaf, fn child ->
        one_of([
          map(list_of(child, max_length: 4), &{:seq, &1}),
          map({integer(0..5), child}, fn {n, c} -> {:explicit, n, c} end)
        ])
      end)
    end

    # Rebuilds the term from the element that was read.
    defp rebuild({0x30, _, _} = el), do: {:seq, el |> DER.children() |> Enum.map(&rebuild/1)}

    defp rebuild({id, _, _} = el) when id in 0xA0..0xA5,
      do: {:explicit, id - 0xA0, el |> DER.children() |> hd() |> rebuild()}

    defp rebuild({0x02, _, _} = el), do: {:int, elem(DER.integer(el), 1)}
    defp rebuild({0x04, _, _} = el), do: {:octets, elem(DER.octets(el), 1)}
    defp rebuild({0x01, _, _} = el), do: {:bool, elem(DER.boolean(el), 1)}
    defp rebuild({0x05, _, _}), do: :null
    defp rebuild({0x06, _, _} = el), do: {:oid, elem(DER.oid(el), 1)}
    defp rebuild({0x0C, _, _} = el), do: {:utf8, elem(DER.utf8(el), 1)}

    property "decode(encode(x)) gives x back" do
      check all t <- der_term() do
        assert {:ok, root} = DER.decode(DER.encode(t))
        assert rebuild(root) == t
      end
    end

    property "an element's raw bytes are the encoding it was read from" do
      check all t <- der_term() do
        der = DER.encode(t)
        assert {:ok, {_, _, ^der}} = DER.decode(der)
      end
    end
  end

  describe "fuzz" do
    defp walk(el) do
      for child <- DER.children(el), do: walk(child)
      DER.octets(el)
      DER.integer(el)
      DER.oid(el)
      DER.named_bits(el)
      DER.utf8(el)
      DER.boolean(el)
    end

    defp survive(input) do
      case DER.decode(input) do
        {:ok, el} -> walk(el)
        {:error, _} -> :ok
      end
    end

    property "changed structures never raise" do
      base =
        DER.encode(
          {:seq,
           [
             {:int, 1},
             {:seq,
              [
                {:seq, [{:oid, {2, 16, 840, 1, 101, 3, 4, 2, 1}}, :null]},
                {:octets, :crypto.strong_rand_bytes(32)}
              ]},
             {:explicit, 0, {:seq, [{:utf8, "x"}, {:named_bits, [0, 15]}]}},
             {:bool, true}
           ]}
        )

      check all input <- TestFuzz.mutated(base), max_runs: TestFuzz.rounds() do
        survive(input)
      end
    end

    property "random bytes never raise" do
      check all input <- TestFuzz.random(), max_runs: TestFuzz.rounds() do
        survive(input)
      end
    end
  end
end
