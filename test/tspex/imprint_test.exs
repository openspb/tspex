defmodule Tspex.ImprintTest do
  use ExUnit.Case, async: true

  alias Tspex.Imprint

  test "every hash has its OID and size, and the OID reads back" do
    for hash <- Imprint.hashes() do
      assert Imprint.from_oid(Imprint.oid(hash)) == {:ok, hash}
      assert byte_size(:crypto.hash(Imprint.crypto_name(hash), "x")) == Imprint.size(hash)
    end
  end

  test "the OIDs are the ones of RFC 3279 and RFC 5754" do
    assert Imprint.oid(:sha1) == {1, 3, 14, 3, 2, 26}
    assert Imprint.oid(:sha256) == {2, 16, 840, 1, 101, 3, 4, 2, 1}
    assert Imprint.oid(:sha384) == {2, 16, 840, 1, 101, 3, 4, 2, 2}
    assert Imprint.oid(:sha512) == {2, 16, 840, 1, 101, 3, 4, 2, 3}
    assert Imprint.oid(:sha224) == {2, 16, 840, 1, 101, 3, 4, 2, 4}
  end

  test "MD5 is known only to be refused, and other algorithms are unknown" do
    assert Imprint.from_oid({1, 2, 840, 113_549, 2, 5}) == {:weak, :md5}
    assert Imprint.from_oid({2, 16, 840, 1, 101, 3, 4, 2, 5}) == :error
    assert Imprint.from_oid({1, 2, 3}) == :error
  end

  test "valid?/2 checks the algorithm and the size" do
    assert Imprint.valid?(:sha256, :binary.copy(<<1>>, 32))
    refute Imprint.valid?(:sha256, :binary.copy(<<1>>, 31))
    refute Imprint.valid?(:md5, :binary.copy(<<1>>, 16))
    refute Imprint.valid?(:sha256, :not_a_binary)
    refute Imprint.valid?("sha256", :binary.copy(<<1>>, 32))
  end

  test "digest/2 of a binary, a stream (read once) and a ready digest" do
    expected = :crypto.hash(:sha256, "hello world")
    assert Imprint.digest("hello world", :sha256) == {:ok, expected}
    assert Imprint.digest({:stream, ["hello", " ", "world"]}, :sha256) == {:ok, expected}
    assert Imprint.digest({:digest, :sha256, expected}, :sha256) == {:ok, expected}
    assert Imprint.digest({:digest, :sha256, expected}, :sha384) == {:error, :hash_mismatch}
  end

  test "a stream is enumerated one time" do
    agent = start_supervised!({Agent, fn -> 0 end})

    stream =
      Stream.map(["a", "b", "c"], fn chunk ->
        Agent.update(agent, &(&1 + 1))
        chunk
      end)

    assert {:ok, _} = Imprint.digest({:stream, stream}, :sha256)
    assert Agent.get(agent, & &1) == 3
  end

  test "a stream of something that is not data raises without showing it" do
    error = assert_raise ArgumentError, fn -> Imprint.digest({:stream, [:atom]}, :sha256) end
    refute error.message =~ "atom"
  end

  test "equal?/2 compares digests of any size" do
    assert Imprint.equal?("abc", "abc")
    refute Imprint.equal?("abc", "abd")
    refute Imprint.equal?("abc", "abcd")
    refute Imprint.equal?("", "a")
  end
end
