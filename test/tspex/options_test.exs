defmodule Tspex.OptionsTest do
  use ExUnit.Case, async: true

  alias Tspex.Options

  @keys [:max_size, :hash, :nonce, :policy, :trust, :policies, :path_validation, :content]

  test "defaults are filled in only for the allowed keys" do
    opts = Options.take!([], [:hash, :nonce])
    assert opts == %{hash: :sha256, nonce: true}
  end

  test "an unknown option raises" do
    assert_raise ArgumentError, ~r/unknown option :bogus/, fn ->
      Options.take!([bogus: 1], @keys)
    end

    assert_raise ArgumentError, ~r/unknown option :nonce/, fn ->
      Options.take!([nonce: true], [:hash])
    end
  end

  test "a repeated option raises" do
    assert_raise ArgumentError, ~r/given more than once/, fn ->
      Options.take!([hash: :sha256, hash: :sha512], @keys)
    end
  end

  test "something that is not a keyword list raises" do
    assert_raise ArgumentError, fn -> Options.take!(%{hash: :sha256}, @keys) end
    assert_raise ArgumentError, fn -> Options.take!([:hash], @keys) end
    assert_raise ArgumentError, fn -> Options.take!([{"hash", 1}], @keys) end
  end

  test "a required option that is missing raises" do
    assert_raise ArgumentError, ~r/:trust is required/, fn ->
      Options.take!([], @keys, [:trust])
    end

    assert %{trust: :none} = Options.take!([trust: :none], @keys, [:trust])
  end

  test "values of the wrong kind raise" do
    for bad <- [
          [max_size: 0],
          [max_size: "big"],
          [hash: :md5],
          [hash: "sha256"],
          [nonce: 0],
          [nonce: -1],
          [nonce: "yes"],
          [policy: {1}],
          [policy: {3, 1}],
          [policy: "1.x"],
          [policy: 7],
          [trust: []],
          [trust: [:atom]],
          [trust: "root"],
          [policies: ["bad"]],
          [path_validation: [:x]],
          [content: 5],
          [content: {:digest, :sha256, "short"}]
        ] do
      assert_raise ArgumentError, fn -> Options.take!(bad, @keys) end
    end
  end

  test "valid values are kept" do
    opts =
      Options.take!(
        [
          max_size: 10,
          hash: :sha384,
          nonce: 5,
          policy: "1.2.3.4",
          trust: [<<1>>],
          policies: [{1, 2}, "1.3.6"],
          content: {:stream, [<<1>>]}
        ],
        @keys
      )

    assert opts.max_size == 10 and opts.hash == :sha384 and opts.nonce == 5
    assert opts.trust == [<<1>>]
  end

  test ":path_validation refuses :verify_fun and points to :revocation" do
    assert_raise ArgumentError, ~r/:revocation/, fn ->
      Options.take!([path_validation: [verify_fun: {fn _, _, s -> {:valid, s} end, []}]], @keys)
    end

    assert %{path_validation: [max_path_length: 3]} =
             Options.take!([path_validation: [max_path_length: 3]], @keys)
  end

  test "the message of an error never shows the value" do
    secret = "the-private-contents"

    for bad <- [[trust: secret], [nonce: secret], [hash: secret], [policy: secret]] do
      error =
        try do
          Options.take!(bad, @keys)
          flunk("expected ArgumentError")
        rescue
          e in ArgumentError -> e
        end

      refute error.message =~ "private"
    end
  end

  test "oid!/2 reads tuples and dotted text" do
    assert Options.oid!({1, 2, 3}, "x") == {1, 2, 3}
    assert Options.oid!("2.5.29.37", "x") == {2, 5, 29, 37}
    assert_raise ArgumentError, fn -> Options.oid!("1.2.", "x") end
    assert_raise ArgumentError, fn -> Options.oid!({1, 40}, "x") end
    assert_raise ArgumentError, fn -> Options.oid!({3, 1}, "x") end
    assert_raise ArgumentError, fn -> Options.oid!({1, 2, -3}, "x") end
  end
end
