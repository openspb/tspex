defmodule Tspex.TimeTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Tspex.{DER, Time}

  test "the genTime examples of RFC 3161 and X.680" do
    assert {:ok, ~U[1992-05-21 00:00:00Z], []} = Time.parse("19920521000000Z")
    assert {:ok, ~U[1992-07-22 13:21:00.300000Z], []} = Time.parse("19920722132100.3Z")
    assert {:ok, ~U[1999-06-09 00:13:26.343520Z], []} = Time.parse("19990609001326.34352Z")
  end

  test "fractions of any length truncate to microseconds" do
    assert {:ok, dt, []} = Time.parse("20261107120000.5Z")
    assert dt.microsecond == {500_000, 6}
    assert {:ok, dt, []} = Time.parse("20261107120000.1234567Z")
    assert dt.microsecond == {123_456, 6}
    assert {:ok, dt, []} = Time.parse("20261107120000.000001Z")
    assert dt.microsecond == {1, 6}
    assert {:ok, dt, []} = Time.parse("20261107120000.0000001Z")
    assert dt.microsecond == {0, 6}
  end

  test "N17: zeros at the end of the fraction are read, with a deviation" do
    assert {:ok, dt, [:gen_time_encoding]} = Time.parse("20261107120000.50Z")
    assert dt.microsecond == {500_000, 6}
    assert {:ok, _, [:gen_time_encoding]} = Time.parse("20261107120000.0Z")
    assert {:ok, _, [:gen_time_encoding]} = Time.parse("20261107120000.500Z")
  end

  test "the limits of the range" do
    assert {:ok, ~U[0001-01-01 00:00:00Z], []} = Time.parse("00010101000000Z")
    assert {:ok, ~U[9999-12-31 23:59:59Z], []} = Time.parse("99991231235959Z")
    assert {:ok, ~U[2024-02-29 12:00:00Z], []} = Time.parse("20240229120000Z")
  end

  test "N11 to N19 and other forms that are errors" do
    for bad <- [
          # N11: no Z
          "20261107212746",
          "20261107120000.5",
          # N12: no seconds
          "202611072127Z",
          "2026110712000.5Z",
          # N13: second 60
          "20261107120060Z",
          # N14: month, day, hour out of range
          "20261307120000Z",
          "20261132120000Z",
          "20261107240000Z",
          "20260230120000Z",
          "20230229120000Z",
          # N15: comma
          "20261107120000,5Z",
          # N16: dot and no digits
          "20261107212746.Z",
          # N18: offsets
          "20261107120000+0300",
          "20261107120000-0300",
          "20261107120000+0300Z",
          # year 0
          "00001107120000Z",
          # junk
          "",
          "Z",
          "2026110712000aZ",
          "20261107120000.5xZ",
          "20261107120000.5ZZ",
          " 20261107120000Z",
          "20261107120000Z "
        ] do
      assert Time.parse(bad) == :error, "expected an error for #{inspect(bad)}"
    end
  end

  test "N19: a UTCTime is not a genTime (the element is checked by the TSTInfo reader)" do
    assert DER.encode({:time, ~U[2026-11-07 12:00:00Z]}) == <<0x17, 13, "261107120000Z">>
    # as content octets, a UTCTime of 13 characters is not a 14-digit time
    assert Time.parse("261107120000Z") == :error
  end

  property "what DER writes, parse reads back, with no deviation" do
    check all seconds <- integer(0..4_000_000_000),
              micro <- integer(0..999_999) do
      time =
        seconds
        |> DateTime.from_unix!()
        |> Map.put(:microsecond, {micro, 6})

      {:ok, {0x18, content, _}} = DER.decode(DER.encode({:generalized_time, time}))
      assert {:ok, parsed, []} = Time.parse(content)
      assert DateTime.compare(parsed, time) == :eq
    end
  end

  property "parse never raises" do
    check all text <- binary(max_length: 30) do
      assert Time.parse(text) == :error or match?({:ok, _, _}, Time.parse(text))
    end
  end
end
