defmodule Tspex.DoctestTest do
  use ExUnit.Case, async: true

  doctest Tspex
  doctest Tspex.Error
  doctest Tspex.TSTInfo
  doctest Tspex.TimeStampedData
end
