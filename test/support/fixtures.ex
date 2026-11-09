defmodule Tspex.Fixtures do
  @moduledoc false
  # Files made by test/support/gen_fixtures.sh with the openssl tool.

  @dir Path.expand("../fixtures/openssl", __DIR__)

  @spec path(String.t()) :: Path.t()
  def path(name), do: Path.join(@dir, name)

  @spec read(String.t()) :: binary()
  def read(name), do: File.read!(path(name))

  @doc "The data every fixture request and response is about."
  @spec data() :: binary()
  def data, do: read("hello.txt")
end
