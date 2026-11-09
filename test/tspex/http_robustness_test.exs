defmodule Tspex.HTTPRobustnessTest do
  # The answer of a server is the bytes of an adversary. `Tspex.HTTP.post/3`
  # returns `{:ok, body}` or `{:error, reason}` for any of them, and never
  # raises: here one byte at a time of three kinds of answer is replaced by
  # values that are not valid text.
  use ExUnit.Case, async: true

  alias Tspex.{HTTP, TestFuzz, TestHTTPServer}

  @answers %{
    length:
      "HTTP/1.1 200 OK\r\ncontent-type: application/timestamp-reply\r\n" <>
        "content-length: 5\r\nx-a: b\r\n\r\nhello",
    chunked:
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" <>
        "5;ext=1\r\nhello\r\n3\r\nabc\r\n0\r\nx-trailer: 1\r\n\r\n",
    redirect:
      "HTTP/1.1 307 Temporary Redirect\r\nlocation: http://localhost:1/other\r\n" <>
        "content-length: 0\r\n\r\n"
  }

  defp accepted?({:ok, body}) when is_binary(body), do: true
  defp accepted?({:error, _reason}), do: true
  defp accepted?(_), do: false

  for {name, _answer} <- @answers do
    test "an answer of the kind #{name} with one byte changed" do
      answer = Map.fetch!(@answers, unquote(name))
      {:ok, agent} = Agent.start_link(fn -> answer end)
      port = TestHTTPServer.start(fn %{send: send} -> send.(Agent.get(agent, & &1)) end)
      url = "http://localhost:#{port}/tsp"

      post = fn changed ->
        Agent.update(agent, fn _ -> changed end)
        HTTP.post(url, "q", timeout: 2_000, max_redirects: 1)
      end

      failures =
        TestFuzz.sweep(answer, post,
          values: [0x00, 0x0A, 0x0D, 0x20, 0x3B, 0x80, 0xC3, 0xFF],
          accept: &accepted?/1,
          concurrent: false
        )

      assert failures == []
    end
  end
end
