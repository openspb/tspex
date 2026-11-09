defmodule Tspex.VerifyCase do
  @moduledoc false
  # Shared by the tests of Tspex.verify/3.

  use ExUnit.CaseTemplate

  using do
    quote do
      import Tspex.VerifyCase

      alias Tspex.{Error, Fixtures, TestPKI, TestTSA}
    end
  end

  @doc "A request for `data` and the response of `tsa` to it."
  def issue(tsa, req_opts \\ [], resp_opts \\ [], data \\ "contract") do
    request = Tspex.request!(data, req_opts)
    {request, Tspex.TestTSA.response(tsa, request, resp_opts)}
  end

  @doc "The token inside a response."
  def token_of(response), do: Tspex.decode_response!(response).token

  @doc "`Tspex.verify/3` trusting the root of `tsa` unless the options say otherwise."
  def verify(tsa, input, expected, opts \\ []),
    do: Tspex.verify(input, expected, Keyword.merge([trust: Tspex.TestTSA.trust(tsa)], opts))

  @doc "The reason of an error, `:ok` for a success."
  def reason({:ok, _}), do: :ok
  def reason({:error, %Tspex.Error{reason: reason}}), do: reason

  @doc "The reason and the detail of an error."
  def failure({:ok, _}), do: :ok
  def failure({:error, %Tspex.Error{reason: reason, detail: detail}}), do: {reason, detail}

  @doc "An old but valid PKI, for the tests that need a genTime in the past."
  def old_root, do: [not_before: ~U[2015-01-01 00:00:00Z], not_after: ~U[2060-01-01 00:00:00Z]]
end
