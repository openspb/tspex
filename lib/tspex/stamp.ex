defmodule Tspex.Stamp do
  @moduledoc false
  # `Tspex.stamp/2`: the request, the transport, the reading of the answer
  # and the verification, in that order. Nothing here decides about trust;
  # that is `Tspex.Verify`.

  alias Tspex.{Error, Options, Request, Verify}

  @transport_options [
    :url,
    :transport,
    :headers,
    :timeout,
    :max_redirects,
    :max_response_bytes,
    :ssl
  ]

  @spec stamp(Tspex.data(), keyword()) :: {:ok, Tspex.Verified.t()} | {:error, Error.t()}
  def stamp(data, opts) do
    keys = Enum.uniq(Request.build_options() ++ Verify.options() ++ @transport_options)
    settings = Options.take!(opts, keys, [:trust])

    if settings.url == nil and settings.transport == nil,
      do: raise(ArgumentError, "the option :url is required without a :transport")

    request = Request.build(data, Keyword.take(opts, Request.build_options()))
    transport = settings.transport || (&Tspex.HTTP.post/3)

    with {:ok, response} <- send_request(transport, settings, request) do
      verify_opts =
        opts
        |> Keyword.take(Verify.options())
        |> Keyword.put_new(:input, :response)

      Verify.verify(response, request, verify_opts)
    end
  end

  defp send_request(transport, settings, request) do
    options = Map.take(settings, [:headers, :timeout, :max_redirects, :max_response_bytes, :ssl])

    case transport.(settings.url, request.der, Map.to_list(options)) do
      {:ok, response} when is_binary(response) ->
        {:ok, response}

      {:error, %Error{} = error} ->
        {:error, error}

      {:error, reason} ->
        {:error, Error.new(:transport, reason)}

      _other ->
        raise ArgumentError,
              "the :transport function must return {:ok, response_der} or {:error, reason}"
    end
  end
end
