defmodule Tspex.TestHTTPServer do
  @moduledoc false
  # A small server on a local port for the tests of the transport: it reads
  # one request, hands it to a function that writes whatever bytes it wants
  # (or waits, or sends in pieces), and closes the connection. HTTP over
  # `:gen_tcp`, https over `:ssl` when given a certificate and a key.
  #
  # The handler gets a map with `:request` (the head and the body as
  # received), `:send` (a function of iodata that returns `:ok` or an
  # error, so a handler can send until the client leaves) and `:socket`.

  @doc """
  Starts the server and returns its port. Options: `:tls`, `{cert_der,
  key}` where `key` is a private key record of `:public_key`; `request:
  false` answers without reading the request.

  The server and its connections are linked to the process that calls it
  and stop with it.
  """
  def start(handler, opts \\ []) do
    tls = Keyword.get(opts, :tls)
    parent = self()
    read? = Keyword.get(opts, :request, true)

    {:ok, listener} =
      case tls do
        nil ->
          :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

        {cert, key} ->
          :ssl.listen(0, [
            :binary,
            active: false,
            reuseaddr: true,
            ip: {127, 0, 0, 1},
            cert: cert,
            key: private_key(key)
          ])
      end

    port = port(listener, tls)
    spawn_link(fn -> accept(listener, handler, tls, {parent, read?}) end)
    port
  end

  @doc "A port where nothing listens."
  def closed_port do
    {:ok, listener} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(listener)
    :gen_tcp.close(listener)
    port
  end

  defp private_key(record) when elem(record, 0) == :RSAPrivateKey,
    do: {:RSAPrivateKey, :public_key.der_encode(:RSAPrivateKey, record)}

  defp private_key(record) when elem(record, 0) == :ECPrivateKey,
    do: {:ECPrivateKey, :public_key.der_encode(:ECPrivateKey, record)}

  defp port(listener, nil) do
    {:ok, port} = :inet.port(listener)
    port
  end

  defp port(listener, _tls) do
    {:ok, {_address, port}} = :ssl.sockname(listener)
    port
  end

  defp accept(listener, handler, nil, context) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        spawn_link(fn -> serve(socket, :gen_tcp, handler, context) end)
        accept(listener, handler, nil, context)

      {:error, _} ->
        :ok
    end
  end

  defp accept(listener, handler, tls, context) do
    case :ssl.transport_accept(listener) do
      {:ok, transport} ->
        spawn_link(fn -> handshake(transport, handler, context) end)
        accept(listener, handler, tls, context)

      {:error, _} ->
        :ok
    end
  end

  defp handshake(transport, handler, context) do
    case :ssl.handshake(transport, 5_000) do
      {:ok, socket} -> serve(socket, :ssl, handler, context)
      {:error, _} -> :ok
    end
  end

  defp serve(socket, mod, handler, {parent, read?}) do
    request = if read?, do: read_request(socket, mod, <<>>), else: ""
    send(parent, {:request, request})

    handler.(%{
      request: request,
      socket: socket,
      send: fn data -> mod.send(socket, data) end
    })

    mod.close(socket)
  catch
    _kind, _reason -> :ok
  end

  defp read_request(socket, mod, buffer) do
    case :binary.split(buffer, "\r\n\r\n") do
      [head, rest] ->
        length =
          case Regex.run(~r/content-length: *(\d+)/i, head) do
            [_, digits] -> String.to_integer(digits)
            _ -> 0
          end

        if byte_size(rest) >= length,
          do: buffer,
          else: read_request(socket, mod, buffer <> more(socket, mod))

      _ ->
        read_request(socket, mod, buffer <> more(socket, mod))
    end
  end

  defp more(socket, mod) do
    {:ok, data} = mod.recv(socket, 0, 5_000)
    data
  end

  @doc "The body of a raw request."
  def body(request) do
    [_head, body] = :binary.split(request, "\r\n\r\n")
    body
  end

  @doc "The headers of a raw request, as a map with the names in lower case."
  def headers(request) do
    [head, _body] = :binary.split(request, "\r\n\r\n")
    [_line | lines] = String.split(head, "\r\n")

    Map.new(lines, fn line ->
      [name, value] = String.split(line, ":", parts: 2)
      {String.downcase(name), String.trim(value)}
    end)
  end

  @doc "The request line of a raw request."
  def request_line(request), do: request |> String.split("\r\n", parts: 2) |> hd()

  @doc "A complete answer with a body."
  def ok(body, headers \\ []) do
    fields = Enum.map(headers, fn {name, value} -> [name, ": ", value, "\r\n"] end)

    [
      "HTTP/1.1 200 OK\r\ncontent-length: ",
      Integer.to_string(byte_size(body)),
      "\r\n",
      fields,
      "\r\n",
      body
    ]
  end
end
