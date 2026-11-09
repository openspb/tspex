defmodule Tspex.HTTP do
  @moduledoc """
  The HTTP transport of `Tspex.stamp/2`: one `POST` of a time-stamp request
  to a TSA (RFC 3161, section 3.4), written on `:gen_tcp` and `:ssl`.

  It is small on purpose, because it only has to do one thing and put
  limits on it that `:httpc` does not offer. For anything else (a proxy, a
  client certificate with an agent, HTTP/2, your own retries) pass your own
  `:transport` function to `Tspex.stamp/2`, a function of the URL, the
  request in DER and the options that returns `{:ok, response_der}` or
  `{:error, reason}`, and use Req, Finch or Mint inside it.

  What it does:

    * `POST` with `Content-Type: application/timestamp-query`, `Accept:
      application/timestamp-reply`, `User-Agent: tspex/<version>` and
      `Connection: close`; one connection for each request.
    * **`https` verifies the server**: `verify_peer`, the system CA
      certificates (`:public_key.cacerts_get/0`) and the name of the URL
      against the certificate. `http` is accepted, because the token
      authenticates itself and many TSAs speak only `http`; the cost is
      that the hash of your data travels in the clear (a matter of privacy,
      not of integrity).
    * **Only the status 200 is a success.** Any other status ends the
      request at once, without reading its body, and is `{:http_status,
      n}`.
    * **The body is limited** by `:max_response_bytes`. A `Content-Length`
      above it is refused before a byte of the body is read, and a chunked
      or close-delimited body is cut at the limit, so a server cannot make
      you allocate what it wants.
    * **No redirect** unless you raise `:max_redirects`, and then only 307
      and 308 (which keep the method and the body), never from `https` to
      `http`, and the `:headers` you gave are not sent to another host.
    * **The type of the body is not required**: some TSAs answer with
      `text/plain`. What decides is that the bytes are a valid DER
      response, which `Tspex.verify/3` checks.
    * The time of `:timeout` is for the whole exchange.

  Options:

    * `:headers` - extra headers as `{name, value}` strings, for
      authentication. They replace `Content-Type`, `Accept` and
      `User-Agent` of the same name; `Host`, `Content-Length`, `Connection`
      and `Transfer-Encoding` are refused. A name with anything that is not
      a token, or a value with a line break, raises `ArgumentError`.
    * `:timeout` - milliseconds for the whole exchange, 30 000.
    * `:max_redirects` - 0.
    * `:max_response_bytes` - 1 MiB.
    * `:ssl` - options for `:ssl.connect/4` that replace the defaults: a
      `cacerts:` or `cacertfile:` for a private CA, or `certfile:` and
      `keyfile:` for a client certificate. `verify: :verify_none` is yours
      to choose, and the token is still verified, but then anyone on the
      path can read your request.

  The reasons of `{:error, reason}`, which `Tspex.stamp/2` turns into the
  `detail` of a `:transport` error: `{:http_status, n}`, `:timeout`,
  `:too_large`, `{:connect, reason}` (no address, connection refused),
  `{:tls, reason}` (the handshake, the certificate or the name) and
  `{:other, reason}` (a response that is not HTTP, a connection closed
  before the end of the body).

  Needs the `:ssl` application only for `https` URLs.
  """

  alias Tspex.Options

  @options [:headers, :timeout, :max_redirects, :max_response_bytes, :ssl]

  @max_head 65_536
  @max_headers 100
  @max_line 1_024
  @max_trailer 8_192
  @refused [:econnrefused, :ehostunreach, :enetunreach, :nxdomain, :etimedout, :econnreset]

  @typedoc "Why the request failed."
  @type reason ::
          {:http_status, pos_integer()}
          | :timeout
          | :too_large
          | {:connect, term()}
          | {:tls, term()}
          | {:other, term()}

  @doc """
  Sends `body` to `url` and returns the body of the answer.

      {:ok, response_der} = Tspex.HTTP.post("http://tsa.example.com/tsp", request.der)

  See the module documentation for the options. A `url` that is not `http`
  or `https` with a host, or a bad option, raises `ArgumentError`.
  """
  @spec post(String.t(), binary(), keyword()) :: {:ok, binary()} | {:error, reason()}
  def post(url, body, opts \\ []) do
    unless is_binary(url) and is_binary(body),
      do: raise(ArgumentError, "the URL and the body must be binaries")

    opts = Options.take!(opts, @options)
    uri = parse!(url)
    deadline = now() + opts.timeout

    exchange(uri, body, opts, opts.headers, deadline, opts.max_redirects)
  end

  defp parse!(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host, userinfo: nil, port: port} = uri
      when scheme in ["http", "https"] and is_binary(host) and host != "" and is_integer(port) ->
        if String.valid?(host),
          do: uri,
          else: raise(ArgumentError, "the host of the URL must be valid UTF-8")

      _other ->
        raise ArgumentError,
              "the URL must be http or https, with a host and without user information"
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp remaining(deadline), do: max(deadline - now(), 0)

  ## One exchange, and redirects

  defp exchange(uri, body, opts, headers, deadline, redirects) do
    case once(uri, body, opts, headers, deadline) do
      {:redirect, status, location} ->
        follow(uri, status, location, {body, opts, headers, deadline, redirects})

      other ->
        other
    end
  end

  defp follow(uri, status, location, {body, opts, headers, deadline, redirects}) do
    with true <- redirects > 0,
         {:ok, target} <- redirect_target(uri, location) do
      headers = if same_host?(uri, target), do: headers, else: []
      exchange(target, body, opts, headers, deadline, redirects - 1)
    else
      _ -> {:error, {:http_status, status}}
    end
  end

  # The Location is the server's word: a URI has only visible ASCII (RFC 3986),
  # so anything else is refused before it is read as a name or written back
  # into a request line.
  defp redirect_target(uri, location) do
    target = URI.merge(uri, location)

    if Regex.match?(~r/\A[\x21-\x7E]+\z/, location) and target.scheme in ["http", "https"] and
         is_binary(target.host) and target.host != "" and target.userinfo == nil and
         not (uri.scheme == "https" and target.scheme == "http"),
       do: {:ok, target},
       else: :error
  rescue
    ArgumentError -> :error
  end

  defp same_host?(a, b), do: String.downcase(a.host) == String.downcase(b.host)

  defp once(uri, body, opts, headers, deadline) do
    with {:ok, conn} <- connect(uri, opts, deadline) do
      try do
        with :ok <- send_request(conn, uri, body, headers),
             {:ok, status, response_headers, rest} <- read_head(conn, <<>>, deadline) do
          answer(conn, status, response_headers, rest, opts, deadline)
        end
      after
        close(conn)
      end
    end
  end

  defp answer(conn, 200, headers, rest, opts, deadline),
    do: read_body(conn, headers, rest, opts.max_response_bytes, deadline)

  defp answer(_conn, status, headers, _rest, _opts, _deadline) when status in [307, 308] do
    case header(headers, "location") do
      nil -> {:error, {:http_status, status}}
      location -> {:redirect, status, location}
    end
  end

  defp answer(_conn, status, _headers, _rest, _opts, _deadline),
    do: {:error, {:http_status, status}}

  ## Connecting

  defp connect(uri, opts, deadline) do
    with {:ok, addresses} <- resolve(uri.host, deadline) do
      connect_each(addresses, uri, opts, deadline, {:error, {:connect, :nxdomain}})
    end
  end

  defp resolve(host, deadline) do
    name = String.to_charlist(host)

    case :inet.parse_address(name) do
      {:ok, ip} -> {:ok, [ip]}
      {:error, _} -> lookup(name, deadline)
    end
  end

  defp lookup(name, deadline) do
    timeout = remaining(deadline)

    case {:inet.getaddrs(name, :inet, timeout), :inet.getaddrs(name, :inet6, timeout)} do
      {{:ok, v4}, {:ok, v6}} -> {:ok, v4 ++ v6}
      {{:ok, v4}, _} -> {:ok, v4}
      {_, {:ok, v6}} -> {:ok, v6}
      {{:error, reason}, _} -> lookup_failed(reason, deadline)
    end
  end

  defp lookup_failed(reason, deadline) do
    if remaining(deadline) == 0, do: {:error, :timeout}, else: {:error, {:connect, reason}}
  end

  defp connect_each([], _uri, _opts, _deadline, last), do: last

  defp connect_each([address | rest], uri, opts, deadline, last) do
    case remaining(deadline) do
      0 ->
        {:error, :timeout}

      time ->
        case open(address, uri, opts, time) do
          {:ok, _conn} = ok -> ok
          {:error, :timeout} = timeout -> timeout
          {:error, _} = error -> connect_each(rest, uri, opts, deadline, worse(last, error))
        end
    end
  end

  # With several addresses, the error to report is the one that says most:
  # a refused certificate over a connection that was refused.
  defp worse({:error, {:connect, _}}, error), do: error
  defp worse(last, {:error, {:connect, _}}), do: last
  defp worse(_last, error), do: error

  defp open(address, %URI{scheme: "http", port: port}, _opts, time) do
    options = [:binary, active: false, packet: :raw, nodelay: true]

    case :gen_tcp.connect(address, port, options, time) do
      {:ok, socket} -> {:ok, {:gen_tcp, socket}}
      {:error, :timeout} -> {:error, :timeout}
      {:error, reason} -> {:error, {:connect, reason}}
    end
  end

  defp open(address, %URI{scheme: "https", host: host, port: port}, opts, time) do
    with :ok <- ensure_ssl(),
         {:ok, options} <- tls_options(host, opts.ssl) do
      case :ssl.connect(address, port, options, time) do
        {:ok, socket} -> check_address(socket, host)
        {:error, :timeout} -> {:error, :timeout}
        {:error, reason} when reason in @refused -> {:error, {:connect, reason}}
        {:error, reason} -> {:error, {:tls, reason}}
      end
    end
  end

  # The OTP checks the name of the server only when it has a name, so a URL
  # with an IP address would take any certificate of a trusted CA. For an
  # address, the check is made here, against the iPAddress names.
  defp check_address(socket, host) do
    with {:ok, ip} <- :inet.parse_address(String.to_charlist(host)),
         {:ok, der} <- :ssl.peercert(socket),
         false <- :public_key.pkix_verify_hostname(der, [{:ip, ip}]) do
      _ = :ssl.close(socket)
      {:error, {:tls, {:hostname_check_failed, {:requested, host}}}}
    else
      _ -> {:ok, {:ssl, socket}}
    end
  end

  defp ensure_ssl do
    case Application.ensure_all_started(:ssl) do
      {:ok, _started} -> :ok
      {:error, reason} -> {:error, {:tls, {:ssl_not_started, reason}}}
    end
  end

  defp tls_options(host, user) do
    with {:ok, cacerts} <- cacerts(user) do
      server_name =
        case :inet.parse_address(String.to_charlist(host)) do
          {:ok, _ip} -> :disable
          {:error, _} -> String.to_charlist(host)
        end

      defaults =
        [
          verify: :verify_peer,
          server_name_indication: server_name,
          customize_hostname_check: [
            match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
          ]
        ] ++ cacerts

      {:ok, Keyword.merge(defaults, user) ++ [mode: :binary, active: false, packet: :raw]}
    end
  end

  defp cacerts(user) do
    if Keyword.has_key?(user, :cacerts) or Keyword.has_key?(user, :cacertfile) do
      {:ok, []}
    else
      {:ok, [cacerts: :public_key.cacerts_get()]}
    end
  catch
    _kind, _reason -> {:error, {:tls, :no_system_cacerts}}
  end

  defp close({mod, socket}), do: _ = mod.close(socket)

  ## The request

  defp send_request({mod, socket}, uri, body, extra) do
    case mod.send(socket, request(uri, body, extra)) do
      :ok -> :ok
      {:error, reason} -> {:error, {:other, reason}}
    end
  end

  defp request(uri, body, extra) do
    target = if(uri.path in [nil, ""], do: "/", else: uri.path) <> query(uri)
    given = MapSet.new(extra, fn {name, _value} -> String.downcase(name) end)

    defaults =
      [
        {"User-Agent", "tspex/" <> version()},
        {"Content-Type", "application/timestamp-query"},
        {"Accept", "application/timestamp-reply"}
      ]
      |> Enum.reject(fn {name, _value} -> String.downcase(name) in given end)

    fields =
      [{"Host", host(uri)}, {"Content-Length", Integer.to_string(byte_size(body))}] ++
        defaults ++ extra ++ [{"Connection", "close"}]

    [
      "POST ",
      target,
      " HTTP/1.1\r\n",
      Enum.map(fields, fn {name, value} -> [name, ": ", value, "\r\n"] end),
      "\r\n",
      body
    ]
  end

  defp query(%URI{query: nil}), do: ""
  defp query(%URI{query: query}), do: "?" <> query

  defp host(%URI{host: host, scheme: scheme, port: port}) do
    name = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host
    if port == default_port(scheme), do: name, else: name <> ":" <> Integer.to_string(port)
  end

  defp default_port("http"), do: 80
  defp default_port("https"), do: 443

  defp version do
    case Application.spec(:tspex, :vsn) do
      nil -> "dev"
      vsn -> to_string(vsn)
    end
  end

  ## The head of the response

  defp read_head(conn, buffer, deadline) do
    case :binary.match(buffer, "\r\n\r\n") do
      {at, 4} ->
        head = binary_part(buffer, 0, at + 4)
        rest = binary_part(buffer, at + 4, byte_size(buffer) - at - 4)
        head_done(conn, head, rest, deadline)

      :nomatch when byte_size(buffer) > @max_head ->
        {:error, {:other, :header_too_large}}

      :nomatch ->
        with {:ok, data} <- recv(conn, deadline), do: read_head(conn, buffer <> data, deadline)
    end
  end

  # A status 1xx (other than 101) is an interim answer: the real one follows.
  defp head_done(conn, head, rest, deadline) do
    case parse_head(head) do
      {:ok, status, _headers} when status in 100..199 and status != 101 ->
        read_head(conn, rest, deadline)

      {:ok, status, headers} ->
        {:ok, status, headers, rest}

      :error ->
        {:error, {:other, :bad_response}}
    end
  end

  defp parse_head(head) do
    case :erlang.decode_packet(:http_bin, head, line_length: @max_line) do
      {:ok, {:http_response, {1, _minor}, status, _text}, rest} when is_integer(status) ->
        with {:ok, headers} <- parse_headers(rest, [], 0), do: {:ok, status, headers}

      _other ->
        :error
    end
  end

  defp parse_headers(_data, _acc, count) when count > @max_headers, do: :error

  defp parse_headers(data, acc, count) do
    case :erlang.decode_packet(:httph_bin, data, line_length: @max_line) do
      {:ok, {:http_header, _, name, _, value}, rest} ->
        parse_headers(rest, [{name |> to_string() |> String.downcase(), value} | acc], count + 1)

      {:ok, :http_eoh, _rest} ->
        {:ok, Enum.reverse(acc)}

      _other ->
        :error
    end
  end

  defp header(headers, name), do: List.keyfind(headers, name, 0) |> value_of()

  defp value_of({_name, value}), do: value
  defp value_of(nil), do: nil

  defp header_values(headers, name), do: for({^name, value} <- headers, do: value)

  ## The body

  defp read_body(conn, headers, rest, max, deadline) do
    case {header(headers, "transfer-encoding"), header_values(headers, "content-length")} do
      {nil, []} -> read_to_close(conn, rest, max, deadline)
      {nil, lengths} -> read_length(conn, lengths, rest, max, deadline)
      {coding, _} -> read_chunked_if(conn, coding, rest, max, deadline)
    end
  end

  defp read_length(conn, lengths, rest, max, deadline) do
    case content_length(lengths) do
      {:ok, length} when length > max -> {:error, :too_large}
      {:ok, length} -> read_exactly(conn, rest, length, deadline)
      :error -> {:error, {:other, :bad_content_length}}
    end
  end

  defp content_length(lengths) do
    case Enum.uniq(lengths) do
      [value] ->
        if Regex.match?(~r/\A[0-9]{1,15}\z/, value),
          do: {:ok, String.to_integer(value)},
          else: :error

      _ ->
        :error
    end
  end

  defp read_exactly(conn, buffer, length, deadline) do
    with {:ok, body, _rest} <- take_bytes(conn, buffer, length, deadline), do: {:ok, body}
  end

  defp read_to_close(_conn, buffer, max, _deadline) when byte_size(buffer) > max,
    do: {:error, :too_large}

  defp read_to_close(conn, buffer, max, deadline) do
    case recv(conn, deadline) do
      {:ok, data} -> read_to_close(conn, buffer <> data, max, deadline)
      {:error, {:other, :closed}} -> {:ok, buffer}
      {:error, _} = error -> error
    end
  end

  defp read_chunked_if(conn, coding, rest, max, deadline) do
    if coding |> String.trim() |> String.downcase() == "chunked",
      do: read_chunks(conn, rest, [], 0, max, deadline),
      else: {:error, {:other, :unsupported_transfer_encoding}}
  end

  defp read_chunks(conn, buffer, acc, total, max, deadline) do
    with {:ok, line, rest} <- take_line(conn, buffer, deadline, @max_line),
         {:ok, size} <- chunk_size(line) do
      cond do
        size == 0 -> last_chunk(conn, rest, acc, deadline)
        total + size > max -> {:error, :too_large}
        true -> read_chunk(conn, rest, size, {acc, total, max}, deadline)
      end
    end
  end

  defp last_chunk(conn, rest, acc, deadline) do
    with :ok <- skip_trailer(conn, rest, deadline, 0),
         do: {:ok, IO.iodata_to_binary(Enum.reverse(acc))}
  end

  defp read_chunk(conn, rest, size, {acc, total, max}, deadline) do
    with {:ok, chunk, rest} <- take_bytes(conn, rest, size, deadline),
         {:ok, <<"\r\n">>, rest} <- take_bytes(conn, rest, 2, deadline) do
      read_chunks(conn, rest, [chunk | acc], total + size, max, deadline)
    else
      {:ok, _not_crlf, _rest} -> {:error, {:other, :bad_chunk}}
      {:error, _} = error -> error
    end
  end

  defp chunk_size(line) do
    [size | _extension] = String.split(line, ";", parts: 2)

    case Regex.match?(~r/\A[0-9a-fA-F]{1,8}\z/, String.trim(size)) do
      true -> {:ok, size |> String.trim() |> String.to_integer(16)}
      false -> {:error, {:other, :bad_chunk}}
    end
  end

  defp skip_trailer(conn, buffer, deadline, seen) do
    with {:ok, line, rest} <- take_line(conn, buffer, deadline, @max_line) do
      cond do
        line == "" -> :ok
        seen + byte_size(line) > @max_trailer -> {:error, {:other, :bad_chunk}}
        true -> skip_trailer(conn, rest, deadline, seen + byte_size(line))
      end
    end
  end

  defp take_line(conn, buffer, deadline, limit) do
    case :binary.match(buffer, "\r\n") do
      {at, 2} ->
        {:ok, binary_part(buffer, 0, at), binary_part(buffer, at + 2, byte_size(buffer) - at - 2)}

      :nomatch when byte_size(buffer) > limit ->
        {:error, {:other, :bad_chunk}}

      :nomatch ->
        with {:ok, data} <- recv(conn, deadline),
             do: take_line(conn, buffer <> data, deadline, limit)
    end
  end

  defp take_bytes(_conn, buffer, count, _deadline) when byte_size(buffer) >= count,
    do:
      {:ok, binary_part(buffer, 0, count), binary_part(buffer, count, byte_size(buffer) - count)}

  defp take_bytes(conn, buffer, count, deadline) do
    with {:ok, data} <- recv(conn, deadline),
         do: take_bytes(conn, buffer <> data, count, deadline)
  end

  defp recv({mod, socket}, deadline) do
    case remaining(deadline) do
      0 ->
        {:error, :timeout}

      time ->
        case mod.recv(socket, 0, time) do
          {:ok, data} -> {:ok, data}
          {:error, :timeout} -> {:error, :timeout}
          {:error, reason} -> {:error, {:other, reason}}
        end
    end
  end
end
