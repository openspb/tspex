defmodule Tspex do
  @moduledoc """
  Time-Stamp Protocol (RFC 3161, RFC 5816) in pure Elixir.

  Work in progress.
  """

  alias Tspex.{Error, Request, Response}

  @doc """
  Builds a time-stamp request (`TimeStampReq`, RFC 3161, 2.4.1) for `data`.

  `data` is a binary, `{:stream, enumerable}` (read once) or
  `{:digest, hash, digest}` (already computed).

      {:ok, request} = Tspex.request(File.read!("contract.pdf"))
      request.der    # the body of the POST to the TSA
      request.nonce  # keep the struct: verify/3 needs it

  Options:

    * `:hash` - `:sha256` (the default), `:sha224`, `:sha384`, `:sha512`;
      `:sha1` only with `allow_sha1: true`. With `{:digest, hash, _}` the
      algorithm is given, and a different `:hash` raises `ArgumentError`.
    * `:policy` - the OID of the policy asked for, as a tuple or as text
      (`"1.2.3.4.5.6"`); none by default.
    * `:nonce` - `true` (the default) makes a random 63-bit nonce, `false`
      leaves it out, a positive integer uses that value.
    * `:cert_req` - ask for the certificate of the TSA in the token (`true`).
    * `:extensions` - `[%{oid: tuple, critical: boolean, value: der}]`.
    * `:allow_sha1` - `false`.

  The hash algorithm is written with NULL parameters, as the `openssl ts`
  tool and the Java `jarsigner` do. A bad argument raises `ArgumentError`
  without showing the data.
  """
  @spec request(Tspex.Imprint.data(), keyword()) :: {:ok, Request.t()}
  def request(data, opts \\ []), do: {:ok, Request.build(data, opts)}

  @doc "Like `request/2`, but returns the request itself."
  @spec request!(Tspex.Imprint.data(), keyword()) :: Request.t()
  def request!(data, opts \\ []), do: Request.build(data, opts)

  @doc """
  Reads a `TimeStampReq`, for a test server or for inspection. Takes the
  limits `:max_size`, `:max_depth` and `:max_nodes`.

  A request with a hash this library does not know is read, with the OID as
  the `:hash`.
  """
  @spec decode_request(binary(), keyword()) :: {:ok, Request.t()} | {:error, Error.t()}
  def decode_request(der, opts \\ []), do: Request.decode(der, opts)

  @doc "Like `decode_request/2`, but raises `Tspex.Error`."
  @spec decode_request!(binary(), keyword()) :: Request.t()
  def decode_request!(der, opts \\ []), do: bang(decode_request(der, opts))

  @doc """
  Reads a `TimeStampResp` (RFC 3161, 2.4.2) without judging it: a rejection
  is a valid response, with `status: :rejection`, the reasons in
  `fail_info` and no token. `verify/3` is what turns a response that is not
  granted into an error. Takes the limits `:max_size`, `:max_depth` and
  `:max_nodes`.

      {:ok, response} = Tspex.decode_response(body)
      response.status       #=> :rejection
      response.fail_info    #=> [:bad_alg]
      response.status_text  #=> ["Message digest algorithm is not supported."]

  A `PKIStatus` outside 0 to 5 is `:unknown_status`. A `failInfo` bit that
  RFC 3161 does not define is read as `{:unknown_bit, n}`.
  """
  @spec decode_response(binary(), keyword()) :: {:ok, Response.t()} | {:error, Error.t()}
  def decode_response(der, opts \\ []), do: Response.decode(der, opts)

  @doc "Like `decode_response/2`, but raises `Tspex.Error`."
  @spec decode_response!(binary(), keyword()) :: Response.t()
  def decode_response!(der, opts \\ []), do: bang(decode_response(der, opts))

  defp bang({:ok, value}), do: value
  defp bang({:error, error}), do: raise(error)
end
