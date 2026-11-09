defmodule Tspex do
  @moduledoc """
  Time-Stamp Protocol (RFC 3161, RFC 5816) in pure Elixir.

  Work in progress.
  """

  alias Tspex.{Error, Request}

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

  defp bang({:ok, value}), do: value
  defp bang({:error, error}), do: raise(error)
end
