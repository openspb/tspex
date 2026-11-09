defmodule Tspex.Request do
  @moduledoc """
  A time-stamp request, the `TimeStampReq` of RFC 3161 (2.4.1).

  `Tspex.request/2` builds one and `Tspex.decode_request/2` reads one (for a
  test server or for inspection). Keep the struct of a request you send:
  `Tspex.verify/3` needs it to check the nonce and the imprint of the
  response.

  Fields:

    * `:der` - the request in DER, the body of the POST.
    * `:version` - always 1.
    * `:hash` - the hash of the message imprint, such as `:sha256`; the OID
      as a tuple when a request that was read uses an algorithm this library
      does not know.
    * `:digest` - the digest, the `hashedMessage`.
    * `:policy` - the requested TSA policy as an OID tuple, or `nil`.
    * `:nonce` - the nonce, or `nil`.
    * `:cert_req` - whether the certificate of the TSA is asked for.
    * `:extensions` - `[%{oid: tuple, critical: boolean, value: binary}]`,
      with the value as the DER bytes of the extension.
  """

  alias Tspex.{Codec, DER, Error, Imprint, Options}

  @type t :: %__MODULE__{
          der: binary(),
          version: 1,
          hash: Codec.hash(),
          digest: binary(),
          policy: tuple() | nil,
          nonce: pos_integer() | nil,
          cert_req: boolean(),
          extensions: [Codec.extension()]
        }

  @enforce_keys [:der, :hash, :digest]
  defstruct [:der, :hash, :digest, :policy, :nonce, version: 1, cert_req: false, extensions: []]

  @max_nonce Bitwise.bsl(1, 255)
  @build_options [:hash, :policy, :nonce, :cert_req, :extensions, :allow_sha1]
  @read_options [:max_size, :max_depth, :max_nodes]

  @doc false
  @spec build(Imprint.data(), keyword()) :: t()
  def build(data, opts) do
    given_hash? = Keyword.has_key?(opts, :hash)
    opts = Options.take!(opts, @build_options)

    unless Options.content?(data),
      do:
        raise(
          ArgumentError,
          "expected a binary, {:stream, enumerable} or {:digest, hash, digest}, got " <>
            Options.kind(data)
        )

    hash = hash!(data, opts, given_hash?)

    unless hash != :sha1 or opts.allow_sha1,
      do: raise(ArgumentError, "SHA-1 needs allow_sha1: true")

    {:ok, digest} = Imprint.digest(data, hash)
    nonce = nonce(opts.nonce)

    body = [
      {:int, 1},
      Codec.message_imprint_term(hash, digest)
    ]

    policy = if opts.policy, do: [{:oid, Options.oid!(opts.policy, ":policy")}], else: []
    nonce_term = if nonce, do: [{:int, nonce}], else: []
    cert_req = if opts.cert_req, do: [{:bool, true}], else: []
    extensions = extensions_term(opts.extensions)

    der = DER.encode({:seq, body ++ policy ++ nonce_term ++ cert_req ++ extensions})

    %__MODULE__{
      der: der,
      hash: hash,
      digest: digest,
      policy: if(opts.policy, do: Options.oid!(opts.policy, ":policy")),
      nonce: nonce,
      cert_req: opts.cert_req,
      extensions: opts.extensions
    }
  end

  defp hash!({:digest, hash, _digest}, opts, given_hash?) do
    if given_hash? and opts.hash != hash,
      do:
        raise(
          ArgumentError,
          "the digest is of #{inspect(hash)}, so :hash cannot be #{inspect(opts.hash)}"
        )

    hash
  end

  defp hash!(_data, opts, _given_hash?), do: opts.hash

  defp nonce(true), do: random_nonce()
  defp nonce(false), do: nil
  defp nonce(n) when is_integer(n) and n > 0 and n < @max_nonce, do: n

  defp nonce(n) when is_integer(n),
    do: raise(ArgumentError, ":nonce must be a positive integer of at most 255 bits")

  defp nonce(_),
    do: raise(ArgumentError, ":nonce must be true, false or a positive integer")

  # 8 random octets with the high bit clear, so that it is positive in
  # 64 bits, and never zero.
  defp random_nonce do
    <<_::1, n::63>> = :crypto.strong_rand_bytes(8)
    if n == 0, do: random_nonce(), else: n
  end

  defp extensions_term([]), do: []

  defp extensions_term(extensions) do
    for %{value: value} <- extensions do
      case DER.decode(value) do
        {:ok, _} -> :ok
        {:error, _} -> raise ArgumentError, "the value of an extension must be DER"
      end
    end

    [{:implicit, 0, {:seq, Codec.extensions_term(extensions)}}]
  end

  @doc false
  @spec decode(binary(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def decode(der, opts) when is_binary(der) do
    opts = Options.take!(opts, @read_options)

    with {:ok, {0x30, _, _} = root} <- Codec.decode(der, opts),
         {:ok, request} <- read(DER.children(root), der) do
      {:ok, request}
    else
      {:ok, _not_a_sequence} -> {:error, Error.new(:malformed)}
      {:error, %Error{}} = error -> error
    end
  end

  def decode(_der, _opts), do: raise(ArgumentError, "expected the request as a binary")

  defp read([version_element, imprint_element | rest], der) do
    with {:ok, 1} <- version(version_element),
         {:ok, hash, digest} <- Codec.message_imprint(imprint_element),
         {:ok, optional} <-
           optional(rest, %{policy: nil, nonce: nil, cert_req: false, extensions: []}, 0) do
      {:ok,
       %__MODULE__{
         der: der,
         hash: hash,
         digest: digest,
         policy: optional.policy,
         nonce: optional.nonce,
         cert_req: optional.cert_req,
         extensions: optional.extensions
       }}
    else
      {:ok, other} when is_integer(other) -> {:error, Error.new(:unsupported_version, other)}
      :error -> {:error, Error.new(:malformed)}
    end
  end

  defp read(_elements, _der), do: {:error, Error.new(:malformed)}

  defp version(element) do
    case Codec.integer(element) do
      {:ok, n} -> {:ok, n}
      :error -> :error
    end
  end

  # reqPolicy, nonce, certReq and extensions, in this order, each optional.
  defp optional([], acc, _stage), do: {:ok, acc}

  defp optional([{0x06, _, _} = element | rest], acc, stage) when stage < 1 do
    with {:ok, oid} <- DER.oid(element), do: optional(rest, %{acc | policy: oid}, 1)
  end

  defp optional([{0x02, _, _} = element | rest], acc, stage) when stage < 2 do
    with {:ok, nonce} <- Codec.integer(element), do: optional(rest, %{acc | nonce: nonce}, 2)
  end

  defp optional([{0x01, _, _} = element | rest], acc, stage) when stage < 3 do
    with {:ok, flag} <- DER.boolean(element), do: optional(rest, %{acc | cert_req: flag}, 3)
  end

  defp optional([{0xA0, _, _} = element | rest], acc, stage) when stage < 4 do
    with {:ok, extensions} <- Codec.extensions(element),
         do: optional(rest, %{acc | extensions: extensions}, 4)
  end

  defp optional(_elements, _acc, _stage), do: :error

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(request, opts) do
      fields = [
        hash: request.hash,
        policy: request.policy,
        nonce: request.nonce,
        cert_req: request.cert_req,
        der: "#{byte_size(request.der)} bytes"
      ]

      concat(["#Tspex.Request<", to_doc(fields, %{opts | limit: :infinity}), ">"])
    end
  end
end
