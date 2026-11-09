defmodule Tspex.Options do
  @moduledoc false
  # The options of the public functions: checked once at the entry, with the
  # defaults filled in, and passed on as a map. An unknown option, one given
  # twice, or a value of the wrong kind raises ArgumentError. The messages
  # never show a value that could be data (a binary, a key, a token): they
  # say what kind of term it was.

  @max_size 1_048_576

  # Written by the HTTP client itself.
  @reserved_headers ["host", "content-length", "connection", "transfer-encoding"]

  @defaults %{
    max_size: @max_size,
    max_depth: 32,
    max_nodes: 100_000,
    max_signers: 64,
    max_certificates: 256,
    max_attributes: 64,
    hash: :sha256,
    allow_sha1: false,
    policy: nil,
    nonce: true,
    cert_req: true,
    extensions: [],
    certificates: [],
    input: :auto,
    policies: [],
    tsa_name: :strict,
    tsa_eku: :strict,
    critical_extensions: :reject,
    granted_with_mods: :accept,
    max_skew: nil,
    now: nil,
    revocation: nil,
    min_rsa_bits: 2048,
    path_validation: [],
    stamps: :all,
    content: nil,
    url: nil,
    transport: nil,
    headers: [],
    timeout: 30_000,
    max_redirects: 0,
    max_response_bytes: @max_size,
    ssl: []
  }

  @type t :: map()

  @doc """
  Checks `opts` against the allowed `keys` and returns them as a map, with
  the defaults of the keys that have one. `required` keys that are missing
  raise `ArgumentError`.
  """
  @spec take!(keyword(), [atom()], [atom()]) :: t()
  def take!(opts, keys, required \\ [])

  def take!(opts, keys, required) when is_list(opts) do
    given =
      Map.new(opts, fn
        {key, value} when is_atom(key) ->
          unless key in keys, do: raise(ArgumentError, "unknown option #{inspect(key)}")
          check!(key, value)
          {key, value}

        _other ->
          raise ArgumentError, "expected a keyword list of options"
      end)

    unique!(opts)

    for key <- required, not Map.has_key?(given, key) do
      raise ArgumentError, "the option #{inspect(key)} is required"
    end

    @defaults |> Map.take(keys) |> Map.merge(given)
  end

  def take!(_opts, _keys, _required),
    do: raise(ArgumentError, "expected a keyword list of options")

  @doc """
  Raises `ArgumentError` when a key of the keyword list `opts` comes more
  than once: which value was meant cannot be told, and taking one in silence
  could weaken a check.
  """
  @spec unique!(list()) :: :ok
  def unique!(opts) do
    keys = for {key, _value} <- opts, do: key

    case keys -- Enum.uniq(keys) do
      [] -> :ok
      [key | _] -> raise ArgumentError, "the option #{inspect(key)} is given more than once"
    end
  end

  @limits [
    :max_size,
    :max_depth,
    :max_nodes,
    :max_signers,
    :max_certificates,
    :max_attributes,
    :min_rsa_bits,
    :max_response_bytes
  ]

  defp check!(key, value) when key in @limits do
    unless is_integer(value) and value > 0,
      do: raise(ArgumentError, "#{inspect(key)} must be a positive integer, got #{kind(value)}")
  end

  defp check!(:hash, value) do
    unless value in [:sha1, :sha224, :sha256, :sha384, :sha512],
      do:
        raise(
          ArgumentError,
          ":hash must be :sha224, :sha256, :sha384, :sha512 or :sha1, got #{kind(value)}"
        )
  end

  defp check!(key, value) when key in [:allow_sha1, :cert_req] do
    unless is_boolean(value),
      do: raise(ArgumentError, "#{inspect(key)} must be a boolean, got #{kind(value)}")
  end

  defp check!(:policy, nil), do: :ok
  defp check!(:policy, value), do: _ = oid!(value, ":policy")

  defp check!(:nonce, value) do
    unless is_boolean(value) or (is_integer(value) and value > 0),
      do:
        raise(ArgumentError, ":nonce must be a boolean or a positive integer, got #{kind(value)}")
  end

  defp check!(:extensions, value) do
    unless is_list(value) and Enum.all?(value, &extension?/1),
      do:
        raise(
          ArgumentError,
          ":extensions must be a list of %{oid: tuple, critical: boolean, value: binary}"
        )
  end

  defp check!(:trust, :none), do: :ok

  defp check!(:trust, value) do
    unless is_list(value) and value != [] and Enum.all?(value, &is_binary/1),
      do:
        raise(
          ArgumentError,
          ":trust must be :none or a non-empty list of DER certificates, got #{kind(value)}"
        )
  end

  defp check!(:certificates, value), do: binaries!(:certificates, value)

  defp check!(:input, value) do
    unless value in [:auto, :response, :token],
      do: raise(ArgumentError, ":input must be :auto, :response or :token, got #{kind(value)}")
  end

  defp check!(:policies, value) do
    unless is_list(value), do: raise(ArgumentError, ":policies must be a list")
    Enum.each(value, &oid!(&1, ":policies"))
  end

  defp check!(:tsa_name, value) do
    unless value in [:strict, :ignore],
      do: raise(ArgumentError, ":tsa_name must be :strict or :ignore, got #{kind(value)}")
  end

  defp check!(:tsa_eku, value) do
    unless value in [:strict, :extra_purposes],
      do: raise(ArgumentError, ":tsa_eku must be :strict or :extra_purposes, got #{kind(value)}")
  end

  defp check!(:critical_extensions, value) do
    unless value in [:reject, :ignore],
      do:
        raise(
          ArgumentError,
          ":critical_extensions must be :reject or :ignore, got #{kind(value)}"
        )
  end

  defp check!(:granted_with_mods, value) do
    unless value in [:accept, :reject],
      do:
        raise(ArgumentError, ":granted_with_mods must be :accept or :reject, got #{kind(value)}")
  end

  defp check!(:max_skew, nil), do: :ok

  defp check!(:max_skew, value) do
    unless is_integer(value) and value >= 0,
      do: raise(ArgumentError, ":max_skew must be nil or a non-negative integer of seconds")
  end

  defp check!(:now, nil), do: :ok

  defp check!(:now, value) do
    unless match?(%DateTime{}, value),
      do: raise(ArgumentError, ":now must be nil or a DateTime, got #{kind(value)}")
  end

  defp check!(:revocation, nil), do: :ok

  defp check!(:revocation, value) do
    unless is_function(value, 2),
      do: raise(ArgumentError, ":revocation must be nil or a function of two arguments")
  end

  defp check!(:path_validation, value) do
    unless Keyword.keyword?(value),
      do: raise(ArgumentError, ":path_validation must be a keyword list")

    if Keyword.has_key?(value, :verify_fun),
      do:
        raise(
          ArgumentError,
          ":path_validation cannot take :verify_fun, which Tspex sets to validate the " <>
            "path at the time of the time-stamp; use :revocation to check revocation"
        )
  end

  defp check!(:stamps, value) do
    unless value in [:all, :any],
      do: raise(ArgumentError, ":stamps must be :all or :any, got #{kind(value)}")
  end

  defp check!(:content, nil), do: :ok

  defp check!(:content, value) do
    unless content?(value),
      do:
        raise(
          ArgumentError,
          ":content must be a binary, {:stream, enumerable} or {:digest, hash, binary}, " <>
            "got #{kind(value)}"
        )
  end

  defp check!(:url, nil), do: :ok

  defp check!(:url, value) do
    unless is_binary(value), do: raise(ArgumentError, ":url must be a string")
  end

  defp check!(:transport, nil), do: :ok

  defp check!(:transport, value) do
    unless is_function(value, 3),
      do: raise(ArgumentError, ":transport must be nil or a function of three arguments")
  end

  defp check!(:headers, value) do
    unless is_list(value) and Enum.all?(value, &header?/1),
      do: raise(ArgumentError, ":headers must be a list of {name, value} strings")

    for {name, _value} <- value, String.downcase(name) in @reserved_headers do
      raise ArgumentError, "the header #{name} is set by Tspex and cannot be given"
    end

    :ok
  end

  defp check!(:ssl, value) do
    unless Keyword.keyword?(value), do: raise(ArgumentError, ":ssl must be a keyword list")
  end

  defp check!(:timeout, value) do
    unless is_integer(value) and value > 0,
      do: raise(ArgumentError, ":timeout must be a positive integer of milliseconds")
  end

  defp check!(:max_redirects, value) do
    unless is_integer(value) and value >= 0,
      do: raise(ArgumentError, ":max_redirects must be a non-negative integer")
  end

  # The other options are checked where they are used.
  defp check!(_key, _value), do: :ok

  # A header field: a token as the name, and a value without a line break
  # or a NUL, so that a header cannot be used to write another one.
  defp header?({name, value}) when is_binary(name) and is_binary(value),
    do: Regex.match?(~r/\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/, name) and not has_break?(value)

  defp header?(_), do: false

  defp has_break?(value), do: String.contains?(value, ["\r", "\n", <<0>>])

  defp binaries!(key, value) do
    unless is_list(value) and Enum.all?(value, &is_binary/1),
      do: raise(ArgumentError, "#{inspect(key)} must be a list of DER binaries")
  end

  defp extension?(%{oid: oid, critical: critical, value: value}),
    do: oid?(oid) and is_boolean(critical) and is_binary(value)

  defp extension?(_), do: false

  @doc """
  An OID given as a tuple of integers or as dotted text, as a tuple. Raises
  `ArgumentError` for anything else; `what` names the option in the message.
  """
  @spec oid!(term(), String.t()) :: tuple()
  def oid!(value, what) when is_tuple(value) do
    if oid?(value),
      do: value,
      else: raise(ArgumentError, "#{what} must be an OID, got #{kind(value)}")
  end

  def oid!(value, what) when is_binary(value) do
    case parse_dotted(value) do
      {:ok, oid} -> oid
      :error -> raise ArgumentError, "#{what} must be an OID such as \"1.2.3.4\""
    end
  end

  def oid!(value, what), do: raise(ArgumentError, "#{what} must be an OID, got #{kind(value)}")

  defp parse_dotted(text) do
    arcs = String.split(text, ".")

    if Enum.all?(arcs, &digits?/1) do
      oid = arcs |> Enum.map(&String.to_integer/1) |> List.to_tuple()
      if oid?(oid), do: {:ok, oid}, else: :error
    else
      :error
    end
  end

  defp digits?(text), do: text != "" and Enum.all?(String.to_charlist(text), &(&1 in ?0..?9))

  @doc "Whether `value` is an OID as a tuple: two or more arcs, the first at most 2."
  @spec oid?(term()) :: boolean()
  def oid?(value) when is_tuple(value) and tuple_size(value) >= 2 do
    [first, second | rest] = Tuple.to_list(value)

    Enum.all?([first, second | rest], &(is_integer(&1) and &1 >= 0)) and first <= 2 and
      (first == 2 or second < 40)
  end

  def oid?(_value), do: false

  @doc "Whether `value` is data as the functions take it."
  @spec content?(term()) :: boolean()
  def content?(value) when is_binary(value), do: true
  def content?({:stream, enumerable}), do: Enumerable.impl_for(enumerable) != nil

  def content?({:digest, hash, digest}) when is_binary(digest),
    do: Tspex.Imprint.valid?(hash, digest)

  def content?(_value), do: false

  @doc """
  What kind of term `value` is, for the message of an `ArgumentError` about
  an argument that may hold data, so it is not shown.
  """
  @spec kind(term()) :: String.t()
  def kind(value) when is_binary(value), do: "a binary"
  def kind(value) when is_list(value), do: "a list"
  def kind(value) when is_tuple(value), do: "a tuple of #{tuple_size(value)} elements"
  def kind(%module{}), do: "a #{inspect(module)} struct"
  def kind(value) when is_map(value), do: "a map"
  def kind(value) when is_atom(value), do: inspect(value)
  def kind(value) when is_number(value), do: "a number"
  def kind(value) when is_function(value), do: "a function"
  def kind(_value), do: "a pid, port or reference"
end
