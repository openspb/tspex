defmodule Tspex.Imprint do
  @moduledoc false
  # The digest of a message imprint: which algorithms the protocol uses, how
  # to hash binaries and streams, and how to compare digests.

  @type hash :: :sha1 | :sha224 | :sha256 | :sha384 | :sha512
  @type data ::
          binary() | {:stream, Enumerable.t()} | {:digest, hash(), binary()}

  # name => {oid, digest size}
  @algorithms %{
    sha1: {{1, 3, 14, 3, 2, 26}, 20},
    sha224: {{2, 16, 840, 1, 101, 3, 4, 2, 4}, 28},
    sha256: {{2, 16, 840, 1, 101, 3, 4, 2, 1}, 32},
    sha384: {{2, 16, 840, 1, 101, 3, 4, 2, 2}, 48},
    sha512: {{2, 16, 840, 1, 101, 3, 4, 2, 3}, 64}
  }

  @md5 {1, 2, 840, 113_549, 2, 5}

  @doc "The hashes a request can use. SHA-1 only with `allow_sha1: true`."
  @spec hashes() :: [hash(), ...]
  def hashes, do: [:sha1, :sha224, :sha256, :sha384, :sha512]

  @doc "The OID of a hash."
  @spec oid(hash()) :: tuple()
  def oid(hash), do: elem(Map.fetch!(@algorithms, hash), 0)

  @doc "The name of `hash` in `:crypto`."
  @spec crypto_name(hash()) :: :sha | :sha224 | :sha256 | :sha384 | :sha512
  def crypto_name(:sha1), do: :sha
  def crypto_name(hash), do: hash

  @doc "The size in bytes of a digest of `hash`."
  @spec size(hash()) :: pos_integer()
  def size(hash), do: elem(Map.fetch!(@algorithms, hash), 1)

  @doc """
  The name of the hash with this OID: `{:ok, hash}`, `{:weak, :md5}` for
  MD5, which is never accepted, or `:error` for an algorithm this library
  does not know.
  """
  @spec from_oid(tuple()) :: {:ok, hash()} | {:weak, :md5} | :error
  def from_oid(@md5), do: {:weak, :md5}

  def from_oid(oid) do
    case Enum.find(@algorithms, fn {_name, {algorithm_oid, _}} -> algorithm_oid == oid end) do
      {name, _} -> {:ok, name}
      nil -> :error
    end
  end

  @doc """
  The size of a digest of `hash`, also for MD5, which is read but never
  written or accepted.
  """
  @spec digest_size(hash() | :md5) :: 16 | 20 | 28 | 32 | 48 | 64
  def digest_size(:md5), do: 16
  def digest_size(hash), do: size(hash)

  @doc "Whether `digest` is a digest of `hash`: a known hash and the right size."
  @spec valid?(term(), term()) :: boolean()
  def valid?(hash, digest) when is_atom(hash) and is_binary(digest) do
    case @algorithms do
      %{^hash => {_oid, size}} -> byte_size(digest) == size
      _ -> false
    end
  end

  def valid?(_hash, _digest), do: false

  @doc """
  The digest of `data` with `hash`. A stream is read once; a ready digest is
  returned as it is, if it is of `hash`.
  """
  @spec digest(data(), hash()) :: {:ok, binary()} | {:error, :hash_mismatch}
  def digest(data, hash) when is_binary(data), do: {:ok, :crypto.hash(crypto_name(hash), data)}

  def digest({:stream, enumerable}, hash) do
    state =
      Enum.reduce(enumerable, :crypto.hash_init(crypto_name(hash)), fn chunk, state ->
        unless is_binary(chunk) or is_list(chunk),
          do: raise(ArgumentError, "the elements of a stream must be binaries")

        :crypto.hash_update(state, chunk)
      end)

    {:ok, :crypto.hash_final(state)}
  end

  def digest({:digest, hash, digest}, hash), do: {:ok, digest}
  def digest({:digest, _other, _digest}, _hash), do: {:error, :hash_mismatch}

  @doc "Compares two digests in constant time, for any sizes."
  @spec equal?(binary(), binary()) :: boolean()
  def equal?(a, b) when byte_size(a) == byte_size(b), do: :crypto.hash_equals(a, b)
  def equal?(_a, _b), do: false
end
