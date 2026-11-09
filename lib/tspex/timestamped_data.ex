defmodule Tspex.TimeStampedData do
  @moduledoc """
  A document bound to a chain of time-stamps: `TimeStampedData`, RFC 5544.

  **Experimental.** RFC 5544 does not say which octets the second and later
  time-stamps cover, and there is no tool to test against; this module
  makes a choice and documents it below. The functions and fields here may
  change in a minor release until the choice is confirmed by another
  implementation. For the same reason only `decode!/2` has a `!` variant for
  now: the other functions return `{:ok, value}` or `{:error, %Tspex.Error{}}`.

  A `TimeStampedData` is a `ContentInfo` (content type
  `id-ct-timestampedData`) that holds the document, or says where to find
  it (`dataUri`); some metadata (`fileName`, `mediaType` and attributes);
  and the temporal evidence, which here is a list of time-stamp tokens. Each
  token covers the one before it, so a long chain shows the document existed
  at the time of the first token, and that each token existed when the next
  one was issued.

      {:ok, imprint} = Tspex.TimeStampedData.imprint(contract, file_name: "contract.pdf")
      {:ok, first} = Tspex.stamp(imprint, url: url, trust: roots)
      {:ok, tsd} = Tspex.TimeStampedData.new(contract, first, file_name: "contract.pdf")
      File.write!("contract.pdf.tsd", Tspex.TimeStampedData.encode(tsd))

      {:ok, result} = Tspex.TimeStampedData.verify(File.read!("contract.pdf.tsd"), trust: roots)
      result.time

  ## What each token covers

    * The first token: the value octets of `content` (or of the document
      given as `:content`, since `dataUri` is never fetched). When the
      metadata has `hashProtected` true, the **DER encoding of the
      `MetaData`, followed by the content** (RFC 5544, section 2).
    * Each later token: **the previous element of the sequence**, as the
      `TimeStampAndCRL` that is in the structure, byte for byte. This is
      the reading of "computed over its preceding element"; it includes the
      `crl` of that element if it has one. The elements this module writes
      are DER when the tokens are.
    * The `crl` of an element shows that the certificate of the TSA of that
      element's token was not revoked when the next element was added, so
      it is put in the element before the next token is asked for: see
      `extension_imprint/2`.

  ## What it does not do

    * It never fetches `dataUri`. Give the document as `:content`.
    * `ersEvidence` and `otherEvidence` are read and written as bytes, and
      `verify/2` answers `:unsupported_evidence` for them.
    * It does not check the `crl` of an element. `verify/2` returns it, with
      the stamps, for you to check (the guide on verification shows how, with
      the recipe for revocation); `:revocation` is called for each token like
      in `Tspex.verify/3`.
    * It does not refuse a chain whose `genTime` goes back unless you give
      `:max_time_back`; `:ordered` in the result says whether it did.
    * The token of a time-stamp is only as good as its TSA, as always: read
      `Tspex.verify/3` for what the checks of each token mean.
  """

  alias Tspex.{Codec, DER, Error, Imprint, Options, TSTInfo, Verified, Verify}

  @content_type {1, 2, 840, 113_549, 1, 9, 16, 1, 31}
  @hashes [:sha1, :sha224, :sha256, :sha384, :sha512]
  @default_max_stamps 64

  @typedoc "The `MetaData`: `other` is a list of attributes, `%{oid: tuple, values: [der]}`."
  @type meta_data :: %{
          hash_protected: boolean(),
          file_name: String.t() | nil,
          media_type: String.t() | nil,
          other: [%{oid: tuple(), values: [binary()]}]
        }

  @typedoc """
  A `TimeStampAndCRL`: the token in DER, the CRL in DER or `nil`, and `raw`,
  the whole element as it is in the structure, which the next token covers.
  """
  @type element :: %{token: binary(), crl: binary() | nil, raw: binary()}

  @typedoc """
  The temporal evidence: a chain of time-stamps (`:tst`), the evidence of an
  archive time-stamp (`:ers`) or another kind, by its OID. Only the first is
  verified.
  """
  @type evidence ::
          {:tst, [element(), ...]}
          | {:ers, binary()}
          | {:other, tuple(), binary()}

  @typedoc "A `TimeStampedData` (RFC 5544), experimental."
  @type t :: %__MODULE__{
          version: 1,
          data_uri: String.t() | nil,
          meta_data: meta_data() | nil,
          content: binary() | nil,
          evidence: evidence()
        }

  @enforce_keys [:evidence]
  defstruct [:data_uri, :meta_data, :content, :evidence, version: 1]

  @meta_options [:file_name, :media_type, :other_meta_data, :hash_protected]
  @read_options [:max_size, :max_depth, :max_nodes, :max_stamps]
  @verify_chain_options [:content, :max_time_back]
  @verify_options Verify.options() -- [:input]

  ## Building

  @doc """
  The imprint to time-stamp first for `content`: the hash of the content, or
  of the `MetaData` and the content when `hash_protected: true`. Returns
  `{:ok, {:digest, hash, digest}}`, which `Tspex.request/2`, `Tspex.stamp/2`
  and `new/3` take.

  `content` is a binary or `{:stream, enumerable}` (read once).

  Options:

    * `:hash` - `:sha256` (the default), `:sha224`, `:sha384`, `:sha512`;
      `:sha1` only with `allow_sha1: true`.
    * `:file_name`, `:media_type`, `:other_meta_data` - the `MetaData`. The
      first is a UTF-8 string, the second ASCII, the third a list of
      attributes `%{oid: tuple, values: [der]}`. At least one is needed for
      there to be a `MetaData`.
    * `:hash_protected` - `true` puts the `MetaData` under the first token
      (`false`, the default). It needs a `MetaData`.
    * `:allow_sha1` - `false`.

  With `hash_protected: true` the imprint covers the file name too, so it is
  not the hash of the content alone:

      iex> alias Tspex.TimeStampedData
      iex> {:ok, {:digest, :sha256, plain}} = TimeStampedData.imprint("hello")
      iex> Base.encode16(plain, case: :lower)
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
      iex> {:ok, bound} = TimeStampedData.imprint("hello", file_name: "a.txt", hash_protected: true)
      iex> bound == {:digest, :sha256, plain}
      false
  """
  @spec imprint(Tspex.data(), keyword()) :: {:ok, {:digest, Tspex.hash(), binary()}}
  def imprint(content, opts \\ []) do
    opts = Options.take!(opts, [:hash, :allow_sha1] ++ @meta_options)
    content = content!(content)
    hash = hash!(opts)
    meta = meta!(opts)

    {:ok, digest} = Imprint.digest(strip(first_input(content, meta)), hash)
    {:ok, {:digest, hash, digest}}
  end

  @doc """
  Makes a `TimeStampedData` of `content` and the time-stamp of its imprint
  (see `imprint/2`).

  `stamp` is a `t:Tspex.Verified.t/0`, taken to have been verified already,
  or a token in DER, which is verified first with the options of
  `Tspex.verify/3` (`:trust` is required). Either way its imprint has to be
  the one of `content` and the `MetaData` (`:imprint_mismatch` otherwise).

  Takes the options of `imprint/2` except `:hash` and `:allow_sha1` (the hash
  is the token's) and:

    * `:data_uri` - where the document can be found, a URI as ASCII text.
    * `:detached` - `true` leaves the content out of the structure, which
      then needs a `:data_uri`. A stream is always detached.
  """
  @spec new(Tspex.data(), Verified.t() | binary(), keyword()) ::
          {:ok, t()} | {:error, Error.t()}
  def new(content, stamp, opts \\ []) do
    keys = [:data_uri, :detached] ++ @meta_options ++ @verify_options
    opts = Options.take!(opts, keys, if(is_binary(stamp), do: [:trust], else: []))
    content = content!(content)
    meta = meta!(opts)
    data_uri = data_uri!(opts[:data_uri])
    detached? = detached?(content, opts)

    if detached? and data_uri == nil,
      do: raise(ArgumentError, "a structure without its content needs a :data_uri")

    with {:ok, token} <- bound(stamp, first_input(content, meta), opts) do
      {:ok,
       %__MODULE__{
         data_uri: data_uri,
         meta_data: meta,
         content: if(detached?, do: nil, else: content),
         evidence: {:tst, [element(token, nil)]}
       }}
    end
  end

  @doc """
  The imprint to time-stamp next, to extend the chain of `tsd`: the hash of
  the last element, with the `crl` that is to go in it.

  Options: `:crl` (a CertificateList in DER, which replaces the one in the
  last element, if any), `:hash` (`:sha256`) and `:allow_sha1`. Ask the TSA
  for a token over this imprint, then give `extend/3` the same `:crl`.
  """
  @spec extension_imprint(t(), keyword()) ::
          {:ok, {:digest, Tspex.hash(), binary()}} | {:error, Error.t()}
  def extension_imprint(%__MODULE__{} = tsd, opts \\ []) do
    opts = Options.take!(opts, [:hash, :allow_sha1, :crl])
    hash = hash!(opts)
    crl = crl!(opts[:crl])

    with {:ok, elements} <- tst_elements(tsd) do
      {_previous, last} = split_last(elements, crl)
      {:ok, digest} = Imprint.digest(last.raw, hash)
      {:ok, {:digest, hash, digest}}
    end
  end

  @doc """
  Adds a time-stamp to the chain of `tsd`. `stamp` is as in `new/3`, and has
  to cover the last element of the chain, with the `:crl` if one is given
  (see `extension_imprint/2`).

  Takes `:crl` and, for a token in DER, the options of `Tspex.verify/3`.
  Only a chain of `tstEvidence` can be extended.
  """
  @spec extend(t(), Verified.t() | binary(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def extend(%__MODULE__{} = tsd, stamp, opts \\ []) do
    opts =
      Options.take!(opts, [:crl] ++ @verify_options, if(is_binary(stamp), do: [:trust], else: []))

    crl = crl!(opts[:crl])

    with {:ok, elements} <- tst_elements(tsd),
         {previous, last} = split_last(elements, crl),
         {:ok, token} <- bound(stamp, {:data, last.raw}, opts) do
      {:ok, %{tsd | evidence: {:tst, previous ++ [last, element(token, nil)]}}}
    end
  end

  ## Writing

  @doc """
  The `ContentInfo` of `tsd` in DER. The elements of the chain are written
  as they are, so what the tokens cover does not change.
  """
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{} = tsd) do
    fields =
      [{:int, tsd.version}] ++
        optional(tsd.data_uri, &{:ia5, &1}) ++
        optional(tsd.meta_data, &{:raw, meta_der(&1)}) ++
        optional(tsd.content, &{:octets, &1}) ++
        [evidence_term(tsd.evidence)]

    DER.encode({:seq, [{:oid, @content_type}, {:explicit, 0, {:seq, fields}}]})
  end

  defp optional(nil, _fun), do: []
  defp optional(value, fun), do: [fun.(value)]

  defp evidence_term({:tst, elements}),
    do: {:implicit, 0, {:seq, Enum.map(elements, &{:raw, &1.raw})}}

  defp evidence_term({:ers, raw}), do: {:raw, raw}

  defp evidence_term({:other, oid, value}),
    do: {:implicit, 2, {:seq, [{:oid, oid}, {:raw, value}]}}

  defp element(token, crl) do
    raw = DER.encode({:seq, [{:raw, token}] ++ optional(crl, &{:raw, &1})})
    %{token: token, crl: crl, raw: raw}
  end

  # The last element with its `crl` set (when one is given), and the ones
  # before it.
  defp split_last(elements, nil) do
    {previous, [last]} = Enum.split(elements, -1)
    {previous, last}
  end

  defp split_last(elements, crl) do
    {previous, [last]} = Enum.split(elements, -1)
    {previous, element(last.token, crl)}
  end

  ## Reading

  @doc """
  Reads a `TimeStampedData` from a `ContentInfo` in BER or DER, without
  verifying it. Takes the limits `:max_size`, `:max_depth`, `:max_nodes` and
  `:max_stamps` (64 elements in the chain).

  Errors: `:malformed`, `:limit_exceeded`, `:unsupported_version`.
  """
  @spec decode(binary(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def decode(der, opts \\ [])

  def decode(der, opts) when is_binary(der) do
    opts = Options.take!(opts, @read_options)
    max_stamps = Map.get(opts, :max_stamps, @default_max_stamps)

    unless is_integer(max_stamps) and max_stamps > 0,
      do: raise(ArgumentError, ":max_stamps must be a positive integer")

    with {:ok, root} <- Codec.decode(der, opts), do: content_info(root, max_stamps)
  end

  def decode(_der, _opts), do: raise(ArgumentError, "expected the structure as a binary")

  @doc "Like `decode/2`, but raises `Tspex.Error`."
  @spec decode!(binary(), keyword()) :: t()
  def decode!(der, opts \\ []) do
    case decode(der, opts) do
      {:ok, tsd} -> tsd
      {:error, error} -> raise error
    end
  end

  defp content_info({0x30, _, _} = root, max_stamps) do
    with [oid, {0xA0, _, _} = wrapper] <- DER.children(root),
         {:ok, @content_type} <- DER.oid(oid),
         [{0x30, _, _} = tsd] <- DER.children(wrapper) do
      time_stamped_data(DER.children(tsd), max_stamps)
    else
      _ -> {:error, Error.new(:malformed)}
    end
  end

  defp content_info(_root, _max_stamps), do: {:error, Error.new(:malformed)}

  defp time_stamped_data([version | rest], max_stamps) do
    with :ok <- version(version),
         {:ok, data_uri, rest} <- take(rest, 0x16, &DER.ia5/1),
         {:ok, meta_data, rest} <- take(rest, 0x30, &meta_data/1),
         {:ok, content, rest} <- content(rest),
         [evidence] <- rest,
         :ok <- content_or_uri(content, data_uri),
         {:ok, evidence} <- evidence(evidence, max_stamps) do
      {:ok,
       %__MODULE__{
         data_uri: data_uri,
         meta_data: meta_data,
         content: content,
         evidence: evidence
       }}
    else
      {:error, %Error{}} = error -> error
      _ -> {:error, Error.new(:malformed)}
    end
  end

  defp time_stamped_data([], _max_stamps), do: {:error, Error.new(:malformed)}

  defp version(element) do
    case DER.integer(element) do
      {:ok, 1} -> :ok
      {:ok, n} -> {:error, Error.new(:unsupported_version, n)}
      :error -> {:error, Error.new(:malformed)}
    end
  end

  # An optional field with the identifier `id`.
  defp take([{id, _, _} = element | rest], id, fun) do
    case fun.(element) do
      {:ok, value} -> {:ok, value, rest}
      :error -> :error
    end
  end

  defp take(rest, _id, _fun), do: {:ok, nil, rest}

  defp content([{id, _, _} = element | rest]) when id in [0x04, 0x24] do
    case DER.octets(element) do
      {:ok, bytes} -> {:ok, bytes, rest}
      :error -> :error
    end
  end

  defp content(rest), do: {:ok, nil, rest}

  # RFC 5544, 2: with no content in the structure there has to be a dataUri.
  defp content_or_uri(nil, nil), do: :error
  defp content_or_uri(_content, _data_uri), do: :ok

  # MetaData: hashProtected, then at least one of fileName, mediaType and
  # otherMetaData.
  defp meta_data({0x30, _, _} = element) do
    with [flag | rest] <- DER.children(element),
         {:ok, hash_protected} <- DER.boolean(flag),
         {:ok, file_name, rest} <- take(rest, 0x0C, &DER.utf8/1),
         {:ok, media_type, rest} <- take(rest, 0x16, &DER.ia5/1),
         {:ok, other, rest} <- take(rest, 0x31, &attributes/1),
         [] <- rest,
         true <- file_name != nil or media_type != nil or other != nil do
      {:ok,
       %{
         hash_protected: hash_protected,
         file_name: file_name,
         media_type: media_type,
         other: other || []
       }}
    else
      _ -> :error
    end
  end

  # SET SIZE (1..MAX) OF Attribute
  defp attributes({0x31, _, _} = set) do
    case DER.children(set) do
      [] -> :error
      attributes -> collect(attributes, &attribute/1)
    end
  end

  defp attribute({0x30, _, _} = element) do
    with [oid, {0x31, _, _} = values] <- DER.children(element),
         {:ok, oid} <- DER.oid(oid),
         [_ | _] = values <- DER.children(values) do
      {:ok, %{oid: oid, values: Enum.map(values, fn {_, _, raw} -> raw end)}}
    else
      _ -> :error
    end
  end

  defp attribute(_element), do: :error

  defp collect(elements, fun) do
    Enum.reduce_while(elements, {:ok, []}, fn element, {:ok, acc} ->
      case fun.(element) do
        {:ok, value} -> {:cont, {:ok, [value | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      :error -> :error
    end
  end

  # [0] TimeStampTokenEvidence, [1] EvidenceRecord, [2] OtherEvidence, all
  # implicit.
  defp evidence({0xA0, _, _} = element, max_stamps) do
    case DER.children(element) do
      [] ->
        :error

      elements when length(elements) > max_stamps ->
        {:error, Error.new(:limit_exceeded, :max_stamps)}

      elements ->
        with {:ok, elements} <- collect(elements, &time_stamp_and_crl/1),
             do: {:ok, {:tst, elements}}
    end
  end

  defp evidence({0xA1, _, raw}, _max_stamps), do: {:ok, {:ers, raw}}

  defp evidence({0xA2, _, _} = element, _max_stamps) do
    with [oid, {_, _, value}] <- DER.children(element),
         {:ok, oid} <- DER.oid(oid) do
      {:ok, {:other, oid, value}}
    else
      _ -> :error
    end
  end

  defp evidence(_element, _max_stamps), do: :error

  defp time_stamp_and_crl({0x30, _, raw} = element) do
    case DER.children(element) do
      [{0x30, _, token}] -> {:ok, %{token: token, crl: nil, raw: raw}}
      [{0x30, _, token}, {0x30, _, crl}] -> {:ok, %{token: token, crl: crl, raw: raw}}
      _ -> :error
    end
  end

  defp time_stamp_and_crl(_element), do: :error

  ## Reading the stamps

  @doc """
  The `TSTInfo` of each token of the chain, read and not verified, in the
  order of the chain. Takes the limits of `decode/2`. A chain of other
  evidence is `:unsupported_evidence`.
  """
  @spec time_stamps(t() | binary(), keyword()) :: {:ok, [TSTInfo.t()]} | {:error, Error.t()}
  def time_stamps(tsd_or_der, opts \\ []) do
    with {:ok, tsd} <- as_struct(tsd_or_der, opts),
         {:ok, elements} <- tst_elements(tsd) do
      read_tokens(elements, Keyword.take(opts, [:max_size, :max_depth, :max_nodes]))
    end
  end

  defp read_tokens(elements, limits) do
    elements
    |> Enum.reduce_while({:ok, []}, fn element, {:ok, acc} ->
      case Tspex.decode_token(element.token, limits) do
        {:ok, info} -> {:cont, {:ok, [info | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      {:error, _} = error -> error
    end
  end

  ## Verifying

  @doc """
  Verifies a `TimeStampedData`, given as DER or as the struct: the content
  and the whole chain.

  Each token is verified like `Tspex.verify/3` verifies a stored token, with
  the same options, against what it has to cover (see the module doc): the
  first against the content (and the `MetaData` if it is hash protected),
  the others against the element before them. The certificate of each TSA
  is judged at the `genTime` of its own token.

  Options: those of `Tspex.verify/3` (`:trust` is required), the limits of
  `decode/2`, and:

    * `:content` - the document, as a binary or `{:stream, enumerable}`, for
      a structure that does not carry it. A structure that carries its
      content and is given `:content` is `:unexpected_content`, and one with
      neither is `:content_missing`. The `dataUri` is not used.
    * `:max_time_back` - how many seconds the `genTime` of a token may be
      earlier than the one of the token before it. A token covers the
      element that holds the one before, so it was issued later; if its
      `genTime` is earlier, one of the two clocks is wrong, or lies. With a
      number, a token earlier by more than that is `:time_order`; `0` asks
      for a strictly non-decreasing chain. `nil` (the default) does not
      refuse: the result says it in `:ordered`. TSAs that are not the same
      have clocks that differ by seconds, so choose the number knowing which.

  Returns `{:ok, result}` with:

    * `:time` - the `genTime` of the first token, when the document existed.
    * `:stamps` - the `t:Tspex.Verified.t/0` of each token, in order.
    * `:ordered` - `true` when no token has a `genTime` earlier than the
      one before it (see `:max_time_back`).
    * `:crls` - the `crl` of each element in DER, or `nil`. Not checked here;
      the guide on verification shows how to check them with the recipe for
      revocation.
    * `:meta_data` - the `MetaData`, or `nil`.

  Evidence that is not `tstEvidence` is `:unsupported_evidence`.
  """
  @spec verify(t() | binary(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def verify(tsd_or_der, opts) do
    opts =
      Options.take!(opts, @verify_chain_options ++ @read_options ++ @verify_options, [:trust])

    max_stamps = Map.get(opts, :max_stamps, @default_max_stamps)
    max_back = max_time_back!(opts)

    with {:ok, tsd} <- as_struct(tsd_or_der, Map.to_list(opts) |> Keyword.take(@read_options)),
         {:ok, elements} <- tst_elements(tsd),
         :ok <- chain_length(elements, max_stamps),
         {:ok, content} <- document(tsd, opts[:content]),
         {:ok, stamps} <-
           chain(elements, first_input(content, tsd.meta_data), token_options(opts)),
         {:ok, ordered} <- time_order(stamps, max_back) do
      {:ok,
       %{
         time: hd(stamps).info.gen_time,
         stamps: stamps,
         ordered: ordered,
         crls: Enum.map(elements, & &1.crl),
         meta_data: tsd.meta_data
       }}
    end
  end

  defp max_time_back!(opts) do
    case Map.get(opts, :max_time_back) do
      nil ->
        nil

      seconds when is_integer(seconds) and seconds >= 0 ->
        seconds

      _other ->
        raise ArgumentError, ":max_time_back must be nil or a non-negative integer of seconds"
    end
  end

  # Whether the genTime never goes back along the chain, and, with a limit,
  # the first token that goes back by more than that.
  defp time_order(stamps, max_back) do
    steps =
      stamps
      |> Enum.map(& &1.info.gen_time)
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.with_index(1)
      |> Enum.filter(fn {[before, later], _position} ->
        DateTime.compare(later, before) == :lt
      end)

    cond do
      steps == [] -> {:ok, true}
      max_back == nil -> {:ok, false}
      true -> too_far_back(steps, max_back)
    end
  end

  defp too_far_back(steps, seconds) do
    case Enum.find(steps, fn {[before, later], _} ->
           DateTime.diff(before, later, :microsecond) > seconds * 1_000_000
         end) do
      nil -> {:ok, false}
      {_, position} -> {:error, Error.new(:time_order, position)}
    end
  end

  defp chain_length(elements, max) when length(elements) > max,
    do: {:error, Error.new(:limit_exceeded, :max_stamps)}

  defp chain_length(_elements, _max), do: :ok

  # The first token covers the document, each later one the element before.
  defp chain(elements, first, opts) do
    elements
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, [], nil}, fn {element, index}, {:ok, acc, previous} ->
      expected = if index == 0, do: first, else: {:data, previous.raw}

      case Verify.verify(element.token, expected, opts) do
        {:ok, verified} -> {:cont, {:ok, [verified | acc], element}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, reversed, _last} -> {:ok, Enum.reverse(reversed)}
      {:error, _} = error -> error
    end
  end

  defp token_options(opts) do
    opts
    |> Map.take(@verify_options)
    |> Map.to_list()
    |> Keyword.put(:input, :token)
  end

  defp as_struct(%__MODULE__{} = tsd, _opts), do: {:ok, tsd}

  defp as_struct(der, opts) when is_binary(der),
    do: decode(der, Keyword.take(opts, @read_options))

  defp as_struct(_other, _opts),
    do: raise(ArgumentError, "expected a Tspex.TimeStampedData or its encoding")

  defp tst_elements(%__MODULE__{evidence: {:tst, elements}}), do: {:ok, elements}
  defp tst_elements(%__MODULE__{}), do: {:error, Error.new(:unsupported_evidence)}

  # The document the first token covers: the content of the structure or the
  # one the caller gave, never one fetched.
  defp document(%__MODULE__{content: nil}, nil), do: {:error, Error.new(:content_missing)}
  defp document(%__MODULE__{content: nil}, given), do: {:ok, content!(given)}
  defp document(%__MODULE__{content: content}, nil), do: {:ok, content}
  defp document(%__MODULE__{}, _given), do: {:error, Error.new(:unexpected_content)}

  # What the first token has to cover, as `Tspex.verify/3` takes it:
  # `{:data, binary}` or `{:stream, enumerable}`.
  defp first_input(content, %{hash_protected: true} = meta) do
    case content do
      content when is_binary(content) -> {:data, meta_der(meta) <> content}
      {:stream, stream} -> {:stream, Stream.concat([meta_der(meta)], stream)}
    end
  end

  defp first_input(content, _meta) when is_binary(content), do: {:data, content}
  defp first_input({:stream, _} = stream, _meta), do: stream

  ## A token that has to cover something

  defp bound(%Verified{token: token, info: info}, expected, _opts) do
    with true <- info.hash in @hashes,
         {:ok, digest} <- Imprint.digest(strip(expected), info.hash),
         true <- Imprint.equal?(info.digest, digest) do
      {:ok, token}
    else
      _ -> {:error, Error.new(:imprint_mismatch, :digest)}
    end
  end

  defp bound(token, expected, opts) when is_binary(token) do
    with {:ok, verified} <- Verify.verify(token, expected, token_options(opts)),
         do: {:ok, verified.token}
  end

  defp strip({:data, bytes}), do: bytes
  defp strip(other), do: other

  ## Arguments

  defp content!(content) when is_binary(content), do: content
  defp content!({:stream, _} = stream), do: stream

  defp content!(_other),
    do: raise(ArgumentError, "the content must be a binary or {:stream, enumerable}")

  defp detached?(content, opts) do
    case {opts[:detached], content} do
      {nil, {:stream, _}} -> true
      {nil, _} -> false
      {true, _} -> true
      {false, {:stream, _}} -> raise ArgumentError, "a stream cannot be put in the structure"
      {false, _} -> false
      {_other, _} -> raise ArgumentError, ":detached must be a boolean"
    end
  end

  defp hash!(opts) do
    hash = Map.get(opts, :hash, :sha256)

    if hash == :sha1 and not Map.get(opts, :allow_sha1, false),
      do: raise(ArgumentError, "SHA-1 needs allow_sha1: true")

    hash
  end

  defp data_uri!(nil), do: nil

  defp data_uri!(uri) when is_binary(uri) do
    if uri != "" and ascii?(uri),
      do: uri,
      else: raise(ArgumentError, ":data_uri must be non-empty ASCII text")
  end

  defp data_uri!(_other), do: raise(ArgumentError, ":data_uri must be a binary")

  defp crl!(nil), do: nil

  defp crl!(crl) when is_binary(crl) do
    case DER.decode(crl) do
      {:ok, {0x30, _, _}} -> crl
      _ -> raise ArgumentError, ":crl must be a CertificateList in DER"
    end
  end

  defp crl!(_other), do: raise(ArgumentError, ":crl must be a binary")

  # The MetaData from the options, or nil when there is none.
  defp meta!(opts) do
    hash_protected = Map.get(opts, :hash_protected, false)
    file_name = file_name!(opts[:file_name])
    media_type = media_type!(opts[:media_type])
    other = attributes!(opts[:other_meta_data])

    unless is_boolean(hash_protected),
      do: raise(ArgumentError, ":hash_protected must be a boolean")

    if file_name == nil and media_type == nil and other == [] do
      if hash_protected,
        do:
          raise(
            ArgumentError,
            ":hash_protected needs a :file_name, :media_type or :other_meta_data"
          )

      nil
    else
      %{
        hash_protected: hash_protected,
        file_name: file_name,
        media_type: media_type,
        other: other
      }
    end
  end

  defp file_name!(nil), do: nil

  defp file_name!(name) when is_binary(name) and name != "" do
    if String.valid?(name),
      do: name,
      else: raise(ArgumentError, ":file_name must be a non-empty UTF-8 string")
  end

  defp file_name!(_other), do: raise(ArgumentError, ":file_name must be a non-empty UTF-8 string")

  defp media_type!(nil), do: nil

  defp media_type!(type) when is_binary(type) and type != "" do
    if ascii?(type),
      do: type,
      else: raise(ArgumentError, ":media_type must be a non-empty ASCII string")
  end

  defp media_type!(_other),
    do: raise(ArgumentError, ":media_type must be a non-empty ASCII string")

  defp attributes!(nil), do: []

  defp attributes!(list) when is_list(list) do
    Enum.map(list, fn
      %{oid: oid, values: [_ | _] = values} when is_tuple(oid) ->
        unless Enum.all?(values, &match?({:ok, _}, DER.decode(&1))),
          do: raise(ArgumentError, "the values of an attribute must be DER")

        %{oid: Options.oid!(oid, ":other_meta_data"), values: values}

      _other ->
        raise ArgumentError, ":other_meta_data must be a list of %{oid: tuple, values: [der]}"
    end)
  end

  defp attributes!(_other), do: raise(ArgumentError, ":other_meta_data must be a list")

  defp ascii?(text), do: text |> :binary.bin_to_list() |> Enum.all?(&(&1 in 0..127))

  # The DER encoding of the MetaData, which is what the first token covers
  # when hashProtected is true.
  defp meta_der(meta) do
    fields =
      [{:bool, meta.hash_protected}] ++
        optional(meta.file_name, &{:utf8, &1}) ++
        optional(meta.media_type, &{:ia5, &1}) ++
        attribute_set(meta.other)

    DER.encode({:seq, fields})
  end

  defp attribute_set([]), do: []

  defp attribute_set(attributes) do
    [
      {:set,
       Enum.map(attributes, fn %{oid: oid, values: values} ->
         {:seq, [{:oid, oid}, {:set, Enum.map(values, &{:raw, &1})}]}
       end)}
    ]
  end
end
