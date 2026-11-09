defmodule Tspex.TSTInfo do
  @moduledoc """
  The `TSTInfo` of a time-stamp token (RFC 3161, 2.4.2): what the TSA signed.

  `Tspex.decode_token/2` reads one **without verifying anything**: the
  signature, the certificate and the match with a request are checked only
  by `Tspex.verify/3`, which returns the same struct as `info` of
  `Tspex.Verified`. Do not trust the time of a `TSTInfo` that was not
  verified.

  Fields:

    * `:version` - always 1.
    * `:policy` - the policy of the TSA, as an OID tuple.
    * `:hash` and `:digest` - the `messageImprint`: the hash as a name such
      as `:sha256` (`:md5`, or the OID tuple, for an algorithm this library
      does not implement) and the digest.
    * `:serial` - the serial number.
    * `:gen_time` - the time, a UTC `DateTime` with up to microseconds.
    * `:accuracy` - `%{seconds: n, millis: n, micros: n}` (what is absent is
      zero) or `nil`; see `bounds/1`.
    * `:ordering` - whether the tokens of this TSA are ordered by `genTime`
      within the accuracy.
    * `:nonce` - the nonce, or `nil`.
    * `:tsa` - the name of the TSA, or `nil`: `{:directory_name, der}` (the
      `Name`, in DER), `{:dns_name, text}`, `{:uri, text}`,
      `{:rfc822_name, text}`, `{:ip_address, octets}` or `{:other, der}`.
    * `:extensions` - `[%{oid: tuple, critical: boolean, value: binary}]`,
      with the value as the DER bytes of the extension.
    * `:deviations` - what was tolerated against the RFC; `:gen_time_encoding`
      when `genTime` has a fraction that is not in DER.
  """

  alias Tspex.{Codec, DER, Error, Options, Time}

  @typedoc "The name of the TSA, as a `GeneralName`."
  @type name :: Tspex.general_name()

  @typedoc "The accuracy of the `genTime`; a part that the token leaves out is 0."
  @type accuracy :: %{seconds: non_neg_integer(), millis: 0..999, micros: 0..999}

  @typedoc "A `TSTInfo`, the content of a token."
  @type t :: %__MODULE__{
          version: 1,
          policy: tuple(),
          hash: Tspex.hash() | :md5 | tuple(),
          digest: binary(),
          serial: integer(),
          gen_time: DateTime.t(),
          accuracy: accuracy() | nil,
          ordering: boolean(),
          nonce: integer() | nil,
          tsa: name() | nil,
          extensions: [Tspex.extension()],
          deviations: [atom()]
        }

  @enforce_keys [:policy, :hash, :digest, :serial, :gen_time]
  defstruct [
    :policy,
    :hash,
    :digest,
    :serial,
    :gen_time,
    :accuracy,
    :nonce,
    :tsa,
    version: 1,
    ordering: false,
    extensions: [],
    deviations: []
  ]

  @max_seconds 2_147_483_647
  @min_unix_micros -62_135_596_800_000_000
  @max_unix_micros 253_402_300_799_999_999

  @read_options [
    :max_size,
    :max_depth,
    :max_nodes,
    :max_signers,
    :max_certificates,
    :max_attributes
  ]

  @doc """
  The interval the time is known to be in: `{earliest, latest}`, `genTime`
  minus and plus the `accuracy`. Both are `genTime` when there is no
  accuracy. The ends are kept inside the years 1 to 9999.

      iex> info = %Tspex.TSTInfo{
      ...>   policy: {1, 2, 3},
      ...>   hash: :sha256,
      ...>   digest: <<0::256>>,
      ...>   serial: 1,
      ...>   gen_time: ~U[2026-11-09 12:00:00Z],
      ...>   accuracy: %{seconds: 1, millis: 500, micros: 0}
      ...> }
      iex> Tspex.TSTInfo.bounds(info)
      {~U[2026-11-09 11:59:58.500000Z], ~U[2026-11-09 12:00:01.500000Z]}
  """
  @spec bounds(t()) :: {DateTime.t(), DateTime.t()}
  def bounds(%__MODULE__{gen_time: gen_time, accuracy: nil}), do: {gen_time, gen_time}

  def bounds(%__MODULE__{gen_time: gen_time, accuracy: accuracy}) do
    delta = accuracy.seconds * 1_000_000 + accuracy.millis * 1_000 + accuracy.micros
    center = DateTime.to_unix(gen_time, :microsecond)
    {at(center - delta), at(center + delta)}
  end

  defp at(micros) do
    {:ok, time} =
      micros |> min(@max_unix_micros) |> max(@min_unix_micros) |> DateTime.from_unix(:microsecond)

    time
  end

  ## Reading a token

  @doc false
  @spec check_options!(keyword()) :: :ok
  def check_options!(opts) do
    Options.take!(opts, @read_options)
    :ok
  end

  @doc false
  # The ContentInfo of a token, and the TSTInfo inside it, without checking
  # signatures. Returns the SignedData too, for the verification.
  @spec read_token(binary(), keyword() | map()) ::
          {:ok, Cmsex.SignedData.t(), t()} | {:error, Error.t()}
  def read_token(token, opts) when is_list(opts),
    do: read_token(token, Options.take!(opts, @read_options))

  def read_token(token, opts) when is_binary(token) and is_map(opts) do
    with {:ok, signed_data, content} <- read_signed_data(token, opts),
         {:ok, info} <- parse(content, opts) do
      {:ok, signed_data, info}
    end
  end

  def read_token(_token, _opts), do: raise(ArgumentError, "expected the token as a binary")

  @doc false
  # The SignedData of a token and the bytes of the TSTInfo it carries, before
  # the TSTInfo is read: the verification looks at the signers in between.
  @spec read_signed_data(binary(), map()) ::
          {:ok, Cmsex.SignedData.t(), binary()} | {:error, Error.t()}
  def read_signed_data(token, opts) do
    with :ok <- check_form(token, opts),
         {:ok, signed_data} <- decode_cms(token, opts),
         {:ok, content} <- tst_info_content(signed_data) do
      {:ok, signed_data, content}
    end
  end

  defp check_form(token, opts) do
    cond do
      byte_size(token) > opts.max_size -> {:error, Error.new(:limit_exceeded, :max_size)}
      match?(<<0x30, _::binary>>, token) -> :ok
      true -> {:error, Error.new(:malformed)}
    end
  end

  defp decode_cms(token, opts) do
    cms_opts = [
      max_depth: opts.max_depth,
      max_elements: opts.max_nodes,
      max_signers: opts.max_signers,
      max_certificates: opts.max_certificates,
      max_attributes: opts.max_attributes
    ]

    case Cmsex.decode(token, cms_opts) do
      {:ok, %Cmsex.SignedData{} = signed_data} ->
        {:ok, signed_data}

      {:ok, _other_type} ->
        {:error, Error.new(:not_a_time_stamp_token, :content_info_type)}

      {:error, %Cmsex.Error{reason: :unsupported_content_type} = cause} ->
        {:error, Error.from_cms(:not_a_time_stamp_token, cause)}

      {:error, %Cmsex.Error{reason: :limit_exceeded} = cause} ->
        {:error, Error.from_cms(:limit_exceeded, cause)}

      {:error, %Cmsex.Error{} = cause} ->
        {:error, Error.from_cms(:malformed, cause)}
    end
  end

  defp tst_info_content(%Cmsex.SignedData{content_type: :tst_info, content: content})
       when is_binary(content),
       do: {:ok, content}

  defp tst_info_content(%Cmsex.SignedData{content_type: :tst_info}),
    do: {:error, Error.new(:not_a_time_stamp_token, :detached)}

  defp tst_info_content(%Cmsex.SignedData{content_type: type}),
    do: {:error, Error.new(:not_a_time_stamp_token, {:content_type, type})}

  ## Reading the TSTInfo

  @doc false
  @spec parse(binary(), keyword() | map()) :: {:ok, t()} | {:error, Error.t()}
  def parse(der, opts) when is_list(opts), do: parse(der, Options.take!(opts, @read_options))

  def parse(der, opts) when is_binary(der) do
    case Codec.decode(der, opts) do
      {:ok, {0x30, _, _} = root} -> read(DER.children(root))
      {:ok, _not_a_sequence} -> {:error, Error.new(:malformed)}
      {:error, %Error{}} = error -> error
    end
  end

  defp read([version, policy, imprint, serial, gen_time | rest]) do
    with {:ok, 1} <- version(version),
         {:ok, policy} <- oid(policy),
         {:ok, hash, digest} <- message_imprint(imprint),
         {:ok, serial} <- integer(serial),
         {:ok, gen_time, deviations} <- gen_time(gen_time),
         {:ok, optional} <- optional(rest, %{}, 0) do
      {:ok,
       %__MODULE__{
         policy: policy,
         hash: hash,
         digest: digest,
         serial: serial,
         gen_time: gen_time,
         accuracy: Map.get(optional, :accuracy),
         ordering: Map.get(optional, :ordering, false),
         nonce: Map.get(optional, :nonce),
         tsa: Map.get(optional, :tsa),
         extensions: Map.get(optional, :extensions, []),
         deviations: deviations
       }}
    else
      {:ok, other} when is_integer(other) -> {:error, Error.new(:unsupported_version, other)}
      :error -> {:error, Error.new(:malformed)}
    end
  end

  defp read(_elements), do: {:error, Error.new(:malformed)}

  defp version(element), do: Codec.integer(element)
  defp oid(element), do: DER.oid(element)
  defp integer(element), do: Codec.integer(element)
  # The size of the digest is checked by the verification (:imprint_mismatch).
  defp message_imprint(element), do: Codec.message_imprint(element, false)

  defp gen_time({0x18, content, _raw}), do: Time.parse(content)
  defp gen_time(_element), do: :error

  # accuracy, ordering, nonce, tsa and extensions, in this order, each optional.
  defp optional([], acc, _stage), do: {:ok, acc}

  defp optional([{0x30, _, _} = element | rest], acc, stage) when stage < 1 do
    with {:ok, accuracy} <- accuracy(element),
         do: optional(rest, Map.put(acc, :accuracy, accuracy), 1)
  end

  defp optional([{0x01, _, _} = element | rest], acc, stage) when stage < 2 do
    with {:ok, flag} <- DER.boolean(element), do: optional(rest, Map.put(acc, :ordering, flag), 2)
  end

  defp optional([{0x02, _, _} = element | rest], acc, stage) when stage < 3 do
    with {:ok, nonce} <- Codec.integer(element),
         do: optional(rest, Map.put(acc, :nonce, nonce), 3)
  end

  defp optional([{0xA0, _, _} = element | rest], acc, stage) when stage < 4 do
    with {:ok, name} <- tsa(element), do: optional(rest, Map.put(acc, :tsa, name), 4)
  end

  defp optional([{0xA1, _, _} = element | rest], acc, stage) when stage < 5 do
    with {:ok, extensions} <- Codec.extensions(element),
         do: optional(rest, Map.put(acc, :extensions, extensions), 5)
  end

  defp optional(_elements, _acc, _stage), do: :error

  ## Accuracy: seconds INTEGER, millis [0] IMPLICIT, micros [1] IMPLICIT.
  # An absent field is zero. The ASN.1 range of millis and micros is
  # 1..999, and a TSA that writes 0 is read.

  defp accuracy(element) do
    accuracy(DER.children(element), %{seconds: 0, millis: 0, micros: 0}, 0)
  end

  defp accuracy([], acc, _stage), do: {:ok, acc}

  defp accuracy([{0x02, _, _} = element | rest], acc, stage) when stage < 1 do
    with {:ok, seconds} <- element |> DER.integer() |> within(0..@max_seconds),
         do: accuracy(rest, %{acc | seconds: seconds}, 1)
  end

  defp accuracy([{0x80, content, raw} | rest], acc, stage) when stage < 2 do
    with {:ok, millis} <- {0x02, content, raw} |> DER.integer() |> within(0..999),
         do: accuracy(rest, %{acc | millis: millis}, 2)
  end

  defp accuracy([{0x81, content, raw} | rest], acc, stage) when stage < 3 do
    with {:ok, micros} <- {0x02, content, raw} |> DER.integer() |> within(0..999),
         do: accuracy(rest, %{acc | micros: micros}, 3)
  end

  defp accuracy(_elements, _acc, _stage), do: :error

  defp within({:ok, n}, range), do: if(n in range, do: {:ok, n}, else: :error)
  defp within(:error, _range), do: :error

  ## The name of the TSA: [0] EXPLICIT GeneralName.

  defp tsa(element) do
    case DER.children(element) do
      [general_name] -> Codec.general_name(general_name)
      _ -> :error
    end
  end
end
