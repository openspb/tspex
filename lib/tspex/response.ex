defmodule Tspex.Response do
  @moduledoc """
  A time-stamp response, the `TimeStampResp` of RFC 3161 (2.4.2), as
  `Tspex.decode_response/2` reads it. Reading only parses: a rejection is a
  valid response, with `token: nil`, and it is `Tspex.verify/3` that turns
  it into an error.

  Fields:

    * `:status` - `:granted`, `:granted_with_mods`, `:rejection`,
      `:waiting`, `:revocation_warning` or `:revocation_notification`.
    * `:status_text` - the `statusString`, a list of strings; `[]` when
      absent.
    * `:fail_info` - the bits of `failInfo`, as `:bad_alg`, `:bad_request`,
      `:bad_data_format`, `:time_not_available`, `:unaccepted_policy`,
      `:unaccepted_extension`, `:add_info_not_available` or
      `:system_failure`; a bit RFC 3161 does not define is
      `{:unknown_bit, n}`. `[]` when absent.
    * `:token` - the `TimeStampToken` (a `ContentInfo`) as received, in
      the bytes of the response; `nil` when there is none.
    * `:deviations` - what was tolerated against the RFC.
  """

  alias Tspex.{Codec, DER, Error, Options}

  @type status ::
          :granted
          | :granted_with_mods
          | :rejection
          | :waiting
          | :revocation_warning
          | :revocation_notification

  @type fail_info ::
          :bad_alg
          | :bad_request
          | :bad_data_format
          | :time_not_available
          | :unaccepted_policy
          | :unaccepted_extension
          | :add_info_not_available
          | :system_failure
          | {:unknown_bit, non_neg_integer()}

  @type t :: %__MODULE__{
          status: status(),
          status_text: [String.t()],
          fail_info: [fail_info()],
          token: binary() | nil,
          deviations: [atom()]
        }

  @enforce_keys [:status]
  defstruct [:status, :token, status_text: [], fail_info: [], deviations: []]

  @statuses %{
    0 => :granted,
    1 => :granted_with_mods,
    2 => :rejection,
    3 => :waiting,
    4 => :revocation_warning,
    5 => :revocation_notification
  }

  @fail_info_bits %{
    0 => :bad_alg,
    2 => :bad_request,
    5 => :bad_data_format,
    14 => :time_not_available,
    15 => :unaccepted_policy,
    16 => :unaccepted_extension,
    17 => :add_info_not_available,
    25 => :system_failure
  }

  @read_options [:max_size, :max_depth, :max_nodes]

  @doc false
  @spec decode(binary(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def decode(der, opts) when is_binary(der) do
    opts = Options.take!(opts, @read_options)

    case Codec.decode(der, opts) do
      {:ok, {0x30, _, _} = root} -> read(DER.children(root))
      {:ok, _not_a_sequence} -> {:error, Error.new(:malformed)}
      {:error, %Error{}} = error -> error
    end
  end

  def decode(_der, _opts), do: raise(ArgumentError, "expected the response as a binary")

  defp read([{0x30, _, _} = status_info]), do: build(status_info, nil)

  defp read([{0x30, _, _} = status_info, {0x30, _, token}]), do: build(status_info, token)

  defp read(_elements), do: {:error, Error.new(:malformed)}

  defp build(status_info, token) do
    with {:ok, status, status_text, fail_info} <- status_info(DER.children(status_info)) do
      {:ok,
       %__MODULE__{status: status, status_text: status_text, fail_info: fail_info, token: token}}
    end
  end

  # PKIStatusInfo: status, then statusString and failInfo, each optional.
  defp status_info([status_element | rest]) do
    with {:ok, status} <- status(status_element),
         {:ok, text, fail_info} <- optional(rest) do
      {:ok, status, text, fail_info}
    end
  end

  defp status_info([]), do: {:error, Error.new(:malformed)}

  defp status(element) do
    case DER.integer(element) do
      {:ok, n} when is_map_key(@statuses, n) -> {:ok, Map.fetch!(@statuses, n)}
      {:ok, n} -> {:error, Error.new(:unknown_status, n)}
      :error -> {:error, Error.new(:malformed)}
    end
  end

  defp optional([]), do: {:ok, [], []}

  defp optional([{0x30, _, _} = text_element | rest]) do
    with {:ok, text} <- free_text(text_element),
         {:ok, fail_info} <- fail_info(rest) do
      {:ok, text, fail_info}
    end
  end

  defp optional([{0x03, _, _} | _] = rest) do
    with {:ok, fail_info} <- fail_info(rest), do: {:ok, [], fail_info}
  end

  defp optional(_), do: {:error, Error.new(:malformed)}

  # PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
  defp free_text(element) do
    case DER.children(element) do
      [] -> {:error, Error.new(:malformed)}
      strings -> collect(strings, [])
    end
  end

  defp collect([], acc), do: {:ok, Enum.reverse(acc)}

  defp collect([string | rest], acc) do
    case DER.utf8(string) do
      {:ok, text} -> collect(rest, [text | acc])
      :error -> {:error, Error.new(:malformed)}
    end
  end

  defp fail_info([]), do: {:ok, []}

  defp fail_info([bits_element]) do
    case DER.named_bits(bits_element) do
      {:ok, positions} -> {:ok, Enum.map(positions, &fail_info_name/1)}
      :error -> {:error, Error.new(:malformed)}
    end
  end

  defp fail_info(_), do: {:error, Error.new(:malformed)}

  defp fail_info_name(position), do: Map.get(@fail_info_bits, position, {:unknown_bit, position})
end
