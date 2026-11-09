defmodule Tspex.PathValidation do
  @moduledoc false
  # The verify_fun that makes `:public_key.pkix_path_validation/3` validate a
  # certificate path at the time of a time-stamp instead of today, and that
  # lets the critical extKeyUsage of a TSA through. See `Tspex.path_validation_at/2`.

  alias Tspex.{Certificate, Options}

  @time_stamping {1, 3, 6, 1, 5, 5, 7, 3, 8}
  @any_eku {2, 5, 29, 37, 0}
  @eku {2, 5, 29, 37}
  @key_usage {2, 5, 29, 15}

  @doc false
  @spec options_at(DateTime.t(), keyword()) :: keyword()
  def options_at(%DateTime{} = time, opts) when is_list(opts) do
    Options.unique!(opts)

    if Keyword.has_key?(opts, :verify_fun),
      do:
        raise(
          ArgumentError,
          ":verify_fun is set by Tspex to validate the path at the time of the " <>
            "time-stamp; use the :revocation option of verify/3 to check revocation"
        )

    Keyword.put(opts, :verify_fun, {&verify_fun/3, time})
  end

  def options_at(_time, _opts), do: raise(ArgumentError, "expected a DateTime and a keyword list")

  @doc """
  Checks a validated path, root first and the signer last, against the time
  of the stamp. The OTP only reports a validity period that is wrong *today*
  and sends no event for the extKeyUsage of some CAs, so the callback alone
  cannot decide: here every certificate, the root included, must be valid at
  `time`, and the extKeyUsage of each CA, if it has one, must allow
  timeStamping (RFC 5280, 4.2.1.12). The reasons are `:not_valid_at_time`,
  `:eku_excludes_time_stamping` and `:invalid_certificate`.
  """
  @spec check_path([binary()], DateTime.t()) :: :ok | {:error, atom()}
  def check_path(path, %DateTime{} = time) when is_list(path) do
    last = length(path) - 1

    path
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {der, index}, :ok ->
      case check_certificate(der, time, index < last) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp check_certificate(der, time, ca?) do
    case Certificate.parse(der) do
      {:ok, cert} ->
        t = DateTime.truncate(time, :second)

        cond do
          DateTime.compare(t, cert.not_before) == :lt -> {:error, :not_valid_at_time}
          DateTime.compare(t, cert.not_after) == :gt -> {:error, :not_valid_at_time}
          ca? -> ca_purposes(cert)
          true -> :ok
        end

      :error ->
        {:error, :invalid_certificate}
    end
  end

  defp ca_purposes(cert) do
    cert
    |> Certificate.extensions(@eku)
    |> Enum.map(&Certificate.eku_list/1)
    |> Enum.reduce_while(:ok, &purpose/2)
  end

  defp purpose({:ok, oids}, :ok) do
    if @time_stamping in oids or @any_eku in oids,
      do: {:cont, :ok},
      else: {:halt, {:error, :eku_excludes_time_stamping}}
  end

  defp purpose(:error, :ok), do: {:halt, {:error, :invalid_certificate}}

  @doc false
  # The callback. `state` is the time of the stamp.
  def verify_fun(cert, {:bad_cert, :cert_expired}, time) do
    if within?(cert, time), do: {:valid, time}, else: {:fail, :not_valid_at_time}
  end

  # The OTP checks keyUsage against extKeyUsage by itself. On a CA, every
  # extKeyUsage that is not just anyExtendedKeyUsage arrives here (RFC 5280,
  # 4.2.1.12: it limits what the CA can certify).
  def verify_fun(
        _cert,
        {:bad_cert, {:key_usage_mismatch, {{:Extension, @key_usage, _, usage}, eku_extension}}},
        time
      ) do
    if :keyCertSign in List.wrap(usage),
      do: eku_allows(eku_extension, time),
      else: {:fail, :key_usage_mismatch}
  end

  def verify_fun(cert, {:bad_cert, :invalid_ext_key_usage}, time) do
    case eku_extension(cert) do
      nil -> {:fail, :invalid_ext_key_usage}
      extension -> eku_allows(extension, time)
    end
  end

  def verify_fun(_cert, {:bad_cert, reason}, _time), do: {:fail, reason}

  # A critical extKeyUsage is reported as an extension that the OTP does not
  # know; here it is the leaf, or a CA that says anyExtendedKeyUsage.
  def verify_fun(_cert, {:extension, {:Extension, @eku, _, _} = extension}, time),
    do: eku_allows(extension, time)

  def verify_fun(_cert, {:extension, _extension}, time), do: {:unknown, time}
  def verify_fun(_cert, :valid, time), do: {:valid, time}
  def verify_fun(_cert, :valid_peer, time), do: {:valid, time}

  defp eku_allows({:Extension, @eku, _, oids}, time) do
    oids = List.wrap(oids)

    if @time_stamping in oids or @any_eku in oids,
      do: {:valid, time},
      else: {:fail, :eku_excludes_time_stamping}
  end

  defp eku_allows(_other, _time), do: {:fail, :eku_excludes_time_stamping}

  defp eku_extension({:OTPCertificate, tbs, _, _}) do
    # OTPTBSCertificate: the extensions are the last field.
    case elem(tbs, tuple_size(tbs) - 1) do
      extensions when is_list(extensions) ->
        Enum.find(extensions, &match?({:Extension, @eku, _, _}, &1))

      _ ->
        nil
    end
  end

  defp eku_extension(_), do: nil

  # OTPTBSCertificate: {tag, version, serial, signature, issuer, validity, ...}
  defp within?({:OTPCertificate, tbs, _, _}, time) do
    {:Validity, not_before, not_after} = elem(tbs, 5)

    with {:ok, from} <- otp_time(not_before),
         {:ok, to} <- otp_time(not_after) do
      t = DateTime.truncate(time, :second)
      DateTime.compare(t, from) != :lt and DateTime.compare(t, to) != :gt
    else
      _ -> false
    end
  end

  defp within?(_cert, _time), do: false

  defp otp_time({:utcTime, chars}) do
    case to_string(chars) do
      <<yy::binary-size(2), rest::binary-size(11)>> ->
        year = String.to_integer(yy)
        datetime(if(year >= 50, do: 1900 + year, else: 2000 + year), rest)

      _ ->
        :error
    end
  end

  defp otp_time({:generalTime, chars}) do
    case to_string(chars) do
      <<year::binary-size(4), rest::binary-size(11)>> -> datetime(String.to_integer(year), rest)
      _ -> :error
    end
  end

  defp datetime(
         year,
         <<mo::binary-size(2), d::binary-size(2), h::binary-size(2), mi::binary-size(2),
           s::binary-size(2), "Z">>
       ) do
    with {:ok, date} <- Date.new(year, String.to_integer(mo), String.to_integer(d)),
         {:ok, time} <-
           Time.new(String.to_integer(h), String.to_integer(mi), String.to_integer(s)),
         do: DateTime.new(date, time, "Etc/UTC")
  end

  defp datetime(_year, _rest), do: :error
end
