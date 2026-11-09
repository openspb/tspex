defmodule Tspex.TSA do
  @moduledoc false
  # The rules for the certificate of a TSA (RFC 3161, 2.3; RFC 5280,
  # 4.2.1.3 and 4.2.1.12), applied to the certificate that signed the token
  # and always, even when the certificate is itself a trust anchor (which
  # `Cmsex.verify/2` accepts without validating).

  alias Tspex.{Certificate, Error}

  @time_stamping {1, 3, 6, 1, 5, 5, 7, 3, 8}
  @eku {2, 5, 29, 37}

  @doc """
  Checks the certificate `der` for a token generated at `gen_time`.
  `eku` is `:strict` (the extKeyUsage holds only timeStamping) or
  `:extra_purposes` (timeStamping among others).
  """
  @spec check(binary(), DateTime.t(), :strict | :extra_purposes) :: :ok | {:error, Error.t()}
  def check(der, gen_time, eku) do
    case Certificate.parse(der) do
      {:ok, cert} ->
        with :ok <- extended_key_usage(cert, eku),
             :ok <- key_usage(cert),
             do: validity(cert, gen_time)

      :error ->
        {:error, Error.new(:bad_tsa_certificate, :unreadable)}
    end
  end

  defp extended_key_usage(cert, eku) do
    case Certificate.extensions(cert, @eku) do
      [] -> bad(:eku_missing)
      [_, _ | _] -> bad(:eku_repeated)
      [%{critical: false}] -> bad(:eku_not_critical)
      [extension] -> purposes(Certificate.eku_list(extension), eku)
    end
  end

  defp purposes(:error, _eku), do: bad(:unreadable)

  defp purposes({:ok, oids}, eku) do
    cond do
      @time_stamping not in oids -> bad(:eku_missing)
      eku == :strict and oids != [@time_stamping] -> bad(:eku_extra_purposes)
      true -> :ok
    end
  end

  # A key that signs: digitalSignature (0) or nonRepudiation (1).
  defp key_usage(cert) do
    case Certificate.key_usage(cert) do
      nil -> :ok
      :error -> bad(:unreadable)
      positions -> if 0 in positions or 1 in positions, do: :ok, else: bad(:key_usage)
    end
  end

  # The validity has the resolution of a second and its ends are included.
  defp validity(cert, gen_time) do
    time = DateTime.truncate(gen_time, :second)

    if DateTime.compare(time, cert.not_before) != :lt and
         DateTime.compare(time, cert.not_after) != :gt,
       do: :ok,
       else: bad(:not_valid_at_time)
  end

  defp bad(detail), do: {:error, Error.new(:bad_tsa_certificate, detail)}
end
