defmodule Tspex.Name do
  @moduledoc false
  # The match of the `tsa` field of a TSTInfo with the names of the
  # certificate of the TSA (RFC 3161, 2.4.2; the rules are in the design
  # notes, 6.8). Names are compared only with a name of the same type.

  alias Tspex.{Certificate, DER}

  @doc "Whether `tsa` corresponds to one of the names of `certificate`."
  @spec matches?(Tspex.Codec.name(), Certificate.t()) :: boolean()
  def matches?(tsa, certificate), do: Enum.any?(Certificate.names(certificate), &same?(tsa, &1))

  @doc false
  @spec same?(Tspex.Codec.name(), Tspex.Codec.name()) :: boolean()
  def same?({:directory_name, a}, {:directory_name, b}), do: same_directory?(a, b)
  def same?({:dns_name, a}, {:dns_name, b}), do: ascii_downcase(a) == ascii_downcase(b)
  def same?({:rfc822_name, a}, {:rfc822_name, b}), do: same_mailbox?(a, b)
  def same?({:uri, a}, {:uri, b}), do: same_uri?(a, b)
  def same?({:ip_address, a}, {:ip_address, b}), do: a == b
  def same?({:other, a}, {:other, b}), do: a == b
  def same?(_, _), do: false

  ## directoryName

  defp same_directory?(a, b) do
    with {:ok, a} <- rdns(a), {:ok, b} <- rdns(b) do
      a == b
    else
      _ -> a == b
    end
  end

  # A Name is a sequence of RDNs; an RDN is a set of attribute type and
  # value pairs, so it is compared as a set.
  defp rdns(der) do
    case DER.decode(der) do
      {:ok, {0x30, _, _} = name} ->
        name |> DER.children() |> Enum.reduce_while({:ok, []}, &add_rdn/2) |> reverse()

      _ ->
        :error
    end
  end

  defp add_rdn({0x31, _, _} = rdn, {:ok, acc}) do
    case rdn |> DER.children() |> Enum.reduce_while({:ok, []}, &add_attribute/2) do
      {:ok, pairs} -> {:cont, {:ok, [Enum.sort(pairs) | acc]}}
      :error -> {:halt, :error}
    end
  end

  defp add_rdn(_other, _acc), do: {:halt, :error}

  defp add_attribute({0x30, _, _} = attribute, {:ok, acc}) do
    with [oid_element, value] <- DER.children(attribute),
         {:ok, oid} <- DER.oid(oid_element) do
      {:cont, {:ok, [{oid, normalize(value)} | acc]}}
    else
      _ -> {:halt, :error}
    end
  end

  defp add_attribute(_other, _acc), do: {:halt, :error}

  defp reverse({:ok, list}), do: {:ok, Enum.reverse(list)}
  defp reverse(:error), do: :error

  # Text values (UTF8String, PrintableString, IA5String) are compared as text:
  # NFKC, case folded, internal runs of spaces collapsed, the ends cut. This
  # is the part of the LDAP StringPrep profile (RFC 4518) that decides the
  # equality of names (RFC 5280, 7.1); the checks for prohibited and
  # bidirectional characters are left out. Other values, byte by byte.
  defp normalize({id, content, _raw}) when id in [0x0C, 0x13, 0x16] do
    if String.valid?(content), do: {:text, fold(content)}, else: {:bytes, content}
  end

  defp normalize({_id, _content, raw}), do: {:bytes, raw}

  defp fold(text) do
    text
    |> :unicode.characters_to_nfkc_binary()
    |> String.downcase()
    |> String.split()
    |> Enum.join(" ")
  end

  ## The other kinds

  defp ascii_downcase(text), do: String.downcase(text, :ascii)

  # RFC 5280, 7.5: the domain is case-insensitive, the local part is exact.
  defp same_mailbox?(a, b) do
    case {split_mailbox(a), split_mailbox(b)} do
      {{local, domain_a}, {local, domain_b}} ->
        ascii_downcase(domain_a) == ascii_downcase(domain_b)

      {nil, nil} ->
        a == b

      _ ->
        false
    end
  end

  defp split_mailbox(text) do
    case String.split(text, "@") do
      [_one] -> nil
      parts -> {parts |> Enum.drop(-1) |> Enum.join("@"), List.last(parts)}
    end
  end

  # Scheme and host without regard to case, the rest exact.
  defp same_uri?(a, b) do
    case {URI.parse(a), URI.parse(b)} do
      {%URI{scheme: sa, host: ha} = ua, %URI{scheme: sb, host: hb} = ub}
      when is_binary(sa) and is_binary(sb) and is_binary(ha) and is_binary(hb) ->
        ascii_downcase(sa) == ascii_downcase(sb) and ascii_downcase(ha) == ascii_downcase(hb) and
          %{ua | scheme: nil, host: nil, authority: nil} == %{
            ub
            | scheme: nil,
              host: nil,
              authority: nil
          }

      _ ->
        a == b
    end
  end
end
