defmodule Tspex.Error do
  @moduledoc """
  Why a time-stamp request, response or token could not be built, read or
  verified.

  The functions of `Tspex` return it as `{:error, %Tspex.Error{}}`, and their
  bang variants raise it. Match on `:reason`, a stable atom; `:detail` adds
  what went wrong where that helps, and never holds the bytes of the data
  that was time-stamped; `:cause` is the `Cmsex.Error` when the error came
  from the CMS layer.

  The message says what happened without showing the data:

      iex> error = %Tspex.Error{reason: :imprint_mismatch, detail: :digest}
      iex> Exception.message(error)
      "the message imprint does not match (:digest)"

  Reading:

    * `:malformed` - not valid BER or DER, or not the structure that was
      expected, or a field out of range (an integer that is too large, an
      invalid `genTime` or `accuracy`).
    * `:limit_exceeded` - the input goes beyond a limit; `detail` is the
      option (`:max_size`, `:max_depth` or `:max_nodes`).
    * `:unsupported_version` - a version other than 1.
    * `:unknown_status` - a `PKIStatus` outside 0 to 5.
    * `:unknown_fail_info` - a granted response with a bit of `failInfo`
      that RFC 3161 does not define.

  Responses:

    * `:rejection` - status 2; `detail` is `%{fail_info: [...], text: [...]}`.
    * `:waiting`, `:revocation_warning`, `:revocation_notification` - status
      3, 4 and 5.
    * `:granted_with_mods` - status 1 with `granted_with_mods: :reject`.
    * `:token_missing` - status 0 or 1 without a token.
    * `:unexpected_token` - a token with a status greater than 1.

  Tokens:

    * `:not_a_time_stamp_token` - not a SignedData, or the content type is
      not `id-ct-TSTInfo`.
    * `:signer_count` - no signer, or more than one.
    * `:token_invalid` - the CMS layer refused the token; `detail` and
      `cause` say why (signature, attributes, certificate). A signature made
      with SHA-1 or MD5 is `:weak_algorithm`, not this.
    * `:signing_certificate_missing` - neither ESSCertID nor ESSCertIDv2.
    * `:bad_tsa_certificate` - the certificate is not one a TSA may use;
      `detail` is `:eku_missing`, `:eku_not_critical`, `:eku_extra_purposes`,
      `:eku_repeated`, `:key_usage` or `:not_valid_at_time`.
    * `:untrusted` - the certificate path did not validate; `detail` is the
      reason, such as `:not_valid_at_time`, `:eku_excludes_time_stamping`,
      `:key_usage_mismatch` or `{:revocation, reason}`.
    * `:imprint_mismatch` - `detail` is `:hash_algorithm`, `:digest` or
      `:length`.
    * `:nonce_missing`, `:nonce_mismatch` - the request had a nonce and the
      token has none, or another one.
    * `:policy_mismatch` - the policy is not the one requested, or is not in
      `:policies`.
    * `:tsa_name_mismatch` - the `tsa` field names none of the names of the
      certificate.
    * `:critical_extension` - an extension of the `TSTInfo` that is critical
      and unknown.
    * `:gen_time_skew` - `:max_skew` exceeded.
    * `:weak_algorithm` - MD5, or SHA-1 without `allow_sha1: true`, in the
      imprint or in the signature of the token (some TSAs sign with SHA-1:
      `detail` is `:sha1`, and `cause` is the error of the CMS layer).

  Signature and content time-stamps:

    * `:cms_invalid` - the CMS message that carries the signature could not
      be read, or its signature did not verify; `detail` and `cause` (a
      `Cmsex.Error`) say why.
    * `:signer_not_found` - no signer, or no countersignature, at the
      position; `detail` is the position.
    * `:no_time_stamp` - the signer has no time-stamp.
    * `:unsupported_evidence` - a `TimeStampedData` with `ersEvidence` or
      `otherEvidence`.
    * `:content_missing`, `:unexpected_content` - a `TimeStampedData` that
      does not carry its content and none was given, or that carries it and
      one was given.
    * `:time_order` - a `TimeStampedData` with a token whose `genTime` is
      earlier than the one before it by more than `:max_time_back`; `detail`
      is the position of that token in the chain (the first is 0).

  Transport:

    * `:transport` - `detail` is `{:http_status, n}`, `:timeout`,
      `:too_large`, `{:connect, reason}`, `{:tls, reason}` or `{:other,
      reason}`.
  """

  @typedoc "Why an operation failed; each reason is described above."
  @type reason ::
          :malformed
          | :limit_exceeded
          | :unsupported_version
          | :unknown_status
          | :unknown_fail_info
          | :rejection
          | :waiting
          | :revocation_warning
          | :revocation_notification
          | :granted_with_mods
          | :token_missing
          | :unexpected_token
          | :not_a_time_stamp_token
          | :signer_count
          | :token_invalid
          | :signing_certificate_missing
          | :bad_tsa_certificate
          | :untrusted
          | :imprint_mismatch
          | :nonce_missing
          | :nonce_mismatch
          | :policy_mismatch
          | :tsa_name_mismatch
          | :critical_extension
          | :gen_time_skew
          | :weak_algorithm
          | :cms_invalid
          | :signer_not_found
          | :no_time_stamp
          | :unsupported_evidence
          | :content_missing
          | :unexpected_content
          | :time_order
          | :transport

  @typedoc """
  The error: the `reason`, a `detail` that depends on it (or `nil`) and the
  `cause`, the error of the layer below when there is one.
  """
  @type t :: %__MODULE__{reason: reason(), detail: term(), cause: Exception.t() | nil}

  defexception [:reason, :detail, :cause]

  @doc false
  @spec new(reason(), term(), Exception.t() | nil) :: t()
  def new(reason, detail \\ nil, cause \\ nil),
    do: %__MODULE__{reason: reason, detail: detail, cause: cause}

  @doc false
  # An error of the CMS layer, as the error of this library: the reason is
  # `reason`, and the original is kept as the cause.
  @spec from_cms(reason(), Cmsex.Error.t()) :: t()
  def from_cms(reason, %Cmsex.Error{} = cause), do: new(reason, cause.detail, cause)

  @impl true
  def message(%__MODULE__{reason: reason, detail: detail}), do: describe(reason, detail)

  defp describe(:malformed, nil), do: "malformed input"
  defp describe(:malformed, detail), do: "malformed input (#{show(detail)})"
  defp describe(:limit_exceeded, option), do: "the input goes beyond the #{show(option)} limit"
  defp describe(:unsupported_version, v), do: "unsupported version #{show(v)}"
  defp describe(:unknown_status, s), do: "unknown PKIStatus #{show(s)}"
  defp describe(:unknown_fail_info, bits), do: "unknown bits in failInfo (#{show(bits)})"

  defp describe(:rejection, %{fail_info: info}),
    do: "the request was rejected (#{show(info)})"

  defp describe(:rejection, _), do: "the request was rejected"
  defp describe(:waiting, _), do: "the request is still being processed (status waiting)"
  defp describe(:revocation_warning, _), do: "status revocationWarning"
  defp describe(:revocation_notification, _), do: "status revocationNotification"
  defp describe(:granted_with_mods, _), do: "granted with modifications, which was refused"
  defp describe(:token_missing, _), do: "the response is granted but has no token"
  defp describe(:unexpected_token, _), do: "the response is not granted but has a token"
  defp describe(:not_a_time_stamp_token, d), do: "not a time-stamp token (#{show(d)})"
  defp describe(:signer_count, n), do: "a token has one signer, this one has #{show(n)}"
  defp describe(:token_invalid, d), do: "the token does not verify (#{show(d)})"
  defp describe(:signing_certificate_missing, _), do: "no signing-certificate attribute"
  defp describe(:bad_tsa_certificate, d), do: "not a time-stamping certificate (#{show(d)})"
  defp describe(:untrusted, d), do: "untrusted certificate (#{show(d)})"
  defp describe(:imprint_mismatch, d), do: "the message imprint does not match (#{show(d)})"
  defp describe(:nonce_missing, _), do: "the token has no nonce, the request had one"
  defp describe(:nonce_mismatch, _), do: "the nonce of the token is not the one requested"
  defp describe(:policy_mismatch, _), do: "the policy of the token is not acceptable"
  defp describe(:tsa_name_mismatch, _), do: "the tsa name matches no name of the certificate"
  defp describe(:critical_extension, oid), do: "unknown critical extension #{show(oid)}"
  defp describe(:gen_time_skew, _), do: "genTime is too far from the local clock"
  defp describe(:weak_algorithm, a), do: "weak algorithm #{show(a)}"
  defp describe(:cms_invalid, d), do: "the CMS message does not verify (#{show(d)})"
  defp describe(:signer_not_found, p), do: "no signer at the position #{show(p)}"
  defp describe(:no_time_stamp, _), do: "no time-stamp to verify"
  defp describe(:unsupported_evidence, _), do: "unsupported temporal evidence"
  defp describe(:content_missing, _), do: "the structure has no content and none was given"

  defp describe(:unexpected_content, _),
    do: "the structure has its own content, and one was given"

  defp describe(:time_order, position),
    do: "the time-stamp at position #{show(position)} is earlier than the one before it"

  defp describe(:transport, d), do: "transport error (#{show(d)})"

  defp show(nil), do: "unknown"

  defp show(value) when is_binary(value) do
    if byte_size(value) <= 64 and String.printable?(value),
      do: value,
      else: inspect(value, limit: 8, printable_limit: 16)
  end

  defp show(value) when is_atom(value), do: inspect(value)
  defp show(value) when is_integer(value), do: Integer.to_string(value)

  defp show(value) when is_tuple(value) do
    parts = Tuple.to_list(value)

    if Enum.all?(parts, &is_integer/1),
      do: Enum.join(parts, "."),
      else: inspect(value, limit: 8, printable_limit: 16)
  end

  defp show(value), do: inspect(value, limit: 8, printable_limit: 16)
end
