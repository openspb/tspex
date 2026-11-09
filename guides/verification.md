# What a verified time-stamp means

`Tspex.verify/3` answers one question: *did a TSA that you trust sign a
statement that this data existed at this time?* This guide says what is
checked to answer it, what is left to you, and what to do with each error.

## Two ways to ask

**Fresh.** You just asked a TSA, and you hold the `Tspex.Request`:

    Tspex.verify(response_der, request, trust: roots)

The nonce and the policy of the request are compared with the token, and the
imprint with the hash in the request. This is the only mode where a stale or
replayed answer is caught: the nonce is what ties the answer to this
request.

**Stored.** You kept a token and the data, and you check them later:

    Tspex.verify(token_der, {:data, data}, trust: roots)

The data is hashed with the algorithm the token declares (if you allow it).
There is no nonce to compare; a nonce in the token is only information.

## The chain is judged at the `genTime`

A TSA certificate lives a few years and a time-stamp has to outlast it, so
the chain is validated **as of the time in the token**, not today. A token
made in 2024 by a certificate that expired in 2026 is still good, if the
certificate was valid in 2024 and the chain (the root included) was too.

This is also what makes the date a claim: the TSA can sign any `genTime`, and
nothing in the token proves it was made then. What stops a TSA from lying
about the past is its reputation, its audits, its key being kept in a
module, and the revocation of the key if it is ever compromised. Which is
why two things below are yours.

## What you decide

1. **The roots.** `:trust` is required. It is your list of TSAs you accept.
   `trust: :none` is allowed and explicit: the result then says `trust: :none`
   and proves only that some key signed this imprint.
2. **Revocation.** The library does not fetch a CRL or an OCSP answer.
   Without `:revocation`, `stamp.revocation` is `:not_checked`. If the key of
   the TSA was revoked for `keyCompromise` (or with no reason), every token
   of that key is void; for another reason, only those made after the
   revocation (RFC 3161, section 4). Give a function that gets the validated
   path and the `genTime`, and returns `:ok` or `{:error, reason}`; it is
   called after everything else passed.
3. **The policy.** `:policies` lists the TSA policies you accept. Without it
   any policy passes, and the policy of a request, if it had one, must still
   be the one of the token.
4. **The clock.** `:max_skew` compares the `genTime` with the local clock,
   allowing for the accuracy the TSA states. It is off by default because the
   time of a stored token is old. Use it for a fresh answer.
5. **How long it lasts.** A token is evidence while its hash and signature
   algorithms hold. For decades, stamp again (an archive time-stamp, outside
   this library) before they weaken.

## A revocation check from CRLs you hold

The library does not go to the network, but `:revocation` is where you plug
what you have. This module turns CRLs you already fetched (DER, the CRL of
each issuer in the path) into that function. It follows RFC 3161, section 4:
a certificate revoked for `keyCompromise` or without a reason voids every
token of its key, and one revoked for another reason voids only the tokens
made at or after the revocation date.

```elixir
defmodule MyApp.TsaRevocation do
  @crl_reason {2, 5, 29, 21}
  @voids_every_token [:unspecified, :keyCompromise, :cACompromise]

  @doc "The `:revocation` function of `Tspex.verify/3`, from CRLs in DER."
  def check(crls, now \\ DateTime.utc_now()) do
    fn path, gen_time -> path_ok(path, gen_time, crls, now) end
  end

  # The path is root first. The root is a trust anchor and has no CRL here.
  defp path_ok(path, gen_time, crls, now) do
    path
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.find_value(:ok, fn [issuer, certificate] ->
      case certificate_ok(issuer, certificate, gen_time, crls, now) do
        :ok -> nil
        {:error, _} = error -> error
      end
    end)
  end

  defp certificate_ok(issuer, certificate, gen_time, crls, now) do
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(certificate, :otp)
    serial = elem(tbs, 2)

    # a CRL counts only if the issuer signed it
    case Enum.find(crls, &:public_key.pkix_crl_verify(&1, issuer)) do
      nil -> {:error, :no_crl}
      crl -> in_crl(:public_key.der_decode(:CertificateList, crl), serial, gen_time, now)
    end
  end

  defp in_crl({:CertificateList, tbs, _, _}, serial, gen_time, now) do
    {:TBSCertList, _, _, _, this_update, next_update, revoked, _} = tbs

    cond do
      DateTime.compare(to_datetime(this_update), now) == :gt ->
        {:error, :crl_not_yet_valid}

      next_update != :asn1_NOVALUE and DateTime.compare(to_datetime(next_update), now) != :gt ->
        {:error, :crl_expired}

      true ->
        revoked_at(revoked, serial, gen_time)
    end
  end

  defp revoked_at(:asn1_NOVALUE, _serial, _gen_time), do: :ok

  defp revoked_at(revoked, serial, gen_time) do
    case List.keyfind(revoked, serial, 1) do
      nil ->
        :ok

      {_, _, date, extensions} ->
        if reason(extensions) in @voids_every_token or
             DateTime.compare(to_datetime(date), gen_time) != :gt,
           do: {:error, :revoked},
           else: :ok
    end
  end

  defp reason(:asn1_NOVALUE), do: :unspecified

  defp reason(extensions) do
    case List.keyfind(extensions, @crl_reason, 1) do
      {:Extension, _, _, value} -> :public_key.der_decode(:CRLReason, value)
      nil -> :unspecified
    end
  end

  defp to_datetime({:utcTime, [y1, y2 | rest]}) do
    year = List.to_integer([y1, y2])

    to_datetime(
      {:generalTime, Integer.to_charlist(if(year >= 50, do: 1900, else: 2000) + year) ++ rest}
    )
  end

  defp to_datetime({:generalTime, chars}) do
    <<y::binary-4, mo::binary-2, d::binary-2, h::binary-2, mi::binary-2, s::binary-2, "Z">> =
      List.to_string(chars)

    DateTime.new!(
      Date.new!(String.to_integer(y), String.to_integer(mo), String.to_integer(d)),
      Time.new!(String.to_integer(h), String.to_integer(mi), String.to_integer(s)),
      "Etc/UTC"
    )
  end
end
```

Use it with the CRLs you hold:

```elixir
Tspex.verify(token, {:data, document},
  trust: roots,
  revocation: MyApp.TsaRevocation.check([intermediate_crl, root_crl])
)
```

What it does not do: it does not fetch anything, it reads no delta CRL, no
indirect CRL and no CRL split by distribution point, and it asks for a CRL
that is current **now** (`now`), not at the `genTime`, because what you want to
know is whether the key has been revoked since. A path with no CRL for one of
its issuers is `{:error, :no_crl}` and the token is refused, so give a CRL for
every issuer in the path. For OCSP, or for CRLs by distribution point, the
OTP has `:public_key.pkix_crls_validate/3` and `:public_key.pkix_ocsp_validate/5`,
and the function you give can call them.

## Checks, in order

Size and form; status and `failInfo`; the token; the `SignedData` and the
type of its content; one signer; the version of the `TSTInfo`; the signature;
the signing-certificate attribute; the rules for the certificate of a TSA; the
chain at the `genTime`; the imprint; the nonce; the policy; the `tsa` name;
critical extensions; the clock; `:revocation`. The error you get is the first
one that fails.

The certificate rules come before the chain so that a certificate that is not
for time-stamping is reported as that, and not as an obscure error of the
OTP's path validation.

## Errors

| `reason` | What happened | What to do |
| --- | --- | --- |
| `:malformed`, `:limit_exceeded` | Not a response or token, or beyond a limit | Do not retry the same bytes |
| `:rejection` | The TSA refused; `detail.fail_info` says why (`:bad_alg`, `:bad_request`, ...) | Fix the request, or the TSA you ask |
| `:waiting`, `:revocation_warning`, `:revocation_notification` | A status that is not a time-stamp | Treat as a failure |
| `:token_invalid` | The signature or the algorithm of the token is refused | Not a valid token |
| `:bad_tsa_certificate` | The certificate is not one a TSA may use (`detail` says which rule) | The TSA or its certificate is wrong |
| `:untrusted` | The chain does not lead to your roots at the `genTime` | Wrong root, or an expired chain at that time |
| `:imprint_mismatch` | The data is not what was stamped | The data was changed, or it is another file |
| `:nonce_mismatch`, `:nonce_missing` | The answer is not for this request | Do not use it |
| `:policy_mismatch`, `:tsa_name_mismatch` | Not the policy you want, or the `tsa` name is not the certificate's | |
| `:weak_algorithm` | MD5, or SHA-1 without `allow_sha1: true` | Some TSAs still sign with SHA-1; opt in knowingly |
| `:gen_time_skew` | The time differs from your clock by more than `:max_skew` | |
| `:transport` | The network failed (`stamp/2`); `detail` says how | Retry is up to you; nothing is retried here |

The full list is in `Tspex.Error`.

## Where the time-stamp goes

For a signature in a CMS message, see `Tspex.add_signature_time_stamp/4` (the
stamp over the signature value, an unsigned attribute) and
`Tspex.verify_at_stamp/2` (the signature and its certificate, judged as of the
stamp). For the content, see `Tspex.content_time_stamp_attribute/1`.
For a document kept with a chain of time-stamps in one file, see
`Tspex.TimeStampedData`: `verify/2` verifies every token as `Tspex.verify/3`
does, each against the certificate of its own TSA at its own `genTime`, and the
first against the document, the others against the element before them. The
time it returns is that of the first token, and a chain says that each token
existed when the next was issued. It is experimental: RFC 5544 leaves open what
the later tokens cover.
`verify_at_stamp/2` does not check a signature policy; whether this signer was
allowed to sign this is for the application.
