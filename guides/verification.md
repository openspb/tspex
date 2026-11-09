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
`verify_at_stamp/2` does not check a signature policy; whether this signer was
allowed to sign this is for the application.
