# Security

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" tab, "Report a vulnerability"). You should get
an answer within a week. Fixes are released for the latest minor version.

## Threat model

The library reads what a TSA sends, which crosses a network, and tokens that
come with documents from anyone. An attacker controls every byte of a
response or a token, and may sit between you and the TSA. The attacker wants:

* a forged, changed or replayed time-stamp accepted;
* a time-stamp of other data, or for another request, accepted;
* a certificate that is not a TSA's, or a chain that does not lead to your
  roots, accepted;
* a weaker algorithm than the TSA used;
* to stop or slow down the process: CPU, memory, atoms, sockets.

Out of the model: an attacker who holds the private key of a TSA you trust,
or who chooses the roots you give to `:trust`; a TSA whose clock is wrong or
that lies; and flaws of the OpenSSL that `:crypto` uses for the hash and
signature operations.

### Malformed input

* Every reader returns `{:error, %Tspex.Error{}}` for input it cannot read and
  does not raise on it. The fuzz tests feed changed and random bytes to the
  readers (`decode_request/2`, `decode_response/2`, `decode_token/2`,
  `verify/3`), to the functions that read time-stamps from a CMS message and
  to `Tspex.TimeStampedData.decode/2` and `verify/2`.
* Parsing is bounded: `:max_size` (1 MiB), `:max_depth` (32) and `:max_nodes`
  (100,000), and the limits of cmsex for the message that carries a token.
  Every length is checked against the input before it is read, and nothing
  is allocated from a declared length. A `TimeStampedData` has one more
  limit, `:max_stamps` (64), for the length of its chain; each token in it is
  read under the same limits.
* Nothing from the input becomes an atom. Unknown algorithms, policies and
  extensions are reported by their OID, as a tuple.
* The result keeps the input binary alive: copy with `:binary.copy/1` what
  you keep from a large message.
* Errors and `inspect/1` show sizes and reasons, never the data that was
  time-stamped. A `Tspex.Verified` is inspected as its fields and the size of
  the token.

### What `verify/3` establishes

* The token is a `SignedData` with exactly one signer, and its signature is
  valid for the `TSTInfo`.
* The signer's certificate is the one the signing-certificate attribute names
  (ESSCertID or ESSCertIDv2, hash included), and it is a certificate for
  time-stamping: `extKeyUsage` critical, once, and with `id-kp-timeStamping`
  alone (`tsa_eku: :strict`, the default), and a key usage, if any, that
  allows signing.
* The chain leads to one of the `:trust` roots, and is validated **at the
  `genTime`** and not today, so that a token outlives the certificate that
  signed it. A trust anchor that has expired, or is not valid at the `genTime`,
  is refused. `:trust` is required; `trust: :none` is explicit, and the result
  says so.
* The imprint is that of the data, with the
  algorithm the token declares when the token is checked later, and with the
  request's when the answer is fresh. In fresh mode the nonce of the request
  is the nonce of the token, and the policy is the one that was asked for.
* The `tsa` name of the token is one of the names of the certificate
  (`tsa_name: :strict`).
* SHA-1 is refused (for the imprint and for the signature) unless
  `allow_sha1: true`. MD5 is never accepted. RSA keys under `:min_rsa_bits`
  (2048) are refused.
* A critical extension of the `TSTInfo` that the library does not know is
  refused, unless `critical_extensions: :ignore`.

### What `verify/3` does not establish

* That the TSA is honest or its clock right. `genTime` is the word of the TSA;
  `:max_skew` compares it with the local clock, plus the accuracy the TSA
  states, and is off by default because a stored token is old. Use more than
  one TSA, with `verify_signature_time_stamps/3` and `stamps: :all`, when one
  clock is not enough for you.
* That the certificate of the TSA was **not revoked**. The result says
  `revocation: :not_checked` unless you give `:revocation`, which receives
  the validated path and the `genTime`. RFC 3161, section 4: a revocation for
  `keyCompromise`, or without a reason, invalidates every token of that key;
  any other reason only the tokens made after the revocation. A path valid at
  a date is not a certificate that was good at that date. The guide
  "What a verified time-stamp means" has a tested recipe that builds this
  function from CRLs you hold.
* That the stamp keeps proving anything for ever. Keys and hash algorithms
  age; a time-stamp is evidence for as long as its algorithms hold. Archive
  time-stamps (a stamp over a stamp) are outside this library.
* That the stamped document or signature is valid, or that the signer was
  authorized to sign. `verify_at_stamp/2` checks a signature and its
  certificate path at the time of the stamp, not a signature policy.
* For a `TimeStampedData` (experimental): that the choice of what the second
  and later tokens cover is the one other implementations make. RFC 5544 does
  not say, and this library reads it as the whole previous element. It does not
  check the `crl` of an element (`verify/2` returns it, and the guide shows how
  to check it), and it refuses a chain whose time goes back only if you give
  `:max_time_back` (`ordered` in the result says it either way). The evidence
  of an archive time-stamp (`ersEvidence`) and other evidence are read and
  written but not verified.
* Unsigned attributes are not protected by the signature. A time-stamp in
  one is verified against the signature value it claims to cover, and a
  stamp that is not about that signature is `:imprint_mismatch`; anyone can
  still remove a stamp from a message.

### The network

* The built-in client, `Tspex.HTTP`, is HTTP/1.1 over `:gen_tcp` or `:ssl`.
  It limits the head, the number of headers, the size of the body (also a
  chunked one, or one that ends when the connection closes) and the time of
  the whole exchange, and reads no body at all from an answer that is not a
  200. A `Content-Length` above the limit is refused before any of the body
  is read.
* It follows no redirect unless `:max_redirects` is raised, and then only
  307 and 308, never from `https` to `http`, and without the headers you gave
  when the new host is another one.
* `https` verifies the peer with the system certificates
  (`:public_key.cacerts_get/0`) and the host name of the URL, also when it is
  an IP address, where the OTP alone would skip the check. The `:ssl` option
  replaces the store (a private CA) or adds a client certificate; turning
  verification off is yours to choose, and the token is still verified.
* `http` works, since many TSAs are served that way, and the hash of your
  data goes in the clear. The answer is verified just the same, but anyone
  on the path learns that you stamp that hash.
* A `TimeStampedData` can carry a `dataUri`. It is never fetched, by this
  library or on any path: the document is given as `:content`, so a
  structure cannot make the verifier open a connection.
* Nothing is retried and nothing is cached. Header names and values given in
  `:headers` are checked, so that a value cannot write another header.
* Request nonces are 63 bits from `:crypto.strong_rand_bytes/1`. An answer
  to another request, or an old one, has another nonce and is refused.
  The imprint and the digests are compared with `:crypto.hash_equals/2`.

### Secrets

The library holds no secret: a time-stamp request carries a hash. Do not
send the data itself, or the hash of something whose hash is itself secret,
to a TSA you do not trust with it.

### Writing

* Hash algorithms for imprints: SHA-224, SHA-256, SHA-384 and SHA-512;
  SHA-1 only with `allow_sha1: true`, and only in a request.
* `add_signature_time_stamp/4` adds a token only if its imprint is the hash
  of the signature value of that signer, so that a stamp of another signature
  is not attached to this one. A token in DER is verified first, with your
  roots.
