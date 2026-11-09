# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `Tspex.TimeStampedData` (RFC 5544, experimental): `imprint/2`, `new/3`,
  `extension_imprint/2`, `extend/3`, `encode/1`, `decode/2`, `time_stamps/2` and
  `verify/2`. A document with a chain of time-stamps, each covering the element
  before it, with the `MetaData` under the first token when it is hash
  protected. The `dataUri` is never fetched; `ersEvidence` and other evidence
  are read and written, not verified.
- The error reasons `:content_missing` and `:unexpected_content`.

### Fixed

- A token signed with SHA-1 (as the TSA of Apple and the LibreSSL of macOS do)
  is `:weak_algorithm` with `detail: :sha1` and the CMS error as `cause`, not
  `:token_invalid`; `allow_sha1: true` accepts it.

## [0.1.0] - not yet published

The first release.

### Added

- `Tspex.request/2`: builds a `TimeStampReq` (RFC 3161, 2.4.1) for a binary, a
  stream or a ready digest, with SHA-224 to SHA-512 (SHA-1 only with
  `allow_sha1: true`), a policy, a random nonce, `certReq` and extensions.
  `Tspex.decode_request/2` reads one back.
- `Tspex.decode_response/2` and `Tspex.decode_token/2`: read a `TimeStampResp`
  and a token (`TSTInfo`, with `accuracy`, `ordering`, `tsa` and extensions)
  without judging them.
- `Tspex.verify/3`: verifies a response or a token against the request that
  asked for it, or against stored data, and returns what it proves in a
  `Tspex.Verified`. The certificate of the TSA is checked (signing
  certificate attribute, critical `extKeyUsage` with timeStamping, key usage),
  and its chain to the `:trust` roots is validated at the `genTime`, so a token
  outlives the certificate that signed it. Nonce, policy, `tsa` name, critical
  extensions, clock skew and a `:revocation` function are checked. Status and
  `failInfo` of a refusal are reported as errors.
- `Tspex.stamp/2`: request, transport, response and verification in one call,
  with `Tspex.HTTP`, an HTTP/1.1 client with limits on the head, the body and
  the time, and a verified TLS connection; or your own `:transport`.
- Time-stamps in CMS messages made with cmsex: `Tspex.signature_imprint/3`,
  `Tspex.add_signature_time_stamp/4`, `Tspex.signature_time_stamps/3` and
  `Tspex.verify_signature_time_stamps/3` (signature time-stamps, CAdES-T);
  `Tspex.content_time_stamp_attribute/1` and
  `Tspex.verify_content_time_stamp/3` (content time-stamps);
  `Tspex.verify_at_stamp/2`, which verifies a signature and its certificate
  path as of the time of its stamp.
- `Tspex.path_validation_at/2`, for validating a certificate path at a date.
- Tested against `openssl ts` (OpenSSL 1.1.1 and 3.x, LibreSSL) and the Java
  `jarsigner`, both ways, with a negative corpus and fuzzing of every reader.
