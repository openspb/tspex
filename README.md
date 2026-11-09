# tspex

Time-Stamp Protocol ([RFC 3161](https://www.rfc-editor.org/rfc/rfc3161),
[RFC 5816](https://www.rfc-editor.org/rfc/rfc5816)) in pure Elixir: build
requests, ask a time-stamping authority (TSA), read the answers, and verify a
time-stamp at the date it was issued, even after the certificate of the TSA
has expired. It also puts time-stamps in signatures made with
[cmsex](https://hex.pm/packages/cmsex).

Everything but the hash and signature operations is written in Elixir on top
of OTP's `:crypto`, `:public_key` and `:ssl`. There is no NIF and no other
dependency than cmsex.

## Installation

```elixir
def deps do
  [{:tspex, "~> 0.1"}]
end
```

Elixir 1.16 and OTP 26 or later.

## A time-stamp of a document

`Tspex.stamp/2` builds the request, sends it, reads the answer and verifies
it. `:trust` is required: it is the list of root certificates (in DER) you
accept for the TSA.

```elixir
tsa_root = File.read!("tsa-root.crt")
contract = File.read!("contract.pdf")

{:ok, stamp} =
  Tspex.stamp(contract, url: "https://tsa.example.com/tsp", trust: [tsa_root])

stamp.info.gen_time
File.write!("contract.pdf.tst", stamp.token)
```

The token is the time-stamp proper. Keep it with the document. Months or years
later, `Tspex.verify/3` checks the pair, judging the chain of the TSA at the
date in the token and not today:

```elixir
token = File.read!("contract.pdf.tst")

{:ok, stamp} = Tspex.verify(token, {:data, contract}, trust: [tsa_root])
stamp.info.gen_time
```

A document that was changed is `{:error, %Tspex.Error{reason: :imprint_mismatch}}`.

### What `{:ok, stamp}` promises

The token is a `SignedData` with one signer; the signer's certificate is the
one the token names, is meant for time-stamping (a critical `extKeyUsage` with
`id-kp-timeStamping`), and chains to one of your roots **as of the `genTime`**;
the signature is valid; the imprint is the hash of your data. It does not
promise that the TSA is honest or its clock right (the roots are your choice
and the time is its word), that the certificate of the TSA was not revoked
(`stamp.revocation` says `:not_checked` unless you give `:revocation`), or that
the stamp will prove anything for ever. The documentation of `Tspex.verify/3`
and `SECURITY.md` have the full list.

### Your own HTTP client

`Tspex.stamp/2` sends the request with `Tspex.HTTP`, a small HTTP/1.1 client
that limits the size of the answer. To use Req, Finch, a proxy or a mock,
give a `:transport`, or do the steps yourself:

```elixir
request = Tspex.request!(contract)
{:ok, answer} = Tspex.HTTP.post("https://tsa.example.com/tsp", request.der)

{:ok, stamp} = Tspex.verify(answer, request, trust: [tsa_root])
```

Keep the `Tspex.Request`: the nonce in it is what ties the answer to this
request.

### Looking at a token

`Tspex.decode_token/2` reads a token without judging it: what the TSA said,
not yet what it proves.

```elixir
{:ok, info} = Tspex.decode_token(token)
{info.gen_time, info.policy, info.serial, info.accuracy}
```

## Time-stamping a signature

A signature made with cmsex becomes a long-lived one by time-stamping its
signature value (RFC 3161, appendix A; the `id-aa-signatureTimeStampToken`
attribute of CAdES-T). The stamp goes in an unsigned attribute, so the
signature does not change.

```elixir
signer = %{certificate: File.read!("signer.crt"), key: File.read!("signer.key")}
{:ok, cms} = Cmsex.sign(contract, signer)

{:ok, imprint} = Tspex.signature_imprint(cms, 0)
{:ok, stamp} = Tspex.stamp(imprint, url: "https://tsa.example.com/tsp", trust: [tsa_root])
{:ok, cms} = Tspex.add_signature_time_stamp(cms, 0, stamp)
```

`Tspex.verify_at_stamp/2` then verifies the signature **as it was at the time
of the stamp**: the stamp is verified, and the signature and the certificate
path of the signer are checked at that time. The certificate of the signer
may have expired since, and the signature is still good.

```elixir
signer_root = File.read!("signer-root.crt")

{:ok, [result]} = Tspex.verify_at_stamp(cms, trust: [signer_root], tsa_trust: [tsa_root])
result.time
```

A signer with no verified stamp is `:no_time_stamp`; it never falls back to the
current date.

A *content* time-stamp (RFC 5126, 5.11.4) goes the other way: the content is
stamped first, and the token is a signed attribute.

```elixir
{:ok, stamp} = Tspex.stamp(contract, url: "https://tsa.example.com/tsp", trust: [tsa_root])
attribute = Tspex.content_time_stamp_attribute(stamp)

{:ok, cms} = Cmsex.sign(contract, Map.put(signer, :signed_attributes, [attribute]))
{:ok, verified} = Cmsex.verify(cms)
{:ok, [_stamp]} = Tspex.verify_content_time_stamp(verified, 0, trust: [tsa_root])
```

## A document with a chain of time-stamps

`Tspex.TimeStampedData` (RFC 5544) keeps a document and its time-stamps in
one file. Each time-stamp covers the one before it, so a new one, from the same
TSA or from another, can be added later, when an algorithm or a key is about to
age out. This part is **experimental**: RFC 5544 leaves open which octets the
later time-stamps cover, and the choice made here is in the module
documentation.

```elixir
alias Tspex.TimeStampedData

{:ok, imprint} = TimeStampedData.imprint(contract, file_name: "contract.pdf", hash_protected: true)
{:ok, first} = Tspex.stamp(imprint, url: "https://tsa.example.com/tsp", trust: [tsa_root])
{:ok, tsd} = TimeStampedData.new(contract, first, file_name: "contract.pdf", hash_protected: true)

# later: a second time-stamp, over the first element
{:ok, next} = TimeStampedData.extension_imprint(tsd)
{:ok, second} = Tspex.stamp(next, url: "https://tsa.example.com/tsp", trust: [tsa_root])
{:ok, tsd} = TimeStampedData.extend(tsd, second)
File.write!("contract.pdf.tsd", TimeStampedData.encode(tsd))

{:ok, result} = TimeStampedData.verify(File.read!("contract.pdf.tsd"), trust: [tsa_root])
result.time
```

`result.time` is the time of the first time-stamp. Every token is verified
like `Tspex.verify/3` does, each against the certificate of its own TSA as of
its own `genTime`. The `dataUri` of a structure that does not carry the
document is never fetched: give the document as `:content`.

## Options worth knowing

* `:policies` - the TSA policies you accept; `:policy` in the request asks for one.
* `:max_skew` - seconds the `genTime` may differ from the local clock.
* `:revocation` - `fun.(path, gen_time)`, called when everything else passed.
* `:allow_sha1` - SHA-1 imprints and signatures are refused by default; some
  TSAs still sign with SHA-1.
* `:tsa_name` and `:tsa_eku` - `:strict` by default; see `Tspex.verify/3`.
* `:max_size`, `:max_depth`, `:max_nodes` - limits for what is read.

Errors are `{:error, %Tspex.Error{}}` with a stable `:reason` atom. A bad
argument raises `ArgumentError`, without showing your data. Every function has
a `!` variant that raises `Tspex.Error`.

## What it checks against

The requests and answers are checked against `openssl ts` (OpenSSL 1.1.1 and
3.x, and LibreSSL) both ways: tokens issued by an OpenSSL TSA verify here, and
what this library writes is read by OpenSSL. The Java `jarsigner` asks a test
TSA for the time-stamp of its signature, and this library reads the request
and the stamp; `jarsigner -verify` accepts a jar whose signature this library
time-stamped. The negative cases (changed tokens, wrong imprints and nonces, certificates that
are not for time-stamping, chains that do not lead to a root) are in the tests,
along with fuzzing of every reader.

## Security

Read [SECURITY.md](SECURITY.md) for the threat model and for how to report a
vulnerability.

## License

Apache-2.0: see the `LICENSE` and `NOTICE` files.
