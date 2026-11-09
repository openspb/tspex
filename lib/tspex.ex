defmodule Tspex do
  @moduledoc """
  Time-Stamp Protocol (RFC 3161, RFC 5816) in pure Elixir.

  Work in progress.
  """

  alias Tspex.{Error, Request, Response, TSTInfo}

  @typedoc "A hash algorithm for a message imprint."
  @type hash :: :sha1 | :sha224 | :sha256 | :sha384 | :sha512

  @typedoc """
  What a time-stamp is about: the data as a binary, `{:stream, enumerable}`
  (read once) or `{:digest, hash, digest}` (already computed).
  """
  @type data :: binary() | {:stream, Enumerable.t()} | {:digest, hash(), binary()}

  @typedoc "An extension: the OID, whether it is critical and the DER of its value."
  @type extension :: %{oid: tuple(), critical: boolean(), value: binary()}

  @typedoc "The name of a TSA in the `tsa` field of a token, as a `GeneralName`."
  @type general_name ::
          {:directory_name, binary()}
          | {:dns_name, String.t()}
          | {:uri, String.t()}
          | {:rfc822_name, String.t()}
          | {:ip_address, binary()}
          | {:other, binary()}

  @doc """
  Builds a time-stamp request (`TimeStampReq`, RFC 3161, 2.4.1) for `data`.

  `data` is a binary, `{:stream, enumerable}` (read once) or
  `{:digest, hash, digest}` (already computed).

      {:ok, request} = Tspex.request(File.read!("contract.pdf"))
      request.der    # the body of the POST to the TSA
      request.nonce  # keep the struct: verify/3 needs it

  Options:

    * `:hash` - `:sha256` (the default), `:sha224`, `:sha384`, `:sha512`;
      `:sha1` only with `allow_sha1: true`. With `{:digest, hash, _}` the
      algorithm is given, and a different `:hash` raises `ArgumentError`.
    * `:policy` - the OID of the policy asked for, as a tuple or as text
      (`"1.2.3.4.5.6"`); none by default.
    * `:nonce` - `true` (the default) makes a random 63-bit nonce, `false`
      leaves it out, a positive integer uses that value.
    * `:cert_req` - ask for the certificate of the TSA in the token (`true`).
    * `:extensions` - `[%{oid: tuple, critical: boolean, value: der}]`.
    * `:allow_sha1` - `false`.

  The hash algorithm is written with NULL parameters, as the `openssl ts`
  tool and the Java `jarsigner` do. A bad argument raises `ArgumentError`
  without showing the data.
  """
  @spec request(data(), keyword()) :: {:ok, Request.t()}
  def request(data, opts \\ []), do: {:ok, Request.build(data, opts)}

  @doc "Like `request/2`, but returns the request itself."
  @spec request!(data(), keyword()) :: Request.t()
  def request!(data, opts \\ []), do: Request.build(data, opts)

  @doc """
  Reads a `TimeStampReq`, for a test server or for inspection. Takes the
  limits `:max_size`, `:max_depth` and `:max_nodes`.

  A request with a hash this library does not know is read, with the OID as
  the `:hash`.
  """
  @spec decode_request(binary(), keyword()) :: {:ok, Request.t()} | {:error, Error.t()}
  def decode_request(der, opts \\ []), do: Request.decode(der, opts)

  @doc "Like `decode_request/2`, but raises `Tspex.Error`."
  @spec decode_request!(binary(), keyword()) :: Request.t()
  def decode_request!(der, opts \\ []), do: bang(decode_request(der, opts))

  @doc """
  Reads a `TimeStampResp` (RFC 3161, 2.4.2) without judging it: a rejection
  is a valid response, with `status: :rejection`, the reasons in
  `fail_info` and no token. `verify/3` is what turns a response that is not
  granted into an error. Takes the limits `:max_size`, `:max_depth` and
  `:max_nodes`.

      {:ok, response} = Tspex.decode_response(body)
      response.status       #=> :rejection
      response.fail_info    #=> [:bad_alg]
      response.status_text  #=> ["Message digest algorithm is not supported."]

  A `PKIStatus` outside 0 to 5 is `:unknown_status`. A `failInfo` bit that
  RFC 3161 does not define is read as `{:unknown_bit, n}`.
  """
  @spec decode_response(binary(), keyword()) :: {:ok, Response.t()} | {:error, Error.t()}
  def decode_response(der, opts \\ []), do: Response.decode(der, opts)

  @doc "Like `decode_response/2`, but raises `Tspex.Error`."
  @spec decode_response!(binary(), keyword()) :: Response.t()
  def decode_response!(der, opts \\ []), do: bang(decode_response(der, opts))

  @doc """
  Reads a time-stamp token (the `ContentInfo` of RFC 3161, 2.4.2) down to
  its `TSTInfo`, **without verifying anything**: not the signature, not the
  certificate of the TSA, not the match with a request. Use it to look at a
  token; use `verify/3` before relying on what it says.

  Takes the limits `:max_size` (1 MiB), `:max_depth`, `:max_nodes`,
  `:max_signers`, `:max_certificates` and `:max_attributes`.

  `:not_a_time_stamp_token` when the `ContentInfo` is not a `SignedData` or
  the signed content is not a `TSTInfo`.
  """
  @spec decode_token(binary(), keyword()) :: {:ok, TSTInfo.t()} | {:error, Error.t()}
  def decode_token(token, opts \\ []) do
    with {:ok, _signed_data, info} <- TSTInfo.read_token(token, opts), do: {:ok, info}
  end

  @doc "Like `decode_token/2`, but raises `Tspex.Error`."
  @spec decode_token!(binary(), keyword()) :: TSTInfo.t()
  def decode_token!(token, opts \\ []), do: bang(decode_token(token, opts))

  @doc """
  The options for the `:path_validation` of `Cmsex.verify/2` (and of the
  `:path_validation` option of `verify/3`) that make the OTP validate a
  certificate path at `time` instead of now.

  `:public_key.pkix_path_validation/3` has no date option and judges a
  certificate by the clock of today, so a token made in 2024 stops
  validating when the certificate of the TSA expires, and a critical
  `extKeyUsage` of a TSA never validates. The `:verify_fun` that comes with
  the options decides the validity of every certificate of the path, the
  root included, by `time`, and lets an `extKeyUsage` through if it holds
  `id-kp-timeStamping` or `anyExtendedKeyUsage`; the OTP does the rest of
  RFC 5280, 6.1. Your own `:verify_fun` is refused (`ArgumentError`): check
  revocation with the `:revocation` option of `verify/3`.

  Notes that matter:

    * Validating at a date is not checking revocation at that date.
    * The root is held to the same rule as the others: one that had expired
      at `time` is refused, one that expires later is accepted. RFC 5280,
      6.1 does not look at the validity of a trust anchor, so this is
      stricter.
    * A CA whose `extKeyUsage` lacks `timeStamping` and
      `anyExtendedKeyUsage` is refused (`:eku_excludes_time_stamping`).
    * A CA with an `extKeyUsage` and no `keyUsage` makes the OTP raise on
      some versions; `Cmsex.verify/2` reports it as `:untrusted`.
  """
  @spec path_validation_at(DateTime.t(), keyword()) :: keyword()
  def path_validation_at(time, opts \\ []), do: Tspex.PathValidation.options_at(time, opts)

  @doc """
  Verifies a time-stamp response or token and returns what it proves.

  `input` is the whole `TimeStampResp` (what the TSA sent) or the token
  alone (the `ContentInfo`, as kept in a file or an attribute). The second
  argument says what was time-stamped:

    * a `Tspex.Request` (**fresh**): the response to that request. The
      nonce and the policy of the request are checked, and so is its
      imprint.
    * `{:data, binary}`, `{:stream, enumerable}` or `{:digest, hash,
      digest}` (**stored**): a token kept for later. The data is hashed with
      the algorithm the token itself declares, if it is allowed. There is no
      nonce to compare, and a nonce in the token is only information.

  ## What `{:ok, verified}` promises

  The token is a `SignedData` with one signer who signed the `TSTInfo`; the
  certificate that signed is the one the signing-certificate attribute
  names and is a certificate of a time-stamping authority (a critical
  `extKeyUsage` with `id-kp-timeStamping`); its chain leads to one of the
  `:trust` roots, **judged at the `genTime` and not today**, so a token stays
  valid after the certificate of the TSA expires; the imprint is that of the
  data, and in fresh mode the nonce is that of the request.

  ## What it does not promise

    * That the TSA is honest or its clock right: `:trust` is your decision
      and `genTime` is the word of the TSA.
    * That the certificate of the TSA was **not revoked**: without
      `:revocation` the result says `revocation: :not_checked`.
    * That the stamp will keep proving anything for ever: keys and
      algorithms age.
    * That the stamped signature or document is valid.

  ## Options

    * `:trust` - **required**: a list of root certificates in DER, or
      `:none`, which gives up checking the chain: the result then says
      `trust: :none` and `signer.path` is `nil`, and the token proves only
      that some key signed this imprint.
    * `:certificates` - certificates in DER to find the TSA and the
      intermediates in, tried before those of the token (needed when the
      request had `cert_req: false`).
    * `:input` - `:auto` (the default), `:response` or `:token`.
    * `:policies` - the TSA policies you accept (OIDs as tuples or text);
      none accepts any. A policy in the request must always be the one of
      the token.
    * `:tsa_name` - `:strict` (the default) checks the `tsa` field against
      the names of the certificate; `:ignore` does not.
    * `:tsa_eku` - `:strict` (the default): the `extKeyUsage` is critical,
      written once, and holds only timeStamping; `:extra_purposes` allows
      other purposes next to it.
    * `:critical_extensions` - `:reject` (the default) or `:ignore` an
      unknown critical extension of the `TSTInfo`.
    * `:granted_with_mods` - `:accept` (the default) or `:reject` status 1.
    * `:max_skew` - seconds of difference allowed between the `genTime` and
      the local clock, plus the accuracy; `nil` (the default) does not look
      at the clock. `:now` replaces the clock, for tests.
    * `:revocation` - `fun.(path, gen_time)` returning `:ok` or `{:error,
      reason}`, called with the validated path (root first, TSA last, in
      DER) after everything else passed. An error is `:untrusted` with
      `{:revocation, reason}`. RFC 3161, section 4: a revocation for
      `keyCompromise` or without a reason invalidates every token of the
      key; any other reason only those made after the revocation.
    * `:allow_sha1` (`false`), `:min_rsa_bits` (2048) - as in `Cmsex`; MD5
      is never accepted.
    * `:path_validation` - options for `:public_key.pkix_path_validation/3`,
      except `:verify_fun`.
    * `:max_size` (1 MiB), `:max_depth`, `:max_nodes` and the limits of
      `Cmsex.decode/2`.

  ## The order of the checks

  Size and form; status and `failInfo`; the token; `SignedData` and the type
  of its content; one signer; the version of the `TSTInfo`; the signature
  (`:token_invalid`); the signing-certificate attribute; the rules for the
  certificate of a TSA (`:bad_tsa_certificate`); the chain to the roots at
  the `genTime` (`:untrusted`); the imprint; the nonce; the policy; the `tsa`
  name; critical extensions; the clock; `:revocation`. The error is the
  first one that fails, and the rules for the certificate come before the
  chain so that a certificate that is not for time-stamping is reported as
  such and not as an error of the OTP.

  Errors are `{:error, %Tspex.Error{}}`; a bad argument raises
  `ArgumentError` without showing the data.
  """
  @spec verify(binary(), Request.t() | tuple(), keyword()) ::
          {:ok, Tspex.Verified.t()} | {:error, Error.t()}
  def verify(input, expected, opts), do: Tspex.Verify.verify(input, expected, opts)

  @doc "Like `verify/3`, but raises `Tspex.Error`."
  @spec verify!(binary(), Request.t() | tuple(), keyword()) :: Tspex.Verified.t()
  def verify!(input, expected, opts), do: bang(verify(input, expected, opts))

  @doc """
  Asks a TSA for a time-stamp of `data` and verifies the answer: `request/2`,
  the transport, `decode_response/2` and `verify/3` in one call.

      {:ok, verified} =
        Tspex.stamp(File.read!("contract.pdf"),
          url: "https://tsa.example.com/tsp",
          trust: [root_der],
          policy: "1.2.3.4.5.6"
        )

      File.write!("contract.pdf.tst", verified.token)

  Takes the options of `request/2` and of `verify/3` (`:trust` is
  required) and these:

    * `:url` - the address of the TSA; required unless there is a
      `:transport`.
    * `:transport` - a function `fun.(url, request_der, options)` that
      sends the request and returns `{:ok, response_der}` or `{:error,
      reason}`. The default is `Tspex.HTTP.post/3`. Use your own for a
      proxy, an HTTP client you already have (Req, Finch, Mint) or a test.
      `options` is a keyword list with `:headers`, `:timeout`,
      `:max_redirects`, `:max_response_bytes` and `:ssl`; a `reason` that is
      not a `Tspex.Error` becomes the `detail` of a `:transport` error.
    * `:headers`, `:timeout` (30 s for the exchange), `:max_redirects` (0),
      `:max_response_bytes` (1 MiB) and `:ssl` - see `Tspex.HTTP`.
    * `:input` - `:response` here, because that is what a TSA answers.

  The error of a TSA that refused is a `:rejection` (or `:waiting` and the
  like) with the `failInfo` in the `detail`; one of the network is a
  `:transport` error. Nothing is retried.

  `http` URLs work, with the hash of your data in the clear on the way: see
  `Tspex.HTTP`.
  """
  @spec stamp(data(), keyword()) :: {:ok, Tspex.Verified.t()} | {:error, Error.t()}
  def stamp(data, opts), do: Tspex.Stamp.stamp(data, opts)

  @doc "Like `stamp/2`, but raises `Tspex.Error`."
  @spec stamp!(data(), keyword()) :: Tspex.Verified.t()
  def stamp!(data, opts), do: bang(stamp(data, opts))

  ## Time-stamps inside a CMS message

  @doc """
  The imprint to time-stamp a signature: the hash of the signature value of
  the signer at `position` (RFC 3161, appendix A), as `{:digest, hash,
  digest}`, which `request/2` and `verify/3` take.

  `position` is the one of `Cmsex`: an integer for a signer, a list such as
  `[0, 0]` for the first countersignature of the first signer.

      {:ok, cms} = Cmsex.sign(content, signer)
      {:ok, imprint} = Tspex.signature_imprint(cms, 0)
      request = Tspex.request!(imprint)

  Options: `:hash`, `:sha256` (the default), `:sha224`, `:sha384` or
  `:sha512`; and the limits `:max_size`, `:max_depth`, `:max_nodes`,
  `:max_signers`, `:max_certificates` and `:max_attributes`.
  """
  @spec signature_imprint(binary(), Cmsex.position(), keyword()) ::
          {:ok, {:digest, hash(), binary()}} | {:error, Error.t()}
  def signature_imprint(cms, position, opts \\ []),
    do: Tspex.Stamps.signature_imprint(cms, position, opts)

  @doc """
  Adds a time-stamp to the signer at `position` as an unsigned attribute
  (`id-aa-timeStampToken`), and returns the new message. The signature does
  not change, since the attribute is not signed, and the signer may have
  several stamps, from different TSAs.

  `stamp` is a `t:Tspex.Verified.t/0` or a token in DER. The imprint has to
  be the hash of that signer's signature (`:imprint_mismatch` otherwise:
  a stamp of another signature must not pass). A token in DER is verified
  first with `opts`, which are those of `verify/3` and need `:trust`; a
  `Tspex.Verified` is taken to have been verified already.
  """
  @spec add_signature_time_stamp(
          binary(),
          Cmsex.position(),
          Tspex.Verified.t() | binary(),
          keyword()
        ) ::
          {:ok, binary()} | {:error, Error.t()}
  def add_signature_time_stamp(cms, position, stamp, opts \\ []),
    do: Tspex.Stamps.add_signature_time_stamp(cms, position, stamp, opts)

  @doc """
  The time-stamps of the signer at `position`, read and not verified: the
  `TSTInfo` of each token of each `id-aa-timeStampToken` attribute, in the
  order of the message. A signer with none gives an empty list. Takes the
  `:max_size`, `:max_depth` and `:max_nodes` limits.
  """
  @spec signature_time_stamps(binary(), Cmsex.position(), keyword()) ::
          {:ok, [TSTInfo.t()]} | {:error, Error.t()}
  def signature_time_stamps(cms, position, opts \\ []),
    do: Tspex.Stamps.signature_time_stamps(cms, position, opts)

  @doc """
  Verifies the time-stamps of the signer at `position` against its
  signature value, with the options of `verify/3` (`:trust` is required and
  names the roots of the TSAs) and:

    * `:stamps` - `:all` (the default) fails with the first stamp that does
      not verify; `:any` returns those that did, and fails with the first
      error only when none did.

  No time-stamp is `:no_time_stamp`.

  This says when the signature existed. It does not check the signature
  itself or the certificate of the signer: see `verify_at_stamp/2`.
  """
  @spec verify_signature_time_stamps(binary(), Cmsex.position(), keyword()) ::
          {:ok, [Tspex.Verified.t()]} | {:error, Error.t()}
  def verify_signature_time_stamps(cms, position, opts),
    do: Tspex.Stamps.verify_signature_time_stamps(cms, position, opts)

  @doc """
  The attribute for a content time-stamp (`id-aa-ets-contentTimestamp`,
  RFC 5126, 5.11.4), from a `Tspex.Verified` whose imprint is the hash of the
  content that is to be signed. It is a *signed* attribute, so the token has
  to exist before the signature:

      {:ok, verified} = Tspex.verify(response, request, trust: tsa_roots)
      attribute = Tspex.content_time_stamp_attribute(verified)
      signer = %{certificate: cert, key: key, signed_attributes: [attribute]}
      {:ok, cms} = Cmsex.sign(content, signer)
  """
  @spec content_time_stamp_attribute(Tspex.Verified.t()) :: Cmsex.Attribute.t()
  def content_time_stamp_attribute(verified),
    do: Tspex.Stamps.content_time_stamp_attribute(verified)

  @doc """
  Verifies the content time-stamp of the signer with index `index` of a
  message that `Cmsex.verify/2` has verified. The imprint has to be the hash
  of the content that the signature covers; for a detached message give
  `content:` (data, as in `request/2`), for one that carries its content
  the content is taken from `verified`.

  Takes the options of `verify/3` (`:trust` is required) and `:stamps`, as
  `verify_signature_time_stamps/3`. A signer with no such attribute is
  `:no_time_stamp`.
  """
  @spec verify_content_time_stamp(Cmsex.Verified.t(), non_neg_integer(), keyword()) ::
          {:ok, [Tspex.Verified.t()]} | {:error, Error.t()}
  def verify_content_time_stamp(verified, index, opts),
    do: Tspex.Stamps.verify_content_time_stamp(verified, index, opts)

  @doc """
  Verifies a signature as it was at the time of its time-stamp, which is
  how a signature outlives the certificate of its signer: for each signer,
  the signature time-stamps are verified, the earliest `genTime` among them
  is taken, and the signature and the certificate path of the signer are
  verified *at that time*.

  Returns `{:ok, [%{signer: signer, stamps: [verified], time: time}]}`, one
  entry per signer, where `signer` is as in `Cmsex.Verified` and `time` the
  earliest `genTime`. A signer without a verified time-stamp is
  `:no_time_stamp`: this never falls back to today's date (use
  `Cmsex.verify/2` for that).

  Options:

    * `:trust` (required) - the roots of the signer's certificates.
    * `:tsa_trust` - the roots of the TSAs (the value of `:trust`).
    * `:stamps` - `:all` or `:any`, as in `verify_signature_time_stamps/3`.
    * `:revocation` - `fn path, time -> :ok | {:error, reason} end`, called
      with the path of the signer and the time of the stamp.
    * `:content`, `:certificates`, `:allow_sha1`, `:min_rsa_bits`,
      `:path_validation` - for the signature, as in `Cmsex.verify/2`.
    * `:policies`, `:tsa_name`, `:tsa_eku`, `:critical_extensions` - for the
      stamps, as in `verify/3`.
    * the limits `:max_size`, `:max_depth`, `:max_nodes`, `:max_signers`,
      `:max_certificates` and `:max_attributes`.

  What this proves is that the signature is older than the time-stamp, and
  that the certificate was valid then. It does not say that the signer was
  authorized to sign: the signature policy of a profile such as CAdES is not
  checked here. Validating at a date is not checking revocation at that date
  (see `path_validation_at/2`).
  """
  @spec verify_at_stamp(binary(), keyword()) :: {:ok, [map()]} | {:error, Error.t()}
  def verify_at_stamp(cms, opts), do: Tspex.Stamps.verify_at_stamp(cms, opts)

  defp bang({:ok, value}), do: value
  defp bang({:error, error}), do: raise(error)
end
