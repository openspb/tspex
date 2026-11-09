defmodule Tspex.Verified do
  @moduledoc """
  The result of `Tspex.verify/3`: a token that passed every check.

  Fields:

    * `:info` - the `Tspex.TSTInfo`, now that the signature and the
      certificate vouch for it. `info.gen_time` is the time the TSA says.
    * `:token` - the verified `ContentInfo`, to keep: it is the time-stamp
      proper, and `verify/3` takes it back months later.
    * `:status` - `:granted` or `:granted_with_mods` when a whole response
      was verified, `nil` for a token that came alone.
    * `:signer` - `%{certificate: der, path: [der] | nil, signer_info:
      Cmsex.SignerInfo.t()}`: the certificate of the TSA, the certificate
      path from the root to it (root first, `nil` with `trust: :none`) and
      the signer of the token.
    * `:certificates` - the certificates that came in the token, in DER.
    * `:trust` - `:validated` when the path leads to one of the `:trust`
      roots, `:none` with `trust: :none`, which proves only that a key signed
      this imprint.
    * `:revocation` - `:checked` when the `:revocation` function accepted
      the path, `:not_checked` otherwise: **nothing has said the certificate
      of the TSA was not revoked.**
    * `:deviations` - what was tolerated against the RFC: `:gen_time_encoding`
      (a `genTime` that is not in DER), `:unrequested_certificates` (the
      request had `cert_req: false` and the token carries certificates),
      `:cert_req_not_honored` (the request asked for the certificate and
      the token has none), and what the CMS layer tolerated.

  `inspect/1` shows the size of the token, not its bytes.
  """

  alias Tspex.TSTInfo

  @typedoc "The certificate of the TSA, its path from the root and the signer of the token."
  @type signer :: %{
          certificate: binary(),
          path: [binary()] | nil,
          signer_info: Cmsex.SignerInfo.t()
        }

  @typedoc "What `Tspex.verify/3` proves; the fields are described above."
  @type t :: %__MODULE__{
          info: TSTInfo.t(),
          token: binary(),
          status: :granted | :granted_with_mods | nil,
          signer: signer(),
          certificates: [binary()],
          trust: :validated | :none,
          revocation: :checked | :not_checked,
          deviations: [atom()]
        }

  @enforce_keys [:info, :token, :signer]
  defstruct [
    :info,
    :token,
    :status,
    :signer,
    certificates: [],
    trust: :validated,
    revocation: :not_checked,
    deviations: []
  ]

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(verified, opts) do
      fields = [
        gen_time: verified.info.gen_time,
        serial: verified.info.serial,
        policy: verified.info.policy,
        status: verified.status,
        trust: verified.trust,
        revocation: verified.revocation,
        deviations: verified.deviations,
        token: "#{byte_size(verified.token)} bytes"
      ]

      concat(["#Tspex.Verified<", to_doc(fields, %{opts | limit: :infinity}), ">"])
    end
  end
end
