defmodule Tspex.StampsTest do
  use Tspex.VerifyCase, async: true

  alias Cmsex.Attribute

  @old ~U[2020-06-01 12:00:00Z]
  @window [not_before: ~U[2015-01-01 00:00:00Z], not_after: ~U[2060-01-01 00:00:00Z]]

  # A signer with a root of its own, so that its certificate can be dated.
  defp signer_pki(tag \\ :signer, opts \\ []) do
    root_key = {:p256, :"#{tag}_root"}

    root =
      TestPKI.cert(
        root_key,
        Keyword.merge([ca: true, subject: "Root of #{tag}"], Keyword.get(opts, :root, []))
      )

    key_name = {:p256, tag}

    cert =
      TestPKI.cert(
        key_name,
        Keyword.merge(
          [subject: "Signer #{tag}", issuer: {root, root_key}, key_usage: [0]],
          Keyword.get(opts, :cert, [])
        )
      )

    %{root: root, cert: cert, key: TestPKI.key(key_name), chain: []}
  end

  defp sign(signer, content \\ "the content", opts \\ []) do
    {:ok, cms} =
      Cmsex.sign(
        content,
        Map.take(signer, [:certificate, :key, :chain, :signed_attributes]),
        opts
      )

    cms
  end

  defp as_signer(pki, extra \\ []),
    do: Map.merge(%{certificate: pki.cert, key: pki.key, chain: []}, Map.new(extra))

  defp stamp(tsa, cms, position, token_opts \\ []) do
    {:ok, imprint} = Tspex.signature_imprint(cms, position)
    request = Tspex.request!(imprint)
    response = TestTSA.response(tsa, request, token_opts)
    Tspex.verify!(response, request, trust: TestTSA.trust(tsa))
  end

  defp stamped(tsa, pki, token_opts \\ []) do
    cms = sign(as_signer(pki))
    {:ok, stamped} = Tspex.add_signature_time_stamp(cms, 0, stamp(tsa, cms, 0, token_opts))
    {cms, stamped}
  end

  setup_all do
    %{tsa: TestTSA.new(), pki: signer_pki()}
  end

  describe "signature_imprint/3" do
    test "is the hash of the signature value", %{pki: pki} do
      cms = sign(as_signer(pki))
      {:ok, %Cmsex.SignedData{signer_infos: [info]}} = Cmsex.decode(cms)
      signature = Cmsex.SignerInfo.signature(info)

      assert {:ok, {:digest, :sha256, digest}} = Tspex.signature_imprint(cms, 0)
      assert digest == :crypto.hash(:sha256, signature)

      assert {:ok, {:digest, :sha384, digest}} = Tspex.signature_imprint(cms, 0, hash: :sha384)
      assert digest == :crypto.hash(:sha384, signature)
    end

    test "feeds a request", %{pki: pki} do
      {:ok, imprint} = Tspex.signature_imprint(sign(as_signer(pki)), 0)
      assert %Tspex.Request{hash: :sha256} = Tspex.request!(imprint)
    end

    test "a signer that is not there", %{pki: pki} do
      cms = sign(as_signer(pki))
      assert failure(Tspex.signature_imprint(cms, 1)) == {:signer_not_found, 1}
      assert failure(Tspex.signature_imprint(cms, [0, 0])) == {:signer_not_found, [0, 0]}
    end

    test "arguments that cannot be right", %{pki: pki} do
      cms = sign(as_signer(pki))
      assert_raise ArgumentError, fn -> Tspex.signature_imprint(cms, -1) end
      assert_raise ArgumentError, fn -> Tspex.signature_imprint(cms, []) end
      assert_raise ArgumentError, fn -> Tspex.signature_imprint(cms, "0") end
      assert_raise ArgumentError, fn -> Tspex.signature_imprint(cms, 0, hash: :sha1) end
      assert_raise ArgumentError, fn -> Tspex.signature_imprint(cms, 0, hash: :md5) end
    end

    test "something that is not a SignedData" do
      assert reason(Tspex.signature_imprint("garbage", 0)) == :cms_invalid
      assert reason(Tspex.signature_imprint(<<0x30, 0>>, 0)) == :cms_invalid
    end
  end

  describe "adding and reading a stamp" do
    test "the cycle: sign, stamp, add, verify, read", %{tsa: tsa, pki: pki} do
      {cms, stamped} = stamped(tsa, pki)

      assert {:ok, %Cmsex.Verified{signers: [signer]}} = Cmsex.verify(stamped)
      assert signer.certificate == pki.cert
      assert {:ok, [info]} = Tspex.signature_time_stamps(stamped, 0)
      assert info.hash == :sha256

      {:ok, %Cmsex.SignedData{signer_infos: [before]}} = Cmsex.decode(cms)
      {:ok, %Cmsex.SignedData{signer_infos: [after_]}} = Cmsex.decode(stamped)
      assert Cmsex.SignerInfo.signature(before) == Cmsex.SignerInfo.signature(after_)

      assert {:ok, [verified]} = Tspex.verify_signature_time_stamps(stamped, 0, trust: [tsa.root])
      assert verified.info.serial == info.serial
      assert verified.status == nil
    end

    test "a token in DER is verified before it is added", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))
      token = stamp(tsa, cms, 0).token

      assert {:ok, stamped} =
               Tspex.add_signature_time_stamp(cms, 0, token, trust: TestTSA.trust(tsa))

      assert {:ok, [_]} = Tspex.signature_time_stamps(stamped, 0)

      other = TestTSA.new(root_tag: :other_root, tag: :other_tsa)

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.add_signature_time_stamp(cms, 0, token, trust: TestTSA.trust(other))
    end

    test "N85: a token in DER without :trust", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))
      token = stamp(tsa, cms, 0).token

      assert_raise ArgumentError, ~r/trust/, fn ->
        Tspex.add_signature_time_stamp(cms, 0, token)
      end
    end

    test "N84: the stamp of another signature", %{tsa: tsa, pki: pki} do
      first = sign(as_signer(pki), "first")
      second = sign(as_signer(pki), "second")
      verified = stamp(tsa, first, 0)

      assert failure(Tspex.add_signature_time_stamp(second, 0, verified)) ==
               {:imprint_mismatch, :digest}

      assert failure(
               Tspex.add_signature_time_stamp(second, 0, verified.token,
                 trust: TestTSA.trust(tsa)
               )
             ) == {:imprint_mismatch, :digest}
    end

    test "a stamp of a digest that is not SHA-2 is not about a signature", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))
      verified = stamp(tsa, cms, 0)
      sha1 = %{verified | info: %{verified.info | hash: :sha1}}

      assert failure(Tspex.add_signature_time_stamp(cms, 0, sha1)) == {:imprint_mismatch, :digest}
      md5 = %{verified | info: %{verified.info | hash: :md5}}

      assert failure(Tspex.add_signature_time_stamp(cms, 0, md5)) ==
               {:imprint_mismatch, :hash_algorithm}
    end

    test "something that is not a stamp raises", %{pki: pki} do
      cms = sign(as_signer(pki))
      assert_raise ArgumentError, fn -> Tspex.add_signature_time_stamp(cms, 0, :nope) end
      assert_raise ArgumentError, fn -> Tspex.add_signature_time_stamp(cms, -1, "x") end
    end

    test "N86: a signer without stamps has an empty list", %{pki: pki} do
      assert Tspex.signature_time_stamps(sign(as_signer(pki)), 0) == {:ok, []}
    end

    test "a stamp that is not a token", %{pki: pki} do
      cms = sign(as_signer(pki))

      {:ok, cms} =
        Cmsex.add_unsigned_attribute(cms, 0, Attribute.new(:time_stamp_token, [<<5, 0>>]))

      assert {:error, %Error{}} = Tspex.signature_time_stamps(cms, 0)
    end

    test "the signer that is not there", %{pki: pki} do
      cms = sign(as_signer(pki))
      assert failure(Tspex.signature_time_stamps(cms, 3)) == {:signer_not_found, 3}
    end

    test "more stamps than the default limit need the limit raised", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))
      token = stamp(tsa, cms, 0)
      raised = [max_attributes: 100]

      many =
        Enum.reduce(1..70, cms, fn _, acc ->
          {:ok, next} = Tspex.add_signature_time_stamp(acc, 0, token, raised)
          next
        end)

      assert reason(Tspex.signature_time_stamps(many, 0)) == :cms_invalid
      assert {:ok, infos} = Tspex.signature_time_stamps(many, 0, raised)
      assert length(infos) == 70
      assert {:ok, imprint} = Tspex.signature_imprint(many, 0, raised)
      assert {:ok, ^imprint} = Tspex.signature_imprint(cms, 0)
      assert reason(Tspex.signature_imprint(many, 0)) == :cms_invalid
    end
  end

  describe "verify_signature_time_stamps/3" do
    test "N87: no stamp", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))

      assert reason(Tspex.verify_signature_time_stamps(cms, 0, trust: [tsa.root])) ==
               :no_time_stamp
    end

    test "trust is required, even where there is nothing to verify", %{pki: pki} do
      cms = sign(as_signer(pki))

      assert_raise ArgumentError, ~r/trust/, fn ->
        Tspex.verify_signature_time_stamps(cms, 0, [])
      end
    end

    test "several stamps from different TSAs", %{tsa: tsa, pki: pki} do
      other = TestTSA.new(root_tag: :second_root, tag: :second_tsa)
      cms = sign(as_signer(pki))
      {:ok, cms} = Tspex.add_signature_time_stamp(cms, 0, stamp(tsa, cms, 0))
      {:ok, cms} = Tspex.add_signature_time_stamp(cms, 0, stamp(other, cms, 0))

      assert {:ok, [_, _]} = Tspex.signature_time_stamps(cms, 0)

      assert {:ok, [_, _]} =
               Tspex.verify_signature_time_stamps(cms, 0, trust: [tsa.root, other.root])

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify_signature_time_stamps(cms, 0, trust: [tsa.root])

      assert {:ok, [only]} =
               Tspex.verify_signature_time_stamps(cms, 0, trust: [tsa.root], stamps: :any)

      assert only.signer.certificate == tsa.cert
    end

    test "N88, N89: a stamp that was tampered with, with :all and with :any", %{
      tsa: tsa,
      pki: pki
    } do
      cms = sign(as_signer(pki))
      good = stamp(tsa, cms, 0)
      bad = Attribute.new(:time_stamp_token, [TestTSA.flip_signature(good.token)])
      {:ok, cms} = Cmsex.add_unsigned_attribute(cms, 0, bad)
      {:ok, cms} = Tspex.add_signature_time_stamp(cms, 0, good)

      assert reason(Tspex.verify_signature_time_stamps(cms, 0, trust: [tsa.root])) ==
               :token_invalid

      assert {:ok, [only]} =
               Tspex.verify_signature_time_stamps(cms, 0, trust: [tsa.root], stamps: :any)

      assert only.token == good.token
    end

    test ":any with no stamp that verifies is the first error", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))
      bad = Attribute.new(:time_stamp_token, [TestTSA.flip_signature(stamp(tsa, cms, 0).token)])
      {:ok, cms} = Cmsex.add_unsigned_attribute(cms, 0, bad)

      assert reason(Tspex.verify_signature_time_stamps(cms, 0, trust: [tsa.root], stamps: :any)) ==
               :token_invalid
    end

    test "a stamp moved to another signature does not verify", %{tsa: tsa, pki: pki} do
      first = sign(as_signer(pki), "first")
      second = sign(as_signer(pki), "second")
      token = stamp(tsa, first, 0).token

      {:ok, moved} =
        Cmsex.add_unsigned_attribute(second, 0, Attribute.new(:time_stamp_token, [token]))

      assert failure(Tspex.verify_signature_time_stamps(moved, 0, trust: [tsa.root])) ==
               {:imprint_mismatch, :digest}
    end

    test "the options of verify/3 apply to each stamp", %{tsa: tsa, pki: pki} do
      {_cms, stamped} = stamped(tsa, pki, policy: {1, 2, 3, 9})

      assert {:ok, _} = Tspex.verify_signature_time_stamps(stamped, 0, trust: [tsa.root])

      assert reason(
               Tspex.verify_signature_time_stamps(stamped, 0,
                 trust: [tsa.root],
                 policies: [{1, 2, 3, 4}]
               )
             ) == :policy_mismatch

      assert_raise ArgumentError, fn ->
        Tspex.verify_signature_time_stamps(stamped, 0, trust: [tsa.root], stamps: :some)
      end
    end

    test "the stamp of a countersignature", %{tsa: tsa, pki: pki} do
      other = signer_pki(:counter)
      cms = sign(as_signer(pki))
      {:ok, cms} = Cmsex.countersign(cms, 0, as_signer(other))

      {:ok, imprint} = Tspex.signature_imprint(cms, [0, 0])
      request = Tspex.request!(imprint)
      response = TestTSA.response(tsa, request)
      verified = Tspex.verify!(response, request, trust: [tsa.root])

      assert {:ok, stamped} = Tspex.add_signature_time_stamp(cms, [0, 0], verified)
      assert {:ok, [_]} = Tspex.signature_time_stamps(stamped, [0, 0])
      assert {:ok, []} = Tspex.signature_time_stamps(stamped, 0)
      assert {:ok, [_]} = Tspex.verify_signature_time_stamps(stamped, [0, 0], trust: [tsa.root])
      assert {:ok, _} = Cmsex.verify(stamped, countersignatures: true)
    end
  end

  describe "verify_at_stamp/2" do
    test "a signature whose certificate has expired, stamped while it was valid" do
      tsa = TestTSA.new(root: @window, cert: @window)

      pki =
        signer_pki(:old,
          root: @window,
          cert: [not_before: ~U[2020-01-01 00:00:00Z], not_after: ~U[2021-01-01 00:00:00Z]]
        )

      {_cms, stamped} = stamped(tsa, pki, gen_time: @old)

      # Today the certificate is no longer valid.
      assert {:error, %Cmsex.Error{reason: :untrusted}} = Cmsex.verify(stamped, trust: [pki.root])

      assert {:ok, [entry]} =
               Tspex.verify_at_stamp(stamped, trust: [pki.root], tsa_trust: [tsa.root])

      assert entry.time == @old
      assert entry.signer.certificate == pki.cert
      assert [root, _leaf] = entry.signer.path
      assert root == pki.root
      assert [%Tspex.Verified{}] = entry.stamps
    end

    test "N90: the certificate had expired at the time of the stamp" do
      tsa = TestTSA.new(root: @window, cert: @window)

      pki =
        signer_pki(:expired,
          root: @window,
          cert: [not_before: ~U[2020-01-01 00:00:00Z], not_after: ~U[2021-01-01 00:00:00Z]]
        )

      {_cms, stamped} = stamped(tsa, pki, gen_time: ~U[2022-06-01 12:00:00Z])

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify_at_stamp(stamped, trust: [pki.root], tsa_trust: [tsa.root])
    end

    test "a certificate that was not yet valid at the time of the stamp" do
      tsa = TestTSA.new(root: @window, cert: @window)

      pki =
        signer_pki(:early,
          root: @window,
          cert: [not_before: ~U[2023-01-01 00:00:00Z], not_after: ~U[2040-01-01 00:00:00Z]]
        )

      {_cms, stamped} = stamped(tsa, pki, gen_time: @old)

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify_at_stamp(stamped, trust: [pki.root], tsa_trust: [tsa.root])
    end

    test "a root that was not yet valid at the time of the stamp" do
      tsa = TestTSA.new(root: @window, cert: @window)

      pki =
        signer_pki(:late_root,
          root: [not_before: ~U[2023-01-01 00:00:00Z], not_after: ~U[2060-01-01 00:00:00Z]],
          cert: [not_before: ~U[2019-01-01 00:00:00Z], not_after: ~U[2040-01-01 00:00:00Z]]
        )

      {_cms, stamped} = stamped(tsa, pki, gen_time: @old)

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify_at_stamp(stamped, trust: [pki.root], tsa_trust: [tsa.root])
    end

    test "N91: no stamp is not today", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))

      assert reason(Tspex.verify_at_stamp(cms, trust: [pki.root], tsa_trust: [tsa.root])) ==
               :no_time_stamp

      assert {:ok, _} = Cmsex.verify(cms, trust: [pki.root])
    end

    test "tsa_trust is the value of trust unless given", %{tsa: tsa, pki: pki} do
      {_cms, stamped} = stamped(tsa, pki)

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify_at_stamp(stamped, trust: [pki.root])

      assert {:ok, [_]} = Tspex.verify_at_stamp(stamped, trust: [pki.root, tsa.root])
    end

    test "another root for the signer", %{tsa: tsa, pki: pki} do
      {_cms, stamped} = stamped(tsa, pki)
      stranger = signer_pki(:stranger)

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify_at_stamp(stamped, trust: [stranger.root], tsa_trust: [tsa.root])
    end

    test "a signature that does not verify", %{tsa: tsa, pki: pki} do
      {_cms, stamped} = stamped(tsa, pki)
      {:ok, %Cmsex.SignedData{signer_infos: [info]}} = Cmsex.decode(stamped)
      signature = Cmsex.SignerInfo.signature(info)
      [before, after_] = :binary.split(stamped, signature)
      <<head::binary-size(byte_size(signature) - 1), last>> = signature
      broken = before <> head <> <<Bitwise.bxor(last, 1)>> <> after_

      assert {:error, %Error{reason: reason}} =
               Tspex.verify_at_stamp(broken, trust: [pki.root], tsa_trust: [tsa.root])

      assert reason in [:cms_invalid, :imprint_mismatch]
    end

    test "an extKeyUsage on the certificate of the signer is not the business of the stamp" do
      tsa = TestTSA.new(root: @window, cert: @window)
      pki = signer_pki(:eku, root: @window, cert: [eku: [TestPKI.client_auth()]])
      {_cms, stamped} = stamped(tsa, pki)

      assert {:ok, [_]} = Tspex.verify_at_stamp(stamped, trust: [pki.root], tsa_trust: [tsa.root])
    end

    test "the revocation callback gets the path of the signer and the time of the stamp" do
      tsa = TestTSA.new(root: @window, cert: @window)
      pki = signer_pki(:revoked, root: @window, cert: @window)
      {_cms, stamped} = stamped(tsa, pki, gen_time: @old)
      test = self()

      check = fn path, time ->
        send(test, {:checked, path, time})
        :ok
      end

      assert {:ok, [_]} =
               Tspex.verify_at_stamp(stamped,
                 trust: [pki.root],
                 tsa_trust: [tsa.root],
                 revocation: check
               )

      assert_received {:checked, [root, leaf], @old}
      assert root == pki.root
      assert leaf == pki.cert

      refuse = fn _, _ -> {:error, :revoked} end

      assert failure(
               Tspex.verify_at_stamp(stamped,
                 trust: [pki.root],
                 tsa_trust: [tsa.root],
                 revocation: refuse
               )
             ) == {:untrusted, {:revocation, :revoked}}
    end

    test "each signer is verified at the time of its own stamp" do
      tsa = TestTSA.new(root: @window, cert: @window)
      first = signer_pki(:first, root: @window, cert: @window)
      second = signer_pki(:second, root: @window, cert: @window)

      cms = sign(as_signer(first), "shared", [])

      {:ok, cms} =
        Cmsex.add_signer(cms, as_signer(second))

      {:ok, cms} = Tspex.add_signature_time_stamp(cms, 0, stamp(tsa, cms, 0, gen_time: @old))

      later = ~U[2021-03-01 08:00:00Z]
      {:ok, cms} = Tspex.add_signature_time_stamp(cms, 1, stamp(tsa, cms, 1, gen_time: later))

      assert {:ok, [one, two]} =
               Tspex.verify_at_stamp(cms,
                 trust: [first.root, second.root],
                 tsa_trust: [tsa.root]
               )

      assert one.time == @old
      assert two.time == later
      assert one.signer.certificate == first.cert
      assert two.signer.certificate == second.cert
    end

    test "the earliest of several stamps is the time" do
      pki = signer_pki(:several, root: @window, cert: @window)
      tsa = TestTSA.new(root: @window, cert: @window)
      other = TestTSA.new(root: @window, cert: @window, root_tag: :late_root, tag: :late_tsa)
      cms = sign(as_signer(pki))

      {:ok, cms} =
        Tspex.add_signature_time_stamp(
          cms,
          0,
          stamp(other, cms, 0, gen_time: ~U[2022-01-01 00:00:00Z])
        )

      {:ok, cms} = Tspex.add_signature_time_stamp(cms, 0, stamp(tsa, cms, 0, gen_time: @old))

      assert {:ok, [entry]} =
               Tspex.verify_at_stamp(cms,
                 trust: [pki.root],
                 tsa_trust: [tsa.root, other.root]
               )

      assert entry.time == @old
      assert length(entry.stamps) == 2
    end

    test "arguments", %{tsa: tsa, pki: pki} do
      {_cms, stamped} = stamped(tsa, pki)
      assert_raise ArgumentError, ~r/trust/, fn -> Tspex.verify_at_stamp(stamped, []) end
      assert_raise ArgumentError, fn -> Tspex.verify_at_stamp(stamped, trust: :none) end

      assert_raise ArgumentError, fn ->
        Tspex.verify_at_stamp(stamped, trust: [pki.root], nope: 1)
      end

      assert reason(Tspex.verify_at_stamp("garbage", trust: [pki.root])) == :cms_invalid
    end
  end

  describe "the content time-stamp" do
    defp content_stamp(tsa, content) do
      request = Tspex.request!(content)
      response = TestTSA.response(tsa, request)
      Tspex.verify!(response, request, trust: TestTSA.trust(tsa))
    end

    defp with_content_stamp(tsa, pki, content, detached? \\ false) do
      attribute = Tspex.content_time_stamp_attribute(content_stamp(tsa, content))
      signer = as_signer(pki, signed_attributes: [attribute])

      if detached? do
        cms = sign(signer, content, detached: true)
        {:ok, verified} = Cmsex.verify(cms, content: content)
        {cms, verified}
      else
        cms = sign(signer, content)
        {:ok, verified} = Cmsex.verify(cms)
        {cms, verified}
      end
    end

    test "the cycle: stamp the content, sign with the attribute, verify", %{tsa: tsa, pki: pki} do
      {_cms, verified} = with_content_stamp(tsa, pki, "the content")

      assert {:ok, [stamp]} = Tspex.verify_content_time_stamp(verified, 0, trust: [tsa.root])
      assert stamp.info.digest == :crypto.hash(:sha256, "the content")
    end

    test "the attribute has the id-aa-ets-contentTimestamp type", %{tsa: tsa} do
      attribute = Tspex.content_time_stamp_attribute(content_stamp(tsa, "x"))
      assert attribute.type == {1, 2, 840, 113_549, 1, 9, 16, 2, 20}
      assert [_token] = attribute.values
    end

    test "a detached message gets the content from the caller", %{tsa: tsa, pki: pki} do
      {_cms, verified} = with_content_stamp(tsa, pki, "the content", true)
      assert verified.content == nil

      assert_raise ArgumentError, ~r/content/, fn ->
        Tspex.verify_content_time_stamp(verified, 0, trust: [tsa.root])
      end

      assert {:ok, [_]} =
               Tspex.verify_content_time_stamp(verified, 0,
                 trust: [tsa.root],
                 content: "the content"
               )

      digest = :crypto.hash(:sha256, "the content")

      assert {:ok, [_]} =
               Tspex.verify_content_time_stamp(verified, 0,
                 trust: [tsa.root],
                 content: {:digest, :sha256, digest}
               )
    end

    test "N92: other content", %{tsa: tsa, pki: pki} do
      {_cms, verified} = with_content_stamp(tsa, pki, "the content", true)

      assert failure(
               Tspex.verify_content_time_stamp(verified, 0,
                 trust: [tsa.root],
                 content: "another content"
               )
             ) == {:imprint_mismatch, :digest}
    end

    test "a stamp of other content than the one that was signed", %{tsa: tsa, pki: pki} do
      attribute = Tspex.content_time_stamp_attribute(content_stamp(tsa, "something else"))
      cms = sign(as_signer(pki, signed_attributes: [attribute]), "the content")
      {:ok, verified} = Cmsex.verify(cms)

      assert failure(Tspex.verify_content_time_stamp(verified, 0, trust: [tsa.root])) ==
               {:imprint_mismatch, :digest}
    end

    test "N93: no such attribute", %{tsa: tsa, pki: pki} do
      cms = sign(as_signer(pki))
      {:ok, verified} = Cmsex.verify(cms)

      assert reason(Tspex.verify_content_time_stamp(verified, 0, trust: [tsa.root])) ==
               :no_time_stamp
    end

    test "a signer that is not there", %{tsa: tsa, pki: pki} do
      {_cms, verified} = with_content_stamp(tsa, pki, "the content")

      assert failure(Tspex.verify_content_time_stamp(verified, 4, trust: [tsa.root])) ==
               {:signer_not_found, 4}
    end

    test "content given for a message that carries it, and a stamp that is not a stamp", %{
      tsa: tsa,
      pki: pki
    } do
      {_cms, verified} = with_content_stamp(tsa, pki, "the content")

      assert_raise ArgumentError, fn ->
        Tspex.verify_content_time_stamp(verified, 0, trust: [tsa.root], content: "x")
      end

      assert_raise ArgumentError, fn -> Tspex.content_time_stamp_attribute("token") end
      assert_raise ArgumentError, fn -> Tspex.verify_content_time_stamp(:nope, 0, trust: []) end
    end

    test "a stamp from a TSA that is not trusted", %{tsa: tsa, pki: pki} do
      {_cms, verified} = with_content_stamp(tsa, pki, "the content")
      other = TestTSA.new(root_tag: :elsewhere, tag: :elsewhere_tsa)

      assert {:error, %Error{reason: :untrusted}} =
               Tspex.verify_content_time_stamp(verified, 0, trust: [other.root])
    end
  end
end
