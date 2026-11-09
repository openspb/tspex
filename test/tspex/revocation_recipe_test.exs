defmodule Tspex.RevocationRecipeTest do
  # The recipe of guides/verification.md ("A revocation check from CRLs you
  # hold") is compiled from the guide and run against CRLs made here, so the
  # text cannot say something the code does not do.
  use Tspex.VerifyCase, async: false

  alias Tspex.{TestPKI, TestTSA, TimeStampedData}

  @guide Path.expand("../../guides/verification.md", __DIR__)
  @serial 424_242
  @ca_serial 777

  setup_all do
    code = recipe()
    [{module, _}] = Code.compile_string(code)
    on_exit(fn -> :code.purge(module) && :code.delete(module) end)

    tsa =
      TestTSA.new(
        tag: :revocation,
        root_tag: :revocation_root,
        intermediate: true,
        cert: [serial: @serial],
        ca: [serial: @ca_serial]
      )

    %{code: code, recipe: module, tsa: tsa}
  end

  # The first block of Elixir after the heading of the recipe.
  defp recipe do
    guide = File.read!(@guide)
    [_, after_heading] = String.split(guide, "## A revocation check from CRLs you hold", parts: 2)
    [_, code | _] = Regex.run(~r/```elixir\n(.*?)```/s, after_heading)
    code
  end

  # The block after the heading of the CRLs inside a TimeStampedData.
  defp tsd_snippet do
    guide = File.read!(@guide)
    [_, after_heading] = String.split(guide, "### The CRLs inside a `TimeStampedData`", parts: 2)
    [_, code | _] = Regex.run(~r/```elixir\n(.*?)```/s, after_heading)
    code
  end

  defp crls(tsa, tsa_crl_opts \\ [], ca_crl_opts \\ []) do
    ca_key = {:p256, :ca_revocation_root}

    [
      TestPKI.crl(tsa.intermediate, ca_key, tsa_crl_opts),
      TestPKI.crl(tsa.root, tsa.root_key, ca_crl_opts)
    ]
  end

  defp stamp(tsa, recipe, crls, gen_time \\ hours_ago(6)) do
    request = Tspex.request!("contract")
    response = TestTSA.response(tsa, request, gen_time: gen_time)

    Tspex.verify(response, request,
      trust: TestTSA.trust(tsa),
      revocation: recipe.check(crls)
    )
  end

  defp hours_ago(n),
    do: DateTime.utc_now() |> DateTime.add(-n * 3600) |> DateTime.truncate(:second)

  test "the recipe in the guide is formatted code", %{code: code} do
    assert code == code |> Code.format_string!() |> IO.iodata_to_binary() |> Kernel.<>("\n")
  end

  test "a certificate that is in no CRL passes", %{tsa: tsa, recipe: recipe} do
    assert {:ok, %{revocation: :checked, signer: %{path: [_, _, _]}}} =
             stamp(tsa, recipe, crls(tsa))

    other = [{99, hours_ago(1), 1}]
    assert {:ok, %{revocation: :checked}} = stamp(tsa, recipe, crls(tsa, revoked: other))
  end

  test "keyCompromise voids tokens made before the revocation too", %{tsa: tsa, recipe: recipe} do
    revoked = [{@serial, hours_ago(1), 1}]

    assert failure(stamp(tsa, recipe, crls(tsa, revoked: revoked))) ==
             {:untrusted, {:revocation, :revoked}}
  end

  test "a revocation with no reason, or unspecified, voids every token", %{
    tsa: tsa,
    recipe: recipe
  } do
    for entry <- [{@serial, hours_ago(1)}, {@serial, hours_ago(1), 0}] do
      assert failure(stamp(tsa, recipe, crls(tsa, revoked: [entry]))) ==
               {:untrusted, {:revocation, :revoked}}
    end
  end

  test "another reason voids only the tokens made at or after the revocation", %{
    tsa: tsa,
    recipe: recipe
  } do
    # cessationOfOperation, 3 hours ago
    crls = crls(tsa, revoked: [{@serial, hours_ago(3), 5}])

    assert {:ok, %{revocation: :checked}} = stamp(tsa, recipe, crls, hours_ago(6))

    assert failure(stamp(tsa, recipe, crls, hours_ago(2))) ==
             {:untrusted, {:revocation, :revoked}}
  end

  test "the intermediate CA is checked too, by the CRL of the root", %{tsa: tsa, recipe: recipe} do
    revoked = [{@ca_serial, hours_ago(1), 1}]

    assert failure(stamp(tsa, recipe, crls(tsa, [], revoked: revoked))) ==
             {:untrusted, {:revocation, :revoked}}
  end

  test "a CRL that is out of date is refused", %{tsa: tsa, recipe: recipe} do
    stale = [next_update: hours_ago(1)]

    assert failure(stamp(tsa, recipe, crls(tsa, stale))) ==
             {:untrusted, {:revocation, :crl_expired}}

    future = [this_update: DateTime.add(DateTime.utc_now(), 3600)]

    assert failure(stamp(tsa, recipe, crls(tsa, future))) ==
             {:untrusted, {:revocation, :crl_not_yet_valid}}
  end

  test "a CRL with no nextUpdate is taken as current", %{tsa: tsa, recipe: recipe} do
    assert {:ok, %{revocation: :checked}} = stamp(tsa, recipe, crls(tsa, next_update: nil))
  end

  test "a path with no CRL for one of its issuers is refused", %{tsa: tsa, recipe: recipe} do
    [for_tsa, _for_ca] = crls(tsa)
    assert failure(stamp(tsa, recipe, [for_tsa])) == {:untrusted, {:revocation, :no_crl}}
    assert failure(stamp(tsa, recipe, [])) == {:untrusted, {:revocation, :no_crl}}
  end

  test "a CRL that the issuer did not sign does not count", %{tsa: tsa, recipe: recipe} do
    forged = TestPKI.crl(tsa.intermediate, {:p256, :someone_else}, revoked: [])
    [_, for_ca] = crls(tsa)
    assert failure(stamp(tsa, recipe, [forged, for_ca])) == {:untrusted, {:revocation, :no_crl}}
  end

  test "now can be given, to check a CRL as of another date", %{tsa: tsa, recipe: recipe} do
    stale = crls(tsa, next_update: hours_ago(1))
    request = Tspex.request!("contract")
    response = TestTSA.response(tsa, request, gen_time: hours_ago(6))
    earlier = hours_ago(2)

    assert {:ok, %{revocation: :checked}} =
             Tspex.verify(response, request,
               trust: TestTSA.trust(tsa),
               revocation: recipe.check(stale, earlier)
             )
  end

  describe "the CRLs of a TimeStampedData" do
    setup %{recipe: _recipe} do
      # a TSA directly under the root, so that one CRL covers its path
      tsa =
        TestTSA.new(tag: :tsd_revocation, root_tag: :tsd_revocation_root, cert: [serial: 31_337])

      %{flat: tsa}
    end

    # Two tokens, the CRL in the first element, as the guide describes.
    defp chain_with_crl(tsa, crl, first_at, second_at) do
      content = "document"
      {:ok, imprint} = TimeStampedData.imprint(content)

      {:ok, tsd} =
        TimeStampedData.new(
          content,
          TestTSA.token(tsa, Tspex.request!(imprint), gen_time: first_at),
          trust: TestTSA.trust(tsa)
        )

      {:ok, next} = TimeStampedData.extension_imprint(tsd, crl: crl)

      {:ok, tsd} =
        TimeStampedData.extend(
          tsd,
          TestTSA.token(tsa, Tspex.request!(next), gen_time: second_at),
          crl: crl,
          trust: TestTSA.trust(tsa)
        )

      TimeStampedData.encode(tsd)
    end

    defp run_snippet(der, tsa) do
      {results, _} = Code.eval_string(tsd_snippet(), der: der, roots: TestTSA.trust(tsa))
      results
    end

    test "a CRL that does not list the TSA passes, as of the second token", %{flat: tsa} do
      first_at = hours_ago(5)
      second_at = hours_ago(4)

      crl =
        TestPKI.crl(tsa.root, tsa.root_key, this_update: hours_ago(6), next_update: hours_ago(3))

      der = chain_with_crl(tsa, crl, first_at, second_at)
      # the CRL is out of date today, and good when the second token was made
      assert run_snippet(der, tsa) == [:ok]
    end

    test "a revocation for key compromise is found", %{flat: tsa} do
      crl =
        TestPKI.crl(tsa.root, tsa.root_key,
          this_update: hours_ago(6),
          revoked: [{31_337, hours_ago(4), 1}]
        )

      der = chain_with_crl(tsa, crl, hours_ago(5), hours_ago(4))
      assert run_snippet(der, tsa) == [{:error, :revoked}]
    end

    test "another reason counts from its date: after the first token it is fine", %{flat: tsa} do
      crl =
        TestPKI.crl(tsa.root, tsa.root_key,
          this_update: hours_ago(6),
          revoked: [{31_337, hours_ago(3), 5}]
        )

      der = chain_with_crl(tsa, crl, hours_ago(5), hours_ago(4))
      assert run_snippet(der, tsa) == [:ok]
    end

    test "a CRL made after the second token is not current at that time", %{flat: tsa} do
      crl = TestPKI.crl(tsa.root, tsa.root_key, this_update: hours_ago(1))
      der = chain_with_crl(tsa, crl, hours_ago(5), hours_ago(4))
      assert run_snippet(der, tsa) == [{:error, :crl_not_yet_valid}]
    end

    test "an element with no CRL is skipped", %{flat: tsa} do
      content = "document"
      {:ok, imprint} = TimeStampedData.imprint(content)
      first = TestTSA.token(tsa, Tspex.request!(imprint), gen_time: hours_ago(5))
      {:ok, tsd} = TimeStampedData.new(content, first, trust: TestTSA.trust(tsa))
      {:ok, next} = TimeStampedData.extension_imprint(tsd)
      second = TestTSA.token(tsa, Tspex.request!(next), gen_time: hours_ago(4))
      {:ok, tsd} = TimeStampedData.extend(tsd, second, trust: TestTSA.trust(tsa))

      assert run_snippet(TimeStampedData.encode(tsd), tsa) == []
    end
  end
end
