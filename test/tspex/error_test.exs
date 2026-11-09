defmodule Tspex.ErrorTest do
  use ExUnit.Case, async: true

  alias Tspex.Error

  test "every reason has a message that says something" do
    reasons = [
      {:malformed, nil},
      {:malformed, :genTime},
      {:limit_exceeded, :max_depth},
      {:unsupported_version, 2},
      {:unknown_status, 6},
      {:unknown_fail_info, [{:unknown_bit, 30}]},
      {:rejection, %{fail_info: [:bad_alg], text: []}},
      {:rejection, nil},
      {:waiting, nil},
      {:revocation_warning, nil},
      {:revocation_notification, nil},
      {:granted_with_mods, nil},
      {:token_missing, nil},
      {:unexpected_token, nil},
      {:not_a_time_stamp_token, :content_type},
      {:signer_count, 2},
      {:token_invalid, :invalid_signature},
      {:signing_certificate_missing, nil},
      {:bad_tsa_certificate, :eku_missing},
      {:untrusted, {:revocation, :keyCompromise}},
      {:imprint_mismatch, :digest},
      {:nonce_missing, nil},
      {:nonce_mismatch, nil},
      {:policy_mismatch, nil},
      {:tsa_name_mismatch, nil},
      {:critical_extension, {1, 2, 3}},
      {:gen_time_skew, nil},
      {:weak_algorithm, :md5},
      {:no_time_stamp, nil},
      {:unsupported_evidence, nil},
      {:time_order, 1},
      {:transport, {:http_status, 500}}
    ]

    for {reason, detail} <- reasons do
      message = Exception.message(Error.new(reason, detail))
      assert is_binary(message) and byte_size(message) > 10, inspect(reason)
    end
  end

  test "OIDs are shown in dotted form" do
    assert Exception.message(Error.new(:critical_extension, {1, 2, 840, 5})) =~ "1.2.840.5"
  end

  test "it can be raised and matched" do
    assert_raise Error, ~r/rejected/, fn -> raise Error.new(:rejection) end
  end

  test "from_cms/2 keeps the original as the cause" do
    cause = Cmsex.Error.new(:invalid_signature)
    error = Error.from_cms(:token_invalid, cause)
    assert error.reason == :token_invalid
    assert error.cause == cause
  end

  test "a detail that is a long binary is not shown whole" do
    message = Exception.message(Error.new(:malformed, {:data, :binary.copy(<<255>>, 400)}))
    assert byte_size(message) < 200
  end
end
