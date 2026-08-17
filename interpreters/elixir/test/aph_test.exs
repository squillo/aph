defmodule APHTest do
  use ExUnit.Case, async: true

  # 427 is the byte length of the published body this golden attests. It is
  # pinned by hand and MOVES WITH THE GOLDEN: comparing against a constant the
  # test knows INDEPENDENTLY of the parse is what detects a number mangled in
  # transit, which an assertion derived from the same parse never could.
  @golden_body_size 427

  test "the published signed golden is admitted and reads as PrincipalSigned" do
    # WHY: this is the whole point of the binding — the bytes this repository
    # publishes, carried across the term boundary, must come back admitted and
    # honestly labelled. PINS: the golden strict-parses through the NIF (so the
    # crate, the shared object and the load path are all real), and the
    # structure gate reads the CHAIN arm as `PrincipalSigned` rather than
    # trusting the self-asserted string in the document.
    golden = APH.TestCorpus.principal_signed_golden()

    assert {:ok, normalized} = APH.parse_envelope_json(golden)
    assert is_binary(normalized)
    assert {:ok, "PrincipalSigned"} = APH.verify_proof_structure(golden)
  end

  test "the golden round-trips through the text boundary losing nothing" do
    # WHY: the JSON-text rule exists to keep the untagged proof union out of a
    # second deserializer's hands, and the CHAIN arm is the one a forged label
    # imitates — so the published golden must survive the route with its arm
    # and its numbers intact. PINS: value-losslessness against the published
    # bytes, the chain arm surviving as a two-element list rather than being
    # collapsed, exact integer fidelity, and that re-feeding the canonical
    # output is a fixed point (so `serialize_envelope/1` and
    # `parse_envelope_json/1` really are one operation from two directions).
    golden = APH.TestCorpus.principal_signed_golden()

    assert {:ok, normalized} = APH.parse_envelope_json(golden)
    assert Jason.decode!(normalized) == Jason.decode!(golden)

    decoded = Jason.decode!(normalized)
    assert is_list(decoded["proof"]), "the golden's proof chain must survive as the chain arm"
    assert length(decoded["proof"]) == 2

    assert get_in(decoded, ["credentialSubject", "communication", "bodySize"]) ==
             @golden_body_size

    assert {:ok, ^normalized} = APH.serialize_envelope(normalized)
  end

  test "a pre-chain envelope survives as the single-object arm" do
    # WHY: the proof union has TWO arms and a term route would put both at
    # risk; the test above pins the chain, this one pins the other. A pre-chain
    # envelope (single-object `proof`, no `attestationMode` at all) must cross
    # value-lossless and come back as a single object — never silently promoted
    # to a one-element chain, which is the shape a careless encoder produces.
    legacy = APH.TestCorpus.legacy_slack_reply()

    assert {:ok, normalized} = APH.serialize_envelope(legacy)
    assert Jason.decode!(normalized) == Jason.decode!(legacy)

    decoded = Jason.decode!(normalized)
    assert is_map(decoded["proof"]), "a single-object proof must not become a chain"
    assert {:ok, "NotaryAttested"} = APH.verify_proof_structure(legacy)
  end

  test "a PrincipalSigned label above a single-object proof is refused with APH_E013" do
    # WHY: `verify_proof_structure/1` is exported precisely so a BEAM consumer
    # can detect a forged `PrincipalSigned` label instead of believing the
    # string in the document. PINS: the refusal happens, and it reaches Elixir
    # as `{:error, message}` whose message LEADS WITH `APH_E013` — the exact
    # identity a caller matches on, and the same one the JS binding puts on a
    # thrown message and the Python binding on `str(e)`.
    #
    # The forged envelope is derived here in full view rather than committed:
    # the corpus is the published one, and nothing new is signed for a test.
    forged =
      APH.TestCorpus.legacy_slack_reply()
      |> Jason.decode!()
      |> put_in(["credentialSubject", "policy", "attestationMode"], "PrincipalSigned")
      |> Jason.encode!()

    assert {:error, message} = APH.verify_proof_structure(forged)

    assert String.starts_with?(message, "APH_E013"),
           "the refusal must lead with the APH_E013 code, got: #{message}"
  end

  test "requiring PrincipalSigned refuses the weaker mode with APH_E012" do
    # WHY: `require_attestation_mode/2` is the no-downgrade gate — a verifier
    # that requires `PrincipalSigned` MUST refuse `NotaryAttested` rather than
    # quietly accept the weaker claim. PINS: both accepting paths return the
    # bare `:ok` this surface promises, the refusal leads with `APH_E012`, and
    # an unrecognized mode spelling is an error rather than a default, because
    # a typo that defaulted to the weaker mode would BE the downgrade.
    golden = APH.TestCorpus.principal_signed_golden()
    legacy = APH.TestCorpus.legacy_slack_reply()

    assert :ok = APH.require_attestation_mode(golden, "PrincipalSigned")
    assert :ok = APH.require_attestation_mode(legacy, "NotaryAttested")

    assert {:error, message} = APH.require_attestation_mode(legacy, "PrincipalSigned")

    assert String.starts_with?(message, "APH_E012"),
           "the refusal must lead with the APH_E012 code, got: #{message}"

    assert {:error, _unknown_mode} = APH.require_attestation_mode(legacy, "Notarized")
  end

  test "a shape refusal carries the parser's message and claims no protocol code" do
    # WHY: the surface promises TWO refusal shapes on one `{:error, message}`
    # tuple — protocol refusals lead with `APH_E*`, shape refusals carry the
    # parser's message — and a caller matching on the code prefix must not be
    # fooled by a document that never reached a protocol rule. PINS: an unknown
    # field is a hard refusal (APH parses with unknown fields DENIED, so it is
    # never silently dropped), and its message is not dressed up with a code it
    # did not earn.
    smuggled =
      APH.TestCorpus.legacy_slack_reply()
      |> Jason.decode!()
      |> put_in(["credentialSubject", "notAField"], true)
      |> Jason.encode!()

    assert {:error, message} = APH.parse_envelope_json(smuggled)

    refute String.starts_with?(message, "APH_E"),
           "a shape refusal must not claim a protocol code, got: #{message}"
  end
end
