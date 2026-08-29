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

  test "a value outside a closed set is refused, and the refusal names the value" do
    # WHY: §7.1.5 and §7.1.6 close the channel and content-class vocabularies,
    # and `aph-core` models them as closed TYPES — so an unrecognized value is
    # a strict-parse refusal (§8.3 step 1) rather than a string that rides
    # through to a delivery decision no verifier can evaluate. What needs a
    # test HERE is the term hop: the refusal is a `serde_json` custom error,
    # stringified in Rust and encoded as a binary, and `mix test` is the only
    # gate that ever sees the term — so nothing else can say whether the
    # offending value and the closed set are still in what a BEAM caller reads.
    # A message flattened to "invalid value" would still refuse and would still
    # be useless to the producer who has to fix it.
    #
    # PINS, per field: the refusal arrives as `{:error, message}`; the offending
    # VALUE survives the boundary; the closed SET survives, including the
    # irregular spellings a producer most plausibly gets wrong (`google_chat`
    # is snake_case among single words, `BulkSend` camel among short names);
    # and the message claims NO `APH_E` code, because §8.3 step 1 is the layer
    # below the taxonomy and a parse dressed as a protocol verdict sends the
    # reader to inspect key material over a typo.
    for {path, offending, member} <- [
          {["credentialSubject", "channel", "kind"], "carrier_pigeon", "google_chat"},
          {["credentialSubject", "policy", "decision"], "Sometimes", "NeverAllow"},
          {["credentialSubject", "communication", "contentClass"], "Digest", "BulkSend"}
        ] do
      document =
        APH.TestCorpus.legacy_slack_reply()
        |> Jason.decode!()
        |> put_in(path, offending)
        |> Jason.encode!()

      assert {:error, message} = APH.parse_envelope_json(document)

      assert String.contains?(message, offending),
             "the refusal must name the offending value #{offending}, got: #{message}"

      assert String.contains?(message, "closed set") and String.contains?(message, member),
             "the refusal must name the closed set (including #{member}), got: #{message}"

      refute String.starts_with?(message, "APH_E"),
             "a strict-parse refusal must not claim a protocol code, got: #{message}"
    end
  end

  test "the golden's embedded mandate answers validity at both sides of its window" do
    # WHY: `mandate_is_valid_at/2` is one of the two verification exports the
    # parity contract owes every binding; inputs DERIVED from the published
    # golden — the mandate embedded at `policy.delegationMandate`, timestamps
    # inside and after its own validFrom/validUntil — so nothing asserts a
    # fact the corpus does not carry.
    # PINS: {:ok, true} inside; {:ok, false} after; {:ok, false} for garbage
    # time (the core's documented "parsing failure returns false", delegated
    # and not re-invented); {:error, _} for a mandate that is not JSON.
    golden = APH.TestCorpus.principal_signed_golden()
    envelope = Jason.decode!(golden)
    mandate = Jason.encode!(envelope["credentialSubject"]["policy"]["delegationMandate"])

    assert {:ok, true} = APH.mandate_is_valid_at(mandate, "2026-05-21T12:00:00Z")
    assert {:ok, false} = APH.mandate_is_valid_at(mandate, "2026-06-01T00:00:00Z")
    assert {:ok, false} = APH.mandate_is_valid_at(mandate, "not-a-timestamp")
    assert {:error, _} = APH.mandate_is_valid_at("{not json", "2026-05-21T12:00:00Z")
  end

  test "the golden's mandate binding verifies and a retargeted mandate refuses" do
    # WHY: the other owed verification export. Admit half runs the WHOLE core
    # check on the published golden; the refusal retargets the embedded
    # mandate's `agentDid` so one §7.1.7.1 identity equality fails and
    # nothing else moves.
    golden = APH.TestCorpus.principal_signed_golden()
    assert :ok = APH.verify_embedded_mandate_binding(golden)

    broken =
      golden
      |> Jason.decode!()
      |> put_in(
        ["credentialSubject", "policy", "delegationMandate", "agentDid"],
        "did:web:other-agent.example"
      )
      |> Jason.encode!()

    assert {:error, message} = APH.verify_embedded_mandate_binding(broken)
    assert message =~ "APH_E"
  end


  describe "the v0.2 wire-version rule at the NIF boundary" do
    # The shared strict-parse entry in the reference core carries the rule;
    # this pins that the NIF boundary inherited it rather than re-implying it.
    test "the draft vector parses and its downgrade refuses" do
      vector =
        Path.join([__DIR__, "..", "..", "..", "examples", "v0.2", "sealed_envelope.json"])
        |> File.read!()

      assert {:ok, _} = APH.parse_envelope_json(vector)

      downgraded = String.replace(vector, ~s("aphVersion": "0.2"), ~s("aphVersion": "0.1"))
      assert {:error, message} = APH.parse_envelope_json(downgraded)
      assert message =~ "not declared"
    end
  end
end
