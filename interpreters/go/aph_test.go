package aph

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// newTestRuntime builds a Runtime and closes it when the test ends.
//
// One instance per test rather than one shared across the suite: a Runtime owns
// mutable linear memory and is documented as not concurrency-safe, and a suite
// that quietly shared one would be modelling a usage the package tells callers
// not to have.
func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	runtime, err := New(context.Background())
	if err != nil {
		t.Fatalf("instantiating the embedded module: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := runtime.Close(context.Background()); closeErr != nil {
			t.Errorf("closing the runtime: %v", closeErr)
		}
	})
	return runtime
}

func TestTheSignedGoldenIsAdmittedByEveryOperation(t *testing.T) {
	// WHY: this is the admit half of the binding's whole claim — the published
	// SIGNED golden, carried across a raw pointer ABI into a WebAssembly module
	// and back, must come out intact and read correctly. It is the first thing
	// that breaks if the embedded artifact, the ABI record layout, or the
	// pointer arithmetic is wrong, and it is the case a stranger will try first.
	//
	// PINS, in one pass over the four operations: the golden strict-parses; the
	// §7.1.11 structure gate names PrincipalSigned, which is the mode its
	// two-element chain actually supports; the no-downgrade gate admits that
	// mode; and parse and serialize agree on canonical compact text, so the two
	// directions of the boundary are one operation and not two.
	ctx := context.Background()
	runtime := newTestRuntime(t)
	golden := principalSignedGolden(t)

	parsed, err := runtime.ParseEnvelopeJSON(ctx, golden)
	if err != nil {
		t.Fatalf("the published golden must parse across the wasm boundary: %v", err)
	}
	if parsed == "" {
		t.Fatal("a successful parse must return the re-emitted envelope, not empty text")
	}

	mode, err := runtime.VerifyProofStructure(ctx, golden)
	if err != nil {
		t.Fatalf("the golden's proof chain must satisfy the structural gate: %v", err)
	}
	if mode != ModePrincipalSigned {
		t.Errorf("the golden's two-proof chain supports %q, got %q", ModePrincipalSigned, mode)
	}

	if err := runtime.RequireAttestationMode(ctx, golden, ModePrincipalSigned); err != nil {
		t.Errorf("the no-downgrade gate must admit the mode the structure proves: %v", err)
	}

	serialized, err := runtime.SerializeEnvelope(ctx, golden)
	if err != nil {
		t.Fatalf("a value that parsed must re-serialize: %v", err)
	}
	if serialized != parsed {
		t.Error("parse and serialize must agree on canonical compact text")
	}
}

func TestAForgedPrincipalLabelIsRefusedWithTheExactCode(t *testing.T) {
	// WHY: VerifyProofStructure is exported precisely so a Go consumer can
	// detect a forged PrincipalSigned label (§7.1.11) instead of trusting the
	// self-asserted string. Writing that label above a single-object proof is
	// the forgery, and the refusal has to arrive with its identity intact after
	// crossing a byte boundary that carries no types.
	//
	// PINS: the refusal is a *aph.Error reachable with errors.As — the Go
	// spelling of the identity the siblings give a caller — its Code is exactly
	// APH_E013 and not merely a message that mentions it, and the message still
	// leads with the reference implementation's own text.
	ctx := context.Background()
	runtime := newTestRuntime(t)

	forged := substituteOnce(
		t,
		legacySlackReply(t),
		`"decision": "AskEveryTime",`,
		`"attestationMode": "PrincipalSigned", "decision": "AskEveryTime",`,
	)

	_, err := runtime.VerifyProofStructure(ctx, forged)
	if err == nil {
		t.Fatal("a PrincipalSigned label above a single proof must be rejected")
	}

	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("the refusal must reach a caller as *aph.Error, got %T: %v", err, err)
	}
	if refusal.Code != CodeForgedPrincipalLabel {
		t.Errorf("Code must be exactly %q, got %q (message: %s)", CodeForgedPrincipalLabel, refusal.Code, refusal.Message)
	}
	if !strings.HasPrefix(refusal.Message, CodeForgedPrincipalLabel+":") {
		t.Errorf("the message must lead with the code, got: %s", refusal.Message)
	}
}

func TestAModeDowngradeIsRefusedWithTheExactCode(t *testing.T) {
	// WHY: RequireAttestationMode is the §8.3.1 step-1a no-downgrade gate; a
	// verifier requiring PrincipalSigned MUST refuse NotaryAttested rather than
	// silently accept the weaker claim.
	//
	// PINS: both accepting paths, the refusal as a *aph.Error whose Code is
	// exactly APH_E012, and that an unrecognized mode spelling errors instead of
	// defaulting — a typo that defaulted weak would BE the downgrade this gate
	// exists to refuse, which is why that branch is duplicated identically in
	// all four bindings rather than centralized.
	ctx := context.Background()
	runtime := newTestRuntime(t)
	golden := principalSignedGolden(t)
	legacy := legacySlackReply(t)

	if err := runtime.RequireAttestationMode(ctx, golden, ModePrincipalSigned); err != nil {
		t.Errorf("the golden satisfies a PrincipalSigned-only policy: %v", err)
	}
	if err := runtime.RequireAttestationMode(ctx, legacy, ModeNotaryAttested); err != nil {
		t.Errorf("a legacy envelope satisfies a NotaryAttested requirement: %v", err)
	}

	err := runtime.RequireAttestationMode(ctx, legacy, ModePrincipalSigned)
	if err == nil {
		t.Fatal("NotaryAttested must not satisfy a PrincipalSigned requirement")
	}
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("the refusal must reach a caller as *aph.Error, got %T: %v", err, err)
	}
	if refusal.Code != CodeModeDowngrade {
		t.Errorf("Code must be exactly %q, got %q (message: %s)", CodeModeDowngrade, refusal.Code, refusal.Message)
	}

	if err := runtime.RequireAttestationMode(ctx, legacy, "Notarized"); err == nil {
		t.Error("an unknown mode string must error, never default to a mode")
	}
}

func TestBothProofArmsRoundTripValueLossless(t *testing.T) {
	// WHY: the envelope's proof field is an untagged union — a single object
	// (NotaryAttested) or a two-element chain (PrincipalSigned, principal first)
	// — and a boundary that got arm selection wrong would corrupt exactly one of
	// the two while looking healthy on the other. Both published arms are
	// therefore driven through, against the bytes this repository publishes.
	//
	// PINS, per arm, with no Go decoder anywhere in the path: the published
	// document is admitted; re-emission is a FIXED POINT, so parsing the output
	// yields the output and nothing was lost that a re-parse would notice; both
	// boundary directions produce the same canonical text; the arm survives as
	// itself, read off the canonical text's proof punctuation; the proof COUNT
	// survives, so a chain cannot be quietly collapsed to one; and the published
	// bodySize survives as a bare integer literal rather than as a float.
	ctx := context.Background()
	runtime := newTestRuntime(t)

	arms := []struct {
		name string
		// document is the published bytes.
		document string
		// proofOpens is the canonical-text punctuation the surviving arm must
		// show: `[` for the chain arm, `{` for the single-object arm.
		proofOpens string
		// proofValues is how many signatures the arm carries.
		proofValues int
		// bodySize is the published integer, pinned as a literal the test knows
		// INDEPENDENTLY of the parse — a constant compared against is what
		// detects a widened integer.
		bodySize string
	}{
		{
			name:        "the signed PrincipalSigned golden (chain arm)",
			document:    principalSignedGolden(t),
			proofOpens:  `"proof":[`,
			proofValues: 2,
			// 427 is the byte length of examples/principal_signed_body.txt, the
			// published body this golden attests.
			bodySize: `"bodySize":427`,
		},
		{
			name:        "a legacy pre-chain envelope (single-object arm)",
			document:    legacySlackReply(t),
			proofOpens:  `"proof":{`,
			proofValues: 1,
			bodySize:    `"bodySize":1842`,
		},
	}

	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			normalized, err := runtime.ParseEnvelopeJSON(ctx, arm.document)
			if err != nil {
				t.Fatalf("the published document must cross the text boundary: %v", err)
			}

			again, err := runtime.ParseEnvelopeJSON(ctx, normalized)
			if err != nil {
				t.Fatalf("the re-emitted text must itself strict-parse: %v", err)
			}
			if again != normalized {
				t.Error("the round trip must be a fixed point; a second pass changed the text")
			}

			serialized, err := runtime.SerializeEnvelope(ctx, arm.document)
			if err != nil {
				t.Fatalf("the published document must serialize: %v", err)
			}
			if serialized != normalized {
				t.Error("both boundary directions must produce the same canonical text")
			}

			if !strings.Contains(normalized, arm.proofOpens) {
				t.Errorf("the proof arm must survive as itself; %s is absent from the canonical text", arm.proofOpens)
			}
			if got := strings.Count(normalized, `"proofValue":`); got != arm.proofValues {
				t.Errorf("the arm carries %d signatures, the canonical text carries %d", arm.proofValues, got)
			}
			if !strings.Contains(normalized, arm.bodySize) {
				t.Errorf("an integer field must cross the boundary without widening; %s is absent", arm.bodySize)
			}
		})
	}
}

func TestAnIntegerNoDoubleCanHoldSurvivesTheTextBoundary(t *testing.T) {
	// WHY: this is the boundary rule's whole reason, stated as an experiment
	// rather than an assertion, and on THIS runtime it carries its original
	// meaning. 2^53 + 1 is the smallest positive integer an IEEE-754 double
	// cannot represent, and Go's encoding/json decodes every JSON number into
	// float64 unless a caller opts out — so an envelope that entered Go as
	// decoded values and came back would arrive rounded.
	//
	// The first half of this test PROVES the hazard is live rather than folklore
	// by running the widened document through Go's own decoder and watching the
	// integer change. The second half proves the binding is immune, because
	// nothing on this side ever decodes it.
	//
	// PINS: exact u64 fidelity of a bodySize no double can express, end to end
	// through the text boundary; and the demonstration that the same document
	// does NOT survive Go's object route, which is what makes the immunity worth
	// asserting.
	const beyondDouble = "9007199254740993"
	const roundedByFloat64 = "9007199254740992"

	ctx := context.Background()
	runtime := newTestRuntime(t)

	widened := substituteOnce(
		t,
		legacySlackReply(t),
		`"bodySize": 1842,`,
		`"bodySize": `+beyondDouble+`,`,
	)

	// The hazard, demonstrated. encoding/json appears in this file and in no
	// other: the package itself decodes no JSON, and a separate test pins that.
	var decoded map[string]any
	if err := json.Unmarshal([]byte(widened), &decoded); err != nil {
		t.Fatalf("the widened document must be valid JSON: %v", err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encoding the decoded document: %v", err)
	}
	if strings.Contains(string(reencoded), beyondDouble) {
		t.Fatalf("this test assumes Go's object route rounds %s; it did not, so the "+
			"demonstration below no longer demonstrates anything", beyondDouble)
	}
	if !strings.Contains(string(reencoded), roundedByFloat64) {
		t.Errorf("Go's object route was expected to round %s down to %s", beyondDouble, roundedByFloat64)
	}

	// The immunity. Same document, across the text boundary, unrounded.
	normalized, err := runtime.ParseEnvelopeJSON(ctx, widened)
	if err != nil {
		t.Fatalf("a bodySize beyond double precision must cross the text boundary: %v", err)
	}
	if !strings.Contains(normalized, `"bodySize":`+beyondDouble) {
		t.Errorf("an integer beyond double precision must cross without rounding; "+
			"the canonical text does not carry %s", beyondDouble)
	}
}

func TestTheBoundaryIsStringInAndStringOut(t *testing.T) {
	// WHY: the boundary rule made mechanical rather than documented. In Elixir
	// this needs a runtime probe because a NIF could grow a term-accepting
	// arity; in Go the type system settles the input side at compile time, so
	// the pin is a set of method EXPRESSIONS — if any signature ever grows a
	// struct, a map, or an io.Reader, this file stops compiling.
	//
	// PINS: (1) all four operations exist with exactly the shapes the four-way
	// parity contract names, string in and string out, and RequireAttestationMode
	// carrying no success value because its success has none; (2) at run time,
	// every operation's output is itself TEXT on the same boundary — the module
	// re-accepts what it emitted — so the boundary cannot start handing back an
	// opaque handle while still type-checking.
	var (
		_ func(*Runtime, context.Context, string) (string, error) = (*Runtime).ParseEnvelopeJSON
		_ func(*Runtime, context.Context, string) (string, error) = (*Runtime).SerializeEnvelope
		_ func(*Runtime, context.Context, string) (string, error) = (*Runtime).VerifyProofStructure
		_ func(*Runtime, context.Context, string, string) error   = (*Runtime).RequireAttestationMode
	)

	ctx := context.Background()
	runtime := newTestRuntime(t)
	golden := principalSignedGolden(t)

	parsed, err := runtime.ParseEnvelopeJSON(ctx, golden)
	if err != nil {
		t.Fatalf("parsing the golden: %v", err)
	}
	if _, err := runtime.ParseEnvelopeJSON(ctx, parsed); err != nil {
		t.Errorf("the parse output must be envelope TEXT the boundary re-accepts: %v", err)
	}

	serialized, err := runtime.SerializeEnvelope(ctx, golden)
	if err != nil {
		t.Fatalf("serializing the golden: %v", err)
	}
	if _, err := runtime.SerializeEnvelope(ctx, serialized); err != nil {
		t.Errorf("the serialize output must be envelope TEXT the boundary re-accepts: %v", err)
	}

	mode, err := runtime.VerifyProofStructure(ctx, golden)
	if err != nil {
		t.Fatalf("verifying the golden's structure: %v", err)
	}
	if err := runtime.RequireAttestationMode(ctx, golden, mode); err != nil {
		t.Errorf("the structure gate's output must be a mode the policy gate accepts: %v", err)
	}
}

func TestAShapeRefusalCarriesNoProtocolCode(t *testing.T) {
	// WHY: the package documents two refusal shapes on ONE error type —
	// protocol refusals carry an APH_E code, shape refusals carry the parser's
	// message — and a caller who reaches for Code must be able to tell them
	// apart. A shape refusal dressed in a protocol code would be a binding
	// claiming a rule was reached when none was.
	//
	// PINS: an unknown field (the deny_unknown_fields rule) refuses as
	// *aph.Error; its Code is EMPTY; and its message does not lead with a code
	// it did not earn.
	ctx := context.Background()
	runtime := newTestRuntime(t)

	smuggled := substituteOnce(
		t,
		legacySlackReply(t),
		`"humanPrincipal": {`,
		`"notAField": true, "humanPrincipal": {`,
	)

	_, err := runtime.ParseEnvelopeJSON(ctx, smuggled)
	if err == nil {
		t.Fatal("an unknown credentialSubject field must be a hard error")
	}
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("a shape refusal must reach a caller as *aph.Error too, got %T: %v", err, err)
	}
	if refusal.Code != "" {
		t.Errorf("a shape refusal must claim no protocol code, got %q", refusal.Code)
	}
	if strings.HasPrefix(refusal.Message, "APH_E") {
		t.Errorf("a shape refusal must not lead with a protocol code, got: %s", refusal.Message)
	}
}

func TestAClosedSetValueThisBuildDoesNotDefineIsRefused(t *testing.T) {
	// WHY: §7.1.5 and §7.1.6 close the channel and content-class vocabularies,
	// and aph-core models them as closed TYPES — so an unrecognized value is a
	// strict-parse refusal (§8.3 step 1) rather than a string that rides through
	// to a delivery decision no verifier can evaluate. What needs a test HERE is
	// the ABI hop: the refusal is a serde_json custom error, stringified inside
	// the module and copied out of linear memory as a status-1 record, and go
	// test is the only gate that ever runs this ABI — so nothing else can say
	// whether the offending value and the closed set are still in what a Go
	// caller reads. A message flattened to "invalid value" would still refuse and
	// would still be useless to the producer who has to fix it.
	//
	// PINS, per field: the refusal reaches a caller as *aph.Error; its Code is
	// EMPTY, because §8.3 step 1 is the layer below the taxonomy and a parse
	// dressed as a protocol verdict sends the reader to inspect key material over
	// a typo; the offending VALUE survives the boundary; and the closed SET
	// survives, including the irregular spellings a producer most plausibly gets
	// wrong (google_chat is snake_case among single words, BulkSend is camel
	// among short names).
	ctx := context.Background()
	runtime := newTestRuntime(t)

	closedSets := []struct {
		name string
		// anchor is the published line this derivation replaces, exactly once.
		anchor string
		// replacement carries the value no build defines.
		replacement string
		// offending is that value, as the refusal must name it.
		offending string
		// member is one member of the set the refusal must still enumerate.
		member string
	}{
		{
			name:        "an unrecognized channel kind (§7.1.5)",
			anchor:      `"kind": "slack",`,
			replacement: `"kind": "squillo",`,
			offending:   "squillo",
			member:      "google_chat",
		},
		{
			name:        "an unrecognized content class (§7.1.6)",
			anchor:      `"contentClass": "Reply",`,
			replacement: `"contentClass": "Digest",`,
			offending:   "Digest",
			member:      "BulkSend",
		},
	}

	for _, closedSet := range closedSets {
		t.Run(closedSet.name, func(t *testing.T) {
			document := substituteOnce(t, legacySlackReply(t), closedSet.anchor, closedSet.replacement)

			_, err := runtime.ParseEnvelopeJSON(ctx, document)
			if err == nil {
				t.Fatal("a value outside the closed set must be refused, never carried")
			}
			var refusal *Error
			if !errors.As(err, &refusal) {
				t.Fatalf("the refusal must reach a caller as *aph.Error, got %T: %v", err, err)
			}
			if refusal.Code != "" {
				t.Errorf("a strict-parse refusal must claim no protocol code, got %q", refusal.Code)
			}
			if !strings.Contains(refusal.Message, closedSet.offending) {
				t.Errorf(
					"the refusal must name the offending value %q, got: %s",
					closedSet.offending, refusal.Message,
				)
			}
			if !strings.Contains(refusal.Message, "closed set") ||
				!strings.Contains(refusal.Message, closedSet.member) {
				t.Errorf(
					"the refusal must name the closed set (including %q), got: %s",
					closedSet.member, refusal.Message,
				)
			}
		})
	}
}
