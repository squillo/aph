// Package aph exposes the APH (Agent per Human) v0.1 envelope operations to Go.
//
// This is a BINDING of the Rust reference implementation, not a second
// implementation of the protocol. There is no protocol logic on this side of
// the boundary: no cryptography, no canonicalization, no JSON re-encoding of an
// envelope. Every operation hands bytes to a compiled WebAssembly module built
// from `aph-core` and reads a verdict back.
//
// # How it works, and why there is no cgo
//
// The module under interpreters/rust/aph-wasm-abi compiles to a plain
// wasm32 artifact with a documented pointer/length ABI — no wasm-bindgen,
// because its exports need JavaScript glue no Go host can supply. This package
// embeds that artifact and runs it in-process under [wazero], a pure-Go
// WebAssembly runtime. The consequence worth stating plainly: `go get` works
// with no C toolchain, no cgo and no per-platform build, and the same artifact
// runs everywhere Go runs. Call overhead is irrelevant at envelope sizes.
//
// The embedded artifact is VERIFIED, not trusted. CI reinstalls the pinned Rust
// toolchain, rebuilds the module and byte-diffs it against the committed copy;
// a mismatch fails the push. See the README for the regeneration recipe.
//
// # Envelopes cross as JSON TEXT, in both directions
//
// Every function takes a JSON string and returns a JSON string. Envelopes never
// cross as maps, structs or any decoded form, and that is a structural safety
// property rather than a convenience — it is the same rule the wasm/TS, Python
// and Elixir bindings enforce.
//
// The envelope's proof field is an untagged union: a single object
// (NotaryAttested) or a two-element chain (PrincipalSigned, principal first).
// Untagged matching is exactly where a value that changed shape can silently
// change which arm deserializes, and a decoded route hands that decision to a
// SECOND deserializer reading whatever the caller's values happen to hold.
//
// ⛔ On this runtime that is the ORIGINAL hazard, in its original form.
// encoding/json decodes every JSON number into float64 unless the caller
// explicitly opts out, so an envelope decoded into Go values and handed back
// would round bodySize at 2^53 — the Elixir binding had to restate the argument
// because Erlang integers are arbitrary precision, and nothing needs restating
// here. Text in, text out: the only number and union parser that ever runs is
// the one inside the module. The suite's 2^53+1 test is the tripwire, and it
// builds its own fixture with a TEXT edit precisely because encoding/json would
// round the number the test exists to protect.
//
// # Export parity, a four-way contract
//
// This binding, the wasm/TS binding, the Python binding and the Elixir binding
// expose the SAME four envelope-facing operations, with the same semantics and
// the same error identity, each in its language's idiom:
//
//	wasm/TS                   Python                      Elixir                            Go
//	parseEnvelopeJson         parse_envelope_json         APH.parse_envelope_json/1         Runtime.ParseEnvelopeJSON
//	serializeEnvelope         serialize_envelope          APH.serialize_envelope/1          Runtime.SerializeEnvelope
//	verifyProofStructure      verify_proof_structure      APH.verify_proof_structure/1      Runtime.VerifyProofStructure
//	requireAttestationMode    require_attestation_mode    APH.require_attestation_mode/2    Runtime.RequireAttestationMode
//
// None of the four may grow an operation, a semantic, or an error spelling the
// others lack: bindings that teach different things about one protocol are how
// a protocol acquires several meanings. Operatively — a change to this surface
// is unfinished until the same change lands in the other three, and the reverse.
//
// What none of them is: independent evidence. A binding that agrees with the
// reference agrees with itself. "Can a stranger build this from the
// specification alone?" is answered by an implementation that shares no code
// with the reference, and no binding is or claims to be one.
//
// # Errors
//
// Every refusal is an [*Error], and a caller matches a protocol code exactly:
//
//	var aphErr *aph.Error
//	if errors.As(err, &aphErr) && aphErr.Code == aph.CodeForgedPrincipalLabel {
//		// a PrincipalSigned label above a structure that cannot bear it
//	}
//
// There are two kinds, and Code is what tells them apart. A PROTOCOL refusal
// carries the reference implementation's own message, which leads with its
// APH_E code, and Code holds that code. A SHAPE refusal (a field APH never
// defined, a malformed document) carries the parser's message and Code is
// empty, because no protocol rule was reached and no code was earned. That
// distinction is the same one a TypeScript caller reads off a thrown message, a
// Python caller off str(e), and an Elixir caller off {:error, "APH_E013" <> _}.
//
// # Concurrency
//
// A [Runtime] is NOT safe for concurrent use. It owns one WebAssembly instance,
// and that instance's linear memory is shared mutable state: two goroutines
// allocating in it at once corrupt each other's buffers. Give each goroutine
// its own Runtime.
//
// No lock is provided, and that is a decision rather than an omission. A mutex
// inside this package would serialize every caller onto one instance and hide
// the contention instead of removing it, while a caller that knows its own
// concurrency shape can hold a pool, a per-worker instance, or a single
// instance behind its existing request path. The type says what it is; the
// caller decides what to do about it.
//
// [wazero]: https://wazero.io
package aph

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Attestation-mode wire spellings, as the protocol puts them on the wire.
//
// These are strings and not a Go enum type on purpose: they are BYTES the
// protocol defines, they travel unchanged through the module, and every sibling
// binding takes them as its language's string. A Go-only enum would be a fifth
// spelling of a four-way contract.
const (
	// ModePrincipalSigned is the stronger mode: the human principal signed, and
	// a two-element proof chain carries that claim.
	ModePrincipalSigned = "PrincipalSigned"
	// ModeNotaryAttested is the weaker mode, and the one an absent
	// attestationMode means.
	ModeNotaryAttested = "NotaryAttested"
)

// Runtime holds one instance of the compiled APH module.
//
// Create it with [New] and release it with [Close]. It is not safe for
// concurrent use — see the package documentation for why no lock is provided.
type Runtime struct {
	runtime wazero.Runtime
	module  api.Module

	// The six exports, resolved once at instantiation. Resolving them up front
	// is what lets [New] report a stale or wrong artifact by NAME instead of
	// letting the first operation fail on a nil function much later.
	alloc                  api.Function
	dealloc                api.Function
	parseEnvelopeJSON      api.Function
	serializeEnvelope      api.Function
	verifyProofStructure   api.Function
	requireAttestationMode api.Function
}

// New compiles the embedded APH module and instantiates it.
//
// It is the expensive call — compilation dominates — so a caller should create
// a Runtime once per goroutine and reuse it, not once per envelope.
//
// A missing, truncated or foreign artifact is reported here, in full, with the
// regeneration command; it never surfaces as a trap inside a later operation.
func New(ctx context.Context) (*Runtime, error) {
	moduleWasm, err := readArtifact(artifactFS)
	if err != nil {
		return nil, err
	}

	wasmRuntime := wazero.NewRuntime(ctx)

	// WithStartFunctions() with no arguments, deliberately: the default asks for
	// `_start`, which belongs to a WASI COMMAND. This artifact is a library —
	// it has no entry point, exports no `_start`, and imports nothing at all —
	// so naming a start function here would invite a question about a function
	// that should not exist.
	config := wazero.NewModuleConfig().WithStartFunctions()

	module, err := wasmRuntime.InstantiateWithConfig(ctx, moduleWasm, config)
	if err != nil {
		// Close the runtime we just built rather than leaking it; the caller
		// gets one error describing the real failure.
		_ = wasmRuntime.Close(ctx)
		return nil, fmt.Errorf("aph: instantiating the embedded module: %w%s", err, regenerateHint)
	}

	r := &Runtime{
		runtime:                wasmRuntime,
		module:                 module,
		alloc:                  module.ExportedFunction("aph_alloc"),
		dealloc:                module.ExportedFunction("aph_dealloc"),
		parseEnvelopeJSON:      module.ExportedFunction("aph_parse_envelope_json"),
		serializeEnvelope:      module.ExportedFunction("aph_serialize_envelope"),
		verifyProofStructure:   module.ExportedFunction("aph_verify_proof_structure"),
		requireAttestationMode: module.ExportedFunction("aph_require_attestation_mode"),
	}

	if err := r.checkExports(); err != nil {
		_ = wasmRuntime.Close(ctx)
		return nil, err
	}
	return r, nil
}

// Close releases the WebAssembly runtime and everything it owns. A Runtime is
// unusable afterwards.
func (r *Runtime) Close(ctx context.Context) error {
	if err := r.runtime.Close(ctx); err != nil {
		return fmt.Errorf("aph: closing the wasm runtime: %w", err)
	}
	return nil
}

// ParseEnvelopeJSON parses JSON text as an APH NotarizationEnvelope and returns
// it re-emitted as canonical compact JSON text.
//
// A nil error proves the input satisfied the strict envelope schema — APH parses
// with unknown fields DENIED, so a key the protocol never defined is a hard
// refusal rather than a silently dropped one.
func (r *Runtime) ParseEnvelopeJSON(ctx context.Context, envelope string) (string, error) {
	return r.callText(ctx, "ParseEnvelopeJSON", r.parseEnvelopeJSON, envelope)
}

// SerializeEnvelope serializes an envelope, given as JSON text, back to
// canonical compact JSON text.
//
// This is [Runtime.ParseEnvelopeJSON] approached from the other direction. Both
// exist because the four-way parity contract names both, and both reduce to one
// parse and one re-emit inside the module.
func (r *Runtime) SerializeEnvelope(ctx context.Context, envelope string) (string, error) {
	return r.callText(ctx, "SerializeEnvelope", r.serializeEnvelope, envelope)
}

// VerifyProofStructure verifies the §7.1.11 proof-chain structural rules and
// returns the attestation mode the STRUCTURE supports: [ModePrincipalSigned] or
// [ModeNotaryAttested].
//
// This is the check that detects a forged PrincipalSigned label: a label written
// above a structure that cannot bear it is refused with
// [CodeForgedPrincipalLabel].
//
// A successful return says the structure is sound. It says NOTHING about whether
// any signature verifies — a caller that reports "the human signed this" on the
// strength of this function alone is reporting a claim no key has backed.
func (r *Runtime) VerifyProofStructure(ctx context.Context, envelope string) (string, error) {
	return r.callText(ctx, "VerifyProofStructure", r.verifyProofStructure, envelope)
}

// RequireAttestationMode refuses an envelope whose DECLARED attestation mode is
// weaker than required — the §8.3.1 step-1a no-downgrade gate — with
// [CodeModeDowngrade].
//
// required must be a wire spelling ([ModePrincipalSigned] or
// [ModeNotaryAttested]). An unrecognized spelling is an error rather than a
// silent default, because a typo that defaulted to the weaker mode would BE the
// downgrade this gate exists to refuse.
//
// It returns error alone, with no result string, and that is parity rather than
// a deviation from it: this gate's success carries no value. Elixir spells that
// as a bare :ok, Python as None, TypeScript as void; Go spells it as error. A
// second return that was always the empty string would be a value the operation
// does not have.
//
// The label alone is not evidence — a caller MUST also run
// [Runtime.VerifyProofStructure], which is what rejects a forged PrincipalSigned
// label. Calling this function alone accepts one.
func (r *Runtime) RequireAttestationMode(ctx context.Context, envelope, required string) error {
	_, err := r.callTextPair(
		ctx,
		"RequireAttestationMode",
		r.requireAttestationMode,
		envelope,
		required,
	)
	return err
}
