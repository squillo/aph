//! `aph-wasm-abi` — a plain WebAssembly C ABI over `aph-core`.
//!
//! This crate compiles to a `wasm32-unknown-unknown` module that imports
//! NOTHING. It is the artifact the Go binding under `interpreters/go` embeds
//! and runs, and it is deliberately written so that any language with a
//! WebAssembly runtime can target it from this document alone, without reading
//! a line of the Go code.
//!
//! # Why a plain C ABI and not `wasm-bindgen`
//!
//! `aph-ts` targets wasm too, but through `wasm-bindgen`, whose exports are
//! only half the interface: the other half is generated JavaScript that
//! marshals strings, manages the heap and unwraps errors. A host that is not a
//! JavaScript engine cannot supply that half. So this crate exports raw
//! `extern "C"` functions over pointer/length pairs, and the marshalling
//! contract lives below in prose instead of in generated glue.
//!
//! # The boundary is JSON TEXT, in both directions
//!
//! Every envelope crossing this ABI crosses as UTF-8 JSON text. This is a
//! structural safety property, not a convenience, and it is the SAME rule
//! `aph-ts` enforces at the JS boundary, `aph-py` at the Python one and the
//! rustler NIF at the BEAM one.
//!
//! `aph_core::EnvelopeProofs` is an untagged object-or-array union, and
//! untagged matching is exactly where a value that changed shape can silently
//! change which arm deserializes. A decoded-object route hands that decision to
//! a SECOND deserializer reading whatever the caller's objects happen to hold.
//!
//! ⛔ For the consumer this module was built for, the hazard is the ORIGINAL
//! one in its original form, not a restatement. Go's `encoding/json` decodes
//! every JSON number into `float64` unless the caller opts out — so an envelope
//! decoded into Go objects and handed back would round `bodySize` at 2^53, and
//! would offer a union arm chosen by a Go type rather than by the bytes. The
//! BEAM binding had to restate the argument because Erlang integers are
//! arbitrary precision; here nothing needs restating. JSON text has one integer
//! spelling and one union spelling, so the only number and union parser that
//! ever runs is `serde_json`'s, and the consumer's `2^53 + 1` tripwire test
//! carries its original meaning.
//!
//! # ⛔ Why every export here is trivially thin
//!
//! This is a TESTABILITY rule, not a style preference, and it is forced by the
//! same inversion the NIF faces. Nothing in `cargo test` can call these exports
//! as the consumer calls them: reaching them means loading a compiled
//! `wasm32-unknown-unknown` module into a WebAssembly runtime, which is what
//! the Go suite does and what a native Rust test binary is not. `go test` is
//! therefore the ONLY gate that exercises this ABI.
//!
//! The mitigation is architectural rather than procedural: every export is
//! decode-bytes → call `aph_core` → encode-result and NOTHING else. All
//! behaviour then lives in `aph_core`, already under `cargo test`, and what
//! only `go test` covers shrinks to pointer glue. An export in this file that
//! grows a branch, a default, or a coercion is a DEFECT precisely because cargo
//! cannot reach it.
//!
//! # The one branch above `aph_core`, and why it is duplicated
//!
//! [`require_attestation_mode_impl`] matches the caller's `required` spelling
//! before dispatching. That branch exists identically in all three sibling
//! bindings, and it must: letting an unrecognized spelling fall through to a
//! default would BE the downgrade the gate refuses. It is deliberate
//! duplication across four bindings now and has to stay identical in all four.
//!
//! # ═══ THE ABI ═══
//!
//! Everything a consumer needs is in this section.
//!
//! ## Memory
//!
//! The module exports its linear memory as `memory`. All pointers below are
//! byte offsets into it. Pointers and lengths are wasm `i32` values
//! (`usize` is 32-bit on this target); a host reading them as unsigned should
//! treat them as `u32`.
//!
//! The module GROWS its memory as it works. A host that caches a view of the
//! memory buffer must re-acquire it after every call, or it will read a stale
//! mapping.
//!
//! ## Exports
//!
//! ```text
//! aph_alloc(len: i32) -> i32                  // ptr
//! aph_dealloc(ptr: i32, len: i32)
//! aph_parse_envelope_json(ptr: i32, len: i32) -> i32              // record ptr
//! aph_serialize_envelope(ptr: i32, len: i32) -> i32               // record ptr
//! aph_verify_proof_structure(ptr: i32, len: i32) -> i32           // record ptr
//! aph_require_attestation_mode(json_ptr: i32, json_len: i32,
//!                              required_ptr: i32, required_len: i32) -> i32
//! ```
//!
//! There are six and there are only six. A host that finds any of them missing
//! is holding an artifact built from different source, and should say so rather
//! than trap at the first call.
//!
//! ## Calling convention
//!
//! 1. `aph_alloc(n)` to obtain a buffer, write the UTF-8 JSON argument into it.
//! 2. Call the operation with that pointer and length.
//! 3. Read the RESULT RECORD at the returned pointer (layout below).
//! 4. Free BOTH buffers — see ownership below.
//!
//! ## The result record
//!
//! Every operation returns ONE pointer to a single allocation laid out as:
//!
//! | offset | size | meaning |
//! |---|---|---|
//! | 0 | 1 | status: `0` = OK, `1` = REFUSED |
//! | 1 | 4 | payload length in bytes, LITTLE-ENDIAN `u32` |
//! | 5 | *len* | payload, UTF-8 |
//!
//! The total allocation is therefore `5 + len` bytes.
//!
//! On `0` the payload is the operation's result text — canonical compact
//! envelope JSON for the two round-trip operations, an attestation-mode wire
//! label for the structure gate, and EMPTY for the no-downgrade gate, whose
//! success carries no value.
//!
//! On `1` the payload is the refusal message, and there are two kinds. A
//! PROTOCOL refusal carries the reference implementation's own message, which
//! LEADS WITH its code in the exact form `APH_Ennn: ` — `APH_E013` for a forged
//! `PrincipalSigned` label, `APH_E012` for a refused mode downgrade. A SHAPE
//! refusal (a field APH never defined, a malformed document, bytes that are not
//! UTF-8) carries the parser's message and NO code, because no protocol rule
//! was reached. That two-shape distinction is the error identity every binding
//! surfaces, and a host is expected to preserve it rather than flatten it.
//!
//! A returned pointer of `0` means the module could not allocate the record.
//! Nothing else returns `0`. It cannot arise from a malformed envelope — every
//! refusal above is a record with status `1` — so a host should treat it as a
//! resource failure and not as a verdict.
//!
//! ## Ownership, and who frees what
//!
//! Every allocation has exactly one owner and exactly one obligation.
//!
//! * INPUT buffers belong to the CALLER for their whole life. The module reads
//!   them during the call and never retains, mutates or frees them. Free each
//!   with `aph_dealloc(ptr, len)` — the same length passed in.
//! * The RESULT RECORD is allocated by the module and OWNERSHIP TRANSFERS to
//!   the caller on return. Free it with `aph_dealloc(record_ptr, 5 + len)`,
//!   using the length read out of the record. Exactly once.
//!
//! `aph_alloc(0)` returns a non-null dangling pointer that must not be written
//! to or read from; `aph_dealloc(ptr, 0)` is a no-op. Rust's allocator has no
//! zero-size allocation, and returning null for length zero would collide with
//! the out-of-memory signal.
//!
//! `aph_alloc` returns `0` if the request cannot be satisfied.
//!
//! ## Traps, and what a trap means
//!
//! This target has no unwinding: a Rust panic aborts, which a host observes as
//! a trap. Nothing in this file panics on any input — malformed bytes, invalid
//! UTF-8 and protocol refusals are all ordinary status-`1` records — so a trap
//! is a defect in the module or a violation of the ownership rules above (a
//! double free, a length that does not match the allocation), never a verdict
//! about an envelope.
//!
//! ## Entropy
//!
//! The module needs none, and asks for none. See the `entropy` module.

/// Length of the result-record header: one status byte plus a little-endian
/// `u32` payload length. Named rather than spelled `5` at each use, because a
/// consumer in another language hard-codes this number and a silent change here
/// would be a silent change to a published wire format.
const RESULT_HEADER_LEN: usize = 5;

/// Result-record status: the payload is the operation's result.
const STATUS_OK: u8 = 0;

/// Result-record status: the payload is a refusal message.
const STATUS_REFUSED: u8 = 1;

// ── The entropy backend ────────────────────────────────────────────────────
//
// `getrandom` will not compile for wasm32-unknown-unknown without a backend,
// and the two on offer are "a JavaScript host supplies it" (which this module
// does not have) or "the crate supplies it". This supplies it, and what it
// supplies is a REFUSAL.
//
// That is the whole point. This module performs no cryptography: the four
// operations are parse, serialize, proof-STRUCTURE and mode-gate, and every
// signature-touching path stays in `aph-core` where a real host calls it with a
// real random source. A backend returning zeros would satisfy the compiler and
// silently manufacture predictable key material the day someone adds a signing
// export. Failing loudly is the only safe answer to a question this module
// should never be asked.
//
// ⛔ If a signing operation is ever added here, the fix is a host-provided
// entropy IMPORT — which makes the module's requirement visible in its import
// section, where a host must consciously satisfy it — and never a stub.
#[cfg(target_arch = "wasm32")]
mod entropy {
  /// Refuses every request for randomness. See the module comment above.
  pub fn refuse(_dest: &mut [u8]) -> std::result::Result<(), getrandom::Error> {
    std::result::Result::Err(getrandom::Error::UNSUPPORTED)
  }
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(entropy::refuse);

// ── The operations, shared with the sibling bindings ───────────────────────

/// Strict-parses `json` into the canonical envelope type, stringifying the
/// parse error. Shared by every export so the boundary has ONE parse path.
fn parse_envelope(
  json: &str,
) -> std::result::Result<aph_core::NotarizationEnvelope, std::string::String> {
  serde_json::from_str(json).map_err(|e| std::format!("{}", e))
}

/// Strict-parses `json` and re-emits it as canonical compact JSON text —
/// the one operation both text-boundary directions reduce to.
fn roundtrip_envelope_json(
  json: &str,
) -> std::result::Result<std::string::String, std::string::String> {
  let envelope = parse_envelope(json)?;
  serde_json::to_string(&envelope).map_err(|e| std::format!("{}", e))
}

/// Runs `aph_core::verify_proof_structure` on JSON text and returns the mode's
/// wire label on success, or the `APH_E*`-prefixed error message.
fn verify_proof_structure_impl(
  json: &str,
) -> std::result::Result<std::string::String, std::string::String> {
  let envelope = parse_envelope(json)?;
  match aph_core::verify_proof_structure(&envelope) {
    std::result::Result::Ok(mode) => {
      std::result::Result::Ok(std::string::String::from(mode.label()))
    }
    std::result::Result::Err(e) => std::result::Result::Err(std::format!("{}", e)),
  }
}

/// Runs `aph_core::require_mode` on JSON text. `required` must be a wire
/// spelling (`PrincipalSigned` | `NotaryAttested`); anything else is an error
/// rather than a silent default, because a typo that defaulted to the weaker
/// mode would BE the downgrade this gate exists to refuse.
fn mandate_is_valid_at_impl(
  mandate_json: &str,
  at: &str,
) -> std::result::Result<std::string::String, std::string::String> {
  // The bool crosses the ABI as text ("true" | "false") — this boundary is
  // string-in string-out everywhere, and a third record shape for one bool
  // would be a second calling convention. Semantics are aph-core's verbatim:
  // an unparseable timestamp is `false`, never an error ("parsing failure
  // returns false" is the core's own documented contract); a mandate that
  // does not strict-parse is the error case, as at every JSON boundary here.
  let mandate: aph_core::DelegationMandate =
    serde_json::from_str(mandate_json).map_err(|e| std::format!("{}", e))?;
  std::result::Result::Ok(std::string::String::from(if mandate.is_valid_at(at) {
    "true"
  } else {
    "false"
  }))
}

fn verify_embedded_mandate_binding_impl(
  json: &str,
) -> std::result::Result<(), std::string::String> {
  let envelope: aph_core::NotarizationEnvelope =
    serde_json::from_str(json).map_err(|e| std::format!("{}", e))?;
  aph_core::verify_embedded_mandate_binding(&envelope).map_err(|e| std::format!("{}", e))
}

fn require_attestation_mode_impl(
  json: &str,
  required: &str,
) -> std::result::Result<(), std::string::String> {
  // One meaning, one place: the spellings live in aph-core's `FromStr`, the
  // inverse of `label()`. This shim used to carry its own copy of this match
  // — as did every sibling binding — and four copies of the downgrade gate's
  // vocabulary is four places a typo could become the downgrade.
  let required_mode: aph_core::AttestationMode = required.parse()?;
  let envelope = parse_envelope(json)?;
  aph_core::require_mode(&envelope, required_mode).map_err(|e| std::format!("{}", e))
}

// ── Marshalling ────────────────────────────────────────────────────────────

/// Borrows a caller-owned buffer as `&str`, refusing bytes that are not UTF-8.
///
/// The refusal is a RETURN VALUE rather than a panic: a host that mis-encoded
/// its argument has made an ordinary mistake, and trapping would leave it with
/// no message to read. This is the decode half of decode → call-core → encode,
/// so it is glue rather than the logic the thin-glue rule forbids.
///
/// # Safety
///
/// `ptr` must point at `len` initialised bytes that stay valid and unmutated
/// for the duration of the call, per the ownership rules in the module docs.
unsafe fn borrow_utf8<'a>(
  ptr: *const u8,
  len: usize,
) -> std::result::Result<&'a str, std::string::String> {
  // A zero length is answered without touching `ptr`, so the documented
  // dangling pointer `aph_alloc(0)` hands out is safe to pass straight back in.
  let bytes: &[u8] = if len == 0 {
    &[]
  } else if ptr.is_null() {
    return std::result::Result::Err(std::string::String::from(
      "null input pointer with a non-zero length",
    ));
  } else {
    unsafe { std::slice::from_raw_parts(ptr, len) }
  };
  std::str::from_utf8(bytes)
    .map_err(|e| std::format!("input buffer is not valid UTF-8: {}", e))
}

/// Packs a result into a freshly allocated record and transfers ownership of it
/// to the caller. Returns null only if the record cannot be allocated.
///
/// The layout written here is the one the module docs publish; the two must
/// change together or a consumer in another language silently misreads bytes.
fn encode_result(
  result: std::result::Result<std::string::String, std::string::String>,
) -> *mut u8 {
  let (status, payload) = match result {
    std::result::Result::Ok(text) => (STATUS_OK, text),
    std::result::Result::Err(message) => (STATUS_REFUSED, message),
  };
  let bytes = payload.as_bytes();
  // Checked rather than assumed: `usize` is 32 bits here, and a host is free to
  // hand in an argument large enough that the header pushes the record over the
  // edge. Null is the documented allocation-failure answer, so an overflow
  // reports as one instead of wrapping to a tiny allocation.
  let total = match bytes.len().checked_add(RESULT_HEADER_LEN) {
    std::option::Option::Some(total) => total,
    std::option::Option::None => return std::ptr::null_mut(),
  };
  let record = aph_alloc(total);
  if record.is_null() {
    return record;
  }
  let length = (bytes.len() as u32).to_le_bytes();
  unsafe {
    std::ptr::write(record, status);
    std::ptr::copy_nonoverlapping(length.as_ptr(), record.add(1), length.len());
    std::ptr::copy_nonoverlapping(
      bytes.as_ptr(),
      record.add(RESULT_HEADER_LEN),
      bytes.len(),
    );
  }
  record
}

/// Packs a valueless result — success carrying nothing, which is what the
/// no-downgrade gate returns — as an OK record with an empty payload.
fn encode_unit_result(
  result: std::result::Result<(), std::string::String>,
) -> *mut u8 {
  encode_result(result.map(|()| std::string::String::new()))
}

// ── Exports ────────────────────────────────────────────────────────────────

/// Allocates `len` bytes of module memory and returns a pointer the caller
/// owns. See the module docs for the ownership rules.
///
/// Returns a non-null dangling pointer for `len == 0`, and null if the request
/// cannot be satisfied.
#[unsafe(no_mangle)]
pub extern "C" fn aph_alloc(len: usize) -> *mut u8 {
  if len == 0 {
    // Not null: null is the out-of-memory signal, and a host must be able to
    // tell "you asked for nothing" from "I could not give you anything".
    return std::ptr::NonNull::<u8>::dangling().as_ptr();
  }
  // Alignment 1 throughout, and the ABI says so: every buffer on this boundary
  // is bytes, and `aph_dealloc` must be able to rebuild the exact layout from
  // the length alone — which is only possible if alignment is a constant.
  match std::alloc::Layout::from_size_align(len, 1) {
    std::result::Result::Ok(layout) => unsafe { std::alloc::alloc(layout) },
    std::result::Result::Err(_) => std::ptr::null_mut(),
  }
}

/// Frees a buffer obtained from [`aph_alloc`] or returned as a result record.
///
/// `len` must be the allocation's size: the length passed to [`aph_alloc`] for
/// an input buffer, or `5 + payload_len` for a result record.
///
/// # Safety
///
/// `ptr` must have come from this module and must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aph_dealloc(ptr: *mut u8, len: usize) {
  // A zero length was never a real allocation (see `aph_alloc`), so freeing it
  // is a no-op rather than an error — that keeps the caller's free path
  // unconditional instead of making it re-derive which case it is in.
  if len == 0 || ptr.is_null() {
    return;
  }
  if let std::result::Result::Ok(layout) = std::alloc::Layout::from_size_align(len, 1) {
    unsafe { std::alloc::dealloc(ptr, layout) }
  }
}

/// Parses UTF-8 JSON text as an APH `NotarizationEnvelope` and returns it
/// re-emitted as canonical compact JSON text.
///
/// # Safety
///
/// `ptr`/`len` must describe a readable buffer per the module docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aph_parse_envelope_json(ptr: *const u8, len: usize) -> *mut u8 {
  match unsafe { borrow_utf8(ptr, len) } {
    std::result::Result::Ok(json) => encode_result(roundtrip_envelope_json(json)),
    std::result::Result::Err(message) => {
      encode_result(std::result::Result::Err(message))
    }
  }
}

/// Serializes an envelope, given as UTF-8 JSON text, back to canonical compact
/// JSON text.
///
/// # Safety
///
/// `ptr`/`len` must describe a readable buffer per the module docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aph_serialize_envelope(ptr: *const u8, len: usize) -> *mut u8 {
  match unsafe { borrow_utf8(ptr, len) } {
    std::result::Result::Ok(json) => encode_result(roundtrip_envelope_json(json)),
    std::result::Result::Err(message) => {
      encode_result(std::result::Result::Err(message))
    }
  }
}

/// Verifies the §7.1.11 proof-chain structural rules and returns the
/// attestation mode the STRUCTURE supports as its wire label.
///
/// # Safety
///
/// `ptr`/`len` must describe a readable buffer per the module docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aph_verify_proof_structure(
  ptr: *const u8,
  len: usize,
) -> *mut u8 {
  match unsafe { borrow_utf8(ptr, len) } {
    std::result::Result::Ok(json) => encode_result(verify_proof_structure_impl(json)),
    std::result::Result::Err(message) => {
      encode_result(std::result::Result::Err(message))
    }
  }
}

/// Refuses an envelope whose DECLARED attestation mode is weaker than
/// `required` — the §8.3.1 step-1a no-downgrade gate — with `APH_E012`.
///
/// Success is an OK record with an EMPTY payload: this gate's success carries
/// no value, and the ABI spells that as zero bytes rather than as a placeholder
/// a consumer might mistake for a verdict.
///
/// # Safety
///
/// Both pointer/length pairs must describe readable buffers per the module
/// docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aph_require_attestation_mode(
  json_ptr: *const u8,
  json_len: usize,
  required_ptr: *const u8,
  required_len: usize,
) -> *mut u8 {
  let json = match unsafe { borrow_utf8(json_ptr, json_len) } {
    std::result::Result::Ok(json) => json,
    std::result::Result::Err(message) => {
      return encode_result(std::result::Result::Err(message));
    }
  };
  let required = match unsafe { borrow_utf8(required_ptr, required_len) } {
    std::result::Result::Ok(required) => required,
    std::result::Result::Err(message) => {
      return encode_result(std::result::Result::Err(message));
    }
  };
  encode_unit_result(require_attestation_mode_impl(json, required))
}

/// Whether a Delegation Mandate is valid at `at` (RFC 3339). Returns the
/// verdict as TEXT — `"true"` | `"false"` — because this boundary is
/// string-in string-out everywhere and one bool does not justify a second
/// calling convention. Semantics are `aph-core`'s verbatim; see the impl.
///
/// # Safety
///
/// Both pointer/length pairs must describe readable buffers per the module
/// docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aph_mandate_is_valid_at(
  mandate_ptr: *const u8,
  mandate_len: usize,
  at_ptr: *const u8,
  at_len: usize,
) -> *mut u8 {
  let mandate_json = match unsafe { borrow_utf8(mandate_ptr, mandate_len) } {
    std::result::Result::Ok(json) => json,
    std::result::Result::Err(message) => {
      return encode_result(std::result::Result::Err(message));
    }
  };
  let at = match unsafe { borrow_utf8(at_ptr, at_len) } {
    std::result::Result::Ok(at) => at,
    std::result::Result::Err(message) => {
      return encode_result(std::result::Result::Err(message));
    }
  };
  encode_result(mandate_is_valid_at_impl(mandate_json, at))
}

/// Verifies the §7.1.7.1 embedded-mandate binding. Success is an OK record
/// with an EMPTY payload, as `aph_require_attestation_mode` spells it; an
/// envelope with NO embedded mandate is ok, exactly as `aph-core` has it —
/// absence of the optional block is not a binding failure.
///
/// # Safety
///
/// `ptr`/`len` must describe a readable buffer per the module docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aph_verify_embedded_mandate_binding(
  ptr: *const u8,
  len: usize,
) -> *mut u8 {
  match unsafe { borrow_utf8(ptr, len) } {
    std::result::Result::Ok(json) => {
      encode_unit_result(verify_embedded_mandate_binding_impl(json))
    }
    std::result::Result::Err(message) => encode_result(std::result::Result::Err(message)),
  }
}
