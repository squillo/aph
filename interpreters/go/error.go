package aph

// The two protocol codes the four operations in this package can produce.
//
// The taxonomy is a closed set of sixteen (APH_E001–APH_E016); these two are
// the only ones REACHABLE from a boundary that parses, re-emits, checks proof
// STRUCTURE and gates the declared mode. The other fourteen arise on signature,
// timestamp, body-hash, discovery, revocation and mandate-rooting paths, none of
// which this binding exposes — so naming them here would advertise refusals no
// call can return.
//
// The value is the wire string and the constant is Go sugar over it: what a
// caller matches is the code the protocol defines, spelled identically in every
// binding.
const (
	// CodeForgedPrincipalLabel — a PrincipalSigned label written above a proof
	// structure that cannot bear it (§7.1.11).
	CodeForgedPrincipalLabel = "APH_E013"
	// CodeModeDowngrade — the envelope's declared attestation mode is weaker
	// than the verifier required (§8.3.1 step 1a).
	CodeModeDowngrade = "APH_E012"
)

// Error is the single error type every refusal crosses the boundary as.
//
// ONE type, because the code lives in the message: a caller distinguishes
// APH_E012 from APH_E013 by reading it, not by catching a different type, and
// that is what keeps this binding's error identity equal to the Python
// binding's single AphError, the TypeScript binding's thrown message, and the
// Elixir binding's {:error, message}.
//
// Code is empty for a SHAPE refusal — a field APH never defined, a malformed
// document, bytes that are not UTF-8 — because no protocol rule was reached and
// no code was earned. Message always carries the reference implementation's own
// text, unaltered.
type Error struct {
	// Code is the APH_E code a protocol refusal leads with, or "" for a shape
	// refusal.
	Code string
	// Message is the reference implementation's own refusal message, verbatim.
	// For a protocol refusal it begins with Code followed by ": ".
	Message string
}

// Error implements the error interface, returning the message unaltered.
//
// Unaltered is the point: every binding surfaces the same text, so a log line
// written by a Go recipient and one written by a BEAM recipient describe the
// same refusal in the same words.
func (e *Error) Error() string { return e.Message }

// newError classifies a refusal message from the module.
func newError(message string) *Error {
	return &Error{Code: leadingCode(message), Message: message}
}

// leadingCode returns the protocol code a message LEADS WITH, or "" if it leads
// with anything else.
//
// The rule is definitional, not a search: the message must begin with "APH_E",
// three decimal digits, and a colon — the exact form the reference
// implementation's Display writes. A code found anywhere else in the text is
// not a leading code and does not count, because a parser message that happened
// to quote a code would otherwise be promoted to a protocol refusal it never
// was. This is the same prefix test a Python caller writes as
// str(e).startswith("APH_E013") and an Elixir caller as {:error, "APH_E013" <> _}.
func leadingCode(message string) string {
	const prefix = "APH_E"
	const digits = 3
	const codeLen = len(prefix) + digits

	// The code, plus the colon that must follow it.
	if len(message) < codeLen+1 {
		return ""
	}
	if message[:len(prefix)] != prefix {
		return ""
	}
	for i := len(prefix); i < codeLen; i++ {
		if message[i] < '0' || message[i] > '9' {
			return ""
		}
	}
	if message[codeLen] != ':' {
		return ""
	}
	return message[:codeLen]
}
