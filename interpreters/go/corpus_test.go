package aph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// examplesDir locates the published corpus relative to this package.
//
// `go test` always runs a test binary with its working directory set to the
// package directory, so a relative path here resolves the same way from
// anywhere the suite is invoked. That matters: a suite that silently read a
// DIFFERENT corpus than the published one would be testing nothing while
// staying green.
//
// The corpus is NOT embedded. go:embed cannot reach outside the module, and
// that limitation is welcome here — it means the published Go module carries
// the binding and not the fixtures, and the fixtures stay the single copy every
// binding's suite reads off disk.
const examplesDir = "../../examples"

// readExample reads a published example envelope by file name.
//
// Fatal on a miss, and that is the point: a renamed or removed example must
// break the suite loudly at the read, not quietly turn a later assertion
// vacuous. Nothing here mints or signs anything — the corpus this repository
// publishes is the entire fixture set, because a fixture invented for a test
// proves only that the test agrees with itself.
func readExample(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(examplesDir, name))
	if err != nil {
		t.Fatalf("reading the published example %s: %v", name, err)
	}
	return string(content)
}

// principalSignedGolden returns the signed PrincipalSigned golden — the CHAIN
// arm of the proof union, and the form a forged label imitates.
func principalSignedGolden(t *testing.T) string {
	t.Helper()
	return readExample(t, "principal_signed_envelope.json")
}

// legacySlackReply returns a pre-chain envelope — the SINGLE-OBJECT arm of the
// proof union, carrying no attestationMode at all, which the protocol reads as
// NotaryAttested.
func legacySlackReply(t *testing.T) string {
	t.Helper()
	return readExample(t, "slack_reply_envelope.json")
}

// substituteOnce derives a test document from a published one by replacing
// exactly one anchor, and fails if the anchor is not found exactly once.
//
// ⛔ TEXT, not a decode-edit-encode round trip, and on THIS runtime that is not
// a stylistic choice. Go's encoding/json widens every number to float64, so
// building the 2^53+1 fixture through a decoder would round the very value the
// fixture exists to carry — the test would pass while measuring nothing. Every
// derivation in this suite therefore edits bytes, in view of the reader, so
// what changed from the published document is visible in the test rather than
// buried in a committed file.
//
// The exactly-once check is what keeps the derivation honest: if the corpus is
// reformatted and an anchor stops matching, the test fails at the edit instead
// of silently asserting something about an unmodified document.
func substituteOnce(t *testing.T, document, anchor, replacement string) string {
	t.Helper()
	if occurrences := strings.Count(document, anchor); occurrences != 1 {
		t.Fatalf(
			"the anchor %q appears %d times in the published document, expected exactly 1: "+
				"the corpus changed and this derivation no longer makes the edit it claims to",
			anchor, occurrences,
		)
	}
	return strings.Replace(document, anchor, replacement, 1)
}
