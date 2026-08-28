package aph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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

// manifestFile names the corpus INVENTORY, which is not itself a vector.
//
// Every enumerator in every binding skips this name for the same reason: it is
// the list, not a thing on the list, and a suite that tried to strict-parse it
// as an envelope would fail on the inventory rather than on a document anyone
// publishes.
const manifestFile = "manifest.json"

// corpusManifest is `examples/manifest.json` — the one inventory every binding
// measures against.
//
// It exists because reading a directory tells you what IS there and a hand-kept
// list tells you what SHOULD be, and only the disagreement between the two is
// evidence. Four bindings previously named two files apiece and enumerated
// nothing, so a vector could land in the corpus and every one of them would
// stay green while never having seen it.
type corpusManifest struct {
	// The top-level files a conformant implementation is expected to handle.
	Conformance []string `json:"conformance"`
	// Present in the repository and deliberately outside the conformance claim,
	// each with the one-line reason it is out.
	Excluded []struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	} `json:"excluded"`
}

// readManifest decodes the corpus inventory, fatal on anything unreadable.
//
// Fatal rather than skip: an inventory that cannot be read is indistinguishable
// from an empty one, and an empty one would make every set comparison below
// pass by comparing nothing against nothing.
func readManifest(t *testing.T) corpusManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(examplesDir, manifestFile))
	if err != nil {
		t.Fatalf("reading the corpus manifest %s: %v", manifestFile, err)
	}
	var manifest corpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("the corpus manifest %s is not valid JSON: %v", manifestFile, err)
	}
	if len(manifest.Conformance) == 0 {
		t.Fatalf("the corpus manifest lists no conformance files, so nothing below compares anything")
	}
	return manifest
}

// listExampleJSON enumerates the top-level `*.json` files on disk, sorted.
//
// The inventory itself is skipped by name — see manifestFile. Subdirectories
// are not descended into: the top level IS the conformance corpus, and what
// lives below it is inventoried as excluded rather than enumerated here.
func listExampleJSON(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(examplesDir)
	if err != nil {
		t.Fatalf("reading the published corpus directory %s: %v", examplesDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name() == manifestFile {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// difference returns everything in `left` that is absent from `right`.
func difference(left, right []string) []string {
	present := make(map[string]bool, len(right))
	for _, name := range right {
		present[name] = true
	}
	var missing []string
	for _, name := range left {
		if !present[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

func TestTheCorpusOnDiskIsExactlyTheCorpusTheManifestClaims(t *testing.T) {
	// WHY THIS TEST EXISTS: this suite used to read exactly two examples BY
	// NAME and enumerate nothing, so a vocabulary change — a new channel shape,
	// a new cryptosuite vector, a renamed file — could land in `examples/` and
	// this binding would report success having never opened it. A count would
	// not have helped either: a floor of "at least twelve" passes forever, and
	// a swap of one file for another leaves the count unmoved.
	//
	// WHAT IT PINS: SET EQUALITY, in both directions, between the manifest's
	// conformance list and the top-level `*.json` files on disk. A file on disk
	// with no manifest entry fails and names itself, which is the direction that
	// catches a vector nobody classified. A manifest entry with no file fails
	// too, which catches a deletion or a rename that a one-directional check
	// would read as "fewer files, still above the floor".
	manifest := readManifest(t)
	onDisk := listExampleJSON(t)

	if undeclared := difference(onDisk, manifest.Conformance); len(undeclared) > 0 {
		t.Errorf(
			"these files are in %s with no entry in %s: %s",
			examplesDir, manifestFile, strings.Join(undeclared, ", "),
		)
	}
	if missing := difference(manifest.Conformance, onDisk); len(missing) > 0 {
		t.Errorf(
			"%s claims these files that are not on disk in %s: %s",
			manifestFile, examplesDir, strings.Join(missing, ", "),
		)
	}
}

func TestEveryConformanceFileTheManifestClaimsIsReadable(t *testing.T) {
	// WHY THIS TEST EXISTS: set equality above compares NAMES. A file can be
	// named in both places and still be a zero-byte stub or unreadable, at which
	// point the inventory is honest and the corpus is not.
	//
	// WHAT IT PINS: every conformance entry opens, parses as JSON, and is a JSON
	// OBJECT — the floor every envelope shape sits on. Deeper verification is
	// this binding's other tests' job; this one only refuses to let a hollow
	// file pass as a corpus member.
	for _, name := range readManifest(t).Conformance {
		text := readExample(t, name)
		var document map[string]any
		if err := json.Unmarshal([]byte(text), &document); err != nil {
			t.Errorf("%s is named in %s and is not a JSON object: %v", name, manifestFile, err)
			continue
		}
		if len(document) == 0 {
			t.Errorf("%s is named in %s and carries no members", name, manifestFile)
		}
	}
}

func TestTheExcludedFilesAreOnDiskAndSayWhyTheyAreExcluded(t *testing.T) {
	// WHY THIS TEST EXISTS: the excluded list is the half of the inventory that
	// rots quietly. A conformance claim that silently covered a deliberately
	// non-conformant document would be false, and a claim that excluded a file
	// nobody can find any more is an exclusion for a file that stopped existing.
	//
	// WHAT IT PINS: every excluded path resolves on disk, and every one carries
	// a non-empty reason — an exclusion with no stated reason is one the next
	// reader cannot tell from an oversight.
	for _, entry := range readManifest(t).Excluded {
		if strings.TrimSpace(entry.Reason) == "" {
			t.Errorf("%s is excluded with no stated reason", entry.Path)
		}
		if _, err := os.Stat(filepath.Join(examplesDir, entry.Path)); err != nil {
			t.Errorf("%s is excluded in %s and is not on disk: %v", entry.Path, manifestFile, err)
		}
	}
}

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
