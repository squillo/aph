package aph

import (
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/tetratelabs/wazero/api"
)

// artifactFS carries the compiled shim: interpreters/rust/aph-wasm-abi built
// for wasm32-unknown-unknown, at [artifactPath] inside it.
//
// That artifact is the repository's ONE deliberate binary, and it is committed
// so that `go get` needs no Rust toolchain. It is verified rather than trusted:
// CI rebuilds it from the recorded toolchain and byte-diffs it against the
// committed copy.
//
// ⛔ The DIRECTORY is embedded rather than the file, and that is load-bearing
// rather than loose. `//go:embed internal/wasm/aph.wasm` fails to COMPILE when
// the artifact is absent, with a message about an unmatched pattern and no way
// to attach the regeneration recipe to it — and absent is the state of a tree
// where the artifact has not been produced yet, which is exactly the reader who
// most needs the recipe. Embedding the directory always matches (a committed
// README.md anchors it), so a missing artifact becomes an ordinary error from
// [readArtifact] carrying [regenerateHint], in the same shape as every other
// damage the artifact can suffer.
//
// The cost, stated rather than hidden: the directory's two small text files
// ride along inside every consumer binary. That is a few kilobytes to make a
// build failure legible, and the same embed.FS-over-a-glob shape the fleet's
// other Go packages use for their template directories.
//
//go:embed internal/wasm
var artifactFS embed.FS

// artifactPath locates the module inside [artifactFS].
//
// A constant rather than a literal at each use because it appears in the error
// messages a reader follows back to the file, and those must name the same path
// the build script writes.
const artifactPath = "internal/wasm/aph.wasm"

// The result-record layout published in the shim's crate documentation. These
// four constants ARE that document's table; a consumer in any language
// hard-codes them, so they change only when the ABI changes.
const (
	resultHeaderLen = 5
	statusOK        = 0
	statusRefused   = 1
	// Payload length is a little-endian u32 occupying bytes 1..5 of the record.
	resultLengthOffset = 1
)

// The first eight bytes of every WebAssembly module: the magic number and the
// binary-format version. Checked before wazero sees the bytes so a truncated or
// wrong-file artifact reads as what it is instead of as a runtime failure.
const wasmHeaderLen = 8

var (
	wasmMagic   = []byte{0x00, 0x61, 0x73, 0x6d}
	wasmVersion = []byte{0x01, 0x00, 0x00, 0x00}
)

// regenerateHint is appended to every artifact complaint. One sentence, one
// command, naming the one thing that produces the module — so a reader who hits
// any of these errors never has to go looking for the recipe.
const regenerateHint = "\n\nREGENERATE FIRST: run ./build-wasm.sh --write from " +
	"the module directory. That script is the only thing that produces the " +
	"committed module, and CI byte-diffs its output against the committed copy."

// readArtifact loads the module bytes out of an embedded filesystem.
//
// fsys is a parameter rather than a reference to [artifactFS] so the failure
// messages below are testable against a synthetic filesystem. The committed
// artifact is the one file in this repository a test must never rewrite, and a
// test that had to delete it to exercise the missing-file path would be one
// interruption away from leaving the tree broken.
func readArtifact(fsys fs.FS) ([]byte, error) {
	artifact, err := fs.ReadFile(fsys, artifactPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The state of a fresh tree whose artifact has not been produced yet.
			// It is the reader who most needs the recipe, which is the whole reason
			// this arrives as an error rather than as a compile failure — see the
			// embed comment above.
			return nil, fmt.Errorf(
				"aph: the WebAssembly artifact %s has not been built%s",
				artifactPath, regenerateHint,
			)
		}
		return nil, fmt.Errorf("aph: reading the embedded artifact %s: %w%s", artifactPath, err, regenerateHint)
	}
	if err := validateArtifact(artifact); err != nil {
		return nil, err
	}
	return artifact, nil
}

// validateArtifact rejects an artifact that cannot be a module.
//
// Split out from New and taking its bytes as a parameter for the same reason
// [readArtifact] takes a filesystem: the failure messages are testable without
// damaging the committed file.
func validateArtifact(artifact []byte) error {
	if len(artifact) == 0 {
		// An empty file, as distinct from an absent one: a placeholder committed to
		// make the tree build, or an interrupted copy. Both deserve the recipe.
		return fmt.Errorf(
			"aph: the embedded WebAssembly artifact %s is empty (0 bytes)%s",
			artifactPath, regenerateHint,
		)
	}
	if len(artifact) < wasmHeaderLen {
		return fmt.Errorf(
			"aph: the embedded WebAssembly artifact %s is truncated: %d bytes, and a module "+
				"header alone is %d%s",
			artifactPath, len(artifact), wasmHeaderLen, regenerateHint,
		)
	}
	if !bytes.Equal(artifact[:4], wasmMagic) {
		return fmt.Errorf(
			"aph: the embedded artifact %s is not a WebAssembly module: it begins %#x, not %#x%s",
			artifactPath, artifact[:4], wasmMagic, regenerateHint,
		)
	}
	if !bytes.Equal(artifact[4:wasmHeaderLen], wasmVersion) {
		return fmt.Errorf(
			"aph: the embedded artifact %s declares WebAssembly binary version %#x, not %#x%s",
			artifactPath, artifact[4:wasmHeaderLen], wasmVersion, regenerateHint,
		)
	}
	return nil
}

// checkExports confirms the instantiated module offers the whole ABI.
//
// The six names below are the ABI, enumerated: a module missing any of them was
// built from different source, and saying so here — by name, all of them at
// once — is the difference between "regenerate the artifact" and a nil-function
// panic several calls later.
func (r *Runtime) checkExports() error {
	required := []struct {
		name     string
		resolved api.Function
	}{
		{"aph_alloc", r.alloc},
		{"aph_dealloc", r.dealloc},
		{"aph_parse_envelope_json", r.parseEnvelopeJSON},
		{"aph_serialize_envelope", r.serializeEnvelope},
		{"aph_verify_proof_structure", r.verifyProofStructure},
		{"aph_require_attestation_mode", r.requireAttestationMode},
	}
	var missing []string
	for _, export := range required {
		if export.resolved == nil {
			missing = append(missing, export.name)
		}
	}
	if r.module.Memory() == nil {
		missing = append(missing, "memory")
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"aph: the embedded module does not export %s; it was built from different "+
				"source than interpreters/rust/aph-wasm-abi%s",
			strings.Join(missing, ", "), regenerateHint,
		)
	}
	return nil
}

// hostBuffer is one caller-owned allocation inside module memory. The shim's
// ABI makes the caller responsible for every buffer it allocates, so every one
// obtained here is paired with a release before the call returns.
type hostBuffer struct {
	ptr    uint32
	length uint32
}

// allocate reserves module memory for text and copies it in.
func (r *Runtime) allocate(ctx context.Context, op, text string) (hostBuffer, error) {
	length := uint32(len(text))
	results, err := r.alloc.Call(ctx, uint64(length))
	if err != nil {
		return hostBuffer{}, fmt.Errorf("aph: %s: allocating %d bytes in the module: %w", op, length, err)
	}
	if len(results) != 1 {
		return hostBuffer{}, fmt.Errorf("aph: %s: aph_alloc returned %d values, expected 1%s", op, len(results), regenerateHint)
	}
	ptr := uint32(results[0])
	if ptr == 0 {
		// Null is the ABI's out-of-memory signal and nothing else; a zero-length
		// request comes back as a non-null dangling pointer by design.
		return hostBuffer{}, fmt.Errorf("aph: %s: the module could not allocate %d bytes", op, length)
	}
	// Writing zero bytes is a no-op that still validates the offset, so the
	// zero-length case needs no special branch here.
	if !r.module.Memory().Write(ptr, []byte(text)) {
		return hostBuffer{}, fmt.Errorf("aph: %s: writing %d bytes at offset %d fell outside module memory", op, length, ptr)
	}
	return hostBuffer{ptr: ptr, length: length}, nil
}

// release returns a buffer to the module allocator.
//
// The error is deliberately dropped. A trap inside dealloc means the module's
// allocator is already corrupt, which no caller can act on differently from the
// result it is being handed anyway, and the next call on this Runtime fails
// loudly. Surfacing it here would let a successful operation return an error it
// did not have.
func (r *Runtime) release(ctx context.Context, buffer hostBuffer) {
	_, _ = r.dealloc.Call(ctx, uint64(buffer.ptr), uint64(buffer.length))
}

// callText runs a one-argument operation: allocate, call, read, free.
func (r *Runtime) callText(ctx context.Context, op string, fn api.Function, text string) (string, error) {
	input, err := r.allocate(ctx, op, text)
	if err != nil {
		return "", err
	}
	defer r.release(ctx, input)

	results, err := fn.Call(ctx, uint64(input.ptr), uint64(input.length))
	if err != nil {
		return "", fmt.Errorf("aph: %s: the module trapped: %w%s", op, err, regenerateHint)
	}
	return r.readResult(ctx, op, results)
}

// callTextPair runs a two-argument operation. Separate from callText rather
// than variadic: the two arities are the whole ABI, and spelling them out keeps
// each call site's argument order visible at the boundary where it matters.
func (r *Runtime) callTextPair(ctx context.Context, op string, fn api.Function, first, second string) (string, error) {
	firstInput, err := r.allocate(ctx, op, first)
	if err != nil {
		return "", err
	}
	defer r.release(ctx, firstInput)

	secondInput, err := r.allocate(ctx, op, second)
	if err != nil {
		return "", err
	}
	defer r.release(ctx, secondInput)

	results, err := fn.Call(
		ctx,
		uint64(firstInput.ptr), uint64(firstInput.length),
		uint64(secondInput.ptr), uint64(secondInput.length),
	)
	if err != nil {
		return "", fmt.Errorf("aph: %s: the module trapped: %w%s", op, err, regenerateHint)
	}
	return r.readResult(ctx, op, results)
}

// readResult decodes the shim's result record and frees it.
//
// Ownership of the record transfers to this side on return from the operation,
// so this function owns the obligation to free it — exactly once, after the
// payload has been copied out.
func (r *Runtime) readResult(ctx context.Context, op string, results []uint64) (string, error) {
	if len(results) != 1 {
		return "", fmt.Errorf("aph: %s: the module returned %d values, expected 1%s", op, len(results), regenerateHint)
	}
	record := uint32(results[0])
	if record == 0 {
		// The ABI reserves null for "could not allocate the record" and nothing
		// else. Every protocol refusal arrives as a record with a refusal status,
		// so this is a resource failure and must not be read as a verdict.
		return "", fmt.Errorf("aph: %s: the module could not allocate a result record", op)
	}

	memory := r.module.Memory()
	header, ok := memory.Read(record, resultHeaderLen)
	if !ok {
		return "", fmt.Errorf("aph: %s: the result record at offset %d lies outside module memory%s", op, record, regenerateHint)
	}
	status := header[0]
	length := binary.LittleEndian.Uint32(header[resultLengthOffset:resultHeaderLen])

	payload := ""
	if length > 0 {
		// wazero hands back a VIEW of module memory, not a copy, so the bytes are
		// converted to a Go string before anything is freed or reallocated.
		view, viewOK := memory.Read(record+resultHeaderLen, length)
		if !viewOK {
			return "", fmt.Errorf("aph: %s: a %d-byte payload at offset %d lies outside module memory%s", op, length, record+resultHeaderLen, regenerateHint)
		}
		payload = string(view)
	}
	r.release(ctx, hostBuffer{ptr: record, length: resultHeaderLen + length})

	switch status {
	case statusOK:
		return payload, nil
	case statusRefused:
		return "", newError(payload)
	default:
		return "", fmt.Errorf("aph: %s: the module returned status byte %d, which the ABI does not define%s", op, status, regenerateHint)
	}
}
