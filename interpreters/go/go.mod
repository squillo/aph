// The module path matches this directory's path inside the repository, which
// is the entire registration story for a Go package: `go get` resolves it by
// fetching the repository and walking to this directory, and pkg.go.dev indexes
// tagged modules on its own. Nothing is submitted anywhere. Get the path wrong
// and the package is simply unreachable, no matter what is published.
//
// The final path element is `go` while the package inside is named `aph`. Go
// permits that — the package name comes from the source, not the directory —
// and the directory is named for the LANGUAGE because it sits beside
// `interpreters/rust`, `interpreters/typescript` and `interpreters/elixir`.
// Import it plainly; an alias is a caller's preference, not a requirement.
module github.com/squillo/aph/interpreters/go

// The declared floor, not the version this is developed on — the same shape
// the Elixir binding uses, where a floor is claimed only for a pair that has
// actually been run. Nothing here uses a language feature newer than this, and
// CI runs a current toolchain so both ends are evidence.
go 1.23

// PINNED to an exact version rather than a caret range, for the same reason
// the second-engine harness pins its engine: this dependency is the WebAssembly
// runtime that decides what the embedded module does, and if it can change
// under CI without a commit then a green run stops being evidence about the
// protocol and becomes a question about which runtime ran.
//
// wazero is a pure-Go runtime with ZERO dependencies of its own, which is why
// this file has exactly one requirement and why `go get` on this package needs
// no C toolchain and no cgo. That property is the reason the binding is a wasm
// embed rather than an FFI shim; losing it would be a reason to revisit the
// whole design, not a dependency bump.
require github.com/tetratelabs/wazero v1.9.0
