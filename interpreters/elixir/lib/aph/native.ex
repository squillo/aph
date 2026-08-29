defmodule APH.Native do
  @moduledoc """
  The NIF boundary. Four functions, each one `decode binary -> call aph-core ->
  encode result`, and nothing else.

  ## ⛔ Why this module is trivially thin, and must stay that way

  This is a TESTABILITY rule, not a style preference, and it is forced by the
  hosting relationship. The Python binding embeds CPython INSIDE Rust, so
  `cargo test` can start an interpreter and drive that whole boundary from the
  Rust side. A rustler NIF is the inverse — Rust embedded IN the BEAM — and
  there is no supported way to embed the BEAM in a Rust test binary. `mix
  test` is therefore the ONLY thing that ever exercises the term boundary.

  The mitigation is architectural rather than procedural. Because every
  function here is a decode, a call into `aph-core`, and an encode, the entire
  behavioural surface already lives in `aph-core` under `cargo test`, and what
  only `mix test` can reach shrinks to term glue. A wrapper on either side of
  this boundary that grows a branch, a default, or a coercion is a DEFECT
  precisely because no Rust test can reach it.

  ## Shapes

  Binaries in, binaries out. `parse_envelope_json/1`, `serialize_envelope/1`
  and `verify_proof_structure/1` answer `{:ok, binary} | {:error, binary}`;
  `require_attestation_mode/2` answers `:ok | {:error, binary}`. The tuples
  are built in Rust, so this module contains no result construction either.

  Handing a term-shaped envelope — a decoded map or list — to any of these
  raises rather than being coerced. There is no arity that accepts one, and
  `test/nif_boundary_test.exs` pins that there never will be.

  `APH` is the documented surface; use it. This module is public only because
  a NIF module has to be.
  """

  # `crate:` names the `[lib]` target in native/aph_nif/Cargo.toml, and the
  # crate directory is `native/<crate>` by convention — the two must agree with
  # the manifest or the load fails at runtime rather than at build time. There
  # is no `compilers: [:rustler]` entry in mix.exs to go with this: since the
  # release pinned there, `use Rustler` drives cargo from a compile hook on
  # THIS module, so the mix compiler entry older guides show is gone.
  use Rustler, otp_app: :aph, crate: :aph_nif

  # The bodies below exist so this module compiles and so a load failure is
  # legible. rustler replaces every one of them when the shared object loads;
  # a call that actually reaches `:erlang.nif_error/1` means it did not, which
  # is a build problem (see the README) and never a protocol result. They are
  # `@doc false` because the prose belongs to `APH`, in one place, where a
  # reader of the parity contract will find it.

  @doc false
  def parse_envelope_json(_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def serialize_envelope(_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def verify_proof_structure(_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def require_attestation_mode(_json, _required), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def mandate_is_valid_at(_mandate_json, _at), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def verify_embedded_mandate_binding(_json), do: :erlang.nif_error(:nif_not_loaded)
end
