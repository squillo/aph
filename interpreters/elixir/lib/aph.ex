defmodule APH do
  @moduledoc """
  APH (Agent per Human) v0.1 envelope operations for the BEAM.

  This is a **binding** of the Rust reference implementation, not a second
  implementation of the protocol. Every operation below is a direct delegation
  to `APH.Native`, which is a NIF over `aph-core`; there is no protocol logic
  on this side of the boundary, and there is deliberately no cryptography —
  not a call to `:crypto`, not a canonicalizer, not a signature check written
  in Elixir. Anything that touches a signature crosses into Rust.

  ## Envelopes cross as JSON TEXT, in both directions

  Every function here takes a JSON string and returns a JSON string. Envelopes
  are never handed across as maps or lists, and that is a structural safety
  property rather than a convenience — it is the same rule the JS and Python
  bindings enforce, for the same reason.

  The envelope's `proof` field is an untagged union: a single object
  (`NotaryAttested`) or a two-element chain (`PrincipalSigned`, principal
  first). Untagged matching is exactly where a value that changed shape can
  silently change which arm deserializes. A term route hands that decision to
  a SECOND deserializer reading whatever the caller's terms happen to hold.

  The BEAM makes that hazard easy to underestimate, which is why it is written
  down: Erlang integers are arbitrary precision, so the integer-widening trap
  that motivates the rule in JS and Python does not bite here. The trap that
  DOES bite is the encoder — a map/list encoder must pick one arm of the union
  with no schema to consult, and a caller who decoded an envelope, edited it,
  and handed the terms back can trivially produce a one-element proof list or
  a float `bodySize` without noticing. JSON text has one spelling of each, so
  the only number and union parser that ever runs is `serde_json`'s.

  Pair these functions with your JSON library of choice:

      {:ok, normalized} = APH.parse_envelope_json(received)
      envelope = Jason.decode!(normalized)
      {:ok, ^normalized} = APH.serialize_envelope(Jason.encode!(envelope))

      {:ok, mode} = APH.verify_proof_structure(received)
      :ok = APH.require_attestation_mode(received, "PrincipalSigned")

  ## Export parity, a four-way contract

  This binding, the wasm/TS binding and the Python binding expose the SAME
  four envelope-facing operations, with the same semantics and the same error
  identity, each in its language's idiom:

  | wasm/TS                  | Python                     | Elixir                          |
  |--------------------------|----------------------------|---------------------------------|
  | `parseEnvelopeJson`      | `parse_envelope_json`      | `APH.parse_envelope_json/1`     |
  | `serializeEnvelope`      | `serialize_envelope`       | `APH.serialize_envelope/1`      |
  | `verifyProofStructure`   | `verify_proof_structure`   | `APH.verify_proof_structure/1`  |
  | `requireAttestationMode` | `require_attestation_mode` | `APH.require_attestation_mode/2`|

  None of the three may grow an operation, a semantic, or an error spelling
  the others lack: bindings that teach different things about one protocol are
  how a protocol acquires several meanings. Operatively — a change to this
  surface is unfinished until the same change lands in the other two, and the
  same holds in reverse.

  What none of them is: independent evidence. A binding that agrees with the
  reference agrees with itself. "Can a stranger build this from the
  specification alone?" is answered by an implementation that shares no code
  with the reference, and none of the four bindings is or claims to be one.

  ## Errors

  Every refusal is `{:error, message}` — a plain string, never an exception,
  because a refused envelope is an ordinary outcome on this boundary and not
  an exceptional one. There are two kinds of message, and the difference is
  visible without pattern matching on anything but the text:

    * a PROTOCOL refusal carries the reference implementation's own message,
      which LEADS WITH the `APH_E*` code — `APH_E013` for a forged
      `PrincipalSigned` label, `APH_E012` for a refused mode downgrade;
    * a SHAPE refusal (a field APH never defined, a malformed document)
      carries the parser's message and no code, because no protocol rule was
      reached.

  A caller matches a code exactly as a TypeScript caller matches it on the
  thrown message and a Python caller on `str(e)`:

      case APH.verify_proof_structure(received) do
        {:ok, mode} -> mode
        {:error, "APH_E013" <> _} -> :forged_label
        {:error, other} -> {:refused, other}
      end
  """

  @typedoc """
  An APH notarization envelope as JSON text. Never a map: see the module docs
  for why the boundary refuses terms.
  """
  @type envelope_json :: String.t()

  @typedoc """
  An attestation mode's wire spelling — `"PrincipalSigned"` or
  `"NotaryAttested"`. These are the bytes the protocol puts on the wire, so
  they are strings here too rather than atoms: converting wire text to atoms
  at a boundary is unbounded atom-table growth driven by input.
  """
  @type mode :: String.t()

  @typedoc """
  A refusal message. A protocol refusal LEADS WITH its `APH_E*` code; a shape
  refusal carries the parser's message and claims no code it did not earn.
  """
  @type refusal :: String.t()

  @doc """
  Parses JSON text as an APH `NotarizationEnvelope` and returns it re-emitted
  as canonical compact JSON text.

  `{:ok, json}` proves the input satisfied the strict envelope schema — APH
  parses with unknown fields DENIED, so a key the protocol never defined is a
  hard refusal rather than a silently dropped one. Decode the returned string
  to obtain a plain map.
  """
  @spec parse_envelope_json(envelope_json()) :: {:ok, envelope_json()} | {:error, refusal()}
  defdelegate parse_envelope_json(json), to: APH.Native

  @doc """
  Serializes an envelope, given as JSON text, back to canonical compact JSON
  text.

  The input must conform to the canonical envelope shape; any deviation is
  `{:error, message}`. This is the same operation as `parse_envelope_json/1`
  approached from the other direction — both exist so the surface reads the
  same in all four bindings, and both reduce to one parse and one re-emit.
  """
  @spec serialize_envelope(envelope_json()) :: {:ok, envelope_json()} | {:error, refusal()}
  defdelegate serialize_envelope(json), to: APH.Native

  @doc """
  Verifies the §7.1.11 proof-chain structural rules and returns the
  attestation mode the STRUCTURE supports.

  This is the check that detects a forged `PrincipalSigned` label: a label
  written above a structure that cannot bear it is refused with `APH_E013`.

  A successful return says the structure is sound. It says NOTHING about
  whether any signature verifies — a caller that reports "the human signed
  this" on the strength of this function alone is reporting a claim no key has
  backed.
  """
  @spec verify_proof_structure(envelope_json()) :: {:ok, mode()} | {:error, refusal()}
  defdelegate verify_proof_structure(json), to: APH.Native

  @doc """
  Refuses an envelope whose DECLARED attestation mode is weaker than
  `required` — the §8.3.1 step-1a no-downgrade gate — with `APH_E012`.

  `required` must be a wire spelling (`"PrincipalSigned"` or
  `"NotaryAttested"`). An unrecognized spelling is an error rather than a
  silent default, because a typo that defaulted to the weaker mode would BE
  the downgrade this gate exists to refuse.

  Returns bare `:ok` rather than `{:ok, term}`: success here carries no value,
  and `:ok | {:error, reason}` is the BEAM's spelling of that. The label alone
  is not evidence — a caller MUST also run `verify_proof_structure/1`, which is
  what rejects a forged `PrincipalSigned` label. Calling this function alone
  accepts one.
  """
  @spec require_attestation_mode(envelope_json(), mode()) :: :ok | {:error, refusal()}
  defdelegate require_attestation_mode(json, required), to: APH.Native

  @doc """
  Whether a Delegation Mandate (JSON text) is valid at `at` (RFC 3339), per
  the mandate's own `validFrom`/`validUntil` window.

  The semantics are `aph-core`'s, verbatim: an unparseable timestamp — in the
  argument OR in the mandate — yields `{:ok, false}`, never an error, because
  the core documents "parsing failure returns false" and a binding that
  invented stricter semantics would be a SECOND definition of one check. What
  IS refused (`{:error, reason}`) is a mandate that does not strict-parse:
  that is the JSON boundary's job in every export of this module.
  """
  @spec mandate_is_valid_at(String.t(), String.t()) :: {:ok, boolean()} | {:error, refusal()}
  defdelegate mandate_is_valid_at(mandate_json, at), to: APH.Native

  @doc """
  Verifies the §7.1.7.1 binding between an envelope (JSON text) and the
  Delegation Mandate embedded at `policy.delegationMandate`: the three
  identity equalities, the window, and the mandate signatures' presence rules
  — everything `aph-core`'s check performs, nothing more.

  An envelope with NO embedded mandate returns `:ok`, exactly as the core has
  it: absence of the optional block is not a binding failure. Returns bare
  `:ok` for the same reason `require_attestation_mode/2` does — success here
  carries no value.
  """
  @spec verify_embedded_mandate_binding(envelope_json()) :: :ok | {:error, refusal()}
  defdelegate verify_embedded_mandate_binding(json), to: APH.Native
end
