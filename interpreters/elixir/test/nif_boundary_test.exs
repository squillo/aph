defmodule APH.NifBoundaryTest do
  use ExUnit.Case, async: true

  # The envelope-facing surface, enumerated. Every claim below is made about
  # exactly these four and nothing wider — the parity contract names four
  # operations, so four is what this file inspects.
  @operations [
    {:parse_envelope_json, 1},
    {:serialize_envelope, 1},
    {:verify_proof_structure, 1},
    {:require_attestation_mode, 2}
  ]

  # 2^53 + 1: the smallest positive integer an IEEE-754 double cannot hold.
  @beyond_double 9_007_199_254_740_993

  test "the NIF surface is string-in and string-out: no term-shaped envelope exists" do
    # WHY: this is the boundary rule made mechanical rather than documented,
    # and it is the ONE property no Rust test can reach — a rustler NIF is Rust
    # embedded in the BEAM, so nothing under `cargo test` ever sees a term.
    #
    # PINS, in both directions: (1) all four operations exist at the arity the
    # three-way parity contract names; (2) every one of them, handed a decoded
    # envelope — the exact term a map/list route would accept — REFUSES it,
    # so there is no arity anywhere that takes an envelope as a term; (3) every
    # success value is a binary or the bare `:ok` atom, never a map or list, so
    # the boundary cannot leak a term outward either. If a future change adds a
    # term-accepting arity, (2) goes green-to-red on the added path only when
    # the operation list above grows with it — which is why that list is the
    # contract and is written out by hand.
    assert Code.ensure_loaded?(APH.Native),
           "the NIF module must load before its surface can be inspected"

    for {name, arity} <- @operations do
      assert function_exported?(APH.Native, name, arity),
             "APH.Native.#{name}/#{arity} is part of the parity contract and must exist"
    end

    golden = APH.TestCorpus.principal_signed_golden()
    term_envelope = Jason.decode!(golden)

    for {name, arity} <- @operations do
      args = if arity == 1, do: [term_envelope], else: [term_envelope, "PrincipalSigned"]

      assert raises?(APH.Native, name, args),
             "APH.Native.#{name}/#{arity} accepted a decoded envelope; the boundary is JSON text"
    end

    assert {:ok, parsed} = APH.Native.parse_envelope_json(golden)
    assert is_binary(parsed)
    assert {:ok, serialized} = APH.Native.serialize_envelope(golden)
    assert is_binary(serialized)
    assert {:ok, mode} = APH.Native.verify_proof_structure(golden)
    assert is_binary(mode)
    assert APH.Native.require_attestation_mode(golden, "PrincipalSigned") == :ok
  end

  test "an integer no double can hold crosses the boundary unrounded" do
    # WHY: this is the sibling bindings' tripwire, kept here so the three test
    # suites pin the same property, and it is worth stating that it means
    # something DIFFERENT on this runtime. In JS and Python the hazard is real
    # rounding — both languages' numbers are doubles, so 2^53 + 1 comes back as
    # 2^53. Erlang integers are arbitrary precision, so the BEAM would not
    # round it; what this test detects here is a boundary that started routing
    # numbers through a term encoder at all, since any such route would have to
    # choose a representation. PINS: exact fidelity of a `bodySize` no double
    # can express, end to end through the text boundary.
    widened =
      APH.TestCorpus.legacy_slack_reply()
      |> Jason.decode!()
      |> put_in(["credentialSubject", "communication", "bodySize"], @beyond_double)
      |> Jason.encode!()

    assert {:ok, normalized} = APH.parse_envelope_json(widened)

    assert get_in(Jason.decode!(normalized), [
             "credentialSubject",
             "communication",
             "bodySize"
           ]) == @beyond_double
  end

  # Answers "did this call refuse?" without pinning HOW it refused. The class
  # of the failure is a decoder detail of the NIF library — a badarg surfacing
  # as one exception struct or another is not a protocol fact — while REFUSING
  # rather than coercing is exactly the protocol fact under test.
  defp raises?(module, name, args) do
    apply(module, name, args)
    false
  rescue
    _ -> true
  catch
    _, _ -> true
  end
end
