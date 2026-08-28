defmodule APH.CorpusTest do
  use ExUnit.Case, async: true

  test "the corpus on disk is exactly the corpus the manifest claims" do
    # WHY: this suite read exactly two published examples BY NAME and
    # enumerated nothing, so a vocabulary change — a new channel shape, a new
    # cryptosuite vector, a renamed file — could land in `examples/` and this
    # binding would report success having never opened it. A count would not
    # have helped: a floor of "at least twelve" passes forever, and swapping one
    # file for another leaves a count unmoved.
    #
    # PINS: SET EQUALITY in BOTH directions between the manifest's conformance
    # list and the top-level `*.json` files on disk. A file on disk with no
    # manifest entry fails and names itself — the direction that catches a
    # vector nobody classified. A manifest entry with no file fails too, which
    # catches a deletion or rename that a one-directional check would read as
    # "fewer files, still above the floor".
    on_disk = APH.TestCorpus.example_files()
    claimed = APH.TestCorpus.conformance_files()

    undeclared = on_disk -- claimed
    missing = claimed -- on_disk

    assert undeclared == [],
           "these files are in examples/ with no entry in manifest.json: " <>
             Enum.join(undeclared, ", ")

    assert missing == [],
           "manifest.json claims these files that are not on disk: " <> Enum.join(missing, ", ")
  end

  test "every conformance file the manifest claims strict-parses through the NIF" do
    # WHY: the set comparison above compares NAMES. A file can be named in both
    # places and still be a zero-byte stub — and an audit found the old floor
    # here ("is a JSON object") let a golden carrying a NEW FIELD pass without
    # the NIF ever seeing the field, so the one gate that runs this boundary
    # was vouching for bytes it never parsed.
    #
    # PINS: every conformance entry strict-parses through APH.parse_envelope_json/1,
    # so every FUTURE golden exercises the NIF the day it lands, with nobody
    # remembering to add a test.
    for name <- APH.TestCorpus.conformance_files() do
      raw = APH.TestCorpus.read!(name)

      assert {:ok, _normalized} = APH.parse_envelope_json(raw),
             "#{name} is named in manifest.json and does not strict-parse through the NIF"
    end
  end

  test "every excluded file is on disk and says why it is excluded" do
    # WHY: the excluded list is the half of the inventory that rots quietly. A
    # conformance claim that silently covered a deliberately non-conformant
    # document would be false, and an exclusion naming a file nobody can find
    # any more is an exclusion for something that stopped existing.
    #
    # PINS: every excluded path resolves on disk, and every one carries a
    # non-empty reason — an exclusion with no stated reason is one the next
    # reader cannot tell from an oversight.
    for entry <- APH.TestCorpus.excluded_entries() do
      path = Map.fetch!(entry, "path")
      reason = Map.get(entry, "reason", "")

      assert String.trim(reason) != "", "#{path} is excluded with no stated reason"

      assert File.exists?(Path.join(APH.TestCorpus.examples_dir(), path)),
             "#{path} is excluded in manifest.json and is not on disk"
    end
  end

  test "the two deep-verified goldens are still the files the manifest claims" do
    # WHY: the named goldens are the ONE place this suite still addresses the
    # corpus by hand — `principal_signed_golden/0` and `legacy_slack_reply/0`
    # carry every cryptographic and boundary assertion in the other test files.
    # A rename that updated the manifest and the disk together would leave those
    # two helpers pointing at nothing, and the failure would surface as a
    # File.read! deep inside an unrelated test.
    #
    # PINS: both hand-named goldens are members of the declared conformance set,
    # so the individual names and the set inventory cannot drift apart.
    claimed = APH.TestCorpus.conformance_files()

    for name <- ["principal_signed_envelope.json", "slack_reply_envelope.json"] do
      assert name in claimed,
             "#{name} is read by name throughout this suite and is not in the conformance manifest"
    end

    assert String.contains?(APH.TestCorpus.principal_signed_golden(), "\"proof\"")
    assert String.contains?(APH.TestCorpus.legacy_slack_reply(), "\"proof\"")
  end
end
