defmodule APH.TestCorpus do
  @moduledoc """
  Reads published example envelopes off disk for the suite.

  The corpus is the one this repository publishes and nothing here mints or
  signs anything new: a binding's tests exist to prove the boundary carries the
  published bytes faithfully, and a fixture invented for a test proves only
  that the test agrees with itself. Where a case needs an envelope the corpus
  does not contain — a forged label, a smuggled field — the test DERIVES it
  from a published one in view of the reader, so what changed is visible in the
  test rather than buried in a committed file.

  Two ways of naming the corpus live here on purpose. `read!/1` and the two
  named goldens address files INDIVIDUALLY, which is what a deep test needs.
  `manifest/0` and `example_files/0` address the corpus as a SET, which is what
  catches the thing individual names never can: this suite once read exactly two
  files by name and enumerated nothing, so a vector could land in `examples/`
  and the binding would report success having never opened it.

  Compiled only under `MIX_ENV=test`; see `elixirc_paths/1` in mix.exs.
  """

  # Resolved from `__DIR__` at compile time rather than from the current
  # working directory: `mix test` can be invoked from anywhere, and a suite
  # that silently read a DIFFERENT corpus than the published one would be
  # testing nothing while staying green. Four levels up is the repository root.
  @examples_dir Path.expand("../../../../examples", __DIR__)

  # The corpus INVENTORY, which is not itself a vector. Every binding's
  # enumerator skips this name for the same reason: it is the list, not a thing
  # on the list, and a suite that strict-parsed it as an envelope would fail on
  # the inventory rather than on a document anyone publishes.
  @manifest_file "manifest.json"

  @doc """
  The examples directory this suite reads, resolved once at compile time.
  """
  @spec examples_dir() :: String.t()
  def examples_dir, do: @examples_dir

  @doc """
  Reads a published example envelope by file name, raising if it is missing.

  Raising is the point: a renamed or removed example must break the suite
  loudly at the read, not quietly turn a later assertion vacuous.
  """
  @spec read!(String.t()) :: String.t()
  def read!(name) do
    @examples_dir |> Path.join(name) |> File.read!()
  end

  @doc """
  The decoded corpus manifest — the one inventory every binding measures
  against.

  Reading a directory tells you what IS there; a kept list tells you what
  SHOULD be. Only the disagreement between the two is evidence, which is why
  this module exposes both and the suite compares them. Raises if the manifest
  is missing or malformed: an inventory that cannot be read is
  indistinguishable from an empty one, and an empty one makes every comparison
  against it pass by comparing nothing to nothing.
  """
  @spec manifest() :: map()
  def manifest do
    @manifest_file |> read!() |> Jason.decode!()
  end

  @doc """
  The file names the manifest claims as the conformance corpus, sorted.
  """
  @spec conformance_files() :: [String.t()]
  def conformance_files do
    manifest() |> Map.fetch!("conformance") |> Enum.sort()
  end

  @doc """
  The manifest's excluded entries: present in the repository, deliberately
  outside the conformance claim, each carrying the one-line reason it is out.
  """
  @spec excluded_entries() :: [map()]
  def excluded_entries do
    Map.fetch!(manifest(), "excluded")
  end

  @doc """
  Every top-level `*.json` in the corpus, ENUMERATED FROM DISK rather than
  remembered, sorted, with the inventory itself skipped by name.

  Subdirectories are deliberately not descended into: the top level IS the
  conformance corpus, and what lives below it is inventoried as excluded rather
  than enumerated here.
  """
  @spec example_files() :: [String.t()]
  def example_files do
    @examples_dir
    |> File.ls!()
    |> Enum.filter(&String.ends_with?(&1, ".json"))
    |> Enum.reject(&(&1 == @manifest_file))
    |> Enum.reject(&File.dir?(Path.join(@examples_dir, &1)))
    |> Enum.sort()
  end

  @doc """
  The signed `PrincipalSigned` golden — the CHAIN arm of the proof union, and
  the form a forged label imitates.
  """
  @spec principal_signed_golden() :: String.t()
  def principal_signed_golden, do: read!("principal_signed_envelope.json")

  @doc """
  A pre-chain envelope — the SINGLE-OBJECT arm of the proof union, carrying no
  `attestationMode` at all, which the protocol reads as `NotaryAttested`.
  """
  @spec legacy_slack_reply() :: String.t()
  def legacy_slack_reply, do: read!("slack_reply_envelope.json")
end
