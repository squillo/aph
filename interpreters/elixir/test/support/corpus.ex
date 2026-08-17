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

  Compiled only under `MIX_ENV=test`; see `elixirc_paths/1` in mix.exs.
  """

  # Resolved from `__DIR__` at compile time rather than from the current
  # working directory: `mix test` can be invoked from anywhere, and a suite
  # that silently read a DIFFERENT corpus than the published one would be
  # testing nothing while staying green. Four levels up is the repository root.
  @examples_dir Path.expand("../../../../examples", __DIR__)

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
