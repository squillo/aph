defmodule APH.MixProject do
  use Mix.Project

  # Equal to the Rust workspace's `workspace.package.version` on purpose: this
  # app is a BINDING of those crates, so a version that drifted from the code
  # it wraps would advertise a compatibility the artifact cannot have. The
  # `-alpha.1` tail is deliberate for the same reason it is in the Cargo
  # manifest — the specification still reads draft, so an adopter opts in on
  # purpose — and it is valid SemVer, which is what Mix requires.
  @version "0.1.0-alpha.1"

  def project do
    [
      app: :aph,
      version: @version,
      # The FLOOR is the oldest pair this binding has actually been run and
      # passed on (Elixir 1.13 / OTP 24), not the newest one available.
      # Declaring higher would refuse a toolchain that demonstrably works;
      # declaring lower would claim one nobody has run. CI runs a current pair
      # instead — see the workflow comment for why the floor cannot run there.
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
      # Deliberately NO `package:` block. This app is not published, and a
      # populated package section is how an unpublished artifact starts
      # looking like a published one in someone's diff. See README.md.
    ]
  end

  def application do
    # No supervision tree, no application callback, no extra applications: the
    # whole binding is four pure functions over bytes. Nothing here starts a
    # process, opens a socket, or holds state — a binding that acquired any of
    # those would be FETCHING, and fetching belongs to the host, never to the
    # thing that parses what the host hands it.
    []
  end

  # `test/support` carries the corpus reader the suite shares. It is compiled
  # only under MIX_ENV=test so a test-only path can never reach a consumer.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # PINNED TIGHT (`~> 0.30.0` admits 0.30.x and nothing else) because the
      # installed toolchain outranks the newest release number. Two published
      # facts set this bound: rustler 0.37.1 records that rustler_mix actually
      # requires Elixir >= 1.15 (0.37.0 shipped claiming ~> 1.11 and was
      # wrong), which puts 0.37+ out of reach of the floor above; and 0.37.0
      # was retired outright over a bug in how it discovers a crate's workspace
      # shape, which is not a thing to be adventurous about when the crate
      # under native/ has an unusual one. 0.30.0 is the release that raised
      # the default NIF version to 2.15 — loadable by OTP 24
      # (NIF 2.16) and by every later OTP, since NIF versions are backwards
      # compatible — and the release that made :rustler compile-time-only.
      #
      # `runtime: false` is the spelling this release's own setup instructions
      # give, and it is honest here: rustler is consumed entirely at compile
      # time — the `use Rustler` hook drives cargo while the module compiles —
      # so nothing it ships needs to be a running application afterwards.
      {:rustler, "~> 0.30.0", runtime: false},
      # Used by the TEST SUITE only — no module under lib/ references it. It
      # is named at top level rather than scoped `only: :test` because rustler
      # already requires it for all environments, and a top-level `only:` that
      # contradicts a dependency's own environment set is a resolution
      # conflict rather than a saving. Naming it makes the suite's decoder an
      # explicit choice instead of one borrowed from a build tool, and adds no
      # supply chain that the build did not already have.
      {:jason, "~> 1.4"}
    ]
  end
end
