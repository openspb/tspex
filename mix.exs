defmodule Tspex.MixProject do
  use Mix.Project

  @version "0.1.0-dev"
  @source_url "https://github.com/openspb/tspex"

  def project do
    [
      app: :tspex,
      version: @version,
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      dialyzer: [
        plt_core_path: "_build/plts",
        plt_local_path: "_build/plts",
        flags: [:error_handling, :extra_return, :missing_return, :underspecs]
      ]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  def application do
    [extra_applications: [:crypto, :public_key, :inets, :ssl]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:cmsex, "~> 0.1"},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors --force",
        "credo --strict",
        "test"
      ]
    ]
  end

  defp description do
    "Time-Stamp Protocol (RFC 3161, RFC 5816) in pure Elixir: build requests, read " <>
      "responses and tokens, and verify a time-stamp at the date it was issued."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE NOTICE CHANGELOG.md SECURITY.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end
end
