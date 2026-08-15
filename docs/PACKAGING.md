# Packaging & PyPI — why, and what it does (and doesn't) do

The engine is published to PyPI as **`llm-provenance-probe`** (`pip install
llm-provenance-probe`). This note records *why* it's packaged, so the decision travels
with the code.

## Why publish to PyPI

1. **Reproducible, pinned installs — the load-bearing reason.** The
   [Observatory](../README.md#-companion--the-observatory) consumes the probe strictly
   as a black-box CLI and its whole value is *signed, trustworthy evidence*. That
   evidence is only as trustworthy as a **known engine version**. Before the release,
   the Observatory's nightly installed the probe from `git+…@main` — a moving target,
   so each run could silently get different code. Publishing lets it pin
   `llm-provenance-probe==<version>` in `requirements.txt` and build/sign the nightly
   catalog + registry on a version you can name and reproduce. A signed artifact from
   an unpinned engine is not really reproducible.

2. **Distribution / adoption.** `pip install llm-provenance-probe` beats
   clone-the-repo-then-`pip install -e .` for anyone who just wants to *run* the tool —
   a security team, a CI job, a federal analyst. One command, no repo checkout.

3. **A declarable dependency.** The Observatory's T7 contract is "consume the probe as
   a CLI, never import its internals." A PyPI package makes that a normal, pinnable
   dependency instead of a git URL.

## What it does NOT do: automate captures

Publishing to PyPI does **not** make web-app **captures** automatable, and that was
never the goal. Capturing a logged-in web app (hix.ai, z.ai, …) is deliberately
**human-in-the-loop**: the login happens in an unrecorded browser the operator drives
("no password handling, ever"). No package changes that.

Where PyPI *does* help automation is the **non-interactive** paths — the ones that run
without a human at the keyboard:

- `assess` / `monitor` (exit-2-on-drift) wired into CI; `watch --once`; `sentinel`
- the Observatory's nightly `build-catalog` / `build-registry` / probing
- `fleet-scan`, `catalog` search, `build-reference`

So: PyPI automates **running the engine in pipelines**, not **capturing credentialed
web apps** — the `provenance-guide` agent just hands that manual step off cleanly.

## Naming: distribution vs. command

- **PyPI distribution name:** `llm-provenance-probe`. `provenance-probe` alone is
  rejected by PyPI as too similar to the pre-existing project
  [`provenance`](https://pypi.org/project/provenance/) (typosquat protection).
- **CLI command:** still `provenance-probe` (the `[project.scripts]` entry-point name
  is independent of the distribution name).
- **Import package:** still `provenance_probe`. **GitHub repo:** still
  `provenance-probe`.

So `pip install llm-provenance-probe` gives you the `provenance-probe` command — only
the install string differs.

## Release mechanism

- **Trusted Publishing (OIDC), tag-driven, gated** — see
  [`.github/workflows/release.yml`](../.github/workflows/release.yml). Push a `vX.Y.Z`
  tag; the gate requires `tag == pyproject version` and a green test + zero-FP eval run;
  publish uses `pypa/gh-action-pypi-publish` with no stored token.
- **Version discipline:** bump `pyproject`/`__init__` + finalize the `CHANGELOG`
  section, then tag. Downstream (the Observatory) bumps its
  `llm-provenance-probe==<version>` pin to adopt a release.
