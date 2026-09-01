# Changelog

## 1.1.1 - 2026-09-01

Small installation and terminal-output corrections:

- Render human-facing cost-estimate text as UTF-8 so punctuation such as an
  em dash is displayed directly instead of as a `\u2014` escape sequence.
- Replace the installer's PEP 668-incompatible recovery command with
  copy-pasteable virtual-environment setup and usage guidance.
- Keep `make check` runnable from the public archive by skipping only
  source-only Jenkins policy assertions when internal build metadata is
  absent. Internal checkouts that contain the publishing configuration still
  validate it. Document installation of the development dependencies.

## 1.1.0 - 2026-09-01

Initial public release of LUCY, an agentic source-code vulnerability scanning
harness for large, complex applications.

- Multi-pass review across authentication, secrets, injection, and
  infrastructure, with cross-repository sweeps and deterministic detectors.
- Adversarial verification of serious findings, including retained refutations
  and explicit dispositions for synthetic canaries and historical findings.
- Blind recall measurement, bounded recapture, and receipt-backed certification
  gates for coverage, convergence, and artifact integrity.
- Resumable scanning with live progress, cost estimates, private external
  result storage, and best-effort masking of finalized narrative and report
  artifacts.
- Gated JSON reports, human-readable findings, certification receipts, and
  SARIF export.
- Claude Code support by default, saved-login Codex CLI support through
  `--host codex`, and an experimental OpenAI-compatible API host. Codex does
  not require Claude or an API key and uses launcher-owned, workspace-confined
  lanes with resumable receipts and token/timing accounting.
- Curated public-release metadata and generic demonstration fixtures, with
  generated caches and private ownership metadata excluded from archives.
- Installation validates Python 3.11+, Git, the required tree-sitter grammar
  pack, and the presence of either Claude Code or Codex CLI before writing
  files. Ripgrep is an optional Codex navigation accelerator. Debian/Ubuntu
  venv setup, the Codex-on-Linux `bubblewrap` sandbox prerequisite, and the
  release-only `ruff` development extra are explicit.
