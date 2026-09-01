#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SKILL_DEST="$CLAUDE_HOME/skills/lucy"
AGENT_DEST="$CLAUDE_HOME/agents"
BIN_DEST="${HOME}/.local/bin"
TEMP_DEST="$CLAUDE_HOME/skills/.lucy-install-$$"

fail() {
  printf '%s\n' "Install blocked: $1" >&2
  exit 1
}

# Validate the supported runtime before writing any installation files. The
# scan command performs the selected host's stronger, host-specific preflight.
command -v python3 >/dev/null 2>&1 || fail \
  "Python 3.11+ is required. Install Python, then run: python3 -m pip install ."
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11+ is required; this python3 is too old."
command -v git >/dev/null 2>&1 || fail \
  "Git is required. Install Git with your operating system's package manager."
HAS_CLAUDE=0
HAS_CODEX=0
command -v claude >/dev/null 2>&1 && HAS_CLAUDE=1
command -v codex >/dev/null 2>&1 && HAS_CODEX=1
if [ "$HAS_CLAUDE" -eq 0 ] && [ "$HAS_CODEX" -eq 0 ]; then
  fail "install and sign in to either Claude Code or Codex CLI, then rerun ./install.sh."
fi
if [ "$(uname -s)" = "Linux" ] && [ "$HAS_CODEX" -eq 1 ] \
  && ! command -v bwrap >/dev/null 2>&1; then
  if [ "$HAS_CLAUDE" -eq 0 ]; then
    fail "Codex CLI on Linux requires bubblewrap (bwrap). Install it with your operating system's package manager."
  fi
  printf '%s\n' \
    "Install note: Codex CLI on Linux requires bubblewrap (bwrap); Claude can run now, but --host codex will remain blocked until it is installed." >&2
fi
python3 -c 'import tree_sitter_language_pack' >/dev/null 2>&1 || fail \
  "tree-sitter-language-pack is required. From this checkout run: python3 -m pip install ."
if ! command -v rg >/dev/null 2>&1; then
  printf '%s\n' \
    "Install note: rg (ripgrep) was not found. It is optional, but recommended for Codex repository navigation." >&2
fi

python3 "$ROOT/tools/import_toolbox.py" --verify --destination "$ROOT/lucy/toolbox"
rm -rf "$TEMP_DEST"
mkdir -p "$TEMP_DEST" "$AGENT_DEST" "$BIN_DEST"
cp -R "$ROOT/lucy/." "$TEMP_DEST/"
rm -rf "$SKILL_DEST"
mv "$TEMP_DEST" "$SKILL_DEST"
cp "$ROOT/lucy/agents/lucy-reader.md" "$AGENT_DEST/lucy-reader.md"
cp "$ROOT/lucy/agents/lucy-court.md" "$AGENT_DEST/lucy-court.md"
for wrapper in lucy lucy-merge lucy-finalize lucy-units lucy-report lucy-toolbox; do
  if [ -f "$ROOT/lucy/bin/$wrapper" ]; then
    cp "$ROOT/lucy/bin/$wrapper" "$BIN_DEST/$wrapper"
    chmod 755 "$BIN_DEST/$wrapper"
  fi
done

printf '%s\n' "Installed: lucy CLI -> $BIN_DEST/lucy  (scan | launch | recapture | export)"
printf '%s\n' "Installed: optional Claude Code skill + reader/court agents -> $SKILL_DEST"
printf '%s\n' "Installed: pinned wrappers (lucy-merge/finalize/units/report/toolbox) -> $BIN_DEST"
printf '%s\n' "Ensure $BIN_DEST is on PATH. Start with: lucy scan --target <estate> --results <dir> --estimate-only"
