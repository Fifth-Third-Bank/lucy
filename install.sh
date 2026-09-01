#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SKILL_DEST="$CLAUDE_HOME/skills/lucy"
AGENT_DEST="$CLAUDE_HOME/agents"
BIN_DEST="${HOME}/.local/bin"
TEMP_DEST="$CLAUDE_HOME/skills/.lucy-install-$$"

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
printf '%s\n' "Installed: Claude Code skill + reader/court agents -> $SKILL_DEST"
printf '%s\n' "Installed: pinned wrappers (lucy-merge/finalize/units/report/toolbox) -> $BIN_DEST"
printf '%s\n' "Ensure $BIN_DEST is on PATH. Start with: lucy scan --target <estate> --results <dir> --estimate-only"