#!/usr/bin/env sh
set -eu

CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
rm -rf "$CLAUDE_HOME/skills/lucy"
rm -f "$CLAUDE_HOME/agents/lucy-reader.md" "$CLAUDE_HOME/agents/lucy-court.md"
for wrapper in lucy lucy-merge lucy-finalize lucy-units lucy-report lucy-toolbox lucy-trial; do
  rm -f "$HOME/.local/bin/$wrapper"
done
echo "Uninstalled LUCY"