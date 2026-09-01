#!/usr/bin/env python3
"""Verify installed deterministic toolbox assets."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def verify(toolbox: Path) -> list[str]:
    manifest = json.loads((toolbox / "assets.json").read_text(encoding="utf-8"))
    errors = []
    for asset in manifest.get("assets", []):
        path = toolbox / asset["path"]
        if not path.is_file():
            errors.append(f"missing asset: {asset['path']}")
            continue
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != asset["sha256"]:
            errors.append(f"asset hash mismatch: {asset['path']}")
        elif "size" in asset and len(content) != asset["size"]:
            # The hash is the security boundary; the size check only stops
            # the manifest from silently drifting into misleading metadata.
            errors.append(f"asset size drift: {asset['path']}")
    if manifest.get("asset_count") != len(manifest.get("assets", [])):
        errors.append("asset_count does not match assets")
    return errors


def verify_asset(script_path: Path) -> None:
    """Verify ONE toolbox script against the pinned manifest at execution
    time. Install-time verification alone cannot detect a later change that
    would otherwise become launcher-executed code."""
    toolbox = script_path.parent
    manifest = json.loads((toolbox / "assets.json").read_text(encoding="utf-8"))
    relative = script_path.name
    for asset in manifest.get("assets", []):
        if asset["path"] == relative:
            actual = hashlib.sha256(script_path.read_bytes()).hexdigest()
            if actual != asset["sha256"]:
                raise ValueError(
                    f"toolbox asset {relative} does not match its pinned hash; "
                    "refusing to execute (reinstall to restore pinned assets)"
                )
            return
    raise ValueError(f"toolbox asset {relative} is not in the pinned manifest")


def main() -> int:
    toolbox = Path(__file__).parents[1] / "toolbox"
    errors = verify(toolbox)
    if errors:
        for error in errors:
            print(f"asset verification failed: {error}", file=sys.stderr)
        return 1
    print("asset verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
