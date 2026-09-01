#!/usr/bin/env python3
"""Import an allowlisted deterministic toolbox subset from lucy.zip."""

from __future__ import annotations

import argparse
from io import BytesIO
import hashlib
import json
from pathlib import Path
import sys
from zipfile import ZipFile


ALLOWLIST = (
    "HERMETIC_RUNNER.py",
    "LENS_BRIEFS.md",
    "SCAN_REPORT_CONTRACT.md",
    "SCAN_REPORT_TEMPLATE.json",
    "SEAL_CARD_TEMPLATE.md",
    "SEVERITY_RUBRIC.md",
    "census.py",
    "certification_gate.py",
    "conservation_gate.py",
    "detector_battery_v3_3_1.py",
    "gates_selftest.py",
    "mint_canaries.py",
    "mutation_battery.py",
    "scam_battery_v1_1.py",
    "scan_report_gate.py",
    "seal_card_gate.py",
    "token_gate.py",
    "visitation_check.py",
)


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def import_toolbox(source_zip: Path, destination: Path) -> dict[str, object]:
    source_zip = source_zip.resolve()
    destination = destination.resolve()
    with ZipFile(source_zip) as outer:
        install_bytes = outer.read("INSTALL_KIT.zip")
    with ZipFile(BytesIO(install_bytes)) as install:
        scripts_bytes = install.read("STEP_1_UPLOAD_PACK/scripts.zip")
    with ZipFile(BytesIO(scripts_bytes)) as scripts:
        available = set(scripts.namelist())
        missing = sorted(set(ALLOWLIST) - available)
        if missing:
            raise ValueError(f"source toolbox is missing allowlisted members: {', '.join(missing)}")
        assets = []
        destination.mkdir(parents=True, exist_ok=True)
        for name in ALLOWLIST:
            content = scripts.read(name)
            output = destination / name
            output.write_bytes(content)
            assets.append({"path": name, "sha256": sha256(content), "size": len(content)})

    manifest = {
        "schema": "lucy-toolbox-assets/v1",
        "source_artifact": "lucy.zip",
        "source_archive_sha256": sha256(source_zip.read_bytes()),
        "install_kit_sha256": sha256(install_bytes),
        "scripts_zip_sha256": sha256(scripts_bytes),
        "asset_count": len(assets),
        "assets": assets,
    }
    (destination / "assets.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def verify_toolbox(destination: Path) -> list[str]:
    manifest_path = destination / "assets.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors = []
    for asset in manifest.get("assets", []):
        path = destination / asset["path"]
        if not path.is_file():
            errors.append(f"missing asset: {asset['path']}")
            continue
        content = path.read_bytes()
        if sha256(content) != asset["sha256"]:
            errors.append(f"asset hash mismatch: {asset['path']}")
        elif "size" in asset and len(content) != asset["size"]:
            errors.append(f"asset size drift: {asset['path']}")
    if manifest.get("asset_count") != len(manifest.get("assets", [])):
        errors.append("asset_count does not match assets")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--destination", type=Path, default=Path("lucy/toolbox"))
    parser.add_argument("--verify", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify:
            errors = verify_toolbox(args.destination)
            if errors:
                for error in errors:
                    print(f"toolbox verification failed: {error}", file=sys.stderr)
                return 1
            print("toolbox verification passed")
            return 0
        if args.source is None:
            raise ValueError("source lucy.zip path is required")
        manifest = import_toolbox(args.source, args.destination)
        print(f"imported {manifest['asset_count']} toolbox assets")
        return 0
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"toolbox import failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())