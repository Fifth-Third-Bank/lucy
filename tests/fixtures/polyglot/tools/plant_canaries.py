#!/usr/bin/env python3
"""Deterministic fixture planter for the polyglot estate (test-only oracle).

Copies apps/, shared/, infra/, deploy/ from --source to --output, applies the
eight fixed mutations (two per family), and writes ANSWER_KEY.json. This is
the CI stand-in for the real ephemeral Claude planter.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys


MUTATIONS = [
    {
        "slot": 1,
        "family": "L1-auth",
        "path": "apps/ledger-api/src/main/java/com/example/ledger/web/LedgerController.java",
        "old": '    @PreAuthorize("hasAuthority(\'SCOPE_ledger:read\')")\n    public ResponseEntity<List<LedgerEntry>> entries(',
        "new": "    public ResponseEntity<List<LedgerEntry>> entries(",
        "anchor": "entries(",
        "title": "Ledger read route lost its authority check and is reachable by any authenticated principal.",
    },
    {
        "slot": 2,
        "family": "L1-auth",
        "path": "apps/admin-ui/middleware.ts",
        "old": "      issuer: ISSUER,\n",
        "new": "",
        "anchor": "audience: AUDIENCE,",
        "title": "Admin UI JWT verification no longer pins the token issuer, accepting tokens from any tenant.",
    },
    {
        "slot": 3,
        "family": "L2-secrets",
        "path": "apps/portal-bff/Program.cs",
        "old": "            ValidateIssuerSigningKey = true,",
        "new": "            ValidateIssuerSigningKey = false,",
        "anchor": "ValidateIssuerSigningKey = false,",
        "title": "Portal BFF token validation disables issuer signing-key checks, accepting unsigned assertions.",
    },
    {
        "slot": 4,
        "family": "L2-secrets",
        "path": "shared/crypto-lib/src/cryptolib/aead.py",
        "old": "        nonce = os.urandom(_NONCE_LEN_BYTES)",
        "new": '        nonce = b"\\x00" * _NONCE_LEN_BYTES',
        "anchor": "_NONCE_LEN_BYTES\n",
        "title": "AEAD encryption reuses an all-zero static nonce for every message under the same key.",
    },
    {
        "slot": 5,
        "family": "L3-injection",
        "path": "apps/notify-svc/store.go",
        "old": "\t\t  WHERE tenant_id = $1\n\t\t  ORDER BY created_at DESC\n\t\t  LIMIT $2`,\n\t\ttenantID, limit)",
        "new": "\t\t  WHERE tenant_id = '` + tenantID + `'\n\t\t  ORDER BY created_at DESC\n\t\t  LIMIT $1`,\n\t\tlimit)",
        "anchor": "WHERE tenant_id = '`",
        "title": "Notification listing interpolates the tenant identifier directly into SQL text.",
    },
    {
        "slot": 6,
        "family": "L3-injection",
        "path": "apps/batch-worker/lib/settlement_service.rb",
        "old": "    result = @conn.exec_params(FIND_JOB_SQL, [job_id, tenant_id])",
        "new": "    result = @conn.exec(\"SELECT * FROM settlement_jobs WHERE id = '#{job_id}' AND tenant_id = '#{tenant_id}'\")",
        "anchor": "settlement_jobs WHERE id =",
        "title": "Batch job lookup builds SQL by string interpolation of request-supplied identifiers.",
    },
    {
        "slot": 7,
        "family": "L4-infra",
        "path": "infra/api_gateway.tf",
        "old": '  authorization_type = "JWT"',
        "new": '  authorization_type = "NONE"',
        "anchor": 'authorization_type = "NONE"',
        "title": "An API Gateway route was switched to authorization type NONE, exposing it without the JWT authorizer.",
        "occurrence": 2,
    },
    {
        "slot": 8,
        "family": "L4-infra",
        "path": "deploy/deployment.yaml",
        "old": "        runAsNonRoot: true",
        "new": "        runAsNonRoot: false",
        "anchor": "runAsNonRoot: false",
        "title": "The workload security context permits the container to run as root.",
    },
]


def apply(source: Path, output: Path) -> list[dict]:
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for top in ("apps", "shared", "infra", "deploy"):
        shutil.copytree(source / top, output / top, ignore=ignore)
    rows = []
    for mutation in MUTATIONS:
        path = output / mutation["path"]
        content = path.read_text(encoding="utf-8")
        occurrence = mutation.get("occurrence", 1)
        pieces = content.split(mutation["old"])
        if len(pieces) <= occurrence:
            raise SystemExit(f"anchor missing for slot {mutation['slot']}: {mutation['path']}")
        prefix = mutation["old"].join(pieces[:occurrence])
        content = prefix + mutation["new"] + mutation["old"].join(pieces[occurrence:])
        path.write_text(content, encoding="utf-8")
        # Line of the mutation = line where the replacement begins (or the
        # first line of the replacement text when it spans lines).
        line = prefix.count("\n") + 1
        rows.append(
            {
                "slot": mutation["slot"],
                "family": mutation["family"],
                "path": mutation["path"],
                "line": line,
                "title": mutation["title"],
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = apply(args.source.resolve(), args.output.resolve())
    (args.output / "ANSWER_KEY.json").write_text(
        json.dumps({"schema": "lucy-answer-key/v1", "canaries": rows}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"planted {len(rows)} canaries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
