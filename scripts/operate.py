#!/usr/bin/env python3
"""Execute an end-to-end PR authority decision and local side-effect dispatch."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pr_authority_matrix import PrAuthorityMatrix, PrAuthorityMatrixRequest, RecordingExecutor


def demo(now: float = 1_800_000_000.0) -> dict:
    matrix = PrAuthorityMatrix(b"demo-only-authority-secret")
    grant = matrix.issue_grant(
        grant_id="demo-grant",
        actor="portfolio-operator",
        repository="GlacierEQ/example",
        roles=("maintain",),
        actions=("label", "comment", "merge"),
        ttl_seconds=300,
        now=now,
    )
    request = PrAuthorityMatrixRequest(
        subject_id="demo-pr-action",
        payload={
            "actor": "portfolio-operator",
            "repository": "GlacierEQ/example",
            "pr_number": 42,
            "action": "label",
            "grant": grant.as_dict(),
            "context": {},
            "side_effect": {"labels": ["crystallized"]},
        },
        budget=1.0,
    )
    executor = RecordingExecutor()
    return matrix.dispatch(request, executor, now=now + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local PR authority matrix demonstration")
    parser.add_argument("--output", help="optional JSON output path")
    args = parser.parse_args()

    receipt = demo()
    text = json.dumps(receipt, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if receipt.get("executed") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
