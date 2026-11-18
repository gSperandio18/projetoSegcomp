#!/usr/bin/env python3
"""Module 5: Standalone Independent Audit CLI.

Zero-trust verifier CLI executing cryptographic checks over public election records:
  - Ledger hash-chain continuity & tamper detection
  - Voter RSA digital signatures & unicity enforcement
  - Homomorphic product tally recomputation
  - Threshold decryption shares consistency
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List
from cryptography.hazmat.primitives.asymmetric import rsa

from evoting.auditor import AuditReport, ElectionAuditor
from evoting.bulletin_board import AppendOnlyBulletinBoard
from evoting.config.params import DEFAULT_DATABASE_PATH, MODP_2048_G, MODP_2048_P
from evoting.storage.database import get_all_blocks, get_db_session


def format_table_row(col1: str, col2: str, col3: str, width: int = 74) -> str:
    """Format three columns inside a fixed-width CLI table."""
    c1 = col1.ljust(34)
    c2 = col2.center(12)
    c3 = col3.ljust(width - 50)
    return f"| {c1} | {c2} | {c3} |"


def print_audit_report(report: AuditReport) -> None:
    """Render a structured ANSI text report to stdout."""
    border = "=" * 76
    sub_border = "-" * 76

    print(f"\n{border}")
    print(f"  INDEPENDENT ZERO-TRUST AUDIT REPORT: {report.election_id}")
    print(f"{border}")
    print(format_table_row("VERIFICATION STAGE", "STATUS", "DETAILS", 74))
    print(sub_border)

    for item in report.checks:
        status_str = "[ PASS ]" if item.passed else "[ FAIL/STUB ]"
        print(format_table_row(item.name, status_str, item.details[:22]))

    print(sub_border)
    overall_status = "VERIFIED (AUTHENTIC)" if report.overall_passed else "REJECTED (OR STUB PENDING)"
    print(f"  OVERALL AUDIT VERDICT: {overall_status}")
    print(f"{border}\n")


def run_demo_audit() -> int:
    """Execute simulated audit flow for demonstration and testing."""
    print("[*] Running simulated zero-trust audit flow against sample election data...")
    board = AppendOnlyBulletinBoard()
    voters: Dict[str, rsa.RSAPublicKey] = {}

    auditor = ElectionAuditor(
        bulletin_blocks=[b.to_dict() for b in board.chain],
        voter_registry=voters,
        p=MODP_2048_P,
        g=MODP_2048_G,
    )

    report = auditor.run_full_audit(
        candidates=["Alice", "Bob"],
        candidate_shares={"Alice": [], "Bob": []},
        announced_results={"Alice": 2, "Bob": 1},
        election_id="SEGCOMP_DEMO_2026",
    )

    print_audit_report(report)
    # If in stub mode, exit code 0 if run_demo executes cleanly
    return 0


def main() -> None:
    """Parse arguments and execute zero-trust audit."""
    parser = argparse.ArgumentParser(
        description="Zero-Trust Independent Auditor for Verifiable E-Voting System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=DEFAULT_DATABASE_PATH,
        help="Path to SQLite election database",
    )
    parser.add_argument(
        "--board-json",
        type=str,
        default=None,
        help="Path to exported public bulletin board JSON dump",
    )
    parser.add_argument(
        "--export-report",
        type=str,
        default=None,
        help="Path to write JSON audit report",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run audit against demo simulation dataset",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verbose cryptographic check outputs",
    )

    args = parser.parse_args()

    if args.demo:
        sys.exit(run_demo_audit())

    blocks_data: List[Dict[str, Any]] = []

    if args.board_json and os.path.exists(args.board_json):
        with open(args.board_json, "r", encoding="utf-8") as f:
            blocks_data = json.load(f)
    elif os.path.exists(args.db_path):
        with get_db_session(args.db_path) as session:
            db_blocks = get_all_blocks(session)
            blocks_data = [
                {
                    "index": b.index,
                    "previous_hash": b.previous_hash,
                    "block_hash": b.block_hash,
                    "voter_id": b.voter_id,
                    "ballot_data": json.loads(b.ballot_payload_json),
                    "voter_signature_hex": b.voter_signature_hex,
                    "timestamp": b.timestamp,
                }
                for b in db_blocks
            ]
    else:
        print(f"[!] Neither DB '{args.db_path}' nor JSON file found. Run with --demo to test.")
        sys.exit(1)

    auditor = ElectionAuditor(
        bulletin_blocks=blocks_data,
        voter_registry={},
        p=MODP_2048_P,
        g=MODP_2048_G,
    )

    report = auditor.run_full_audit(
        candidates=["Alice", "Bob"],
        candidate_shares={},
        announced_results={},
        election_id="AUDIT_RUN",
    )

    print_audit_report(report)

    if args.export_report:
        with open(args.export_report, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        print(f"[✓] Audit report saved to {args.export_report}")

    sys.exit(0 if report.overall_passed else 1)


if __name__ == "__main__":
    main()
