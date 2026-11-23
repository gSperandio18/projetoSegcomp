#!/usr/bin/env python3
"""Module 5: Standalone Independent Audit CLI.

Zero-trust verifier CLI executing cryptographic checks over public election records:
  - Ledger hash-chain continuity & tamper detection
  - Voter RSA digital signatures & unicity enforcement
  - Homomorphic product tally recomputation
  - Threshold decryption shares consistency
"""

import argparse
import hashlib
import json
import os
import sys
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.auditor import AuditReport, ElectionAuditor
from evoting.config.params import (
    DEFAULT_DATABASE_PATH,
    GENESIS_PREVIOUS_HASH,
    MODP_2048_G,
    MODP_2048_P,
)
from evoting.storage.database import get_all_blocks, get_db_session


def format_table_row(col1: str, col2: str, col3: str, width: int = 74) -> str:
    """Format three columns inside a fixed-width CLI table."""
    c1 = col1.ljust(34)
    c2 = col2.center(12)
    c3 = col3.ljust(width - 50)
    return f"| {c1} | {c2} | {c3} |"


def print_audit_report(report: AuditReport, verbose: bool = False) -> None:
    """Render a structured ANSI text report to stdout."""
    border = "=" * 76
    sub_border = "-" * 76

    print(f"\n{border}")
    print(f"  INDEPENDENT ZERO-TRUST AUDIT REPORT: {report.election_id}")
    print(f"{border}")
    print(format_table_row("VERIFICATION STAGE", "STATUS", "DETAILS", 74))
    print(sub_border)

    for item in report.checks:
        status_str = "[ PASS ]" if item.passed else "[ FAIL ]"
        summary = item.details if len(item.details) <= 24 else f"{item.details[:21]}..."
        print(format_table_row(item.name, status_str, summary))
        if verbose:
            print(f"    -> Full details: {item.details}")
            if item.error:
                print(f"    -> Error: {item.error}")

    if report.recomputed_tallies:
        print(sub_border)
        tallies_str = ", ".join(f"{k} = {v}" for k, v in report.recomputed_tallies.items())
        print(f"  VERIFIED TALLIES: {tallies_str}")

    print(sub_border)
    verdict = (
        "VERIFIED (AUTHENTIC)"
        if report.overall_passed
        else "REJECTED (TAMPERING OR INVALID PROOF DETECTED)"
    )
    print(f"  OVERALL AUDIT VERDICT: {verdict}")
    print(f"{border}\n")


def _build_demo_election() -> tuple[
    list[dict[str, Any]],
    dict[str, rsa.RSAPublicKey],
    list[str],
    dict[str, list[int]],
    dict[str, int],
]:
    """Construct a self-contained 3-voter, 3-authority demo dataset."""
    p, g = MODP_2048_P, MODP_2048_G
    authority_secrets = [101, 202, 303]
    joint_h = 1
    for x_i in authority_secrets:
        joint_h = (joint_h * pow(g, x_i, p)) % p

    def canon(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def block_hash(
        prev_h: str, idx: int, vid: str, ballot: dict[str, Any], sig_hex: str, ts: str
    ) -> str:
        comp = json.dumps(
            [prev_h, idx, vid, canon(ballot).decode("utf-8"), sig_hex, ts],
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(comp).hexdigest()

    genesis_ballot: dict[str, Any] = {"genesis": True}
    genesis_ts = "2026-11-22T12:00:00Z"
    blocks: list[dict[str, Any]] = [
        {
            "index": 0,
            "previous_hash": GENESIS_PREVIOUS_HASH,
            "voter_id": "SYSTEM_GENESIS",
            "ballot_data": genesis_ballot,
            "voter_signature_hex": "",
            "timestamp": genesis_ts,
            "block_hash": block_hash(
                GENESIS_PREVIOUS_HASH, 0, "SYSTEM_GENESIS", genesis_ballot, "", genesis_ts
            ),
        }
    ]

    voter_registry: dict[str, rsa.RSAPublicKey] = {}
    ballot_specs = [
        ("voter_001", {"Alice": 1, "Bob": 0}, 1001),
        ("voter_002", {"Alice": 1, "Bob": 0}, 2002),
        ("voter_003", {"Alice": 0, "Bob": 1}, 3003),
    ]

    for idx, (vid, choices, base_r) in enumerate(ballot_specs, start=1):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        voter_registry[vid] = priv.public_key()

        ballot_data: dict[str, dict[str, int]] = {}
        for offset, (cand, vote_bit) in enumerate(choices.items()):
            r = base_r + offset
            ballot_data[cand] = {
                "c1": pow(g, r, p),
                "c2": (pow(g, vote_bit, p) * pow(joint_h, r, p)) % p,
            }

        sig_hex = priv.sign(
            canon(ballot_data),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        ).hex()

        ts = f"2026-11-22T12:0{idx}:00Z"
        prev_h = blocks[-1]["block_hash"]
        blocks.append(
            {
                "index": idx,
                "previous_hash": prev_h,
                "voter_id": vid,
                "ballot_data": ballot_data,
                "voter_signature_hex": sig_hex,
                "timestamp": ts,
                "block_hash": block_hash(prev_h, idx, vid, ballot_data, sig_hex, ts),
            }
        )

    candidates = ["Alice", "Bob"]
    candidate_shares: dict[str, list[int]] = {}
    for cand in candidates:
        c1_total = 1
        for blk in blocks[1:]:
            c1_total = (c1_total * blk["ballot_data"][cand]["c1"]) % p
        candidate_shares[cand] = [pow(c1_total, x_i, p) for x_i in authority_secrets]

    return blocks, voter_registry, candidates, candidate_shares, {"Alice": 2, "Bob": 1}


def run_demo_audit(verbose: bool = False) -> int:
    """Execute simulated audit flow for demonstration and testing."""
    print("[*] Running simulated zero-trust audit flow against sample election data...")
    blocks, voters, candidates, shares, announced = _build_demo_election()

    auditor = ElectionAuditor(
        bulletin_blocks=blocks,
        voter_registry=voters,
        p=MODP_2048_P,
        g=MODP_2048_G,
    )

    report = auditor.run_full_audit(
        candidates=candidates,
        candidate_shares=shares,
        announced_results=announced,
        election_id="SEGCOMP_DEMO_2026",
    )

    print_audit_report(report, verbose=verbose)
    return 0 if report.overall_passed else 1


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
        sys.exit(run_demo_audit(verbose=args.verbose))

    blocks_data: list[dict[str, Any]] = []

    if args.board_json and os.path.exists(args.board_json):
        with open(args.board_json, encoding="utf-8") as f:
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
                    "ballot_data": (
                        json.loads(b.ballot_payload_json)
                        if hasattr(b, "ballot_payload_json")
                        else b.ballot_data
                    ),
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

    print_audit_report(report, verbose=args.verbose)

    if args.export_report:
        with open(args.export_report, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        print(f"[✓] Audit report saved to {args.export_report}")

    sys.exit(0 if report.overall_passed else 1)


if __name__ == "__main__":
    main()
