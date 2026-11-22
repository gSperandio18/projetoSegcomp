"""Module 5 Test Suite: Independent Auditor & System Integration.

Covers audit report data structures, server coordination, and full unit +
integration tests for zero-trust cryptographic verification checks.
Assigned to: Integrante 5 (Dev E)
"""

import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.auditor import AuditReport, ElectionAuditor
from evoting.config.params import (
    GENESIS_PREVIOUS_HASH,
    MIN_AUTHORITIES,
    MODP_2048_G,
    MODP_2048_P,
    MODP_2048_Q,
)
from evoting.crypto.elgamal import EncryptedVote
from evoting.crypto.modular import (
    generate_secure_random_exponent,
    mod_inverse,
    mod_pow,
)
from evoting.server import ElectionServer


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Serialize payload into deterministic canonical JSON bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_block_hash(
    previous_hash: str,
    index: int,
    voter_id: str,
    ballot_data: dict[str, Any],
    voter_signature_hex: str,
    timestamp: str,
) -> str:
    """Compute SHA-256 digest matching the bulletin board block framing."""
    canonical_ballot_str = _canonical_json(ballot_data).decode("utf-8")
    composite = json.dumps(
        [
            previous_hash,
            index,
            voter_id,
            canonical_ballot_str,
            voter_signature_hex,
            timestamp,
        ],
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(composite).hexdigest()


def _sign_ballot(private_key: rsa.RSAPrivateKey, ballot_data: dict[str, Any]) -> str:
    """Sign canonical ballot JSON using RSA-PSS + SHA-256 and return hex string."""
    sig_bytes = private_key.sign(
        _canonical_json(ballot_data),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return sig_bytes.hex()


@pytest.fixture
def election_fixture() -> dict[str, Any]:
    """Build a complete valid 3-voter, 3-authority, 2-candidate election fixture."""
    p = MODP_2048_P
    g = MODP_2048_G

    # 3 Authorities with secret shares x_i and joint public key h = prod(g^{x_i}) mod p
    authority_secrets = [101, 202, 303]
    joint_h = 1
    for x_i in authority_secrets:
        joint_h = (joint_h * pow(g, x_i, p)) % p

    # 3 Registered voters with RSA-2048 keypairs
    voter_ids = ["voter_001", "voter_002", "voter_003"]
    private_keys: dict[str, rsa.RSAPrivateKey] = {}
    voter_registry: dict[str, rsa.RSAPublicKey] = {}
    for vid in voter_ids:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_keys[vid] = priv
        voter_registry[vid] = priv.public_key()

    # Genesis block (index 0)
    genesis_ballot: dict[str, Any] = {"genesis": True}
    genesis_ts = "2026-11-22T10:00:00Z"
    genesis_hash = _compute_block_hash(
        GENESIS_PREVIOUS_HASH, 0, "SYSTEM_GENESIS", genesis_ballot, "", genesis_ts
    )
    blocks: list[dict[str, Any]] = [
        {
            "index": 0,
            "previous_hash": GENESIS_PREVIOUS_HASH,
            "voter_id": "SYSTEM_GENESIS",
            "ballot_data": genesis_ballot,
            "voter_signature_hex": "",
            "timestamp": genesis_ts,
            "block_hash": genesis_hash,
        }
    ]

    # Votes: voter_001 -> Alice, voter_002 -> Alice, voter_003 -> Bob
    choices_per_voter = [
        ("voter_001", {"Alice": 1, "Bob": 0}, 1111),
        ("voter_002", {"Alice": 1, "Bob": 0}, 2222),
        ("voter_003", {"Alice": 0, "Bob": 1}, 3333),
    ]

    for idx, (vid, choices, base_r) in enumerate(choices_per_voter, start=1):
        ballot_data: dict[str, dict[str, int]] = {}
        for offset, (cand, vote_bit) in enumerate(choices.items()):
            r = base_r + offset
            c1 = pow(g, r, p)
            c2 = (pow(g, vote_bit, p) * pow(joint_h, r, p)) % p
            ballot_data[cand] = {"c1": c1, "c2": c2}

        sig_hex = _sign_ballot(private_keys[vid], ballot_data)
        ts = f"2026-11-22T10:0{idx}:00Z"
        prev_hash = blocks[-1]["block_hash"]
        b_hash = _compute_block_hash(prev_hash, idx, vid, ballot_data, sig_hex, ts)
        blocks.append(
            {
                "index": idx,
                "previous_hash": prev_hash,
                "voter_id": vid,
                "ballot_data": ballot_data,
                "voter_signature_hex": sig_hex,
                "timestamp": ts,
                "block_hash": b_hash,
            }
        )

    # Compute aggregated C1_total per candidate to derive authority decryption shares
    candidates = ["Alice", "Bob"]
    candidate_shares: dict[str, list[int]] = {}
    for cand in candidates:
        c1_total = 1
        for block in blocks[1:]:
            c1_total = (c1_total * block["ballot_data"][cand]["c1"]) % p
        candidate_shares[cand] = [pow(c1_total, x_i, p) for x_i in authority_secrets]

    return {
        "blocks": blocks,
        "voter_registry": voter_registry,
        "private_keys": private_keys,
        "candidates": candidates,
        "candidate_shares": candidate_shares,
        "announced_results": {"Alice": 2, "Bob": 1},
    }


class TestAuditReportInfrastructure:
    """Tests for audit report formatting, serialization, and server coordination."""

    def test_audit_check_item_and_report_json(self):
        """Test AuditReport construction and JSON serialization."""
        report = AuditReport(election_id="TEST_ELECTION_2026")
        report.add_check("Check 1", True, "Passed successfully")
        report.add_check("Check 2", False, "Failed verification", "Signature mismatch")

        assert len(report.checks) == 2
        assert report.evaluate_overall() is False

        d = report.to_dict()
        assert d["election_id"] == "TEST_ELECTION_2026"
        assert d["overall_passed"] is False

        json_str = report.to_json()
        assert "TEST_ELECTION_2026" in json_str

    def test_server_registration_and_casting_pipeline(self, tmp_path):
        """Test ElectionServer registration, public key setup, and ledger querying."""
        db_path = str(tmp_path / "server_test.db")
        server = ElectionServer(
            election_id="ELEC_01",
            candidates=["Alice", "Bob"],
            db_path=db_path,
        )
        assert server.election_id == "ELEC_01"
        assert len(server.candidates) == 2
        assert server.server_public_key is not None

        server.set_joint_public_key(123456789)
        assert server.joint_public_key_h == 123456789

        ledger = server.get_public_ledger()
        assert len(ledger) == 1
        assert ledger[0].index == 0

    def test_system_parameters_invariants(self):
        """Verify RFC 3526 MODP-2048 prime bit length and generator."""
        assert MODP_2048_P.bit_length() == 2048
        assert MODP_2048_G == 2
        assert MODP_2048_Q == (MODP_2048_P - 1) // 2
        assert MIN_AUTHORITIES == 3


class TestModularStubs:
    """Verify modular arithmetic stubs."""

    def test_mod_pow_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            mod_pow(2, 5, 13)
        assert "TODO (Crypto Core)" in str(exc_info.value)

    def test_mod_inverse_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            mod_inverse(3, 11)
        assert "TODO (Crypto Core)" in str(exc_info.value)

    def test_generate_secure_random_exponent_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            generate_secure_random_exponent(MODP_2048_P)
        assert "TODO (Crypto Core)" in str(exc_info.value)


class TestElectionAuditorVerification:
    """Zero-trust verification tests for all 4 ElectionAuditor methods."""

    def test_full_audit_passes_on_valid_election(self, election_fixture):
        """End-to-end audit succeeds when chain, signatures, and tallies are valid."""
        auditor = ElectionAuditor(
            bulletin_blocks=election_fixture["blocks"],
            voter_registry=election_fixture["voter_registry"],
        )
        report = auditor.run_full_audit(
            candidates=election_fixture["candidates"],
            candidate_shares=election_fixture["candidate_shares"],
            announced_results=election_fixture["announced_results"],
            election_id="SEGCOMP_2026",
        )

        assert report.overall_passed is True
        assert len(report.checks) == 3
        assert all(c.passed for c in report.checks)
        assert report.recomputed_tallies == {"Alice": 2, "Bob": 1}

    def test_hash_chain_detects_empty_board(self):
        """Empty bulletin board must fail hash chain integrity."""
        auditor = ElectionAuditor(bulletin_blocks=[], voter_registry={})
        result = auditor.audit_hash_chain_integrity()
        assert result.passed is False

    def test_hash_chain_detects_tampered_ballot_data(self, election_fixture):
        """Modifying ballot ciphertext invalidates block SHA-256 hash."""
        blocks = election_fixture["blocks"]
        blocks[1]["ballot_data"]["Alice"]["c1"] += 1

        auditor = ElectionAuditor(
            bulletin_blocks=blocks,
            voter_registry=election_fixture["voter_registry"],
        )
        result = auditor.audit_hash_chain_integrity()
        assert result.passed is False
        assert "hash does not match" in result.details

    def test_hash_chain_detects_broken_previous_hash_link(self, election_fixture):
        """Altering previous_hash pointer between blocks must fail chain check."""
        blocks = election_fixture["blocks"]
        blocks[2]["previous_hash"] = "f" * 64

        auditor = ElectionAuditor(
            bulletin_blocks=blocks,
            voter_registry=election_fixture["voter_registry"],
        )
        result = auditor.audit_hash_chain_integrity()
        assert result.passed is False
        assert "previous_hash" in result.details

    def test_signatures_detect_unregistered_voter(self, election_fixture):
        """Ballot from a voter absent from voter_registry must be rejected."""
        registry = dict(election_fixture["voter_registry"])
        del registry["voter_002"]

        auditor = ElectionAuditor(
            bulletin_blocks=election_fixture["blocks"],
            voter_registry=registry,
        )
        result = auditor.audit_voter_signatures_and_unicity()
        assert result.passed is False
        assert "not registered" in result.details

    def test_signatures_detect_double_voting(self, election_fixture):
        """Same voter casting two ballots must fail unicity verification."""
        blocks = election_fixture["blocks"]
        # Re-sign a duplicate block for voter_001 at index 4
        dup_ballot = blocks[1]["ballot_data"]
        sig_hex = _sign_ballot(election_fixture["private_keys"]["voter_001"], dup_ballot)
        ts = "2026-11-22T10:04:00Z"
        prev_hash = blocks[-1]["block_hash"]
        b_hash = _compute_block_hash(prev_hash, 4, "voter_001", dup_ballot, sig_hex, ts)
        blocks.append(
            {
                "index": 4,
                "previous_hash": prev_hash,
                "voter_id": "voter_001",
                "ballot_data": dup_ballot,
                "voter_signature_hex": sig_hex,
                "timestamp": ts,
                "block_hash": b_hash,
            }
        )

        auditor = ElectionAuditor(
            bulletin_blocks=blocks,
            voter_registry=election_fixture["voter_registry"],
        )
        result = auditor.audit_voter_signatures_and_unicity()
        assert result.passed is False
        assert "Double voting" in result.details

    def test_signatures_detect_forged_rsa_signature(self, election_fixture):
        """Corrupted RSA-PSS signature bytes must fail verification."""
        blocks = election_fixture["blocks"]
        orig_sig = bytearray.fromhex(blocks[1]["voter_signature_hex"])
        orig_sig[0] ^= 0xFF
        blocks[1]["voter_signature_hex"] = orig_sig.hex()

        auditor = ElectionAuditor(
            bulletin_blocks=blocks,
            voter_registry=election_fixture["voter_registry"],
        )
        result = auditor.audit_voter_signatures_and_unicity()
        assert result.passed is False
        assert "Invalid RSA signature" in result.details

    def test_homomorphic_tally_aggregation_returns_encrypted_votes(self, election_fixture):
        """Aggregated tallies must match component-wise modular product of ciphertexts."""
        blocks = election_fixture["blocks"]
        auditor = ElectionAuditor(
            bulletin_blocks=blocks,
            voter_registry=election_fixture["voter_registry"],
        )
        tallies = auditor.audit_homomorphic_tally_aggregation(["Alice", "Bob"])

        assert set(tallies.keys()) == {"Alice", "Bob"}
        assert isinstance(tallies["Alice"], EncryptedVote)

        expected_alice_c1 = 1
        expected_alice_c2 = 1
        for b in blocks[1:]:
            expected_alice_c1 = (expected_alice_c1 * b["ballot_data"]["Alice"]["c1"]) % MODP_2048_P
            expected_alice_c2 = (expected_alice_c2 * b["ballot_data"]["Alice"]["c2"]) % MODP_2048_P

        assert tallies["Alice"].c1 == expected_alice_c1
        assert tallies["Alice"].c2 == expected_alice_c2

    def test_decryption_audit_detects_falsified_announced_results(self, election_fixture):
        """Auditor must reject when scoreboard results disagree with decrypted tallies."""
        auditor = ElectionAuditor(
            bulletin_blocks=election_fixture["blocks"],
            voter_registry=election_fixture["voter_registry"],
        )
        tallies = auditor.audit_homomorphic_tally_aggregation(election_fixture["candidates"])
        result = auditor.audit_decryption_shares_and_results(
            tally_ciphers=tallies,
            candidate_shares=election_fixture["candidate_shares"],
            announced_results={"Alice": 1, "Bob": 2},  # Falsified scoreboard
        )
        assert result.passed is False
        assert "Tally mismatch" in result.details

    def test_decryption_audit_detects_incomplete_authority_shares(self, election_fixture):
        """Missing an authority's decryption share prevents valid discrete log recovery."""
        auditor = ElectionAuditor(
            bulletin_blocks=election_fixture["blocks"],
            voter_registry=election_fixture["voter_registry"],
        )
        tallies = auditor.audit_homomorphic_tally_aggregation(election_fixture["candidates"])
        incomplete_shares = {
            cand: shares[:2]  # Only 2 of 3 authorities provided shares
            for cand, shares in election_fixture["candidate_shares"].items()
        }
        result = auditor.audit_decryption_shares_and_results(
            tally_ciphers=tallies,
            candidate_shares=incomplete_shares,
            announced_results=election_fixture["announced_results"],
        )
        assert result.passed is False
