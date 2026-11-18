"""Module 5 Test Suite: Independent Auditor & System Integration.

Covers audit report data structures, CLI execution models, and provides
TDD test specifications for independent zero-trust verification checks.
Assigned to: Integrante 5 (Dev E)
"""

import pytest

from evoting.auditor import AuditReport, ElectionAuditor
from evoting.config.params import (
    MIN_AUTHORITIES,
    MODP_2048_G,
    MODP_2048_P,
    MODP_2048_Q,
)
from evoting.crypto.modular import (
    generate_secure_random_exponent,
    mod_inverse,
    mod_pow,
)
from evoting.server import ElectionServer


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

        # Verify joint public key registration
        server.set_joint_public_key(123456789)
        assert server.joint_public_key_h == 123456789

        # Verify initial ledger contains Genesis
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


class TestAuditorCryptoStubs:
    """Educational verification: auditor check stubs raise NotImplementedError."""

    def test_audit_hash_chain_stub(self):
        auditor = ElectionAuditor(bulletin_blocks=[], voter_registry={})
        with pytest.raises(NotImplementedError) as exc_info:
            auditor.audit_hash_chain_integrity()
        assert "TODO (Module 5 - Dev E)" in str(exc_info.value)

    def test_audit_voter_signatures_stub(self):
        auditor = ElectionAuditor(bulletin_blocks=[], voter_registry={})
        with pytest.raises(NotImplementedError) as exc_info:
            auditor.audit_voter_signatures_and_unicity()
        assert "TODO (Module 5 - Dev E)" in str(exc_info.value)

    def test_audit_homomorphic_tally_stub(self):
        auditor = ElectionAuditor(bulletin_blocks=[], voter_registry={})
        with pytest.raises(NotImplementedError) as exc_info:
            auditor.audit_homomorphic_tally_aggregation(["Alice", "Bob"])
        assert "TODO (Module 5 - Dev E)" in str(exc_info.value)

    def test_audit_decryption_shares_stub(self):
        auditor = ElectionAuditor(bulletin_blocks=[], voter_registry={})
        with pytest.raises(NotImplementedError) as exc_info:
            auditor.audit_decryption_shares_and_results({}, {}, {})
        assert "TODO (Module 5 - Dev E)" in str(exc_info.value)

    def test_run_full_audit_handles_stubs_gracefully(self):
        auditor = ElectionAuditor(bulletin_blocks=[], voter_registry={})
        report = auditor.run_full_audit(
            candidates=["Alice", "Bob"],
            candidate_shares={},
            announced_results={},
        )
        assert report.overall_passed is False
        assert len(report.checks) == 3
        assert all("Stub not implemented" in c.details for c in report.checks)


# ==============================================================================
# TDD Test Templates for Integrante 5 (Dev E) to activate after implementation:
# ==============================================================================
# def test_audit_detects_tampered_block():
#     blocks = [
#         {"index": 0, "previous_hash": "000000", "block_hash": "H0", ...},
#         {"index": 1, "previous_hash": "H0", "block_hash": "TAMPERED", ...},
#     ]
#     auditor = ElectionAuditor(bulletin_blocks=blocks, voter_registry={})
#     result = auditor.audit_hash_chain_integrity()
#     assert result.passed is False
