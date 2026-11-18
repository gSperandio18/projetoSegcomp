"""Module 1 Test Suite: Voter Identity & RSA Signatures.

Covers non-cryptographic Voter models/persistence and provides TDD test specifications
for RSA-2048 key generation, canonicalization, PSS signatures, and unicity checks.
Assigned to: Integrante 1 (Dev A)
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from evoting.crypto.rsa import (
    canonicalize_payload,
    check_voter_eligibility_and_unicity,
    generate_voter_rsa_keypair,
    sign_ballot_payload,
    verify_ballot_signature,
)
from evoting.storage.database import drop_db, get_db_session, get_voter, init_db
from evoting.voter import Voter, VoterRegistrationDTO


@pytest.fixture
def temp_db(tmp_path):
    """Provide a fresh isolated SQLite database file for testing."""
    db_file = str(tmp_path / "test_election.db")
    init_db(db_file)
    yield db_file
    drop_db(db_file)


class TestVoterInfrastructure:
    """Tests for Voter data models, DTOs, and persistence plumbing."""

    def test_voter_dto_serialization(self):
        """Test VoterRegistrationDTO dictionary export."""
        dto = VoterRegistrationDTO(voter_id="voter_101", public_key_pem="PEM_DATA", has_voted=False)
        d = dto.to_dict()
        assert d["voter_id"] == "voter_101"
        assert d["public_key_pem"] == "PEM_DATA"
        assert d["has_voted"] is False

    def test_voter_initialization_and_repr(self):
        """Test Voter instance creation and string representation."""
        v = Voter("voter_001", generate_keys=False)
        assert v.voter_id == "voter_001"
        assert v.private_key is None
        assert "voter_001" in repr(v)

    def test_voter_db_persistence(self, temp_db):
        """Test saving and retrieving voter registration from SQLite."""
        v = Voter("voter_test_db", generate_keys=False)
        v.public_key_pem = "MOCK_PEM_KEY"
        v.persist_registration(temp_db)

        with get_db_session(temp_db) as session:
            v_model = get_voter(session, "voter_test_db")
            assert v_model is not None
            assert v_model.voter_id == "voter_test_db"
            assert v_model.rsa_public_key_pem == "MOCK_PEM_KEY"
            assert v_model.has_voted is False

    def test_sign_ballot_without_keys_raises_error(self):
        """Test that signing a ballot without loaded private key raises NotImplementedError."""
        v = Voter("voter_no_keys", generate_keys=False)
        with pytest.raises(NotImplementedError):
            v.sign_ballot({"candidate": "Alice"})


class TestRSACryptoStubs:
    """Educational verification: stubs raise NotImplementedError with helpful guidance."""

    def test_generate_voter_rsa_keypair_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            generate_voter_rsa_keypair()
        assert "TODO (Module 1 - Dev A)" in str(exc_info.value)

    def test_canonicalize_payload_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            canonicalize_payload({"b": 2, "a": 1})
        assert "TODO (Module 1 - Dev A)" in str(exc_info.value)

    def test_sign_ballot_payload_stub(self):
        mock_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(NotImplementedError) as exc_info:
            sign_ballot_payload(mock_key, {"vote": 1})
        assert "TODO (Module 1 - Dev A)" in str(exc_info.value)

    def test_verify_ballot_signature_stub(self):
        mock_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(NotImplementedError) as exc_info:
            verify_ballot_signature(mock_key.public_key(), b"sig", {"vote": 1})
        assert "TODO (Module 1 - Dev A)" in str(exc_info.value)

    def test_check_voter_eligibility_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            check_voter_eligibility_and_unicity("v1", {"v1"}, set())
        assert "TODO (Module 1 - Dev A)" in str(exc_info.value)


# ==============================================================================
# TDD Test Templates for Integrante 1 (Dev A) to activate after implementation:
# ==============================================================================
# def test_rsa_keypair_generation_active():
#     priv, pub = generate_voter_rsa_keypair(key_size=2048)
#     assert priv.key_size == 2048
#     assert pub.public_numbers().e == 65537
#
# def test_canonicalize_payload_determinism():
#     p1 = {"b": 2, "a": 1, "nested": {"y": 2, "x": 1}}
#     p2 = {"nested": {"x": 1, "y": 2}, "a": 1, "b": 2}
#     assert canonicalize_payload(p1) == canonicalize_payload(p2)
#
# def test_sign_and_verify_signature_cycle():
#     priv, pub = generate_voter_rsa_keypair()
#     payload = {"Alice": {"c1": 123, "c2": 456}}
#     sig = sign_ballot_payload(priv, payload)
#     assert verify_ballot_signature(pub, sig, payload) is True
#     assert verify_ballot_signature(pub, sig, {"Alice": {"c1": 999, "c2": 456}}) is False
