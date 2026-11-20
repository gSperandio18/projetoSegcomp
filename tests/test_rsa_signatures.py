"""Module 1 Test Suite: Voter Identity & RSA Signatures.

Covers Voter models, persistence, RSA key generation, canonicalization,
PSS signatures, and voter eligibility checks.
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
from evoting.storage.database import (
    drop_db,
    get_db_session,
    get_voter,
    init_db,
)
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
        dto = VoterRegistrationDTO(
            voter_id="voter_101",
            public_key_pem="PEM_DATA",
            has_voted=False,
        )
        d = dto.to_dict()

        assert d["voter_id"] == "voter_101"
        assert d["public_key_pem"] == "PEM_DATA"
        assert d["has_voted"] is False

    def test_voter_initialization_and_repr(self):
        v = Voter("voter_001", generate_keys=False)

        assert v.voter_id == "voter_001"
        assert v.private_key is None
        assert "voter_001" in repr(v)

    def test_voter_db_persistence(self, temp_db):
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
        v = Voter("voter_no_keys", generate_keys=False)

        with pytest.raises(NotImplementedError):
            v.sign_ballot({"candidate": "Alice"})


class TestRSACrypto:
    """Tests for RSA cryptographic functions."""

    def test_rsa_keypair_generation(self):
        priv, pub = generate_voter_rsa_keypair(key_size=2048)

        assert isinstance(priv, rsa.RSAPrivateKey)
        assert isinstance(pub, rsa.RSAPublicKey)
        assert priv.key_size == 2048
        assert pub.public_numbers().e == 65537

    def test_canonicalize_payload_determinism(self):
        p1 = {"b": 2, "a": 1, "nested": {"y": 2, "x": 1}}
        p2 = {"nested": {"x": 1, "y": 2}, "a": 1, "b": 2}

        result = canonicalize_payload(p1)

        assert isinstance(result, bytes)
        assert result == canonicalize_payload(p2)
        assert result == b'{"a":1,"b":2,"nested":{"x":1,"y":2}}'

    def test_sign_ballot_payload(self):
        private_key, public_key = generate_voter_rsa_keypair()
        payload = {"vote": 1}

        signature = sign_ballot_payload(private_key, payload)

        assert isinstance(signature, bytes)
        assert len(signature) == 256
        assert public_key is not None

    def test_verify_ballot_signature(self):
        private_key, public_key = generate_voter_rsa_keypair()
        payload = {"vote": 1}

        signature = sign_ballot_payload(private_key, payload)

        assert verify_ballot_signature(public_key, signature, payload) is True

        assert verify_ballot_signature(public_key, signature, {"vote": 2}) is False

    def test_check_voter_eligibility_and_unicity(self):
        registered_voters = {"v1", "v2", "v3"}
        cast_voters = {"v2"}

        assert check_voter_eligibility_and_unicity("v1", registered_voters, cast_voters) == (
            True,
            "OK",
        )

        assert check_voter_eligibility_and_unicity("v4", registered_voters, cast_voters) == (
            False,
            "Voter not registered",
        )

        assert check_voter_eligibility_and_unicity("v2", registered_voters, cast_voters) == (
            False,
            "Double voting detected",
        )
