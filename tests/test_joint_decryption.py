"""Module 3 Test Suite: Distributed Key Generation & Threshold Decryption.

Covers non-cryptographic ElectionAuthority metadata/persistence and provides
TDD test specifications for joint public keys, partial shares, and discrete log recovery.
Assigned to: Integrante 3 (Dev C)
"""

import pytest

from evoting.authority import AuthorityDTO, ElectionAuthority
from evoting.config.params import MODP_2048_G, MODP_2048_P
from evoting.crypto.dkg import (
    combine_decryption_shares_and_recover,
    compute_joint_public_key,
    compute_partial_decryption_share,
    generate_authority_keypair,
)
from evoting.crypto.elgamal import EncryptedVote
from evoting.storage.database import drop_db, get_authorities, get_db_session, init_db


@pytest.fixture
def temp_db(tmp_path):
    """Provide a fresh isolated SQLite database file for testing."""
    db_file = str(tmp_path / "test_election.db")
    init_db(db_file)
    yield db_file
    drop_db(db_file)


class TestAuthorityInfrastructure:
    """Tests for authority metadata, DTOs, and persistence."""

    def test_authority_dto_serialization(self):
        """Test AuthorityDTO dictionary export."""
        dto = AuthorityDTO(authority_id=1, name="Trustee 1", public_key_h="0x1234")
        d = dto.to_dict()
        assert d["authority_id"] == 1
        assert d["name"] == "Trustee 1"
        assert d["public_key_h"] == "0x1234"

    def test_authority_initialization_and_repr(self):
        """Test ElectionAuthority instance creation."""
        auth = ElectionAuthority(1, MODP_2048_P, MODP_2048_G, name="Auth_Alpha", generate_keys=False)
        assert auth.authority_id == 1
        assert auth.name == "Auth_Alpha"
        assert auth.private_key_x is None
        assert "Auth_Alpha" in repr(auth)

    def test_authority_db_persistence(self, temp_db):
        """Test saving and retrieving authority record from SQLite."""
        auth = ElectionAuthority(2, MODP_2048_P, MODP_2048_G, name="Auth_Beta", generate_keys=False)
        auth.public_key_h = 0xABCD
        auth.persist_authority(temp_db)

        with get_db_session(temp_db) as session:
            auths = get_authorities(session)
            assert len(auths) == 1
            assert auths[0].authority_id == 2
            assert auths[0].name == "Auth_Beta"


class TestDKGCryptoStubs:
    """Educational verification: stubs raise NotImplementedError with helpful guidance."""

    def test_generate_authority_keypair_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            generate_authority_keypair(MODP_2048_P, MODP_2048_G)
        assert "TODO (Module 3 - Dev C)" in str(exc_info.value)

    def test_compute_joint_public_key_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            compute_joint_public_key([10, 20, 30], MODP_2048_P)
        assert "TODO (Module 3 - Dev C)" in str(exc_info.value)

    def test_compute_partial_decryption_share_stub(self):
        cipher = EncryptedVote(100, 200)
        with pytest.raises(NotImplementedError) as exc_info:
            compute_partial_decryption_share(cipher, 12345, MODP_2048_P)
        assert "TODO (Module 3 - Dev C)" in str(exc_info.value)

    def test_combine_decryption_shares_stub(self):
        cipher = EncryptedVote(100, 200)
        with pytest.raises(NotImplementedError) as exc_info:
            combine_decryption_shares_and_recover(cipher, [1, 2, 3], MODP_2048_P, MODP_2048_G)
        assert "TODO (Module 3 - Dev C)" in str(exc_info.value)


# ==============================================================================
# TDD Test Templates for Integrante 3 (Dev C) to activate after implementation:
# ==============================================================================
# def test_joint_public_key_homomorphic_property():
#     p = 467
#     g = 2
#     x1, x2, x3 = 10, 20, 30
#     h1 = pow(g, x1, p)
#     h2 = pow(g, x2, p)
#     h3 = pow(g, x3, p)
#     h_joint = compute_joint_public_key([h1, h2, h3], p)
#     expected_h = pow(g, x1 + x2 + x3, p)
#     assert h_joint == expected_h
#
# def test_incomplete_authorities_fails_decryption():
#     p = 467
#     g = 2
#     cipher = EncryptedVote(100, 200)
#     # Providing only 2 shares when 3 were involved
#     with pytest.raises(ValueError):
#         combine_decryption_shares_and_recover(cipher, [123, 456], p, g, max_expected_votes=10)
