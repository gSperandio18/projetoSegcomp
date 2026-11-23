"""Module 3 Test Suite: Distributed Key Generation & Threshold Decryption.

Covers non-cryptographic ElectionAuthority metadata/persistence and provides
TDD test specifications for joint public keys, partial shares, and discrete log recovery.
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
        auth = ElectionAuthority(
            1, MODP_2048_P, MODP_2048_G, name="Auth_Alpha", generate_keys=False
        )
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


def test_authority_generate_keys():
    ElectionAuthority(1, MODP_2048_P, MODP_2048_G, "TSE", True)


class TestDKGCrypto:
    def test_generate_authority_keypair(self):
        (x_i, h_i) = generate_authority_keypair(MODP_2048_P, MODP_2048_G)
        assert h_i == pow(MODP_2048_G, x_i, MODP_2048_P)

    def test_compute_joint_public_key(self):
        shares = [10, 20, 30]
        public_key = 1
        for key_share in shares:
            public_key = (public_key * key_share) % MODP_2048_P

        h = compute_joint_public_key(shares, MODP_2048_P)

        assert h == public_key

    def test_compute_partial_decryption_share(self):
        cipher = EncryptedVote(100, 200)
        private_key = 12345
        d = compute_partial_decryption_share(cipher, private_key, MODP_2048_P)

        assert d == pow(cipher.c1, private_key, MODP_2048_P)

    def test_combine_decryption_shares(self):
        import secrets

        # par de chaves de autoridades
        keypairs = [
            generate_authority_keypair(MODP_2048_P, MODP_2048_G),
            generate_authority_keypair(MODP_2048_P, MODP_2048_G),
            generate_authority_keypair(MODP_2048_P, MODP_2048_G),
        ]

        # soma dos chaves privadas (expoentes)
        key_sum = 0
        for kp in keypairs:
            key_sum += kp[0]

        # chave conjunta
        h = compute_joint_public_key([keypairs[0][1], keypairs[1][1], keypairs[2][1]], MODP_2048_P)

        vote_count = 12

        blinding_factor_r = secrets.randbelow(MODP_2048_P - 3) + 2
        c1 = pow(MODP_2048_G, blinding_factor_r, MODP_2048_P)
        gm = pow(MODP_2048_G, vote_count, MODP_2048_P)
        hr = pow(h, blinding_factor_r, MODP_2048_P)
        c2 = (gm * hr) % MODP_2048_P
        cipher = EncryptedVote(c1, c2)

        vote_shares = []
        for kp in keypairs:
            vote_shares.append(compute_partial_decryption_share(cipher, kp[0], MODP_2048_P))

        # TODO: arrumar teste da decifragem, m sempre dá 1 (implementação de cipher?)
        m = combine_decryption_shares_and_recover(cipher, vote_shares, MODP_2048_P, MODP_2048_G)

        assert m == vote_count


def test_joint_public_key_homomorphic_property():
    p = 467
    g = 2
    x1, x2, x3 = 10, 20, 30
    h1 = pow(g, x1, p)
    h2 = pow(g, x2, p)
    h3 = pow(g, x3, p)
    h_joint = compute_joint_public_key([h1, h2, h3], p)
    expected_h = pow(g, x1 + x2 + x3, p)
    assert h_joint == expected_h


def test_incomplete_authorities_fails_joint():
    p = 467
    # Providing only 2 shares when 3 were involved
    with pytest.raises(ValueError):
        compute_joint_public_key([123, 456], p)


def test_incomplete_authorities_fails_decryption():
    p = 467
    g = 2
    cipher = EncryptedVote(100, 200)
    # Providing only 2 shares when 3 were involved
    with pytest.raises(ValueError):
        combine_decryption_shares_and_recover(cipher, [123, 456], p, g, max_expected_votes=10)
