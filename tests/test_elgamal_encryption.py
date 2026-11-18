"""Module 2 Test Suite: Exponential ElGamal & Ballot Schemas.

Covers non-cryptographic BallotContainer schemas/serialization and provides
TDD test specifications for ElGamal encryption and homomorphic addition.
Assigned to: Integrante 2 (Dev B)
"""

import json

import pytest
from evoting.ballot import BallotContainer, CandidateCiphertext
from evoting.config.params import MODP_2048_G, MODP_2048_P
from evoting.crypto.elgamal import (
    EncryptedVote,
    encrypt_vote,
    homomorphic_multiply_ciphertexts,
    sample_random_blinding_factor,
)


class TestBallotContainerInfrastructure:
    """Tests for ballot schemas, serialization, and candidate containers."""

    def test_encrypted_vote_dataclass_serialization(self):
        """Test EncryptedVote dictionary export and reconstruction."""
        vote = EncryptedVote(c1=12345, c2=67890)
        d = vote.to_dict()
        assert d == {"c1": 12345, "c2": 67890}

        reconstructed = EncryptedVote.from_dict(d)
        assert reconstructed.c1 == 12345
        assert reconstructed.c2 == 67890

    def test_candidate_ciphertext_dataclass(self):
        """Test CandidateCiphertext container serialization."""
        cc = CandidateCiphertext(candidate="Alice", c1=111, c2=222)
        d = cc.to_dict()
        assert d == {"candidate": "Alice", "c1": 111, "c2": 222}

        rec = CandidateCiphertext.from_dict(d)
        assert rec.candidate == "Alice"
        assert rec.c1 == 111
        assert rec.c2 == 222

    def test_ballot_container_serialization(self):
        """Test multi-candidate BallotContainer dictionary and JSON export."""
        ballot = BallotContainer()
        ballot.add_candidate_vote("Alice", EncryptedVote(c1=101, c2=102))
        ballot.add_candidate_vote("Bob", EncryptedVote(c1=201, c2=202))

        b_dict = ballot.to_dict()
        assert "Alice" in b_dict
        assert "Bob" in b_dict
        assert b_dict["Alice"] == {"c1": 101, "c2": 102}

        json_str = ballot.to_json()
        deserialized = BallotContainer.from_dict(json.loads(json_str))
        assert deserialized.votes["Alice"].c1 == 101
        assert deserialized.votes["Bob"].c2 == 202


class TestElGamalCryptoStubs:
    """Educational verification: stubs raise NotImplementedError with helpful guidance."""

    def test_sample_random_blinding_factor_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            sample_random_blinding_factor(MODP_2048_P)
        assert "TODO (Module 2 - Dev B)" in str(exc_info.value)

    def test_encrypt_vote_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            encrypt_vote(1, 9999999, MODP_2048_P, MODP_2048_G)
        assert "TODO (Module 2 - Dev B)" in str(exc_info.value)

    def test_homomorphic_multiply_stub(self):
        c1 = EncryptedVote(1, 2)
        c2 = EncryptedVote(3, 4)
        with pytest.raises(NotImplementedError) as exc_info:
            homomorphic_multiply_ciphertexts([c1, c2], MODP_2048_P)
        assert "TODO (Module 2 - Dev B)" in str(exc_info.value)


# ==============================================================================
# TDD Test Templates for Integrante 2 (Dev B) to activate after implementation:
# ==============================================================================
# def test_encrypt_vote_binary_guardrail():
#     with pytest.raises(ValueError, match="Vote must be 0 or 1"):
#         encrypt_vote(2, 9999, MODP_2048_P, MODP_2048_G)
#
# def test_exponential_elgamal_math_invariants():
#     # Using small mock prime for deterministic test
#     p = 467
#     g = 2
#     x = 127
#     h = pow(g, x, p)
#     r = 53
#     # Encrypt vote 1
#     c = encrypt_vote(1, h, p, g, blinding_factor_r=r)
#     assert c.c1 == pow(g, r, p)
#     assert c.c2 == (pow(g, 1, p) * pow(h, r, p)) % p
#
# def test_homomorphic_addition_of_two_votes():
#     # Encrypting m1 = 1, m2 = 1 -> Homomorphic product should encrypt M = 2
#     p = 467
#     g = 2
#     h = 153
#     c1 = encrypt_vote(1, h, p, g, blinding_factor_r=10)
#     c2 = encrypt_vote(1, h, p, g, blinding_factor_r=20)
#     c_sum = homomorphic_multiply_ciphertexts([c1, c2], p)
#     assert c_sum.c1 == (c1.c1 * c2.c1) % p
#     assert c_sum.c2 == (c1.c2 * c2.c2) % p
