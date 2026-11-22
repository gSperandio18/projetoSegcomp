import json

import pytest

from evoting.ballot import BallotContainer, CandidateCiphertext
from evoting.crypto.elgamal import (
    EncryptedVote,
    encrypt_vote,
    homomorphic_multiply_ciphertexts,
    sample_random_blinding_factor,
)


class TestBallotContainerInfrastructure:
    def test_encrypted_vote_dataclass_serialization(self):
        vote = EncryptedVote(c1=12345, c2=67890)

        data = vote.to_dict()
        assert data == {"c1": 12345, "c2": 67890}

        reconstructed = EncryptedVote.from_dict(data)
        assert reconstructed == vote

    def test_candidate_ciphertext_dataclass(self):
        cipher = CandidateCiphertext(candidate="Alice", c1=111, c2=222)

        data = cipher.to_dict()
        assert data == {"candidate": "Alice", "c1": 111, "c2": 222}

        reconstructed = CandidateCiphertext.from_dict(data)
        assert reconstructed == cipher

    def test_ballot_container_serialization(self):
        ballot = BallotContainer()
        ballot.add_candidate_vote("Alice", EncryptedVote(c1=101, c2=102))
        ballot.add_candidate_vote("Bob", EncryptedVote(c1=201, c2=202))

        data = ballot.to_dict()
        assert data["Alice"] == {"c1": 101, "c2": 102}
        assert data["Bob"] == {"c1": 201, "c2": 202}

        reconstructed = BallotContainer.from_dict(json.loads(ballot.to_json()))
        assert reconstructed.to_dict() == data

    def test_create_encrypted_ballot(self):
        ballot = BallotContainer.create_encrypted_ballot(
            {"Alice": 1, "Bob": 0},
            joint_public_key_h=8,
            p=23,
            g=2,
        )

        assert set(ballot.votes) == {"Alice", "Bob"}
        assert all(isinstance(cipher, EncryptedVote) for cipher in ballot.votes.values())


class TestElGamalCrypto:
    def test_sample_random_blinding_factor(self, monkeypatch):
        monkeypatch.setattr(
            "evoting.crypto.elgamal.secrets.randbelow",
            lambda limite: 0,
        )
        assert sample_random_blinding_factor(11) == 2

        monkeypatch.setattr(
            "evoting.crypto.elgamal.secrets.randbelow",
            lambda limite: limite - 1,
        )
        assert sample_random_blinding_factor(11) == 9

        with pytest.raises(ValueError):
            sample_random_blinding_factor(4)

    def test_encrypt_vote(self):
        assert encrypt_vote(0, 8, 23, 2, 3) == EncryptedVote(c1=8, c2=6)
        assert encrypt_vote(1, 8, 23, 2, 3) == EncryptedVote(c1=8, c2=12)

    def test_encrypt_vote_rejects_invalid_value(self):
        with pytest.raises(ValueError, match="Vote must be 0 or 1"):
            encrypt_vote(2, 8, 23, 2, 3)

    def test_homomorphic_multiplication(self):
        first = encrypt_vote(1, 8, 23, 2, 3)
        second = encrypt_vote(0, 8, 23, 2, 4)

        result = homomorphic_multiply_ciphertexts([first, second], 23)

        assert result == EncryptedVote(c1=13, c2=1)

    def test_homomorphic_multiplication_empty_list(self):
        result = homomorphic_multiply_ciphertexts([], 23)
        assert result == EncryptedVote(c1=1, c2=1)
