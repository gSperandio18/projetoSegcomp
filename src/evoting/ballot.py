"""Module 2: Multi-Candidate Ballot Container & Schemas.

Full implementation of ballot schemas, JSON serialization/deserialization,
and candidate choices validation for Exponential ElGamal voting.
Assigned to: Integrante 2 (Dev B)
"""

from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional

from evoting.crypto.elgamal import EncryptedVote, encrypt_vote


@dataclass
class CandidateCiphertext:
    """Represents the encrypted vote pair (c1, c2) for a specific candidate."""

    candidate: str
    c1: int
    c2: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert candidate ciphertext to dictionary representation."""
        return {
            "candidate": self.candidate,
            "c1": self.c1,
            "c2": self.c2,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CandidateCiphertext":
        """Reconstruct candidate ciphertext from dictionary."""
        return cls(
            candidate=str(data["candidate"]),
            c1=int(data["c1"]),
            c2=int(data["c2"]),
        )


@dataclass
class BallotContainer:
    """Container holding encrypted votes for all candidates in an election contest.

    Attributes
    ----------
    votes : Dict[str, EncryptedVote]
        Mapping from candidate name to their EncryptedVote (c1, c2).
    metadata : Dict[str, Any]
        Optional election metadata (e.g. contest ID, timestamp).
    """

    votes: Dict[str, EncryptedVote] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_candidate_vote(self, candidate: str, cipher: EncryptedVote) -> None:
        """Add an encrypted vote for a candidate."""
        self.votes[candidate] = cipher

    def to_dict(self) -> Dict[str, Dict[str, int]]:
        """Serialize ballot votes to dictionary format suitable for signing and ledger storage."""
        return {
            cand: {"c1": cipher.c1, "c2": cipher.c2}
            for cand, cipher in sorted(self.votes.items())
        }

    def to_json(self) -> str:
        """Serialize ballot to deterministic canonical JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Dict[str, int]]) -> "BallotContainer":
        """Deserialize ballot container from dictionary."""
        container = cls()
        for cand, c_dict in data.items():
            cipher = EncryptedVote(c1=int(c_dict["c1"]), c2=int(c_dict["c2"]))
            container.add_candidate_vote(cand, cipher)
        return container

    @classmethod
    def create_encrypted_ballot(
        cls,
        candidate_choices: Dict[str, int],
        joint_public_key_h: int,
        p: int,
        g: int,
    ) -> "BallotContainer":
        """Factory method to construct an encrypted ballot across candidates.

        Parameters
        ----------
        candidate_choices : Dict[str, int]
            Mapping candidate name to binary vote bit (0 or 1).
        joint_public_key_h : int
            The election joint public key.
        p : int
            Group prime modulus.
        g : int
            Subgroup generator.

        Returns
        -------
        BallotContainer
            Constructed ballot with encrypted votes.
        """
        container = cls()
        for candidate, vote_bit in candidate_choices.items():
            cipher = encrypt_vote(vote_bit, joint_public_key_h, p, g)
            container.add_candidate_vote(candidate, cipher)
        return container


__all__ = [
    "CandidateCiphertext",
    "BallotContainer",
]
