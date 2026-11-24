import json
from dataclasses import dataclass, field
from typing import Any

from evoting.crypto.elgamal import EncryptedVote, encrypt_vote


@dataclass
class CandidateCiphertext:
    candidate: str
    c1: int
    c2: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate,
            "c1": self.c1,
            "c2": self.c2,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CandidateCiphertext":
        return cls(
            candidate=str(data["candidate"]),
            c1=int(data["c1"]),
            c2=int(data["c2"]),
        )


@dataclass
class BallotContainer:
    votes: dict[str, EncryptedVote] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_candidate_vote(self, candidate: str, cipher: EncryptedVote) -> None:
        self.votes[candidate] = cipher

    def to_dict(self) -> dict[str, dict[str, int]]:
        return {
            cand: {"c1": cipher.c1, "c2": cipher.c2} for cand, cipher in sorted(self.votes.items())
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, dict[str, int]]) -> "BallotContainer":
        container = cls()
        for cand, c_dict in data.items():
            cipher = EncryptedVote(c1=int(c_dict["c1"]), c2=int(c_dict["c2"]))
            container.add_candidate_vote(cand, cipher)
        return container

    @classmethod
    def create_encrypted_ballot(
        cls,
        candidate_choices: dict[str, int],
        joint_public_key_h: int,
        p: int,
        g: int,
    ) -> "BallotContainer":
        if any(
            type(vote_bit) is not int or vote_bit not in (0, 1)
            for vote_bit in candidate_choices.values()
        ):
            raise ValueError("Each candidate vote must be 0 or 1")

        if sum(candidate_choices.values()) != 1:
            raise ValueError("Select exactly one candidate")

        container = cls()
        for candidate, vote_bit in candidate_choices.items():
            cipher = encrypt_vote(vote_bit, joint_public_key_h, p, g)
            container.add_candidate_vote(candidate, cipher)

        return container


__all__ = [
    "CandidateCiphertext",
    "BallotContainer",
]
