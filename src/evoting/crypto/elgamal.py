import secrets
from dataclasses import dataclass

from evoting.config.params import MODP_2048_G, MODP_2048_P


@dataclass(frozen=True)
class EncryptedVote:
    c1: int
    c2: int

    def to_dict(self) -> dict[str, int]:
        return {"c1": self.c1, "c2": self.c2}

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> "EncryptedVote":
        return cls(c1=int(data["c1"]), c2=int(data["c2"]))


def sample_random_blinding_factor(p: int) -> int:
    if p < 5:
        raise ValueError("p must be at least 5")

    r = secrets.randbelow(p - 3) + 2
    return r


def encrypt_vote(
    vote_bit: int,
    joint_public_key_h: int,
    p: int = MODP_2048_P,
    g: int = MODP_2048_G,
    blinding_factor_r: int | None = None,
) -> EncryptedVote:
    if type(vote_bit) is not int or vote_bit not in (0, 1):
        raise ValueError("Vote must be 0 or 1")

    if type(p) is not int or p < 5:
        raise ValueError("Invalid modulus p")
    if type(g) is not int or not (1 < g < p):
        raise ValueError("Invalid generator g")
    if type(joint_public_key_h) is not int or not (1 < joint_public_key_h < p):
        raise ValueError("Invalid public key h")

    if blinding_factor_r is None:
        r = sample_random_blinding_factor(p)
    else:
        r = blinding_factor_r

    if type(r) is not int or not (2 <= r <= p - 2):
        raise ValueError("Invalid blinding factor r")

    c1 = pow(g, r, p)
    gm = pow(g, vote_bit, p)
    hr = pow(joint_public_key_h, r, p)
    c2 = (gm * hr) % p

    return EncryptedVote(c1=c1, c2=c2)


def homomorphic_multiply_ciphertexts(
    ciphers: list[EncryptedVote],
    p: int = MODP_2048_P,
) -> EncryptedVote:
    prod_c1 = 1
    prod_c2 = 1

    for c in ciphers:
        prod_c1 = (prod_c1 * c.c1) % p
        prod_c2 = (prod_c2 * c.c2) % p

    return EncryptedVote(c1=prod_c1, c2=prod_c2)


__all__ = [
    "EncryptedVote",
    "sample_random_blinding_factor",
    "encrypt_vote",
    "homomorphic_multiply_ciphertexts",
]
