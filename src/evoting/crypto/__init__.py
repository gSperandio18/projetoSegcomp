"""Cryptographic primitives package for Secure E-Voting System."""

from evoting.crypto.dkg import (
    combine_decryption_shares_and_recover,
    compute_joint_public_key,
    compute_partial_decryption_share,
    generate_authority_keypair,
)
from evoting.crypto.elgamal import (
    EncryptedVote,
    encrypt_vote,
    homomorphic_multiply_ciphertexts,
    sample_random_blinding_factor,
)
from evoting.crypto.modular import (
    generate_secure_random_exponent,
    mod_inverse,
    mod_pow,
)
from evoting.crypto.rsa import (
    canonicalize_payload,
    check_voter_eligibility_and_unicity,
    generate_voter_rsa_keypair,
    sign_ballot_payload,
    verify_ballot_signature,
)

__all__ = [
    "mod_pow",
    "mod_inverse",
    "generate_secure_random_exponent",
    "generate_voter_rsa_keypair",
    "canonicalize_payload",
    "sign_ballot_payload",
    "verify_ballot_signature",
    "check_voter_eligibility_and_unicity",
    "EncryptedVote",
    "sample_random_blinding_factor",
    "encrypt_vote",
    "homomorphic_multiply_ciphertexts",
    "generate_authority_keypair",
    "compute_joint_public_key",
    "compute_partial_decryption_share",
    "combine_decryption_shares_and_recover",
]
