"""Module 1: RSA-2048 Digital Signatures & Identity Verification.

Educational stubs and specifications for Voter Identity, Ballot Authentication,
and Non-repudiation in Electronic Voting.
Assigned to: Integrante 1 (Dev A)
"""

import json
from typing import Any, Dict, Set, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.config.params import DEFAULT_RSA_KEY_SIZE, DEFAULT_RSA_PUBLIC_EXPONENT


def generate_voter_rsa_keypair(
    key_size: int = DEFAULT_RSA_KEY_SIZE,
    public_exponent: int = DEFAULT_RSA_PUBLIC_EXPONENT,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA keypair for a registered voter.

    Parameters
    ----------
    key_size : int, optional
        Bit length of modulus n = p * q, by default 2048.
    public_exponent : int, optional
        Public exponent e (typically 65537 / F4), by default 65537.

    Returns
    -------
    Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]
        The private signing key and public verification key.

    Notes
    -----
    Mathematical Invariants:
- n = p * q, where p and q are large distinct prime numbers generated via CSPRNG.
- lambda(n) = lcm(p-1, q-1) or phi(n) = (p-1)*(q-1).
- e and phi(n) must be coprime: gcd(e, phi(n)) == 1.
- d = e^(-1) mod phi(n).
- Public key is (n, e); Private key is (n, d).

    Security Pitfalls:
- Never use small exponents (e.g. e = 3) without strict padding to avoid cube root attacks.
- Never use moduli < 2048 bits for production voting systems.
- Ensure robust random prime generation to prevent Coppersmith or Fermat factorization.

    TODO (Module 1 - Dev A):
1. Call `rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)`.
2. Extract public key via `private_key.public_key()`.
3. Return `(private_key, public_key)`.
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )

    public_key = private_key.public_key()

    return private_key, public_key


def canonicalize_payload(payload: Dict[str, Any]) -> bytes:
    """Serialize a dictionary into a deterministic canonical UTF-8 byte stream.

    Parameters
    ----------
    payload : Dict[str, Any]
        Arbitrary dictionary representing ballot or voting message.

    Returns
    -------
    bytes
        Canonical byte sequence with sorted keys and minimal JSON delimiters.

    Notes
    -----
    Mathematical Invariants:
- Digital signatures authenticate byte sequences, not high-level abstract objects.
- The mapping `canonicalize: Dict -> bytes` MUST be deterministic and injective:
      forall d1, d2: d1 == d2 <=> canonicalize(d1) == canonicalize(d2).

    Security Pitfalls:
- In Python, dictionary key ordering or varying indentation/spaces will alter
      the resulting SHA-256 hash, causing legitimate signatures to fail verification.
- Floating point serialization can introduce non-determinism; ensure integer IDs.

    TODO (Module 1 - Dev A):
1. Serialize payload using `json.dumps(payload, sort_keys=True, separators=(',', ':'))`.
2. Encode string to UTF-8 bytes: `.encode('utf-8')`.
3. Return resulting bytes.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_ballot_payload(
    private_key: rsa.RSAPrivateKey,
    payload: Dict[str, Any],
) -> bytes:
    """Digitally sign a canonicalized ballot payload using RSA-PSS and SHA-256.

    Parameters
    ----------
    private_key : rsa.RSAPrivateKey
        The voter's private signing key.
    payload : Dict[str, Any]
        The ballot content (e.g., encrypted candidate vectors).

    Returns
    -------
    bytes
        Raw signature bytes.

    Notes
    -----
    Mathematical Invariants:
- Signature s = (m_padded)^d mod n.
- RSA-PSS incorporates random salt and mask generation (MGF1 with SHA-256),
      providing provable security against chosen-message attacks.

    Security Pitfalls:
- Never sign raw digests with textbook RSA (s = H(m)^d mod n) without padding,
      due to homomorphic malleability (s1 * s2 = (m1 * m2)^d mod n).
- Always use PSS padding with maximum salt length or matching hash length.

    TODO (Module 1 - Dev A):
1. Canonicalize payload to bytes using `canonicalize_payload(payload)`.
2. Sign data using `private_key.sign()`:
  - padding: `padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)`
  - algorithm: `hashes.SHA256()`
3. Return the signature bytes.
    """
    data = canonicalize_payload(payload)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return signature


def verify_ballot_signature(
    public_key: rsa.RSAPublicKey,
    signature: bytes,
    payload: Dict[str, Any],
) -> bool:
    """Verify an RSA-PSS digital signature against a ballot payload."""

    from cryptography.exceptions import InvalidSignature

    data = canonicalize_payload(payload)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True

    except InvalidSignature:
        return False

def check_voter_eligibility_and_unicity(
    voter_id: str,
    registered_voters: Set[str],
    cast_voters: Set[str],
) -> Tuple[bool, str]:
    """Check if a voter is registered and has not voted yet."""

    if voter_id not in registered_voters:
        return False, "Voter not registered"

    if voter_id in cast_voters:
        return False, "Double voting detected"

    return True, "OK"

__all__ = [
    "generate_voter_rsa_keypair",
    "canonicalize_payload",
    "sign_ballot_payload",
    "verify_ballot_signature",
    "check_voter_eligibility_and_unicity",
]