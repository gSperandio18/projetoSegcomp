"""Module 4: Coercion-Resistant Voter Receipts.

Full implementation of receipt containers and verification models alongside
educational cryptographic stubs for server-signed receipts.
Assigned to: Integrante 4 (Dev D)
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.bulletin_board import BulletinBlock


@dataclass
class VoterReceipt:
    """A cryptographic receipt provided to the voter upon successful ballot commitment.

    CRITICAL SECURITY INVARIANT (Coercion Resistance):
    --------------------------------------------------
    This receipt explicitly EXCLUDES the voter's ElGamal blinding factor 'r'
    and plaintext vote 'm'. It proves solely that the voter's encrypted ballot
    was included in the public ledger at block_index with block_hash.
    """

    receipt_id: str
    block_index: int
    voter_id: str
    block_hash: str
    server_signature_hex: str
    issued_at: str

    def to_dict(self) -> dict[str, Any]:
        """Convert receipt to dictionary representation."""
        return asdict(self)

    def to_json(self) -> str:
        """Export receipt as formatted JSON."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoterReceipt":
        """Reconstruct receipt from dictionary."""
        return cls(
            receipt_id=str(data["receipt_id"]),
            block_index=int(data["block_index"]),
            voter_id=str(data["voter_id"]),
            block_hash=str(data["block_hash"]),
            server_signature_hex=str(data["server_signature_hex"]),
            issued_at=str(data["issued_at"]),
        )


def _build_receipt_message(block_index: int, block_hash: str, voter_id: str) -> bytes:
    """Build deterministic UTF-8 message bytes for server receipt signing/verification."""
    return f"{block_index}:{block_hash}:{voter_id}".encode()


def issue_voter_receipt(
    block: BulletinBlock,
    server_private_key: rsa.RSAPrivateKey,
) -> VoterReceipt:
    """Generate a server-signed receipt confirming bulletin board inclusion.

    Parameters
    ----------
    block : BulletinBlock
        The newly committed ledger block.
    server_private_key : rsa.RSAPrivateKey
        The election server's private RSA signing key.

    Returns
    -------
    VoterReceipt
        A signed receipt containing block index, block hash, and server signature.

    Notes
    -----
    Mathematical Invariants:
        Message = "RECEIPT:index={block.index}:hash={block.block_hash}:voter={block.voter_id}"
        Sig_server = Sign_{SK_server}(H(Message))

    Security Pitfalls:
    - Never include ElGamal randomizer r or plaintext choices! If included, vote buyers
      can compel the voter to surrender the receipt to verify how they voted.
    - Deterministic message formatting prevents receipt forgery.

    TODO (Module 4 - Dev D):
    1. Construct canonical message bytes:
       `f"{block.index}:{block.block_hash}:{block.voter_id}".encode("utf-8")`.
    2. Sign message bytes using `server_private_key.sign(msg, padding.PSS(...), hashes.SHA256())`.
    3. Construct and return `VoterReceipt`.
    """
    message = _build_receipt_message(block.index, block.block_hash, block.voter_id)

    signature_bytes = server_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return VoterReceipt(
        receipt_id=f"rcpt_{block.index}_{block.block_hash[:8]}",
        block_index=block.index,
        voter_id=block.voter_id,
        block_hash=block.block_hash,
        server_signature_hex=signature_bytes.hex(),
        issued_at=datetime.now(timezone.utc).isoformat(),
    )


def verify_receipt(
    receipt: VoterReceipt,
    server_public_key: rsa.RSAPublicKey,
) -> bool:
    """Verify that a receipt was authentically signed by the election server.

    Parameters
    ----------
    receipt : VoterReceipt
        The receipt presented for verification.
    server_public_key : rsa.RSAPublicKey
        The election server's public verification key.

    Returns
    -------
    bool
        True if the signature is valid; False otherwise.

    TODO (Module 4 - Dev D):
    1. Reconstruct canonical message bytes:
       `f"{receipt.block_index}:{receipt.block_hash}:{receipt.voter_id}".encode("utf-8")`.
    2. Decode signature from hex bytes: `bytes.fromhex(receipt.server_signature_hex)`.
    3. In a try-except block, call `server_public_key.verify(...)`.
    4. Return True on success; return False if `InvalidSignature` caught.
    """
    message = _build_receipt_message(
        receipt.block_index,
        receipt.block_hash,
        receipt.voter_id,
    )

    try:
        signature_bytes = bytes.fromhex(receipt.server_signature_hex)
    except ValueError:
        return False

    try:
        server_public_key.verify(
            signature_bytes,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


__all__ = [
    "VoterReceipt",
    "issue_voter_receipt",
    "verify_receipt",
]
