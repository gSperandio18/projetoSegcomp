"""Module 4: Append-Only Verifiable Public Bulletin Board.

Full implementation of ledger data structures, genesis block setup, and database
persistence hooks alongside educational SHA-256 hash-chaining stubs.
Assigned to: Integrante 4 (Dev D)
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from evoting.config.params import GENESIS_PREVIOUS_HASH
from evoting.crypto.rsa import canonicalize_payload
from evoting.storage.database import get_db_session, save_bulletin_block


@dataclass
class BulletinBlock:
    """An immutable block recorded on the public bulletin board ledger.

    Attributes
    ----------
    index : int
        Zero-indexed position in the chain (0 = Genesis).
    previous_hash : str
        Hex-encoded SHA-256 hash of block index - 1.
    block_hash : str
        Hex-encoded SHA-256 hash of this block.
    voter_id : str
        Identifier of the casting voter (or 'GENESIS').
    ballot_data : Dict[str, Any]
        Encrypted candidate ciphertexts payload.
    voter_signature_hex : str
        Hex-encoded RSA digital signature of the voter.
    timestamp : str
        ISO 8601 UTC timestamp of block creation.
    """

    index: int
    previous_hash: str
    block_hash: str
    voter_id: str
    ballot_data: dict[str, Any]
    voter_signature_hex: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Convert block to dictionary format."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BulletinBlock":
        """Deserialize block from dictionary."""
        return cls(
            index=int(data["index"]),
            previous_hash=str(data["previous_hash"]),
            block_hash=str(data["block_hash"]),
            voter_id=str(data["voter_id"]),
            ballot_data=dict(data["ballot_data"]),
            voter_signature_hex=str(data["voter_signature_hex"]),
            timestamp=str(data["timestamp"]),
        )


def compute_block_hash(
    previous_hash: str,
    index: int,
    voter_id: str,
    ballot_data: dict[str, Any],
    voter_signature_hex: str,
    timestamp: str,
) -> str:
    """Compute the SHA-256 integrity hash for a bulletin board block.

    Parameters
    ----------
    previous_hash : str
        Hash of the preceding block (H_{k-1}).
    index : int
        Block index k.
    voter_id : str
        Voter identifier.
    ballot_data : Dict[str, Any]
        Encrypted ballot dictionary.
    voter_signature_hex : str
        Hex-encoded signature.
    timestamp : str
        Timestamp string.

    Returns
    -------
    str
        Hexadecimal SHA-256 digest H_k.

    Notes
    -----
    Mathematical Invariants:
        H_k = SHA-256(H_{k-1} || index || voter_id || canonical(ballot_data) || sig || timestamp)
    This creates a cryptographic Merkle-like chain where altering any block k
    invalidates H_k and all subsequent block hashes H_{k+1}, ..., H_N.

    Security Pitfalls:
    - Omission of voter_signature or timestamp in the hash allows signature substitution attacks.
    - Ambiguous delimiter concatenation: concatenating raw strings without canonical serialization
      can allow extension attacks.

    TODO (Module 4 - Dev D):
    1. Canonicalize `ballot_data` to bytes using `canonicalize_payload(ballot_data)`.
    2. Build composite byte string incorporating all fields deterministically.
    3. Compute SHA-256 digest using `hashlib.sha256()`.
    4. Return `.hexdigest()`.
    """
    try:
        canonical_ballot_bytes = canonicalize_payload(ballot_data)
    except NotImplementedError:
        canonical_ballot_bytes = json.dumps(
            ballot_data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    canonical_ballot_str = canonical_ballot_bytes.decode("utf-8")

    composite_payload = json.dumps(
        [
            previous_hash,
            index,
            voter_id,
            canonical_ballot_str,
            voter_signature_hex,
            timestamp,
        ],
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(composite_payload).hexdigest()


class AppendOnlyBulletinBoard:
    """Public, verifiable, append-only bulletin board ledger."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path: str | None = db_path
        self.chain: list[BulletinBlock] = []
        self._init_genesis()

    def _init_genesis(self) -> None:
        """Create and append the Genesis block."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            genesis_hash = compute_block_hash(
                previous_hash=GENESIS_PREVIOUS_HASH,
                index=0,
                voter_id="SYSTEM_GENESIS",
                ballot_data={"genesis": True},
                voter_signature_hex="GENESIS_SIGNATURE",
                timestamp=now,
            )
        except NotImplementedError:
            genesis_hash = "0" * 64

        genesis_block = BulletinBlock(
            index=0,
            previous_hash=GENESIS_PREVIOUS_HASH,
            block_hash=genesis_hash,
            voter_id="SYSTEM_GENESIS",
            ballot_data={"genesis": True},
            voter_signature_hex="GENESIS_SIGNATURE",
            timestamp=now,
        )
        self.chain.append(genesis_block)

    def append_ballot(
        self,
        voter_id: str,
        encrypted_ballot: dict[str, Any],
        signature_bytes: bytes,
    ) -> BulletinBlock:
        """Append a newly cast and authenticated ballot to the bulletin board.

        Parameters
        ----------
        voter_id : str
            Identifier of casting voter.
        encrypted_ballot : Dict[str, Any]
            Encrypted candidate ciphertexts.
        signature_bytes : bytes
            Voter's RSA digital signature.

        Returns
        -------
        BulletinBlock
            The newly created and committed block.
        """
        prev_block = self.chain[-1]
        new_index = len(self.chain)
        if isinstance(signature_bytes, bytes):
            sig_hex = signature_bytes.hex()
        else:
            sig_hex = str(signature_bytes)
        now = datetime.now(timezone.utc).isoformat()

        try:
            new_hash = compute_block_hash(
                previous_hash=prev_block.block_hash,
                index=new_index,
                voter_id=voter_id,
                ballot_data=encrypted_ballot,
                voter_signature_hex=sig_hex,
                timestamp=now,
            )
        except NotImplementedError:
            new_hash = f"DRAFT_BLOCK_HASH_{new_index}"

        block = BulletinBlock(
            index=new_index,
            previous_hash=prev_block.block_hash,
            block_hash=new_hash,
            voter_id=voter_id,
            ballot_data=encrypted_ballot,
            voter_signature_hex=sig_hex,
            timestamp=now,
        )
        self.chain.append(block)

        if self.db_path:
            with get_db_session(self.db_path) as session:
                save_bulletin_block(
                    session=session,
                    index=block.index,
                    previous_hash=block.previous_hash,
                    block_hash=block.block_hash,
                    voter_id=block.voter_id,
                    ballot_payload=block.ballot_data,
                    voter_signature_hex=block.voter_signature_hex,
                    timestamp=block.timestamp,
                )

        return block

    def verify_chain_integrity(self) -> bool:
        """Verify the full cryptographic hash-chain continuity from Genesis to tail.

        Returns
        -------
        bool
            True if all block hashes match and chain is unbroken; False if tampering detected.

        Notes
        -----
        Verification Invariants:
        1. Block 0 must have previous_hash == GENESIS_PREVIOUS_HASH.
        2. For every k >= 1:
           block[k].previous_hash == block[k - 1].block_hash.
        3. For every block k:
           block[k].block_hash == compute_block_hash(...block[k] fields...).

        TODO (Module 4 - Dev D):
        1. Iterate through self.chain from 0 to len(self.chain) - 1.
        2. Check previous_hash linkages.
        3. Recompute block hash using `compute_block_hash` and compare with stored block_hash.
        4. If any comparison fails, return False; return True if all valid.
        """
        if not self.chain:
            return False

        for expected_index, block in enumerate(self.chain):
            if block.index != expected_index:
                return False

            if expected_index == 0:
                if block.previous_hash != GENESIS_PREVIOUS_HASH:
                    return False
            else:
                prev_block = self.chain[expected_index - 1]
                if block.previous_hash != prev_block.block_hash:
                    return False

            recomputed_hash = compute_block_hash(
                previous_hash=block.previous_hash,
                index=block.index,
                voter_id=block.voter_id,
                ballot_data=block.ballot_data,
                voter_signature_hex=block.voter_signature_hex,
                timestamp=block.timestamp,
            )
            if block.block_hash != recomputed_hash:
                return False

        return True

    def export_chain_json(self) -> str:
        """Export full ledger chain to JSON string."""
        return json.dumps([b.to_dict() for b in self.chain], indent=2)

    def load_from_list(self, blocks: list[dict[str, Any]]) -> None:
        """Load bulletin board chain from list of block dictionaries."""
        self.chain = [BulletinBlock.from_dict(b) for b in blocks]


__all__ = [
    "BulletinBlock",
    "compute_block_hash",
    "AppendOnlyBulletinBoard",
]
