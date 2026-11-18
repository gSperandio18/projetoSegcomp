"""Module 3: Election Authority Entity & Orchestration.

Full implementation of authority metadata, key ceremony state, and partial
decryption share packaging alongside educational DKG stubs.
Assigned to: Integrante 3 (Dev C)
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from evoting.config.params import MODP_2048_G, MODP_2048_P
from evoting.crypto.dkg import (
    compute_partial_decryption_share,
    generate_authority_keypair,
)
from evoting.crypto.elgamal import EncryptedVote
from evoting.storage.database import get_db_session, save_authority


@dataclass
class AuthorityDTO:
    """Data Transfer Object representing an election authority's public registration."""

    authority_id: int
    name: str
    public_key_h: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert DTO to dictionary representation."""
        return {
            "authority_id": self.authority_id,
            "name": self.name,
            "public_key_h": self.public_key_h,
        }


class ElectionAuthority:
    """Represents an independent election trustee/authority holding a private key share.

    Parameters
    ----------
    authority_id : int
        Unique numerical identifier for the authority (e.g. 1, 2, 3).
    p : int, optional
        Prime modulus, by default MODP_2048_P.
    g : int, optional
        Generator, by default MODP_2048_G.
    name : Optional[str], optional
        Human-readable authority label.
    generate_keys : bool, optional
        Whether to generate keypair upon creation, by default True.
    """

    def __init__(
        self,
        authority_id: int,
        p: int = MODP_2048_P,
        g: int = MODP_2048_G,
        name: Optional[str] = None,
        generate_keys: bool = True,
    ) -> None:
        self.authority_id: int = authority_id
        self.p: int = p
        self.g: int = g
        self.name: str = name or f"Election_Trustee_{authority_id}"
        self._private_key_x: Optional[int] = None
        self.public_key_h: int = 0

        if generate_keys:
            self._setup_keys()

    def _setup_keys(self) -> None:
        """Execute key ceremony step to obtain private and public shares."""
        try:
            self._private_key_x, self.public_key_h = generate_authority_keypair(self.p, self.g)
        except NotImplementedError:
            # Pedagogical fallback if student has not implemented generate_authority_keypair
            self._private_key_x = None
            self.public_key_h = 0

    @property
    def private_key_x(self) -> Optional[int]:
        """Access the authority's secret share x_i."""
        return self._private_key_x

    def compute_decryption_share(self, tally_cipher: EncryptedVote) -> int:
        """Produce partial decryption share D_i = (C1)^(x_i) mod p for a tally ciphertext.

        Parameters
        ----------
        tally_cipher : EncryptedVote
            The homomorphically aggregated tally ciphertext.

        Returns
        -------
        int
            Partial decryption share D_i.
        """
        if self._private_key_x is None:
            raise NotImplementedError(
                f"Authority {self.authority_id} has no private key. Student must implement "
                "generate_authority_keypair and compute_partial_decryption_share in Module 3."
            )
        return compute_partial_decryption_share(tally_cipher, self._private_key_x, self.p)

    def persist_authority(self, db_path: Optional[str] = None) -> AuthorityDTO:
        """Persist authority public registration in the election database."""
        dto = AuthorityDTO(
            authority_id=self.authority_id,
            name=self.name,
            public_key_h=hex(self.public_key_h),
        )
        if db_path:
            with get_db_session(db_path) as session:
                save_authority(session, self.authority_id, self.name, hex(self.public_key_h))
        return dto

    def __repr__(self) -> str:
        return f"<ElectionAuthority id={self.authority_id} name='{self.name}'>"


__all__ = [
    "ElectionAuthority",
    "AuthorityDTO",
]
