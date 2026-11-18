"""Module 1: Voter Identity & Registration Entity.

Full implementation of non-cryptographic plumbing (Voter data models, registration,
CLI/DTO serialization, and persistence hooks) alongside educational cryptographic stubs.
Assigned to: Integrante 1 (Dev A)
"""

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from evoting.crypto.rsa import (
    generate_voter_rsa_keypair,
    sign_ballot_payload,
)
from evoting.storage.database import get_db_session, save_voter


@dataclass
class VoterRegistrationDTO:
    """Data Transfer Object representing a registered voter."""

    voter_id: str
    public_key_pem: str
    has_voted: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert DTO to dictionary representation."""
        return {
            "voter_id": self.voter_id,
            "public_key_pem": self.public_key_pem,
            "has_voted": self.has_voted,
        }


class Voter:
    """Represents a voter participating in the electronic voting system.

    Parameters
    ----------
    voter_id : str
        Unique identifier for the voter (e.g. voter_001).
    generate_keys : bool, optional
        Whether to generate an RSA keypair on instantiation, by default True.
    """

    def __init__(self, voter_id: str, generate_keys: bool = True) -> None:
        self.voter_id: str = voter_id
        self._private_key: rsa.RSAPrivateKey | None = None
        self._public_key: rsa.RSAPublicKey | None = None
        self.public_key_pem: str = ""

        if generate_keys:
            self._setup_keys()

    def _setup_keys(self) -> None:
        """Initialize RSA keypair for the voter."""
        try:
            self._private_key, self._public_key = generate_voter_rsa_keypair()
            self.public_key_pem = self._export_public_key_pem()
        except NotImplementedError:
            # Pedagogical stub fallback: if student has not yet implemented
            # generate_voter_rsa_keypair, keep attributes None and warn in doc.
            self._private_key = None
            self._public_key = None
            self.public_key_pem = f"PENDING_RSA_IMPLEMENTATION_FOR_{self.voter_id}"

    @property
    def private_key(self) -> rsa.RSAPrivateKey | None:
        """Access the voter's private signing key."""
        return self._private_key

    @property
    def public_key(self) -> rsa.RSAPublicKey | None:
        """Access the voter's public verification key."""
        return self._public_key

    def _export_public_key_pem(self) -> str:
        """Export RSA public key to standard PEM format."""
        if self._public_key is None:
            return ""
        pem_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    def sign_ballot(self, ballot_payload: dict[str, Any]) -> bytes:
        """Digitally sign an encrypted ballot payload.

        Parameters
        ----------
        ballot_payload : Dict[str, Any]
            The ballot content to sign.

        Returns
        -------
        bytes
            The RSA-PSS signature bytes.
        """
        if self._private_key is None:
            raise NotImplementedError(
                f"Voter {self.voter_id} has no private key. Student must implement "
                "generate_voter_rsa_keypair and sign_ballot_payload in Module 1."
            )
        return sign_ballot_payload(self._private_key, ballot_payload)

    def persist_registration(self, db_path: str | None = None) -> VoterRegistrationDTO:
        """Save voter registration credentials to the election database."""
        dto = VoterRegistrationDTO(
            voter_id=self.voter_id,
            public_key_pem=self.public_key_pem,
            has_voted=False,
        )
        if db_path:
            with get_db_session(db_path) as session:
                save_voter(session, self.voter_id, self.public_key_pem)
        return dto

    def __repr__(self) -> str:
        return f"<Voter id='{self.voter_id}' has_keys={self._private_key is not None}>"


__all__ = [
    "Voter",
    "VoterRegistrationDTO",
]
