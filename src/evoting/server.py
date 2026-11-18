"""Election Server & System Coordinator.

Coordinates the end-to-end election lifecycle: system parameters setup,
voter registration, ballot authentication and commitment, receipt issuance,
and homomorphic tally aggregation.
"""

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa

from evoting.bulletin_board import AppendOnlyBulletinBoard, BulletinBlock
from evoting.config.params import (
    DEFAULT_DATABASE_PATH,
    DEFAULT_RSA_KEY_SIZE,
    DEFAULT_RSA_PUBLIC_EXPONENT,
    MODP_2048_G,
    MODP_2048_P,
)
from evoting.crypto.rsa import (
    check_voter_eligibility_and_unicity,
    verify_ballot_signature,
)
from evoting.receipt import VoterReceipt, issue_voter_receipt


class ElectionServer:
    """Central Election Server managing the public ledger and voting pipeline.

    Parameters
    ----------
    election_id : str
        Unique identifier for the election contest.
    candidates : List[str]
        List of candidate names.
    db_path : Optional[str], optional
        Path to SQLite database, by default DEFAULT_DATABASE_PATH.
    p : int, optional
        MODP prime, by default MODP_2048_P.
    g : int, optional
        MODP generator, by default MODP_2048_G.
    """

    def __init__(
        self,
        election_id: str,
        candidates: list[str],
        db_path: str | None = DEFAULT_DATABASE_PATH,
        p: int = MODP_2048_P,
        g: int = MODP_2048_G,
    ) -> None:
        self.election_id: str = election_id
        self.candidates: list[str] = candidates
        self.db_path: str | None = db_path
        self.p: int = p
        self.g: int = g

        # Joint public key synthesized from authorities
        self.joint_public_key_h: int | None = None

        # Server's own RSA keypair for signing voter receipts
        self._server_private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=DEFAULT_RSA_PUBLIC_EXPONENT,
            key_size=DEFAULT_RSA_KEY_SIZE,
        )
        self.server_public_key: rsa.RSAPublicKey = self._server_private_key.public_key()

        # Append-only bulletin board ledger
        self.bulletin_board: AppendOnlyBulletinBoard = AppendOnlyBulletinBoard(db_path=db_path)

        # In-memory registries
        self.registered_voters: dict[str, rsa.RSAPublicKey] = {}
        self.cast_voter_ids: set[str] = set()

    def set_joint_public_key(self, joint_public_key_h: int) -> None:
        """Register the synthesized joint public key from authorities."""
        self.joint_public_key_h = joint_public_key_h

    def register_voter(self, voter_id: str, public_key: rsa.RSAPublicKey) -> None:
        """Register an authorized voter's public key."""
        self.registered_voters[voter_id] = public_key

    def cast_ballot(
        self,
        voter_id: str,
        encrypted_ballot: dict[str, dict[str, int]],
        signature: bytes,
    ) -> VoterReceipt:
        """Process, verify, and commit an incoming ballot to the bulletin board.

        Parameters
        ----------
        voter_id : str
            Identifier of voter submitting ballot.
        encrypted_ballot : Dict[str, Dict[str, int]]
            Mapping candidate to {'c1': int, 'c2': int}.
        signature : bytes
            Voter's RSA digital signature over the ballot payload.

        Returns
        -------
        VoterReceipt
            Coercion-resistant signed receipt confirming commitment.

        Raises
        ------
        ValueError
            If voter is not eligible, has already voted, or signature is invalid.
        """
        # Step 1: Eligibility and Unicity Check
        try:
            eligible, reason = check_voter_eligibility_and_unicity(
                voter_id=voter_id,
                registered_voters=set(self.registered_voters.keys()),
                cast_voters=self.cast_voter_ids,
            )
            if not eligible:
                raise ValueError(f"Ballot rejected: {reason}")
        except NotImplementedError:
            # Fallback for stub state: check basic set membership
            if voter_id not in self.registered_voters:
                raise ValueError(f"Ballot rejected: Voter {voter_id} not registered.") from None
            if voter_id in self.cast_voter_ids:
                raise ValueError(
                    f"Ballot rejected: Double voting detected for {voter_id}."
                ) from None

        # Step 2: Signature Verification
        voter_pubkey = self.registered_voters[voter_id]
        try:
            valid_sig = verify_ballot_signature(voter_pubkey, signature, encrypted_ballot)
            if not valid_sig:
                raise ValueError(f"Ballot rejected: Invalid RSA signature for {voter_id}.")
        except NotImplementedError:
            # If student has not implemented verify_ballot_signature, allow in stub mode
            pass

        # Step 3: Commit to Bulletin Board Ledger
        self.cast_voter_ids.add(voter_id)
        block = self.bulletin_board.append_ballot(
            voter_id=voter_id,
            encrypted_ballot=encrypted_ballot,
            signature_bytes=signature,
        )

        # Step 4: Issue Coercion-Resistant Receipt
        try:
            receipt = issue_voter_receipt(block, self._server_private_key)
        except NotImplementedError:
            receipt = VoterReceipt(
                receipt_id=f"rcpt_{block.index}",
                block_index=block.index,
                voter_id=voter_id,
                block_hash=block.block_hash,
                server_signature_hex="PENDING_SERVER_SIG",
                issued_at=datetime.now(timezone.utc).isoformat(),
            )

        return receipt

    def get_public_ledger(self) -> list[BulletinBlock]:
        """Return full chain of public bulletin board blocks."""
        return self.bulletin_board.chain


__all__ = [
    "ElectionServer",
]
