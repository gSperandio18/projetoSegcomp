"""Module 5: Independent Zero-Trust Audit Engine.

Full implementation of audit report schemas, execution orchestration, and CLI
formatting alongside educational ZERO-TRUST verification stubs.
Assigned to: Integrante 5 (Dev E)
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.config.params import GENESIS_PREVIOUS_HASH, MODP_2048_G, MODP_2048_P
from evoting.crypto.dkg import combine_decryption_shares_and_recover
from evoting.crypto.elgamal import EncryptedVote


@dataclass
class AuditCheckItem:
    """Individual audit step result."""

    name: str
    passed: bool
    details: str
    error: str | None = None


@dataclass
class AuditReport:
    """Complete election audit report containing all verification phases."""

    election_id: str
    overall_passed: bool = False
    checks: list[AuditCheckItem] = field(default_factory=list)
    recomputed_tallies: dict[str, int] = field(default_factory=dict)

    def add_check(self, name: str, passed: bool, details: str, error: str | None = None) -> None:
        """Append an audit check outcome."""
        self.checks.append(AuditCheckItem(name=name, passed=passed, details=details, error=error))

    def evaluate_overall(self) -> bool:
        """Compute overall election validity (all individual checks must pass)."""
        self.overall_passed = len(self.checks) > 0 and all(c.passed for c in self.checks)
        return self.overall_passed

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary format."""
        return asdict(self)

    def to_json(self) -> str:
        """Export report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class ElectionAuditor:
    """Zero-trust independent auditor verifying public election records without private keys."""

    def __init__(
        self,
        bulletin_blocks: list[dict[str, Any]],
        voter_registry: dict[str, rsa.RSAPublicKey],
        p: int = MODP_2048_P,
        g: int = MODP_2048_G,
    ) -> None:
        self.blocks = bulletin_blocks
        self.voter_registry = voter_registry
        self.p = p
        self.g = g

    @staticmethod
    def _canonicalize_json(payload: dict[str, Any]) -> bytes:
        """Equivalent to evoting.crypto.rsa.canonizalize_payload, by DevA"""
        return json.dumps(
            payload,  # ballot_data
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _recompute_block_hash(cls, block: dict[str, Any]) -> str:
        """Equivalent to evoting.storage.bulletin_board.compute_block_hash, by DevD"""

        canonical_ballot_bytes = cls._canonicalize_json(block["ballot_data"])
        canonical_ballot_str = canonical_ballot_bytes.decode("utf-8")

        composite_payload = json.dumps(
            [
                block["previous_hash"],
                block["index"],
                block["voter_id"],
                canonical_ballot_str,
                block["voter_signature_hex"],
                block["timestamp"],
            ],
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(composite_payload).hexdigest()

    @staticmethod
    def _recover_tally_fallback(
        tally_cipher: EncryptedVote,
        shares: list[int],
        p: int,
        g: int,
        max_votes: int,
    ) -> int:
        """Equivalent to evoting.crypto.dkg.combine_decryption_shares_and_recover, by DevC"""
        combined_share = 1
        for share in shares:
            combined_share = (combined_share * int(share)) % p

        share_inverse = pow(combined_share, -1, p)
        encoded_tally = (tally_cipher.c2 * share_inverse) % p

        current_power = 1
        for v in range(max_votes + 1):
            if current_power == encoded_tally:
                return v
            current_power = (current_power * g) % p

        raise ValueError(f"Discrete log not found in [0, {max_votes}].")

    def audit_hash_chain_integrity(self) -> AuditCheckItem:
        """Verify that the bulletin board hash chain is unbroken and unmodified."""
        if not self.blocks:
            return AuditCheckItem(
                name="Hash Chain Integrity",
                passed=False,
                details="Bulletin board is empty or does not exist",
            )

        try:
            for expected_index, block in enumerate(self.blocks):
                if block["index"] != expected_index:
                    return AuditCheckItem(
                        name="Hash Chain Integrity",
                        passed=False,
                        details=(
                            f"Block index {block['index']} does not match "
                            f"expected position {expected_index}"
                        ),
                    )

                if expected_index == 0:
                    if block["previous_hash"] != GENESIS_PREVIOUS_HASH:
                        return AuditCheckItem(
                            name="Hash Chain Integrity",
                            passed=False,
                            details="Genesis block previous_hash does "
                            "not match GENESIS_PREVIOUS_HASH.",
                        )

                else:
                    previous_block = self.blocks[expected_index - 1]
                    if block["previous_hash"] != previous_block["block_hash"]:
                        return AuditCheckItem(
                            name="Hash Chain Integrity",
                            passed=False,
                            details=(
                                f"Block {expected_index} previous_hash does not match "
                                f"block {expected_index - 1} block_hash."
                            ),
                        )

                recomputed_hash = self._recompute_block_hash(block)
                if block["block_hash"] != recomputed_hash:
                    return AuditCheckItem(
                        name="Hash Chain Integrity",
                        passed=False,
                        details=(
                            f"Block {block['index']} hash does not match recomputed SHA-256 digest."
                        ),
                    )
        except KeyError as e:
            return AuditCheckItem(
                name="Hash Chain Integrity",
                passed=False,
                details="Malformed block missing required field",
                error=f"Missing key: {e}",
            )

        return AuditCheckItem(
            name="Hash Chain Integrity",
            passed=True,
            details=f"Chain integrity verified across {len(self.blocks)} block(s)",
        )

    def audit_voter_signatures_and_unicity(self) -> AuditCheckItem:
        """Verify that every cast ballot has a valid RSA signature and no voter cast twice."""

        if not self.voter_registry:
            return AuditCheckItem(
                name="Voter Signatures & Unicity",
                passed=False,
                details="Voter registry is empty or does not exist.",
            )

        seen_voters: set[str] = set()
        verified_ballots = 0

        try:
            for block in self.blocks:
                voter_id = block["voter_id"]

                # bloco Genesis
                if block.get("index") == 0 or voter_id == "SYSTEM_GENESIS":
                    continue

                # Each ballot's voter_id must exist in voter_registry.
                if voter_id not in self.voter_registry:
                    return AuditCheckItem(
                        name="Voter Signatures & Unicity",
                        passed=False,
                        details=(f"Voter '{voter_id}' in block {block['index']} is not registered"),
                    )

                # No voter_id may appear more than once across non-genesis blocks
                if voter_id in seen_voters:
                    return AuditCheckItem(
                        name="Voter Signatures & Unicity",
                        passed=False,
                        details=(
                            f"Double voting detected for voter '{voter_id}' in "
                            f"block {block['index']}"
                        ),
                    )

                voters_signature_hex = block["voter_signature_hex"]

                try:
                    sig_hex_to_bytes = bytes.fromhex(voters_signature_hex)
                except ValueError as e:
                    return AuditCheckItem(
                        name="Voter Signatures & Unicity",
                        passed=False,
                        details=(
                            f"Invalid signature hex in block "
                            f"{block['index']} for voter '{voter_id}'"
                        ),
                        error=f"Value error: {str(e)}",
                    )

                # The RSA-PSS signature must verify over the canonical ballot dictionary
                canonical_ballot = self._canonicalize_json(block["ballot_data"])
                public_key = self.voter_registry[voter_id]

                try:
                    public_key.verify(
                        signature=sig_hex_to_bytes,
                        data=canonical_ballot,
                        padding=padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        algorithm=hashes.SHA256(),
                    )
                except InvalidSignature:
                    return AuditCheckItem(
                        name="Voter Signatures & Unicity",
                        passed=False,
                        details=(
                            f"Invalid RSA signature in block "
                            f"{block['index']} for voter '{voter_id}'"
                        ),
                    )

                seen_voters.add(voter_id)
                verified_ballots += 1

        except KeyError as e:
            return AuditCheckItem(
                name="Voter Signatures & Unicity",
                passed=False,
                details=("Malformed block missing required field"),
                error=f"Missing key: {e}",
            )

        return AuditCheckItem(
            name="Voter Signatures & Unicity",
            passed=True,
            details=(
                f"Verified {verified_ballots} ballot signature(s) and unicity "
                f"across {len(seen_voters)} voter(s)."
            ),
        )

    def audit_homomorphic_tally_aggregation(
        self,
        candidates: list[str],
    ) -> dict[str, EncryptedVote]:
        """Recompute homomorphic product C1_total and C2_total for all candidates."""
        if not candidates:
            return {}

        # Initialize `prod_c1 = {c: 1 for c in candidates}` and `prod_c2 = {c: 1 ...}`
        prod_c1: dict[str, int] = {candidate: 1 for candidate in candidates}
        prod_c2: dict[str, int] = {candidate: 1 for candidate in candidates}

        # For each non-genesis block, multiply candidate ciphertexts modulo p
        for block in self.blocks:
            # pular o bloco de genesis
            if block.get("index") == 0 or block.get("voter_id") == "SYSTEM_GENESIS":
                continue

            ballot_data = block["ballot_data"]
            candidate_entries = ballot_data.get("votes", ballot_data)

            for candidate in candidates:
                raw_cipher = candidate_entries[candidate]
                if isinstance(raw_cipher, EncryptedVote):
                    c1, c2 = raw_cipher.c1, raw_cipher.c2
                else:
                    c1, c2 = int(raw_cipher["c1"]), int(raw_cipher["c2"])

                prod_c1[candidate] = (prod_c1[candidate] * c1) % self.p
                prod_c2[candidate] = (prod_c2[candidate] * c2) % self.p

        # Return Dict mapping candidate to EncryptedVote
        return {
            candidate: EncryptedVote(c1=prod_c1[candidate], c2=prod_c2[candidate])
            for candidate in candidates
        }

    def audit_decryption_shares_and_results(
        self,
        tally_ciphers: dict[str, EncryptedVote],
        candidate_shares: dict[str, list[int]],
        announced_results: dict[str, int],
    ) -> AuditCheckItem:
        """Verify that combining authority decryption shares reproduces the announced results."""

        if not tally_ciphers:
            return AuditCheckItem(
                name="Homomorphic Tally & Decryption",
                passed=False,
                details=("No aggregated tally ciphertexts provided for verification"),
            )

        # Checando que o máximo de votos = 1 por eleitor
        max_votes = sum(
            1
            for block in self.blocks
            if not (block.get("index") == 0 or block.get("voter_id") == "SYSTEM_GENESIS")
        )

        try:
            for candidate, total_cipher in tally_ciphers.items():
                if candidate not in candidate_shares or candidate not in announced_results:
                    return AuditCheckItem(
                        name="Homomorphic Tally & Decryption",
                        passed=False,
                        details=(
                            "Missing decryption shares or announced result "
                            f"for candidate '{candidate}'"
                        ),
                    )

                shares = candidate_shares[candidate]
                if not shares:
                    return AuditCheckItem(
                        name="Homomorphic Tally & Decryption",
                        passed=False,
                        details=(f"Empty decryption share list for candidate '{candidate}'"),
                    )

                # For each candidate, combine shares using `combine_decryption_shares_and_recover`
                try:
                    recovered_votes = combine_decryption_shares_and_recover(
                        total_cipher, shares, self.p, self.g, max_votes
                    )

                except NotImplementedError:
                    recovered_votes = self._recover_tally_fallback(
                        tally_cipher=total_cipher,
                        shares=shares,
                        p=self.p,
                        g=self.g,
                        max_votes=max_votes,
                    )

                # Compare recovered total against `announced_results[cand]`.
                if recovered_votes != announced_results[candidate]:
                    return AuditCheckItem(
                        name="Homomorphic Tally & Decryption",
                        passed=False,
                        details=(
                            f"Tally mismatch for '{candidate}': auditor recovered "
                            f"{recovered_votes}, but announced result is "
                            f"{announced_results[candidate]}."
                        ),
                    )

        except (KeyError, ValueError) as e:
            return AuditCheckItem(
                name="Homomorphic Tally & Decryption",
                passed=False,
                details=("Decryption share verification or discrete log recovery failed."),
                error=f"{str(e)}",
            )

        return AuditCheckItem(
            name="Homomorphic Tally & Decryption",
            passed=True,
            details=(
                f"Recomputed homomorphic tallies and decryption shares match announced results "
                f"for all {len(tally_ciphers)} candidate(s)."
            ),
        )

    def run_full_audit(
        self,
        candidates: list[str],
        candidate_shares: dict[str, list[int]],
        announced_results: dict[str, int],
        election_id: str = "election_2026",
    ) -> AuditReport:
        """Execute the complete zero-trust independent audit suite."""
        report = AuditReport(election_id=election_id)

        try:
            c1 = self.audit_hash_chain_integrity()
            report.checks.append(c1)
        except NotImplementedError as e:
            report.add_check("Hash Chain Integrity", False, "Stub not implemented", str(e))

        try:
            c2 = self.audit_voter_signatures_and_unicity()
            report.checks.append(c2)
        except NotImplementedError as e:
            report.add_check("Voter Signatures & Unicity", False, "Stub not implemented", str(e))

        try:
            tally_ciphers = self.audit_homomorphic_tally_aggregation(candidates)
            c3 = self.audit_decryption_shares_and_results(
                tally_ciphers, candidate_shares, announced_results
            )
            report.checks.append(c3)

            if c3.passed:
                report.recomputed_tallies = dict(announced_results)

        except NotImplementedError as e:
            report.add_check(
                "Homomorphic Tally & Decryption", False, "Stub not implemented", str(e)
            )

        report.evaluate_overall()
        return report


__all__ = [
    "AuditCheckItem",
    "AuditReport",
    "ElectionAuditor",
]
