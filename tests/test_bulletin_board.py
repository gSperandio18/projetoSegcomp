"""Module 4 Test Suite: Append-Only Bulletin Board & Voter Receipts.

Covers ledger persistence, block and receipt models, SHA-256 hash-chain
integrity verification, and RSA-PSS coercion-resistant voter receipts.
Assigned to: Integrante 4 (Dev D)
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from evoting.bulletin_board import (
    AppendOnlyBulletinBoard,
    BulletinBlock,
    compute_block_hash,
)
from evoting.receipt import (
    VoterReceipt,
    issue_voter_receipt,
    verify_receipt,
)
from evoting.storage.database import drop_db, get_all_blocks, get_db_session, init_db


@pytest.fixture
def temp_db(tmp_path):
    """Provide a fresh isolated SQLite database file for testing."""
    db_file = str(tmp_path / "test_election.db")
    init_db(db_file)
    yield db_file
    drop_db(db_file)


class TestBulletinBoardInfrastructure:
    """Tests for ledger block data structures, DB persistence, and receipt models."""

    def test_bulletin_block_serialization(self):
        """Test BulletinBlock conversion to and from dictionary."""
        block = BulletinBlock(
            index=1,
            previous_hash="000000",
            block_hash="111111",
            voter_id="voter_1",
            ballot_data={"Alice": {"c1": 10, "c2": 20}},
            voter_signature_hex="abcdef",
            timestamp="2026-11-23T12:00:00Z",
        )
        d = block.to_dict()
        assert d["index"] == 1
        assert d["voter_id"] == "voter_1"
        assert d["ballot_data"]["Alice"]["c1"] == 10

        reconstructed = BulletinBlock.from_dict(d)
        assert reconstructed.index == 1
        assert reconstructed.block_hash == "111111"

    def test_append_only_board_memory_and_db(self, temp_db):
        """Test appending ballot to bulletin board with SQLite persistence."""
        board = AppendOnlyBulletinBoard(db_path=temp_db)
        assert len(board.chain) == 1  # Genesis block
        assert board.chain[0].index == 0

        ballot = {"Alice": {"c1": 123, "c2": 456}}
        sig = b"voter_signature_bytes"
        b1 = board.append_ballot("voter_001", ballot, sig)

        assert len(board.chain) == 2
        assert b1.index == 1
        assert b1.voter_id == "voter_001"

        with get_db_session(temp_db) as session:
            blocks = get_all_blocks(session)
            assert len(blocks) == 1
            assert blocks[0].voter_id == "voter_001"

    def test_voter_receipt_dataclass_and_json(self):
        """Test VoterReceipt serialization and absence of ElGamal blinding factor r."""
        receipt = VoterReceipt(
            receipt_id="rcpt_001",
            block_index=1,
            voter_id="voter_001",
            block_hash="hash_123",
            server_signature_hex="sig_hex_789",
            issued_at="2026-11-23T12:00:00Z",
        )
        d = receipt.to_dict()
        assert "receipt_id" in d
        assert "server_signature_hex" in d
        # CRITICAL COERCION RESISTANCE CHECK:
        assert "r" not in d
        assert "vote" not in d
        assert "blinding_factor" not in d

        json_str = receipt.to_json()
        assert "rcpt_001" in json_str


class TestBulletinBoardHashChain:
    """Tests for SHA-256 block hashing and tamper detection on the bulletin board."""

    def test_compute_block_hash_format_and_determinism(self):
        """SHA-256 hash must be 64 hex chars and invariant to dictionary key order."""
        ballot_a = {"Alice": {"c1": 10, "c2": 20}, "Bob": {"c1": 30, "c2": 40}}
        ballot_b = {"Bob": {"c2": 40, "c1": 30}, "Alice": {"c2": 20, "c1": 10}}

        hash_a = compute_block_hash(
            "0" * 64, 1, "voter_1", ballot_a, "abcd", "2026-11-23T12:00:00Z"
        )
        hash_b = compute_block_hash(
            "0" * 64, 1, "voter_1", ballot_b, "abcd", "2026-11-23T12:00:00Z"
        )

        assert len(hash_a) == 64
        int(hash_a, 16)  # Valid hexadecimal string
        assert hash_a == hash_b

    def test_compute_block_hash_avalanche_on_all_fields(self):
        """Changing any single field in a block must produce a different SHA-256 digest."""
        base_ballot = {"Alice": {"c1": 10, "c2": 20}}
        base_hash = compute_block_hash(
            "0" * 64, 1, "voter_1", base_ballot, "abcd", "2026-11-23T12:00:00Z"
        )

        assert (
            compute_block_hash("1" * 64, 1, "voter_1", base_ballot, "abcd", "2026-11-23T12:00:00Z")
            != base_hash
        )
        assert (
            compute_block_hash("0" * 64, 2, "voter_1", base_ballot, "abcd", "2026-11-23T12:00:00Z")
            != base_hash
        )
        assert (
            compute_block_hash("0" * 64, 1, "voter_2", base_ballot, "abcd", "2026-11-23T12:00:00Z")
            != base_hash
        )
        assert (
            compute_block_hash(
                "0" * 64,
                1,
                "voter_1",
                {"Alice": {"c1": 11, "c2": 20}},
                "abcd",
                "2026-11-23T12:00:00Z",
            )
            != base_hash
        )
        assert (
            compute_block_hash("0" * 64, 1, "voter_1", base_ballot, "abce", "2026-11-23T12:00:00Z")
            != base_hash
        )
        assert (
            compute_block_hash("0" * 64, 1, "voter_1", base_ballot, "abcd", "2026-11-23T12:00:01Z")
            != base_hash
        )

    def test_verify_chain_integrity_valid_chain(self):
        """Genesis-only and multi-ballot chains must pass integrity verification."""
        board = AppendOnlyBulletinBoard()
        assert board.verify_chain_integrity() is True

        b1 = board.append_ballot("v1", {"Alice": {"c1": 1, "c2": 2}}, b"sig1")
        b2 = board.append_ballot("v2", {"Alice": {"c1": 3, "c2": 4}}, b"sig2")

        assert b1.previous_hash == board.chain[0].block_hash
        assert b2.previous_hash == b1.block_hash
        assert board.verify_chain_integrity() is True

    def test_tamper_detection_in_chain_ballot_data(self):
        """Altering an encrypted ballot value in a committed block must be detected."""
        board = AppendOnlyBulletinBoard()
        board.append_ballot("v1", {"Alice": {"c1": 1, "c2": 2}}, b"sig1")
        board.append_ballot("v2", {"Alice": {"c1": 3, "c2": 4}}, b"sig2")
        assert board.verify_chain_integrity() is True

        # Tamper with Block 1 ballot data
        board.chain[1].ballot_data["Alice"]["c1"] = 999999
        assert board.verify_chain_integrity() is False

    def test_tamper_detection_metadata_and_signature(self):
        """Altering voter signature or timestamp must invalidate chain integrity."""
        board = AppendOnlyBulletinBoard()
        board.append_ballot("v1", {"Alice": {"c1": 1, "c2": 2}}, b"sig1")

        original_sig = board.chain[1].voter_signature_hex
        board.chain[1].voter_signature_hex = "deadbeef"
        assert board.verify_chain_integrity() is False
        board.chain[1].voter_signature_hex = original_sig

        board.chain[1].timestamp = "2099-01-01T00:00:00Z"
        assert board.verify_chain_integrity() is False

    def test_tamper_detection_broken_linkage_and_genesis(self):
        """Altering Genesis previous_hash or inter-block hash linkage must fail verification."""
        board = AppendOnlyBulletinBoard()
        board.append_ballot("v1", {"Alice": {"c1": 1, "c2": 2}}, b"sig1")
        board.append_ballot("v2", {"Alice": {"c1": 3, "c2": 4}}, b"sig2")

        # Break link between Block 1 and Block 2
        original_prev = board.chain[2].previous_hash
        board.chain[2].previous_hash = "f" * 64
        assert board.verify_chain_integrity() is False
        board.chain[2].previous_hash = original_prev

        # Break Genesis previous_hash invariant
        board.chain[0].previous_hash = "1" * 64
        assert board.verify_chain_integrity() is False

    def test_tamper_detection_empty_removed_or_reordered(self):
        """Empty chain, deleted block, or reordered blocks must all fail verification."""
        board = AppendOnlyBulletinBoard()
        board.append_ballot("v1", {"Alice": {"c1": 1, "c2": 2}}, b"sig1")
        board.append_ballot("v2", {"Alice": {"c1": 3, "c2": 4}}, b"sig2")

        # Reorder blocks 1 and 2
        board.chain[1], board.chain[2] = board.chain[2], board.chain[1]
        assert board.verify_chain_integrity() is False
        board.chain[1], board.chain[2] = board.chain[2], board.chain[1]

        # Delete middle block
        board.chain.pop(1)
        assert board.verify_chain_integrity() is False

        # Empty chain
        board.chain = []
        assert board.verify_chain_integrity() is False

    def test_export_and_load_chain_preserves_integrity(self):
        """Exporting ledger to JSON and loading it back must preserve chain validity."""
        board = AppendOnlyBulletinBoard()
        board.append_ballot("v1", {"Alice": {"c1": 1, "c2": 2}}, b"sig1")
        board.append_ballot("v2", {"Alice": {"c1": 3, "c2": 4}}, "abcd")

        exported_json = board.export_chain_json()
        reloaded = AppendOnlyBulletinBoard()
        reloaded.load_from_list(json.loads(exported_json))

        assert len(reloaded.chain) == 3
        assert reloaded.verify_chain_integrity() is True


@pytest.fixture(scope="module")
def server_keypair():
    """Generate a reusable RSA-2048 keypair for receipt tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


class TestVoterReceipts:
    """Tests for server-signed coercion-resistant voter receipts."""

    def test_issue_and_verify_valid_receipt(self, server_keypair):
        """Issued receipt must match block metadata, omit r/m, and verify cleanly."""
        server_priv, server_pub = server_keypair
        board = AppendOnlyBulletinBoard()
        block = board.append_ballot("voter_001", {"Alice": {"c1": 10, "c2": 20}}, b"sig1")

        receipt = issue_voter_receipt(block, server_priv)

        assert receipt.block_index == block.index
        assert receipt.block_hash == block.block_hash
        assert receipt.voter_id == "voter_001"
        assert verify_receipt(receipt, server_pub) is True

        # Coercion resistance: receipt must never expose vote m or blinding factor r
        receipt_dict = receipt.to_dict()
        assert "r" not in receipt_dict
        assert "m" not in receipt_dict
        assert "vote" not in receipt_dict
        assert "blinding_factor" not in receipt_dict

    def test_receipt_from_dict_roundtrip_and_verification(self, server_keypair):
        """Serializing and deserializing a signed receipt must preserve validity."""
        server_priv, server_pub = server_keypair
        board = AppendOnlyBulletinBoard()
        block = board.append_ballot("voter_002", {"Alice": {"c1": 30, "c2": 40}}, b"sig2")

        receipt = issue_voter_receipt(block, server_priv)
        reconstructed = VoterReceipt.from_dict(json.loads(receipt.to_json()))

        assert reconstructed == receipt
        assert verify_receipt(reconstructed, server_pub) is True

    def test_verify_receipt_fails_on_tampered_fields(self, server_keypair):
        """Altering block_index, block_hash, or voter_id must invalidate the receipt."""
        server_priv, server_pub = server_keypair
        board = AppendOnlyBulletinBoard()
        block = board.append_ballot("voter_003", {"Alice": {"c1": 50, "c2": 60}}, b"sig3")
        receipt = issue_voter_receipt(block, server_priv)

        tampered_index = VoterReceipt.from_dict({**receipt.to_dict(), "block_index": 99})
        assert verify_receipt(tampered_index, server_pub) is False

        tampered_hash = VoterReceipt.from_dict({**receipt.to_dict(), "block_hash": "0" * 64})
        assert verify_receipt(tampered_hash, server_pub) is False

        tampered_voter = VoterReceipt.from_dict({**receipt.to_dict(), "voter_id": "attacker"})
        assert verify_receipt(tampered_voter, server_pub) is False

    def test_verify_receipt_fails_with_wrong_public_key(self, server_keypair):
        """Receipt signed by one server must fail verification with another key."""
        server_priv, _ = server_keypair
        other_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

        board = AppendOnlyBulletinBoard()
        block = board.append_ballot("voter_004", {"Alice": {"c1": 70, "c2": 80}}, b"sig4")
        receipt = issue_voter_receipt(block, server_priv)

        assert verify_receipt(receipt, other_pub) is False

    def test_verify_receipt_fails_on_corrupted_or_invalid_hex_signature(self, server_keypair):
        """Corrupted signature bytes or non-hex signature strings must return False."""
        server_priv, server_pub = server_keypair
        board = AppendOnlyBulletinBoard()
        block = board.append_ballot("voter_005", {"Alice": {"c1": 90, "c2": 100}}, b"sig5")
        receipt = issue_voter_receipt(block, server_priv)

        # Flip first hex nibble (valid hex, invalid RSA-PSS signature)
        first_char = "0" if receipt.server_signature_hex[0] != "0" else "1"
        corrupted_sig = first_char + receipt.server_signature_hex[1:]
        corrupted_receipt = VoterReceipt.from_dict(
            {**receipt.to_dict(), "server_signature_hex": corrupted_sig}
        )
        assert verify_receipt(corrupted_receipt, server_pub) is False

        # Non-hex string (triggers ValueError handling)
        malformed_receipt = VoterReceipt.from_dict(
            {**receipt.to_dict(), "server_signature_hex": "NOT_VALID_HEX"}
        )
        assert verify_receipt(malformed_receipt, server_pub) is False
