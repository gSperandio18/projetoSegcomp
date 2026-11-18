"""Module 4 Test Suite: Append-Only Bulletin Board & Voter Receipts.

Covers non-cryptographic ledger storage, block models, receipt DTOs, and provides
TDD test specifications for hash-chain continuity and coercion-resistant receipts.
Assigned to: Integrante 4 (Dev D)
"""

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


class TestBulletinBoardCryptoStubs:
    """Educational verification: stubs raise NotImplementedError with helpful guidance."""

    def test_compute_block_hash_stub(self):
        with pytest.raises(NotImplementedError) as exc_info:
            compute_block_hash("prev", 1, "v1", {"a": 1}, "sig", "time")
        assert "TODO (Module 4 - Dev D)" in str(exc_info.value)

    def test_verify_chain_integrity_stub(self):
        board = AppendOnlyBulletinBoard()
        with pytest.raises(NotImplementedError) as exc_info:
            board.verify_chain_integrity()
        assert "TODO (Module 4 - Dev D)" in str(exc_info.value)

    def test_issue_voter_receipt_stub(self):
        block = BulletinBlock(1, "p", "h", "v", {}, "s", "t")
        mock_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(NotImplementedError) as exc_info:
            issue_voter_receipt(block, mock_key)
        assert "TODO (Module 4 - Dev D)" in str(exc_info.value)

    def test_verify_receipt_stub(self):
        receipt = VoterReceipt("r1", 1, "v1", "h", "s", "t")
        mock_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(NotImplementedError) as exc_info:
            verify_receipt(receipt, mock_key.public_key())
        assert "TODO (Module 4 - Dev D)" in str(exc_info.value)


# ==============================================================================
# TDD Test Templates for Integrante 4 (Dev D) to activate after implementation:
# ==============================================================================
# def test_tamper_detection_in_chain():
#     board = AppendOnlyBulletinBoard()
#     board.append_ballot("v1", {"Alice": {"c1": 1, "c2": 2}}, b"sig1")
#     assert board.verify_chain_integrity() is True
#     # Tamper with Block 1
#     board.chain[1].ballot_data["Alice"]["c1"] = 999999
#     assert board.verify_chain_integrity() is False
