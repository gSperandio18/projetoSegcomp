"""Storage & Database Layer for Secure E-Voting System.

Implements SQLAlchemy 2.0 ORM models, session management, and persistence helpers
for voters, authorities, immutable bulletin board blocks, receipts, and tallies.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from typing import Any, Dict, Generator, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from evoting.config.params import DEFAULT_DATABASE_PATH


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""


class ElectionMetaModel(Base):
    """Stores high-level election configuration and status."""

    __tablename__ = "election_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    election_id = Column(String(64), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    joint_public_key_h = Column(Text, nullable=False)
    modulus_p = Column(Text, nullable=False)
    generator_g = Column(Integer, nullable=False)
    status = Column(String(32), default="CREATED")  # CREATED, VOTING, TALLYING, CLOSED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class VoterModel(Base):
    """Persists registered voter identities and public credentials."""

    __tablename__ = "voters"

    id = Column(Integer, primary_key=True, autoincrement=True)
    voter_id = Column(String(128), unique=True, nullable=False, index=True)
    rsa_public_key_pem = Column(Text, nullable=False)
    has_voted = Column(Boolean, default=False, nullable=False)
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuthorityModel(Base):
    """Persists election authorities and their public key shares."""

    __tablename__ = "authorities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    authority_id = Column(Integer, unique=True, nullable=False)
    name = Column(String(128), nullable=False)
    public_key_h = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class BulletinBlockModel(Base):
    """Persists append-only blocks of the public bulletin board ledger."""

    __tablename__ = "bulletin_board"

    index = Column(Integer, primary_key=True, autoincrement=False)
    previous_hash = Column(String(64), nullable=False)
    block_hash = Column(String(64), nullable=False, unique=True)
    voter_id = Column(String(128), nullable=False)
    ballot_payload_json = Column(Text, nullable=False)
    voter_signature_hex = Column(Text, nullable=False)
    timestamp = Column(String(64), nullable=False)


class ReceiptModel(Base):
    """Persists receipts issued to voters confirming bulletin board inclusion."""

    __tablename__ = "receipts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    receipt_id = Column(String(64), unique=True, nullable=False)
    block_index = Column(Integer, nullable=False)
    voter_id = Column(String(128), nullable=False)
    block_hash = Column(String(64), nullable=False)
    server_signature_hex = Column(Text, nullable=False)
    issued_at = Column(String(64), nullable=False)


class TallyResultModel(Base):
    """Persists final decrypted election results per candidate."""

    __tablename__ = "tally_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    candidate = Column(String(128), unique=True, nullable=False)
    c1_product = Column(Text, nullable=False)
    c2_product = Column(Text, nullable=False)
    total_votes = Column(Integer, nullable=False)
    tallied_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def get_engine(db_path: str = DEFAULT_DATABASE_PATH):
    """Create and return a SQLAlchemy database engine."""
    connection_url = f"sqlite:///{db_path}"
    return create_engine(connection_url, echo=False)


def get_session_factory(engine=None, db_path: str = DEFAULT_DATABASE_PATH):
    """Create and return a sessionmaker bound to the engine."""
    if engine is None:
        engine = get_engine(db_path)
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def get_db_session(
    db_path: str = DEFAULT_DATABASE_PATH,
) -> Generator[Session, None, None]:
    """Context manager for database transactional sessions."""
    engine = get_engine(db_path)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session: Session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(db_path: str = DEFAULT_DATABASE_PATH) -> None:
    """Initialize database schema, creating all tables if not present."""
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)


def drop_db(db_path: str = DEFAULT_DATABASE_PATH) -> None:
    """Drop all tables in the database (for testing cleanup)."""
    engine = get_engine(db_path)
    Base.metadata.drop_all(engine)


# CRUD Helper Functions
def save_voter(session: Session, voter_id: str, public_key_pem: str) -> VoterModel:
    """Register a new voter in the database."""
    voter = VoterModel(voter_id=voter_id, rsa_public_key_pem=public_key_pem, has_voted=False)
    session.add(voter)
    return voter


def get_voter(session: Session, voter_id: str) -> Optional[VoterModel]:
    """Retrieve voter model by voter_id."""
    return session.query(VoterModel).filter_by(voter_id=voter_id).first()


def mark_voter_voted(session: Session, voter_id: str) -> bool:
    """Mark a voter as having cast their ballot."""
    voter = get_voter(session, voter_id)
    if voter:
        voter.has_voted = True
        return True
    return False


def save_authority(
    session: Session, authority_id: int, name: str, public_key_h: str
) -> AuthorityModel:
    """Save an election authority metadata record."""
    auth = AuthorityModel(authority_id=authority_id, name=name, public_key_h=public_key_h)
    session.add(auth)
    return auth


def get_authorities(session: Session) -> List[AuthorityModel]:
    """Retrieve all registered authorities."""
    return session.query(AuthorityModel).order_by(AuthorityModel.authority_id).all()


def save_bulletin_block(
    session: Session,
    index: int,
    previous_hash: str,
    block_hash: str,
    voter_id: str,
    ballot_payload: Dict[str, Any],
    voter_signature_hex: str,
    timestamp: str,
) -> BulletinBlockModel:
    """Append a verified ballot block to the bulletin board database."""
    block = BulletinBlockModel(
        index=index,
        previous_hash=previous_hash,
        block_hash=block_hash,
        voter_id=voter_id,
        ballot_payload_json=json.dumps(ballot_payload, sort_keys=True),
        voter_signature_hex=voter_signature_hex,
        timestamp=timestamp,
    )
    session.add(block)
    return block


def get_all_blocks(session: Session) -> List[BulletinBlockModel]:
    """Retrieve all bulletin board blocks ordered by index."""
    return session.query(BulletinBlockModel).order_by(BulletinBlockModel.index).all()


__all__ = [
    "Base",
    "ElectionMetaModel",
    "VoterModel",
    "AuthorityModel",
    "BulletinBlockModel",
    "ReceiptModel",
    "TallyResultModel",
    "get_engine",
    "get_session_factory",
    "get_db_session",
    "init_db",
    "drop_db",
    "save_voter",
    "get_voter",
    "mark_voter_voted",
    "save_authority",
    "get_authorities",
    "save_bulletin_block",
    "get_all_blocks",
]
