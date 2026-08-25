"""Declarative base and shared model conventions for SentinelGPT."""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Deterministic constraint naming keeps Alembic autogenerate diffs stable and
# makes downgrades referenceable (SRS Chapter 4, Section 14).
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all SentinelGPT persistence models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
