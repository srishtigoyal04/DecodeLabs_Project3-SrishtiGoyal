# =============================================================================
# models.py
# =============================================================================
# PURPOSE:
#   Defines the SQLAlchemy ORM model for the `users` table.
#   Each Python class attribute decorated with `Column` maps to a DB column.
#
# KEY DESIGN DECISIONS:
#   - `hashed_password` (NOT `password`) → we NEVER store plain-text passwords
#   - `created_at` with `server_default` → the DB sets the timestamp automatically
#   - `unique=True` on username AND email → enforced at DB level as a safety net
#
# ORM IN ONE SENTENCE:
#   Write Python classes → SQLAlchemy generates the SQL → Database stores data.
#   You never write INSERT/SELECT/UPDATE/DELETE manually.
# =============================================================================

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from database import Base


class User(Base):
    """
    ORM model for the `users` table.

    Maps directly to a database table row. Each instance of this class
    represents one user record.
    """

    # -------------------------------------------------------------------------
    # TABLE NAME
    # -------------------------------------------------------------------------
    __tablename__ = "users"

    # -------------------------------------------------------------------------
    # COLUMNS
    # -------------------------------------------------------------------------

    # PRIMARY KEY — auto-incrementing integer, indexed automatically
    id = Column(Integer, primary_key=True, index=True)

    # USERNAME — must be unique across all users
    # `index=True` creates a B-tree index for fast lookups
    username = Column(String(50), unique=True, nullable=False, index=True)

    # EMAIL — must be unique; used for login
    email = Column(String(255), unique=True, nullable=False, index=True)

    # HASHED PASSWORD
    # ─────────────────────────────────────────────────────────────────────────
    # CRITICAL SECURITY RULE: Never store plain-text passwords.
    #
    # We store the bcrypt hash of the password (a 60-character string).
    # Even if the database is stolen, the attacker cannot recover passwords.
    #
    # The column is named `hashed_password` (not `password`) as a constant
    # reminder that this is a hash, not the original value.
    # ─────────────────────────────────────────────────────────────────────────
    hashed_password = Column(String(255), nullable=False)

    # CREATED AT — automatically set to the current UTC timestamp on insert
    # `server_default=func.now()` tells the DATABASE to set this value,
    # so it's always accurate even if the app server clock is wrong.
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        """Human-readable representation for debugging."""
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"
