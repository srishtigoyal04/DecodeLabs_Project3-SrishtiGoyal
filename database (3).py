# =============================================================================
# database.py
# =============================================================================
# PURPOSE:
#   The database configuration layer. This single file owns:
#     1. The database URL (where is the database?)
#     2. The SQLAlchemy Engine (how do we connect?)
#     3. The SessionLocal factory (how do we create a session per request?)
#     4. The Base class (parent for all ORM table models)
#     5. The `get_db` dependency (how does FastAPI inject sessions into routes?)
#
# WHY KEEP THIS SEPARATE?
#   Every other module (models, auth, routes) imports from here.
#   If you ever switch from SQLite to PostgreSQL, you change only this file.
#   Nothing else needs to know about the database driver.
# =============================================================================

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# -----------------------------------------------------------------------------
# DATABASE URL
# -----------------------------------------------------------------------------
# `sqlite:///./auth.db` means:
#   - Driver:  sqlite
#   - Path:    ./auth.db  (relative to where you run the server)
#   - A file called `auth.db` will be created automatically on first run.
#
# For PostgreSQL you would use:
#   "postgresql://user:password@localhost:5432/dbname"
# -----------------------------------------------------------------------------
DATABASE_URL = "sqlite:///./auth.db"

# -----------------------------------------------------------------------------
# ENGINE
# -----------------------------------------------------------------------------
# The engine is the low-level connection to the database.
# SQLAlchemy uses it to send SQL statements and manage connection pooling.
#
# `check_same_thread=False` is required for SQLite only.
#   - SQLite normally restricts access to the thread that created the connection.
#   - FastAPI handles requests across multiple threads, so we disable this check.
#   - SQLAlchemy's own session management keeps things thread-safe.
# -----------------------------------------------------------------------------
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# -----------------------------------------------------------------------------
# SESSION FACTORY
# -----------------------------------------------------------------------------
# `SessionLocal` is a class. Each call to `SessionLocal()` returns a new
# database session — an independent "unit of work" for one HTTP request.
#
# autocommit=False → We call db.commit() manually (safer, allows rollbacks)
# autoflush=False  → We control exactly when SQL is sent to the DB
# bind=engine      → Every session created by this factory uses our engine
# -----------------------------------------------------------------------------
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# -----------------------------------------------------------------------------
# DECLARATIVE BASE
# -----------------------------------------------------------------------------
# All ORM model classes inherit from `Base`. When `create_all()` is called
# in main.py, SQLAlchemy reads every subclass of Base and generates the
# corresponding CREATE TABLE statements automatically.
# -----------------------------------------------------------------------------
Base = declarative_base()


# -----------------------------------------------------------------------------
# DEPENDENCY: get_db
# -----------------------------------------------------------------------------
# This generator is used with FastAPI's `Depends(get_db)` system.
#
# FLOW:
#   1. FastAPI calls get_db() before the route handler runs.
#   2. A new session is created and yielded to the route handler as `db`.
#   3. The route handler does its database work using `db`.
#   4. After the route finishes (success OR exception), the `finally` block
#      runs and closes the session, releasing the connection back to the pool.
#
# This pattern guarantees:
#   - Every request gets a fresh, isolated session.
#   - Sessions are ALWAYS closed — no connection leaks.
#   - No manual session management in route handlers.
# -----------------------------------------------------------------------------
def get_db():
    """
    FastAPI dependency: yields a database session, then closes it.
    Use with: `db: Session = Depends(get_db)`
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
