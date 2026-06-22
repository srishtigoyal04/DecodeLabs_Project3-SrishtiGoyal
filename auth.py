# =============================================================================
# auth.py
# =============================================================================
# PURPOSE:
#   The security engine of the entire application. All cryptographic
#   operations live here:
#     1. Password hashing (bcrypt via Passlib)
#     2. Password verification
#     3. JWT token creation (python-jose)
#     4. JWT token validation & decoding
#     5. `get_current_user` dependency — the "authentication gate" for all
#        protected routes
#
# ─────────────────────────────────────────────────────────────────────────────
# SECURITY CONCEPTS EXPLAINED
# ─────────────────────────────────────────────────────────────────────────────
#
# 1. HASHING vs ENCRYPTION
# ─────────────────────────────────────────────────────────────────────────────
#   Encryption:  Two-way. You can decrypt the ciphertext back to plaintext
#                if you have the key. Used for data in transit (HTTPS).
#
#   Hashing:     One-way. Once hashed, you CANNOT reverse it back to the
#                original. There is no "unhash" operation.
#                Used for passwords — even we as developers cannot see passwords.
#
#   Example:
#     hash("password123") → "$2b$12$eImiTXuWVxfM37uY4..." (bcrypt hash)
#     There is NO function to go from that hash back to "password123".
#
# 2. WHY BCRYPT?
# ─────────────────────────────────────────────────────────────────────────────
#   bcrypt is slow BY DESIGN. It uses a "work factor" (cost parameter, default=12)
#   that makes each hash take ~100ms on modern hardware.
#
#   Why slow is GOOD for passwords:
#     - User feels nothing (100ms is imperceptible for one login)
#     - Attacker trying to crack 1 billion passwords would take 3 years
#     - Work factor can be increased as hardware gets faster (future-proof)
#
#   bcrypt also includes a random "salt" in every hash:
#     hash("password123") → "$2b$12$ABCrandomsalt...actualHash"
#     hash("password123") → "$2b$12$XYZdifferentsalt...differentHash"
#   Same input → DIFFERENT outputs. This defeats rainbow table attacks.
#
# 3. HOW JWT WORKS
# ─────────────────────────────────────────────────────────────────────────────
#   JWT = JSON Web Token. A compact, self-contained token with 3 parts:
#
#   HEADER.PAYLOAD.SIGNATURE
#      │        │        └── HMAC-SHA256 of header+payload using SECRET_KEY
#      │        └── JSON: { "user_id": 1, "email": "j@x.com", "exp": 1234567890 }
#      └── JSON: { "alg": "HS256", "typ": "JWT" }
#
#   Each part is Base64URL-encoded and joined with dots.
#
#   VERIFICATION:
#     Server recomputes the signature from header+payload+SECRET_KEY.
#     If it matches the signature in the token → token is authentic.
#     If someone altered the payload → signature won't match → rejected.
#
#   STATELESS:
#     No database lookup needed to verify a JWT. The server just checks
#     the signature. This is why JWTs scale well.
#
# 4. AUTHENTICATION vs AUTHORIZATION
# ─────────────────────────────────────────────────────────────────────────────
#   Authentication: "Who are you?" → Verify identity via JWT
#   Authorization:  "What can you do?" → Check permissions/roles
#   This app implements authentication. Authorization would be:
#   "Is this user an admin? Can they access this specific resource?"
# =============================================================================

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================
# ─────────────────────────────────────────────────────────────────────────────
# SECRET KEY
# ─────────────────────────────────────────────────────────────────────────────
# This key is used to SIGN JWT tokens. It must be:
#   1. Long (at least 32 characters for HS256)
#   2. Random (use: openssl rand -hex 32)
#   3. SECRET — never commit to git, never expose in logs
#
# In production: load from environment variable
#   import os
#   SECRET_KEY = os.environ.get("SECRET_KEY")
#   if not SECRET_KEY:
#       raise RuntimeError("SECRET_KEY environment variable not set")
#
# FOR LEARNING: hardcoded here. NEVER do this in production.
# ─────────────────────────────────────────────────────────────────────────────
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

# Algorithm used to sign the JWT
# HS256 = HMAC with SHA-256 — fast, symmetric (same key to sign & verify)
ALGORITHM = "HS256"

# How long until the access token expires
# 30 minutes is a common default — short enough to limit damage if stolen,
# long enough to be usable. Production apps also use refresh tokens.
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# =============================================================================
# PASSWORD HASHING — using Passlib + bcrypt
# =============================================================================
# `CryptContext` creates a hashing manager that supports multiple schemes.
# `schemes=["bcrypt"]` tells it to use the bcrypt algorithm.
# `deprecated="auto"` means if we add a new scheme later, old hashes are
# automatically re-hashed on next login (seamless security upgrades).
# =============================================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using bcrypt.

    WHAT HAPPENS INTERNALLY:
      1. A random 22-character salt is generated
      2. The password + salt are processed through the bcrypt algorithm
         with 12 rounds of hashing (2^12 = 4096 iterations)
      3. Returns a string like:
         "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
         └──┘└──┘└──────────────────────────────────────────────────────┘
         alg cost        salt (22) + hash (31)

    Args:
        plain_password: The raw password from the registration form

    Returns:
        A bcrypt hash string (always ~60 characters)
    """
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.

    HOW IT WORKS:
      bcrypt extracts the salt from the stored hash string, re-hashes the
      input password with that SAME salt, then compares the two hashes.
      If they match → password is correct.

      You cannot "reverse" a hash. Verification always requires re-hashing.

    Args:
        plain_password:  What the user typed in the login form
        hashed_password: What's stored in the database

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


# =============================================================================
# JWT TOKEN CREATION
# =============================================================================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT access token containing the given payload data.

    TOKEN STRUCTURE:
      The final token looks like (broken into parts for clarity):
        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9    ← Header (alg + type)
        .
        eyJzdWIiOiIxIiwiZW1haWwiOi...            ← Payload (user data + exp)
        .
        SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature

    PAYLOAD FIELDS:
      "sub"  (subject)  → user id as string (JWT convention for subject)
      "email"           → user's email
      "exp"  (expiry)   → Unix timestamp when token expires
      "iat"  (issued at)→ Unix timestamp when token was created

    Args:
        data:          Dict with user data to embed in the token
        expires_delta: How long until the token expires (default: 30 min)

    Returns:
        Encoded JWT string (what the client stores and sends back)
    """
    to_encode = data.copy()

    # Set expiration time
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Add standard JWT claims
    to_encode.update({
        "exp": expire,                              # Expiry (auto-validated by jose)
        "iat": datetime.now(timezone.utc),          # Issued at
    })

    # Sign and encode the token
    # jwt.encode() = Base64URL(header) + "." + Base64URL(payload) + "." + HMAC_SHA256(header+payload, SECRET_KEY)
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# =============================================================================
# JWT TOKEN VALIDATION
# =============================================================================
def decode_access_token(token: str) -> schemas.TokenData:
    """
    Decode and validate a JWT token.

    VALIDATION STEPS (all done by python-jose automatically):
      1. Check the signature is valid (not tampered with)
      2. Check the token has not expired (`exp` claim)
      3. Check the algorithm matches (HS256)

    If any check fails → JWTError is raised → we return 401 Unauthorized.

    Args:
        token: The raw JWT string from the Authorization header

    Returns:
        TokenData with user_id and email extracted from payload

    Raises:
        HTTPException 401: If token is invalid, expired, or tampered with
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},    # RFC standard header
    )

    try:
        # Decode and verify the token in one step
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Extract user identity from payload
        user_id: str = payload.get("sub")      # "sub" is the standard JWT subject claim
        email: str = payload.get("email")

        if user_id is None or email is None:
            raise credentials_exception

        return schemas.TokenData(user_id=int(user_id), email=email)

    except JWTError:
        # Covers: invalid signature, expired token, malformed token
        raise credentials_exception


# =============================================================================
# HTTP BEARER SECURITY SCHEME
# =============================================================================
# Tells FastAPI (and Swagger UI) that protected endpoints expect:
#   Authorization: Bearer <token>
#
# `auto_error=False` means we handle the error ourselves (better error messages)
# =============================================================================
bearer_scheme = HTTPBearer(auto_error=False)


# =============================================================================
# AUTHENTICATION DEPENDENCY — the "guard" for protected routes
# =============================================================================
def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    """
    FastAPI dependency that protects routes.

    HOW IT WORKS:
      1. FastAPI extracts the `Authorization: Bearer <token>` header
      2. `bearer_scheme` parses it into `credentials.credentials` (the raw token)
      3. We validate the JWT token → extract user_id and email
      4. We look up the user in the database to confirm they still exist
      5. We return the full User ORM object to the route handler

    Usage in a route:
        @app.get("/profile")
        def profile(current_user: User = Depends(get_current_user)):
            return current_user   # Only reaches here if token is valid

    If authentication fails at any step → 401 Unauthorized is raised
    automatically, and the route handler is NEVER called.

    Args:
        credentials: HTTP Bearer token credentials from the request header
        db:          Database session (from get_db dependency)

    Returns:
        User ORM object for the authenticated user

    Raises:
        HTTPException 401: Missing, invalid, expired, or revoked token
        HTTPException 404: Token valid but user no longer exists in DB
    """
    # Step 1: Check that the Authorization header was actually provided
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Step 2: Validate and decode the JWT
    token_data = decode_access_token(credentials.credentials)

    # Step 3: Confirm the user still exists in the database
    # (Important: a valid token could belong to a deleted account)
    user = db.query(models.User).filter(
        models.User.id == token_data.user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found. The account may have been deleted.",
        )

    # Step 4: Return the authenticated user to the route handler
    return user
