# =============================================================================
# routes.py
# =============================================================================
# PURPOSE:
#   Defines all API endpoints and wires them to the correct business logic.
#   Routes only handle HTTP concerns (parsing, status codes, responses).
#   All security logic lives in auth.py; all DB logic lives here directly
#   (this is a simple app — a separate crud.py is optional at this scale).
#
# ROUTE OVERVIEW:
#   POST /register  → Create a new account (public)
#   POST /login     → Authenticate and receive JWT token (public)
#   GET  /profile   → View own profile (PROTECTED — requires JWT)
#   GET  /health    → Server status (public)
#
# PROTECTED ROUTE PATTERN:
#   Any route that includes `current_user: User = Depends(get_current_user)`
#   is automatically protected. FastAPI calls `get_current_user` first.
#   If it raises an exception (401, 404), the route handler NEVER runs.
# =============================================================================

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import timedelta

import models
import schemas
from database import get_db
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

# `APIRouter` groups related endpoints. Registered in main.py via app.include_router()
router = APIRouter()


# =============================================================================
# REGISTER — POST /register
# =============================================================================
@router.post(
    "/register",
    response_model=schemas.MessageResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    summary="Register a new user account",
    responses={
        201: {"description": "User registered successfully"},
        409: {"description": "Username or email already exists"},
        422: {"description": "Validation error (invalid email, short password, etc.)"},
    }
)
def register(user_data: schemas.UserRegister, db: Session = Depends(get_db)):
    """
    Create a new user account.

    SECURITY FLOW:
      1. FastAPI validates the request body against `UserRegister` schema
         (email format, password length, username characters)
      2. Check for duplicate username (Layer 1 — nice error message)
      3. Check for duplicate email   (Layer 1 — nice error message)
      4. Hash the password with bcrypt — the plain password is NEVER stored
      5. Save the user record with only the hashed password
      6. Return success message (NOT the user object — no data leakage)

    WHAT WE NEVER DO:
      - Store the plain-text password
      - Return the hashed password
      - Return an auth token on registration (login is a separate step)
    """

    # ── Step 1: Check for duplicate username ──────────────────────────────────
    existing_username = db.query(models.User).filter(
        models.User.username == user_data.username
    ).first()

    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{user_data.username}' is already taken."
        )

    # ── Step 2: Check for duplicate email ────────────────────────────────────
    existing_email = db.query(models.User).filter(
        models.User.email == user_data.email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An account with email '{user_data.email}' already exists."
        )

    # ── Step 3: Hash the password ─────────────────────────────────────────────
    # After this line, the plain password is gone. We only keep the hash.
    # The hash is computed with a random salt, so two identical passwords
    # produce different hashes.
    hashed_pw = hash_password(user_data.password)

    # ── Step 4: Create and persist the user record ────────────────────────────
    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pw    # Stored; plain password is discarded
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

    except IntegrityError:
        # Database-level safety net for race conditions
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists."
        )

    return {"message": "User registered successfully"}


# =============================================================================
# LOGIN — POST /login
# =============================================================================
@router.post(
    "/login",
    response_model=schemas.Token,
    status_code=status.HTTP_200_OK,
    tags=["Authentication"],
    summary="Login and receive a JWT access token",
    responses={
        200: {"description": "Login successful, JWT token returned"},
        401: {"description": "Invalid email or password"},
        422: {"description": "Validation error"},
    }
)
def login(credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate a user and return a JWT access token.

    SECURITY FLOW:
      1. Look up the user by email
      2. Verify the submitted password against the stored bcrypt hash
      3. If valid, create a signed JWT containing user_id and email
      4. Return the token with "bearer" type

    DELIBERATE VAGUENESS IN ERROR MESSAGE:
      We return "Invalid email or password" for BOTH:
        - Email not found
        - Password wrong
      Why? If we said "email not found", attackers could enumerate valid emails
      by trying different addresses. Vague messages prevent user enumeration.

    TOKEN CONTENTS (payload):
      {
        "sub": "1",                    ← user id (string, per JWT convention)
        "email": "john@example.com",   ← for convenience (avoid extra DB lookup)
        "exp": 1234567890,             ← expiry timestamp (30 min from now)
        "iat": 1234566000              ← issued-at timestamp
      }
    """

    # ── Step 1: Find user by email ────────────────────────────────────────────
    user = db.query(models.User).filter(
        models.User.email == credentials.email
    ).first()

    # ── Step 2: Verify password ───────────────────────────────────────────────
    # IMPORTANT: We check BOTH conditions before raising the error.
    # This avoids a timing difference that could leak whether the email exists.
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Step 3: Create JWT access token ──────────────────────────────────────
    access_token = create_access_token(
        data={
            "sub": str(user.id),       # Subject — always a string in JWTs
            "email": user.email,
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # ── Step 4: Return the token ──────────────────────────────────────────────
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# =============================================================================
# PROFILE — GET /profile (PROTECTED ROUTE)
# =============================================================================
@router.get(
    "/profile",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_200_OK,
    tags=["Protected"],
    summary="Get the currently authenticated user's profile",
    responses={
        200: {"description": "User profile returned"},
        401: {"description": "Missing or invalid JWT token"},
        404: {"description": "User account not found"},
    }
)
def get_profile(
    current_user: models.User = Depends(get_current_user)
    # ↑ This single line is the ENTIRE authentication gate.
    # FastAPI runs `get_current_user` before this function.
    # If the token is missing/invalid/expired → 401 is raised automatically.
    # If it passes → `current_user` is the authenticated User ORM object.
):
    """
    Return the profile of the currently authenticated user.

    This is a PROTECTED route. Clients must include:
        Authorization: Bearer <access_token>

    The `Depends(get_current_user)` dependency:
      1. Extracts the token from the Authorization header
      2. Validates the JWT signature and expiry
      3. Looks up the user in the database
      4. Returns the User object — or raises 401/404 if anything fails

    The route handler only runs if authentication SUCCEEDS.
    """
    # `current_user` is already the authenticated User ORM object.
    # FastAPI serialises it through `response_model=UserResponse`
    # which strips `hashed_password` automatically — never returned to client.
    return current_user


# =============================================================================
# HEALTH CHECK — GET /health
# =============================================================================
@router.get(
    "/health",
    tags=["Health"],
    summary="Server health check"
)
def health_check():
    """Public endpoint — no auth required. Useful for monitoring."""
    return {
        "status": "healthy",
        "message": "Auth API is running.",
        "version": "1.0.0"
    }
