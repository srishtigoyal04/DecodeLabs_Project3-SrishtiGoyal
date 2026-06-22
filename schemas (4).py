# =============================================================================
# schemas.py
# =============================================================================
# PURPOSE:
#   Pydantic models (schemas) that define the shape of:
#     - Incoming HTTP request bodies (validated automatically by FastAPI)
#     - Outgoing HTTP response bodies (serialised automatically by FastAPI)
#
# PYDANTIC vs SQLALCHEMY — WHY BOTH?
#   ┌────────────────────────┬───────────────────────────────────────────────┐
#   │ SQLAlchemy (models.py) │ Talks to the DATABASE                         │
#   │                        │ Represents a row in a table                   │
#   │                        │ Has `hashed_password`, `created_at`, etc.     │
#   ├────────────────────────┼───────────────────────────────────────────────┤
#   │ Pydantic (schemas.py)  │ Talks to the CLIENT (HTTP)                    │
#   │                        │ Validates what comes in / shapes what goes out │
#   │                        │ NEVER exposes `hashed_password` to clients    │
#   └────────────────────────┴───────────────────────────────────────────────┘
#
# SECURITY PRINCIPLE:
#   The `UserResponse` schema deliberately omits `hashed_password`.
#   Even if a developer accidentally tries to return the full ORM object,
#   FastAPI's response_model will strip fields not in the schema.
# =============================================================================

from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime


# =============================================================================
# REGISTRATION SCHEMA — POST /register
# =============================================================================
class UserRegister(BaseModel):
    """
    Validates the request body for user registration.

    Rules enforced automatically before the route handler runs:
    - username: 3–50 chars, alphanumeric + underscores only
    - email: must be a valid email format
    - password: minimum 8 characters
    """

    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique username (letters, numbers, underscores)",
        examples=["john_doe"]
    )

    email: EmailStr = Field(
        ...,
        description="Valid, unique email address",
        examples=["john@example.com"]
    )

    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (minimum 8 characters)",
        examples=["securepass123"]
    )

    # Custom validator: enforce username character restrictions
    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, value: str) -> str:
        """Username can only contain letters, digits, and underscores."""
        import re
        if not re.match(r"^[a-zA-Z0-9_]+$", value):
            raise ValueError(
                "Username may only contain letters, numbers, and underscores."
            )
        return value.lower()   # Normalise to lowercase for consistency

    # Custom validator: strip whitespace from email
    @field_validator("email")
    @classmethod
    def email_lowercase(cls, value: str) -> str:
        """Normalise email to lowercase."""
        return value.lower().strip()

    # Custom validator: basic password strength
    @field_validator("password")
    @classmethod
    def password_not_whitespace(cls, value: str) -> str:
        """Password must not be blank or all whitespace."""
        if value.strip() == "":
            raise ValueError("Password cannot be blank.")
        return value


# =============================================================================
# LOGIN SCHEMA — POST /login
# =============================================================================
class UserLogin(BaseModel):
    """
    Validates the request body for user login.
    Only email and password are needed — username is not required.
    """

    email: EmailStr = Field(
        ...,
        description="Registered email address",
        examples=["john@example.com"]
    )

    password: str = Field(
        ...,
        min_length=1,          # Minimum 1 so we get a clear "required" error
        description="Account password",
        examples=["securepass123"]
    )

    @field_validator("email")
    @classmethod
    def email_lowercase(cls, value: str) -> str:
        return value.lower().strip()


# =============================================================================
# USER RESPONSE SCHEMA — returned for /profile and registration
# =============================================================================
class UserResponse(BaseModel):
    """
    Safe user representation returned to clients.

    SECURITY: Does NOT include hashed_password or any internal DB fields.
    FastAPI's `response_model=UserResponse` automatically strips any extra
    fields before sending the response.
    """

    id: int
    username: str
    email: str
    created_at: Optional[datetime] = None

    # `from_attributes=True` allows Pydantic to read values from SQLAlchemy
    # ORM objects (which use attribute access, not dict access).
    model_config = {"from_attributes": True}


# =============================================================================
# TOKEN SCHEMAS — returned after successful login
# =============================================================================
class Token(BaseModel):
    """
    JWT token response returned after successful login.

    access_token: The signed JWT string the client must include in future requests.
    token_type:   Always "bearer" — this tells clients how to send the token:
                  `Authorization: Bearer <access_token>`
    """
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """
    Data extracted from a decoded JWT payload.
    Used internally by `auth.py` to carry user identity after token validation.
    """
    user_id: Optional[int] = None
    email: Optional[str] = None


# =============================================================================
# GENERIC RESPONSE SCHEMAS
# =============================================================================
class MessageResponse(BaseModel):
    """Simple message-only response (e.g., registration success)."""
    message: str


class ErrorResponse(BaseModel):
    """Consistent error response envelope."""
    success: bool = False
    message: str
    detail: Optional[str] = None
