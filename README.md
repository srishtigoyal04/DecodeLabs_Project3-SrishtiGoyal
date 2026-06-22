# Secure Authentication API

A production-quality JWT authentication backend built with **FastAPI**, **SQLAlchemy ORM**, **bcrypt**, and **python-jose**.

---

## Project Structure

```
auth-api/
├── main.py                  # App entry point — creates FastAPI instance, registers routes
├── database.py              # DB engine, session factory, Base class, get_db dependency
├── models.py                # SQLAlchemy ORM User model (users table)
├── schemas.py               # Pydantic schemas: validation + response shaping
├── auth.py                  # bcrypt hashing, JWT creation/validation, auth dependency
├── routes.py                # All API route handlers (register, login, profile)
├── requirements.txt         # Pinned Python dependencies
├── postman_collection.json  # 10 ready-to-import Postman test requests
└── README.md
```

---

## Setup & Run

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate        # macOS/Linux
.\venv\Scripts\Activate.ps1     # Windows PowerShell

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
uvicorn main:app --reload

# Server is running at http://127.0.0.1:8000
# Swagger UI: http://127.0.0.1:8000/docs
```

---

## API Endpoints

| Method | Path | Auth Required | Description |
|---|---|---|---|
| GET | `/` | No | API overview |
| GET | `/health` | No | Health check |
| POST | `/register` | No | Create account |
| POST | `/login` | No | Login, get JWT |
| GET | `/profile` | **YES** | View own profile |

---

## JWT Authentication Flow

```
┌──────────┐                    ┌─────────────┐                  ┌──────────┐
│  Client  │                    │  FastAPI     │                  │  SQLite  │
└────┬─────┘                    └──────┬───────┘                  └────┬─────┘
     │                                 │                               │
     │  POST /register                 │                               │
     │  {username, email, password}    │                               │
     │────────────────────────────────▶│                               │
     │                                 │  hash(password) → bcrypt_hash │
     │                                 │  INSERT user (bcrypt_hash)   │
     │                                 │──────────────────────────────▶│
     │  201 {message: "registered"}    │                               │
     │◀────────────────────────────────│                               │
     │                                 │                               │
     │  POST /login {email, password}  │                               │
     │────────────────────────────────▶│                               │
     │                                 │  SELECT user WHERE email=...  │
     │                                 │──────────────────────────────▶│
     │                                 │◀──────────────────────────────│
     │                                 │  bcrypt.verify(pw, hash) ✓   │
     │                                 │  jwt.sign({id, email}, secret)│
     │  200 {access_token: "eyJ..."}   │                               │
     │◀────────────────────────────────│                               │
     │                                 │                               │
     │  GET /profile                   │                               │
     │  Authorization: Bearer eyJ...   │                               │
     │────────────────────────────────▶│                               │
     │                                 │  jwt.verify(token, secret) ✓  │
     │                                 │  SELECT user WHERE id=...     │
     │                                 │──────────────────────────────▶│
     │                                 │◀──────────────────────────────│
     │  200 {id, username, email}      │                               │
     │◀────────────────────────────────│                               │
```

---

## Example Requests & Responses

### POST /register

**Request:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepass123"
}
```

**Response 201:**
```json
{ "message": "User registered successfully" }
```

**Response 409 (duplicate):**
```json
{ "detail": "Username 'john_doe' is already taken." }
```

**Response 422 (validation):**
```json
{
  "success": false,
  "message": "Validation failed. Please check your input.",
  "errors": [
    { "loc": ["body", "password"], "msg": "String should have at least 8 characters" }
  ]
}
```

---

### POST /login

**Request:**
```json
{ "email": "john@example.com", "password": "securepass123" }
```

**Response 200:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIi...",
  "token_type": "bearer"
}
```

**Response 401:**
```json
{ "detail": "Invalid email or password." }
```

---

### GET /profile

**Request:**
```
GET /profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response 200:**
```json
{
  "id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Response 401 (no/bad token):**
```json
{ "detail": "Authentication required. Please provide a Bearer token." }
```

---

## HTTP Status Codes

| Code | Meaning | When Used |
|---|---|---|
| 200 | OK | Login success, profile fetch |
| 201 | Created | Registration success |
| 400 | Bad Request | General client error |
| 401 | Unauthorized | Missing/invalid/expired JWT |
| 404 | Not Found | User account deleted but token valid |
| 409 | Conflict | Duplicate username or email |
| 422 | Unprocessable | Validation failure (bad email, short password) |
| 500 | Server Error | Unexpected internal error |

---

## Security Concepts Explained

### 1. What Is Password Hashing?

Hashing converts a password into a fixed-length, irreversible string.

```
"securepass123"  →  bcrypt  →  "$2b$12$N9qo8uLOickgx2ZMRZoMye..."
```

There is NO mathematical function to reverse this. It's a one-way street.

When a user logs in:
- We hash what they typed
- Compare it to the stored hash
- They match → password is correct

We **never** compare against the original password — we don't have it.

---

### 2. Why bcrypt?

bcrypt is deliberately slow. Each hash takes ~100ms.

| Hash Algorithm | Time per hash | Attacker trying 1 billion passwords |
|---|---|---|
| MD5 | 0.000001ms | 0.001 seconds |
| SHA-256 | 0.0001ms | 1.7 minutes |
| **bcrypt (cost=12)** | **~100ms** | **~3 years** |

bcrypt also adds a random **salt** — a random value mixed into each hash:
- Same password → different hash every time
- Defeats pre-computed "rainbow table" attacks

---

### 3. Encryption vs Hashing

| | Encryption | Hashing |
|---|---|---|
| **Direction** | Two-way (encrypt/decrypt) | One-way only |
| **Key needed?** | Yes — to decrypt | No — can't reverse |
| **Use case** | Data in transit (HTTPS), files | Passwords |
| **Example** | AES-256, RSA | bcrypt, SHA-256 |
| **If DB stolen** | Attacker decrypts with key | Cannot recover passwords |

**Rule**: Always HASH passwords. Never ENCRYPT them.

---

### 4. How JWT Works

A JWT is three Base64URL-encoded JSON objects joined with dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9      ← Header
.
eyJzdWIiOiIxIiwiZW1haWwiOiJqb2huQGV4YW1wbGUuY29tIiwiZXhwIjoxNzA1MzI0NjAwfQ
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature
```

**Header** (decoded):
```json
{ "alg": "HS256", "typ": "JWT" }
```

**Payload** (decoded):
```json
{
  "sub": "1",
  "email": "john@example.com",
  "exp": 1705324600,
  "iat": 1705322800
}
```

**Signature**:
```
HMAC-SHA256(Base64(header) + "." + Base64(payload), SECRET_KEY)
```

To verify: recompute the signature. If it matches → token is authentic.
If someone changes the payload → signature won't match → rejected.

---

### 5. Authentication vs Authorization

| | Authentication | Authorization |
|---|---|---|
| **Question** | "Who are you?" | "What can you do?" |
| **Checks** | Is the token valid? | Does this user have permission? |
| **This app** | ✅ Implemented | ❌ Not implemented (no roles) |
| **Example** | Login, JWT validation | "Admin only", "Owner only" |

---

### 6. Token Expiration

Our tokens expire after 30 minutes (`ACCESS_TOKEN_EXPIRE_MINUTES = 30`).

**Why expire tokens?**
- If a token is stolen, it becomes useless after 30 minutes
- Limits damage from token leakage

**Production pattern** (two-token system):
- `access_token`: expires in 15-30 minutes (short-lived)
- `refresh_token`: expires in 7-30 days (long-lived, used only to get new access tokens)

---

### 7. Protected Routes & Middleware

In this app, "middleware" is implemented via FastAPI's dependency injection:

```python
@router.get("/profile")
def get_profile(current_user = Depends(get_current_user)):
    ...
```

`Depends(get_current_user)` is a **dependency** — FastAPI runs it before the route handler. If it raises an exception, the handler never runs.

This is equivalent to middleware but scoped to individual routes rather than all requests.

---

## Common Authentication Mistakes

| ❌ Mistake | ✅ Correct Approach |
|---|---|
| Store plain-text passwords | Always bcrypt hash before storing |
| Return plain password in any response | Never — not even the hash |
| Use MD5/SHA1 for passwords | Use bcrypt, Argon2, or scrypt only |
| Hardcode SECRET_KEY in source | Load from environment variable |
| Commit SECRET_KEY to git | Add to `.gitignore`, use `.env` file |
| Return "email not found" error | Return vague "Invalid email or password" |
| Never expire tokens | Short expiry (15-30 min) + refresh tokens |
| Skip input validation | Always validate with Pydantic schemas |
| Trust the JWT payload without verification | Always verify signature + expiry |
| Store JWT in localStorage | Prefer httpOnly cookies in production |

---

## Interview Questions & Answers

**Q: What is JWT and why is it stateless?**
A: JWT (JSON Web Token) is a self-contained token. The server doesn't store sessions — all necessary data (user id, expiry) is IN the token, cryptographically signed. Any server instance can verify it by recomputing the signature with the secret key.

**Q: What is the difference between hashing and encryption?**
A: Encryption is reversible (you can decrypt back to original). Hashing is one-way (irreversible). Passwords must be hashed, not encrypted — if a key is ever compromised, encrypted passwords can be decrypted.

**Q: Why use bcrypt instead of SHA-256 for passwords?**
A: SHA-256 is extremely fast (~1 billion hashes/second on modern hardware). An attacker can try all common passwords trivially. bcrypt is designed to be slow (100ms/hash), making brute-force attacks computationally infeasible.

**Q: What is a JWT secret key and why must it be protected?**
A: The secret key is used to sign and verify JWTs. Anyone with the secret can create valid tokens for any user. It must be: long (32+ characters), random, never in source code, never in version control.

**Q: What does `Depends(get_current_user)` do?**
A: It's FastAPI's dependency injection system. Before running the route handler, FastAPI calls `get_current_user`, which extracts and validates the JWT. If validation fails, a 401 is returned and the handler never runs.

**Q: What is the `sub` claim in JWT?**
A: "sub" (subject) is a standard JWT claim identifying the principal. By convention it's a string — we store the user's ID as a string. This identifies "whose token is this."

**Q: Why return "Invalid email or password" instead of "Email not found"?**
A: Specific error messages enable user enumeration — attackers can discover which emails are registered. Vague messages prevent this information leak.

**Q: What is bcrypt salt?**
A: A random value mixed into the hash input before hashing. The salt is stored alongside the hash. It ensures that two identical passwords produce different hashes, defeating rainbow table attacks (pre-computed hash lookup tables).

**Q: What happens when a JWT expires?**
A: `python-jose` automatically raises a `JWTError` when decoding an expired token. Our `decode_access_token()` catches this and raises HTTP 401. The client must log in again to get a new token.

**Q: What is the difference between 401 and 403?**
A: 401 Unauthorized = "I don't know who you are" (not authenticated / bad token). 403 Forbidden = "I know who you are, but you don't have permission" (authenticated but not authorized).
