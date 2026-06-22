# =============================================================================
# main.py
# =============================================================================
# PURPOSE:
#   Application entry point. Responsibilities:
#     1. Create the FastAPI application instance
#     2. Auto-create all database tables on startup
#     3. Register global exception handlers
#     4. Mount the router (all routes from routes.py)
#     5. Provide the ASGI app object (`app`) that uvicorn serves
#
# HOW TO RUN:
#   uvicorn main:app --reload
#         │    │
#         │    └── `app` = the FastAPI instance defined below
#         └── `main` = this file (main.py)
# =============================================================================

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

import models
from database import engine, Base
from routes import router

# =============================================================================
# AUTO-CREATE DATABASE TABLES
# =============================================================================
# SQLAlchemy inspects all classes that inherit from `Base` (defined in
# models.py → User) and generates CREATE TABLE IF NOT EXISTS statements.
#
# Running on every startup is safe because of IF NOT EXISTS.
# Existing tables and data are never modified or dropped.
#
# ⚠ PRODUCTION NOTE:
#   Replace `create_all` with Alembic migrations for schema change tracking.
#   `create_all` cannot add new columns to existing tables safely.
# =============================================================================
models.Base.metadata.create_all(bind=engine)

# =============================================================================
# FASTAPI APPLICATION INSTANCE
# =============================================================================
app = FastAPI(
    title="Secure Authentication API",
    description=(
        "A complete JWT authentication system built with FastAPI.\n\n"
        "## Authentication Flow\n"
        "1. **Register** → `POST /register` with username, email, password\n"
        "2. **Login** → `POST /login` → receive `access_token`\n"
        "3. **Access protected routes** → Include `Authorization: Bearer <token>` header\n\n"
        "## Security Features\n"
        "- Passwords hashed with **bcrypt** (never stored in plain text)\n"
        "- **JWT** tokens with 30-minute expiry\n"
        "- Token validated on every protected request\n"
        "- Duplicate username/email prevention\n"
        "- Input validation via Pydantic\n"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# =============================================================================
# CORS MIDDLEWARE
# =============================================================================
# CORS (Cross-Origin Resource Sharing) controls which web origins can call
# this API from a browser.
#
# In development: `allow_origins=["*"]` allows all origins.
# In production: restrict to your frontend domain:
#   allow_origins=["https://yourapp.com"]
#
# CORS is only relevant for browser-based clients. Postman, curl, and
# mobile apps are not affected by CORS.
# =============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Development: allow all. Restrict in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# GLOBAL EXCEPTION HANDLERS
# =============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Override FastAPI's default 422 Unprocessable Entity response.

    Default FastAPI format is verbose. We wrap it in a consistent envelope
    matching all our other error responses.

    Triggered when: missing required field, invalid email format, short
    password, invalid username characters, etc.
    """
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "message": "Validation failed. Please check your input.",
            "errors": exc.errors()
        }
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unhandled exceptions.
    Prevents Python tracebacks from leaking to API clients.
    In production: log to error tracker (Sentry, DataDog, etc.)
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "An unexpected internal server error occurred."
        }
    )


# =============================================================================
# REGISTER ROUTES
# =============================================================================
# Include all routes from routes.py.
# All endpoints defined there become available under the app.
# =============================================================================
app.include_router(router)


# =============================================================================
# ROOT ENDPOINT
# =============================================================================
@app.get("/", tags=["Root"], summary="API overview")
def root():
    """
    Landing page — shows available endpoints.
    """
    return {
        "name": "Secure Authentication API",
        "version": "1.0.0",
        "endpoints": {
            "register":      "POST /register",
            "login":         "POST /login",
            "profile":       "GET  /profile  (requires JWT)",
            "health":        "GET  /health",
            "swagger_docs":  "/docs",
            "redoc":         "/redoc",
        }
    }
