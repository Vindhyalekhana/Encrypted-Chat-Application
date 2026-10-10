import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# --------------------------------------------------
# Configuration
# --------------------------------------------------

DATABASE_PATH = Path(
    os.environ.get(
        "CHAT_DATABASE_PATH",
        str(Path(__file__).resolve().parent / "web_chat.db")
    )
)

TOKEN_SECRET = os.environ.get("CHAT_TOKEN_SECRET")

if not TOKEN_SECRET or len(TOKEN_SECRET) < 32:
    raise RuntimeError(
        "Set CHAT_TOKEN_SECRET to a secure random value "
        "of at least 32 characters."
    )

FRONTEND_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "FRONTEND_ORIGINS",
        "http://localhost:3000"
    ).split(",")
    if origin.strip()
]

PASSWORD_ITERATIONS = 600_000
TOKEN_LIFETIME = timedelta(hours=1)


# --------------------------------------------------
# Database
# --------------------------------------------------

def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Encrypted Chat Web Backend",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


# --------------------------------------------------
# Request models
# --------------------------------------------------

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


# --------------------------------------------------
# Authentication helpers
# --------------------------------------------------

def validate_username(username: str) -> bool:
    return bool(
        re.fullmatch(r"[A-Za-z0-9_]{3,32}", username)
    )


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_ITERATIONS,
        dklen=32
    )


def create_token(username: str) -> str:
    expiry = int(
        (
            datetime.now(timezone.utc) + TOKEN_LIFETIME
        ).timestamp()
    )

    payload = f"{username}|{expiry}"

    signature = hmac.new(
        TOKEN_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{payload}|{signature}"


def verify_token(token: str):
    try:
        username, expiry_text, signature = token.rsplit("|", 2)

        if not validate_username(username):
            return None

        payload = f"{username}|{expiry_text}"

        expected_signature = hmac.new(
            TOKEN_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            signature,
            expected_signature
        ):
            return None

        expiry = int(expiry_text)

        if expiry <= int(
            datetime.now(timezone.utc).timestamp()
        ):
            return None

        return username

    except (ValueError, TypeError):
        return None


# --------------------------------------------------
# Health endpoint
# --------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


# --------------------------------------------------
# Registration
# --------------------------------------------------

@app.post("/api/register", status_code=201)
def register(credentials: Credentials):
    username = credentials.username.strip()

    if not validate_username(username):
        raise HTTPException(
            status_code=400,
            detail=(
                "Username must contain 3-32 letters, "
                "numbers, or underscores."
            )
        )

    salt = secrets.token_bytes(16)

    password_hash = hash_password(
        credentials.password,
        salt
    )

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    try:
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (
                    username,
                    password_salt,
                    password_hash,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    salt.hex(),
                    password_hash.hex(),
                    created_at
                )
            )

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Username already exists."
        )

    return {
        "message": "Registration successful."
    }


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.post("/api/login")
def login(credentials: Credentials):
    username = credentials.username.strip()

    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT username, password_salt, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    salt = bytes.fromhex(user["password_salt"])

    candidate_hash = hash_password(
        credentials.password,
        salt
    )

    stored_hash = bytes.fromhex(
        user["password_hash"]
    )

    if not hmac.compare_digest(
        candidate_hash,
        stored_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password."
        )

    return {
        "username": username,
        "access_token": create_token(username),
        "token_type": "bearer"
    }


# --------------------------------------------------
# WebSocket connection
# --------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    username = verify_token(token or "")

    if not username:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    try:
        while True:
            # Messaging is deliberately disabled until
            # end-to-end encryption is integrated.
            await websocket.receive_text()

            await websocket.send_json({
                "type": "error",
                "message": (
                    "Messaging is not enabled until "
                    "the encrypted protocol is implemented."
                )
            })

    except WebSocketDisconnect:
        pass