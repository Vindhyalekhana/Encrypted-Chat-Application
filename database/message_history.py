import base64
import hashlib
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATABASE_PATH = Path(__file__).resolve().parent / "chat_history.db"
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
ITERATIONS = 600_000


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_history_database():
    connection = get_connection()
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS history_metadata (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS message_history (
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_username TEXT NOT NULL,
                conversation_with TEXT NOT NULL,
                sender TEXT NOT NULL,
                encrypted_message TEXT NOT NULL,
                nonce TEXT NOT NULL,
                sent INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_history_owner_conversation
            ON message_history(owner_username, conversation_with, message_id)
            """
        )
        connection.commit()
    finally:
        connection.close()


def _get_or_create_salt(username):
    initialize_history_database()
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT salt FROM history_metadata WHERE username = ?",
            (username,)
        ).fetchone()

        if row:
            return bytes(row["salt"])

        salt = os.urandom(SALT_SIZE)
        connection.execute(
            "INSERT INTO history_metadata (username, salt) VALUES (?, ?)",
            (username, salt)
        )
        connection.commit()
        return salt
    finally:
        connection.close()


def derive_history_key(username, password):
    salt = _get_or_create_salt(username)
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=KEY_SIZE
    )


def _build_aad(owner_username, conversation_with, sender, timestamp):
    return "|".join(
        [
            owner_username,
            conversation_with,
            sender,
            timestamp
        ]
    ).encode("utf-8")


def save_message(
    owner_username,
    conversation_with,
    sender,
    message,
    sent,
    timestamp,
    history_key
):
    if len(history_key) != KEY_SIZE:
        raise ValueError("History encryption key must be 32 bytes long.")

    if not isinstance(timestamp, datetime):
        raise TypeError("timestamp must be a datetime object.")

    timestamp_text = timestamp.isoformat(timespec="seconds")
    nonce = os.urandom(NONCE_SIZE)
    aad = _build_aad(
        owner_username,
        conversation_with,
        sender,
        timestamp_text
    )
    ciphertext = AESGCM(history_key).encrypt(
        nonce,
        message.encode("utf-8"),
        aad
    )

    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO message_history (
                owner_username,
                conversation_with,
                sender,
                encrypted_message,
                nonce,
                sent,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_username,
                conversation_with,
                sender,
                base64.b64encode(ciphertext).decode("ascii"),
                base64.b64encode(nonce).decode("ascii"),
                1 if sent else 0,
                timestamp_text
            )
        )
        connection.commit()
    finally:
        connection.close()


def _decrypt_row(row, history_key):
    timestamp_text = row["timestamp"]
    aad = _build_aad(
        row["owner_username"],
        row["conversation_with"],
        row["sender"],
        timestamp_text
    )

    ciphertext = base64.b64decode(
        row["encrypted_message"],
        validate=True
    )
    nonce = base64.b64decode(
        row["nonce"],
        validate=True
    )

    plaintext = AESGCM(history_key).decrypt(
        nonce,
        ciphertext,
        aad
    ).decode("utf-8")

    try:
        display_time = datetime.fromisoformat(
            timestamp_text
        ).strftime("%H:%M")
    except ValueError:
        display_time = timestamp_text

    return {
        "sender": row["sender"],
        "message": plaintext,
        "time": display_time,
        "sent": bool(row["sent"])
    }


def load_all_conversations(owner_username, history_key):
    if len(history_key) != KEY_SIZE:
        raise ValueError("History encryption key must be 32 bytes long.")

    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                message_id,
                owner_username,
                conversation_with,
                sender,
                encrypted_message,
                nonce,
                sent,
                timestamp
            FROM message_history
            WHERE owner_username = ?
            ORDER BY message_id ASC
            """,
            (owner_username,)
        ).fetchall()
    finally:
        connection.close()

    conversations = {}

    for row in rows:
        message = _decrypt_row(row, history_key)
        conversations.setdefault(
            row["conversation_with"],
            []
        ).append(message)

    return conversations
