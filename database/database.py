import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent / "chat.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.commit()

    finally:
        connection.close()


def create_user(username, password):
    from security.auth import hash_password

    password_hash = hash_password(password)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash)
        )

        connection.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        connection.close()


def get_user(username):
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            SELECT user_id, username, password_hash, public_key, created_at
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        return cursor.fetchone()

    finally:
        connection.close()


def update_public_key(username, public_key):
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            UPDATE users
            SET public_key = ?
            WHERE username = ?
            """,
            (public_key, username)
        )

        connection.commit()

        return cursor.rowcount == 1

    finally:
        connection.close()