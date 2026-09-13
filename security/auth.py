import base64
import hashlib
import hmac
import os


SALT_SIZE = 16
HASH_SIZE = 32
ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8


def validate_password(password):
    return len(password) >= MIN_PASSWORD_LENGTH


def hash_password(password):
    salt = os.urandom(SALT_SIZE)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=HASH_SIZE
    )

    encoded_salt = base64.b64encode(salt).decode("utf-8")
    encoded_hash = base64.b64encode(password_hash).decode("utf-8")

    return f"{encoded_salt}${encoded_hash}"


def verify_password(password, stored_password):
    try:
        encoded_salt, encoded_hash = stored_password.split("$", 1)

        salt = base64.b64decode(encoded_salt)
        expected_hash = base64.b64decode(encoded_hash)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            ITERATIONS,
            dklen=HASH_SIZE
        )

        return hmac.compare_digest(password_hash, expected_hash)

    except (ValueError, TypeError):
        return False