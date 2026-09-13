import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32
NONCE_SIZE = 12


def generate_session_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(message, key):
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be 32 bytes long.")

    nonce = os.urandom(NONCE_SIZE)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce, ciphertext


def decrypt_message(nonce, ciphertext, key):
    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be 32 bytes long.")

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")