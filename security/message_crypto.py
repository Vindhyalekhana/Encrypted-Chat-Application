import base64

from security.aes_utils import (
    generate_session_key,
    encrypt_message,
    decrypt_message
)
from security.rsa_utils import (
    encrypt_with_public_key,
    decrypt_with_private_key
)


def encrypt_chat_message(message, recipient_public_key):
    aes_key = generate_session_key()

    nonce, ciphertext = encrypt_message(
        message,
        aes_key
    )

    encrypted_aes_key = encrypt_with_public_key(
        aes_key,
        recipient_public_key
    )

    return {
        "encrypted_key": base64.b64encode(
            encrypted_aes_key
        ).decode("utf-8"),

        "nonce": base64.b64encode(
            nonce
        ).decode("utf-8"),

        "ciphertext": base64.b64encode(
            ciphertext
        ).decode("utf-8")
    }


def decrypt_chat_message(
    encrypted_key,
    nonce,
    ciphertext,
    recipient_private_key
):
    encrypted_aes_key = base64.b64decode(
        encrypted_key
    )

    nonce_bytes = base64.b64decode(
        nonce
    )

    ciphertext_bytes = base64.b64decode(
        ciphertext
    )

    aes_key = decrypt_with_private_key(
        encrypted_aes_key,
        recipient_private_key
    )

    return decrypt_message(
        nonce_bytes,
        ciphertext_bytes,
        aes_key
    )