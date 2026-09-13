import base64

from cryptography.hazmat.primitives import serialization

from security.aes_utils import (
    generate_session_key,
    encrypt_message,
    decrypt_message
)
from security.message_crypto import (
    encrypt_chat_message,
    decrypt_chat_message
)
from security.rsa_utils import (
    load_private_key,
    load_public_key
)


def test_aes_tampering():
    key = generate_session_key()

    nonce, ciphertext = encrypt_message(
        "Confidential message",
        key
    )

    tampered_ciphertext = bytearray(
        ciphertext
    )

    tampered_ciphertext[0] ^= 1

    try:
        decrypt_message(
            nonce,
            bytes(tampered_ciphertext),
            key
        )

        return False

    except Exception:
        return True


def test_hybrid_tampering():
    recipient_public_key = load_public_key(
        "siri"
    )

    recipient_private_key = load_private_key(
        "siri"
    )

    packet = encrypt_chat_message(
        "Confidential hybrid message",
        recipient_public_key
    )

    ciphertext = base64.b64decode(
        packet["ciphertext"]
    )

    tampered_ciphertext = bytearray(
        ciphertext
    )

    tampered_ciphertext[0] ^= 1

    packet["ciphertext"] = base64.b64encode(
        bytes(tampered_ciphertext)
    ).decode("utf-8")

    try:
        decrypt_chat_message(
            packet["encrypted_key"],
            packet["nonce"],
            packet["ciphertext"],
            recipient_private_key
        )

        return False

    except Exception:
        return True


def test_rsa_key_tampering():
    recipient_public_key = load_public_key(
        "siri"
    )

    recipient_private_key = load_private_key(
        "siri"
    )

    packet = encrypt_chat_message(
        "RSA protected message",
        recipient_public_key
    )

    encrypted_key = base64.b64decode(
        packet["encrypted_key"]
    )

    tampered_key = bytearray(
        encrypted_key
    )

    tampered_key[0] ^= 1

    packet["encrypted_key"] = base64.b64encode(
        bytes(tampered_key)
    ).decode("utf-8")

    try:
        decrypt_chat_message(
            packet["encrypted_key"],
            packet["nonce"],
            packet["ciphertext"],
            recipient_private_key
        )

        return False

    except Exception:
        return True


def main():
    print()
    print("========================================")
    print("   END-TO-END TAMPERING TESTS")
    print("========================================")
    print()

    aes_result = test_aes_tampering()

    print(
        "AES-GCM TAMPER TEST:",
        "PASS" if aes_result else "FAIL"
    )

    hybrid_result = test_hybrid_tampering()

    print(
        "HYBRID CIPHERTEXT TAMPER TEST:",
        "PASS" if hybrid_result else "FAIL"
    )

    rsa_result = test_rsa_key_tampering()

    print(
        "RSA ENCRYPTED-KEY TAMPER TEST:",
        "PASS" if rsa_result else "FAIL"
    )

    print()
    print("========================================")

    if (
        aes_result
        and hybrid_result
        and rsa_result
    ):
        print(
            "END-TO-END TAMPERING TEST: SUCCESS"
        )
        print(
            "All modified encrypted data was rejected."
        )
    else:
        print(
            "END-TO-END TAMPERING TEST: FAILED"
        )

    print("========================================")


if __name__ == "__main__":
    main()