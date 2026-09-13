import os

from security.aes_utils import (
    generate_session_key,
    encrypt_message,
    decrypt_message
)
from security.rsa_utils import (
    generate_key_pair,
    load_private_key,
    load_public_key,
    encrypt_with_public_key,
    decrypt_with_private_key
)


SENDER = "hybrid_sender"
RECIPIENT = "hybrid_recipient"


def main():
    print("Generating RSA key pairs...")

    generate_key_pair(SENDER)
    generate_key_pair(RECIPIENT)

    recipient_public_key = load_public_key(RECIPIENT)
    recipient_private_key = load_private_key(RECIPIENT)

    message = "Hello Siri! This message uses hybrid encryption."

    print("\nOriginal message:")
    print(message)

    aes_key = generate_session_key()

    nonce, ciphertext = encrypt_message(
        message,
        aes_key
    )

    print("\nAES-256-GCM encryption completed.")
    print(f"AES key size: {len(aes_key)} bytes")
    print(f"Nonce size: {len(nonce)} bytes")
    print(f"Ciphertext size: {len(ciphertext)} bytes")

    encrypted_aes_key = encrypt_with_public_key(
        aes_key,
        recipient_public_key
    )

    print("\nAES session key encrypted with recipient's RSA public key.")
    print(f"Encrypted AES key size: {len(encrypted_aes_key)} bytes")

    recovered_aes_key = decrypt_with_private_key(
        encrypted_aes_key,
        recipient_private_key
    )

    print("AES session key recovered using recipient's RSA private key.")

    decrypted_message = decrypt_message(
        nonce,
        ciphertext,
        recovered_aes_key
    )

    print("\nDecrypted message:")
    print(decrypted_message)

    if message == decrypted_message:
        print("\nHYBRID ENCRYPTION TEST: SUCCESS")
    else:
        print("\nHYBRID ENCRYPTION TEST: FAILED")
        return

    print("\nTesting ciphertext tampering...")

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 1

    try:
        decrypt_message(
            nonce,
            bytes(tampered_ciphertext),
            recovered_aes_key
        )

        print("TAMPER TEST: FAILED")

    except Exception:
        print("TAMPER TEST: SUCCESS")
        print("Modified ciphertext was rejected.")

    print("\nTesting encrypted AES key tampering...")

    tampered_encrypted_key = bytearray(encrypted_aes_key)
    tampered_encrypted_key[0] ^= 1

    try:
        decrypt_with_private_key(
            bytes(tampered_encrypted_key),
            recipient_private_key
        )

        print("RSA TAMPER TEST: FAILED")

    except Exception:
        print("RSA TAMPER TEST: SUCCESS")
        print("Modified encrypted AES key was rejected.")


if __name__ == "__main__":
    main()