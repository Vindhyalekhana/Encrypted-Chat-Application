from security.aes_utils import (
    generate_session_key,
    encrypt_message,
    decrypt_message
)


def main():
    key = generate_session_key()

    original_message = "AES-256-GCM security test"

    nonce, ciphertext = encrypt_message(
        original_message,
        key
    )

    decrypted_message = decrypt_message(
        nonce,
        ciphertext,
        key
    )

    if decrypted_message == original_message:
        print("AES-GCM DECRYPTION TEST: PASS")
    else:
        print("AES-GCM DECRYPTION TEST: FAIL")
        return

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 1

    try:
        decrypt_message(
            nonce,
            bytes(tampered_ciphertext),
            key
        )

        print("AES-GCM TAMPER TEST: FAIL")

    except Exception:
        print("AES-GCM TAMPER TEST: PASS")

    print("AES-256-GCM TEST: SUCCESS")


if __name__ == "__main__":
    main()