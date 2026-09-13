from aes_utils import (
    generate_session_key,
    encrypt_message,
    decrypt_message
)


def main():
    message = "Hello Siri! This is a secret message."

    key = generate_session_key()

    nonce, ciphertext = encrypt_message(
        message,
        key
    )

    decrypted_message = decrypt_message(
        nonce,
        ciphertext,
        key
    )

    print("Original message:")
    print(message)

    print("\nEncrypted ciphertext:")
    print(ciphertext.hex())

    print("\nDecrypted message:")
    print(decrypted_message)

    if message == decrypted_message:
        print("\nAES-GCM DECRYPTION TEST: SUCCESS")
    else:
        print("\nAES-GCM DECRYPTION TEST: FAILED")

    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 1

    print("\nTesting modified ciphertext...")

    try:
        decrypt_message(
            nonce,
            bytes(tampered_ciphertext),
            key
        )

        print("TAMPER TEST: FAILED")

    except Exception:
        print("TAMPER TEST: SUCCESS")
        print("Modified ciphertext was rejected.")


if __name__ == "__main__":
    main()