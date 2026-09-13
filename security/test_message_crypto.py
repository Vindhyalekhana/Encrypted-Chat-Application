from security.message_crypto import (
    encrypt_chat_message,
    decrypt_chat_message
)
from security.rsa_utils import (
    generate_key_pair,
    load_private_key,
    load_public_key
)


TEST_USERNAME = "message_test"


def main():
    print("Preparing RSA keys...")

    generate_key_pair(TEST_USERNAME)

    public_key = load_public_key(TEST_USERNAME)
    private_key = load_private_key(TEST_USERNAME)

    message = "Hello Siri! This is an encrypted chat message."

    print("\nOriginal message:")
    print(message)

    encrypted_packet = encrypt_chat_message(
        message,
        public_key
    )

    print("\nEncrypted packet created.")

    print(
        f"Encrypted AES key length: "
        f"{len(encrypted_packet['encrypted_key'])} Base64 characters"
    )

    print(
        f"Nonce length: "
        f"{len(encrypted_packet['nonce'])} Base64 characters"
    )

    print(
        f"Ciphertext length: "
        f"{len(encrypted_packet['ciphertext'])} Base64 characters"
    )

    decrypted_message = decrypt_chat_message(
        encrypted_packet["encrypted_key"],
        encrypted_packet["nonce"],
        encrypted_packet["ciphertext"],
        private_key
    )

    print("\nDecrypted message:")
    print(decrypted_message)

    if message == decrypted_message:
        print("\nMESSAGE CRYPTO TEST: SUCCESS")
    else:
        print("\nMESSAGE CRYPTO TEST: FAILED")


if __name__ == "__main__":
    main()