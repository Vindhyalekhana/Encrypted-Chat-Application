from security.rsa_utils import (
    decrypt_with_private_key,
    encrypt_with_public_key,
    generate_key_pair,
    load_private_key,
    load_public_key
)
from security.aes_utils import generate_session_key


TEST_USERNAME = "rsatest"


def main():
    print("Generating RSA key pair...")

    generate_key_pair(TEST_USERNAME)

    public_key = load_public_key(TEST_USERNAME)
    private_key = load_private_key(TEST_USERNAME)

    aes_key = generate_session_key()

    print("Generated AES-256 session key.")
    print(f"AES key size: {len(aes_key)} bytes")

    encrypted_key = encrypt_with_public_key(
        aes_key,
        public_key
    )

    print("AES session key encrypted with RSA public key.")
    print(f"Encrypted key size: {len(encrypted_key)} bytes")

    decrypted_key = decrypt_with_private_key(
        encrypted_key,
        private_key
    )

    print("AES session key decrypted with RSA private key.")

    if aes_key == decrypted_key:
        print("\nRSA-OAEP TEST: SUCCESS")
        print("The AES session key was recovered correctly.")
    else:
        print("\nRSA-OAEP TEST: FAILED")


if __name__ == "__main__":
    main()