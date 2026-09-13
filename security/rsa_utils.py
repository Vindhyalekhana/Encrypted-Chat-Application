from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_SIZE = 3072
KEY_DIRECTORY = Path(__file__).resolve().parent / "keys"


def generate_key_pair(username):
    KEY_DIRECTORY.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE
    )

    public_key = private_key.public_key()

    private_key_path = KEY_DIRECTORY / f"{username}_private.pem"
    public_key_path = KEY_DIRECTORY / f"{username}_public.pem"

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_path.write_bytes(private_key_bytes)
    public_key_path.write_bytes(public_key_bytes)

    return public_key_bytes.decode("utf-8")


def load_private_key(username):
    private_key_path = KEY_DIRECTORY / f"{username}_private.pem"

    if not private_key_path.exists():
        raise FileNotFoundError(
            f"Private key not found for user: {username}"
        )

    return serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None
    )


def load_public_key(username):
    public_key_path = KEY_DIRECTORY / f"{username}_public.pem"

    if not public_key_path.exists():
        raise FileNotFoundError(
            f"Public key not found for user: {username}"
        )

    return serialization.load_pem_public_key(
        public_key_path.read_bytes()
    )


def encrypt_with_public_key(data, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_with_private_key(encrypted_data, private_key):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )