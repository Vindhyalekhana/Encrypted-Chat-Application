import socket

from cryptography.hazmat.primitives import serialization

from security.network_protocol import send_json, receive_json


HOST = "127.0.0.1"
PORT = 5000


def get_public_key(username):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((HOST, PORT))

        send_json(
            client_socket,
            {
                "type": "get_public_key",
                "username": username
            }
        )

        response = receive_json(client_socket)

        if response.get("status") != "success":
            print(f"Server: {response.get('message')}")
            return None

        public_key = serialization.load_pem_public_key(
            response["public_key"].encode("utf-8")
        )

        return public_key

    finally:
        client_socket.close()


def main():
    username = input("Enter username whose public key should be retrieved: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    try:
        public_key = get_public_key(username)

        if public_key is None:
            print("PUBLIC KEY RETRIEVAL: FAILED")
            return

        public_numbers = public_key.public_numbers()

        print("Public key retrieved successfully.")
        print(f"RSA key size: {public_key.key_size} bits")
        print(f"Public exponent: {public_numbers.e}")

        print("\nPUBLIC KEY RETRIEVAL TEST: SUCCESS")

    except (ConnectionError, OSError, ValueError) as error:
        print(f"Connection error: {error}")
        print("PUBLIC KEY RETRIEVAL TEST: FAILED")


if __name__ == "__main__":
    main()