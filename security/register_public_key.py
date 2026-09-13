import socket

from cryptography.hazmat.primitives import serialization

from security.rsa_utils import load_public_key
from security.network_protocol import send_json, receive_json


HOST = "127.0.0.1"
PORT = 5000


def register_public_key(username):
    public_key = load_public_key(username)

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((HOST, PORT))

        send_json(
            client_socket,
            {
                "type": "public_key",
                "username": username,
                "public_key": public_key_bytes.decode("utf-8")
            }
        )

        response = receive_json(client_socket)

        print(f"Server: {response.get('message')}")

        return response.get("status") == "success"

    finally:
        client_socket.close()


def main():
    username = input("Enter username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    try:
        if register_public_key(username):
            print("Public key registration: SUCCESS")
        else:
            print("Public key registration: FAILED")

    except FileNotFoundError as error:
        print(f"Key error: {error}")

    except (ConnectionError, OSError, ValueError) as error:
        print(f"Connection error: {error}")


if __name__ == "__main__":
    main()