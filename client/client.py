import socket
import sys
import threading

from cryptography.hazmat.primitives import serialization

from security.auth import validate_password
from security.message_crypto import (
    encrypt_chat_message,
    decrypt_chat_message
)
from security.rsa_utils import (
    generate_key_pair,
    load_private_key
)
from security.network_protocol import send_json, receive_json


HOST = "127.0.0.1"
PORT = 5000


def connect_to_server():
    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    client_socket.connect((HOST, PORT))

    return client_socket


def register():
    print("\n--- Register ---")

    username = input("Enter username: ").strip()
    password = input("Enter password: ")

    if not username:
        print("Username cannot be empty.")
        return

    if not validate_password(password):
        print("Password must be at least 8 characters long.")
        return

    client_socket = connect_to_server()

    try:
        send_json(
            client_socket,
            {
                "type": "register",
                "username": username,
                "password": password
            }
        )

        response = receive_json(client_socket)

        print(f"\nServer: {response.get('message')}")

        if response.get("status") != "success":
            return

    except (ConnectionError, ValueError, OSError) as error:
        print(f"Connection error: {error}")
        return

    finally:
        client_socket.close()

    try:
        generate_key_pair(username)

        print("RSA key pair generated successfully.")

        register_public_key(username)

    except (FileNotFoundError, OSError, ValueError) as error:
        print(f"Key generation error: {error}")


def register_public_key(username):
    from security.rsa_utils import load_public_key

    public_key = load_public_key(username)

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_socket = connect_to_server()

    try:
        send_json(
            key_socket,
            {
                "type": "public_key",
                "username": username,
                "public_key": public_key_bytes.decode("utf-8")
            }
        )

        response = receive_json(key_socket)

        print(f"Server: {response.get('message')}")

        return response.get("status") == "success"

    finally:
        key_socket.close()


def get_public_key(client_socket, username):
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

    return serialization.load_pem_public_key(
        response["public_key"].encode("utf-8")
    )


def receive_messages(client_socket, private_key):
    while True:
        try:
            message = receive_json(client_socket)

            if message.get("type") != "encrypted_message":
                continue

            decrypted_message = decrypt_chat_message(
                message["encrypted_key"],
                message["nonce"],
                message["ciphertext"],
                private_key
            )

            print(
                f"\n{message['sender']}: "
                f"{decrypted_message}"
            )

            print("Enter message: ", end="", flush=True)

        except ConnectionError:
            print("\nServer connection closed.")
            break

        except Exception as error:
            print(f"\nFailed to decrypt message: {error}")
            print("Enter message: ", end="", flush=True)


def chat(client_socket, username):
    recipient = input(
        "Enter recipient username: "
    ).strip()

    if not recipient:
        print("Recipient cannot be empty.")
        return

    print(f"Retrieving public key for {recipient}...")

    try:
        recipient_public_key = get_public_key(
            client_socket,
            recipient
        )

    except (ConnectionError, ValueError, OSError) as error:
        print(f"Connection error: {error}")
        return

    if recipient_public_key is None:
        return

    print(
        f"Public key for {recipient} retrieved successfully."
    )

    private_key = load_private_key(username)

    receiver_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket, private_key),
        daemon=True
    )

    receiver_thread.start()

    print("\n=== Encrypted Chat ===")
    print("Type /exit to leave the chat.")

    while True:
        message = input("Enter message: ")

        if message == "/exit":
            break

        if not message.strip():
            continue

        try:
            encrypted_packet = encrypt_chat_message(
                message,
                recipient_public_key
            )

            encrypted_packet.update(
                {
                    "type": "encrypted_message",
                    "sender": username,
                    "recipient": recipient
                }
            )

            send_json(
                client_socket,
                encrypted_packet
            )

            print("Message sent securely.")

        except (ConnectionError, OSError, ValueError) as error:
            print(f"Failed to send message: {error}")
            break


def login():
    print("\n--- Login ---")

    username = input("Enter username: ").strip()
    password = input("Enter password: ")

    if not username or not password:
        print("Username and password are required.")
        return

    client_socket = connect_to_server()

    try:
        send_json(
            client_socket,
            {
                "type": "login",
                "username": username,
                "password": password
            }
        )

        response = receive_json(client_socket)

        print(f"\nServer: {response.get('message')}")

        if response.get("status") != "success":
            client_socket.close()
            return

        print(f"Logged in as: {response.get('username')}")

        if not response.get("has_public_key"):
            print("RSA public key is not registered.")
            print("Generating RSA key pair...")

            generate_key_pair(username)

            print("RSA key pair generated successfully.")

            public_key_socket = connect_to_server()

            try:
                from security.rsa_utils import load_public_key

                public_key = load_public_key(username)

                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                send_json(
                    public_key_socket,
                    {
                        "type": "public_key",
                        "username": username,
                        "public_key": public_key_bytes.decode("utf-8")
                    }
                )

                key_response = receive_json(
                    public_key_socket
                )

                print(
                    f"Server: "
                    f"{key_response.get('message')}"
                )

                if key_response.get("status") != "success":
                    client_socket.close()
                    return

            finally:
                public_key_socket.close()

        else:
            print(
                "RSA public key is registered with the server."
            )

        chat(
            client_socket,
            username
        )

    except (ConnectionError, ValueError, OSError) as error:
        print(f"Connection error: {error}")

    finally:
        client_socket.close()


def main():
    while True:
        print("\n=== Encrypted Chat Application ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            register()

        elif choice == "2":
            login()

        elif choice == "3":
            print("Goodbye.")
            sys.exit(0)

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()