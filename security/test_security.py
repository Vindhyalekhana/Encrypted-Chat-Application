import socket

from security.network_protocol import (
    send_json,
    receive_json
)

HOST = "127.0.0.1"
PORT = 5000


def connect_to_server():
    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )
    client_socket.connect(
        (HOST, PORT)
    )
    return client_socket


def test_wrong_password(username, password):
    client_socket = connect_to_server()

    try:
        send_json(
            client_socket,
            {
                "type": "login",
                "username": username,
                "password": password + "_wrong"
            }
        )

        response = receive_json(
            client_socket
        )

        success = (
            response.get("status") == "error"
            and
            "Invalid username or password."
            in response.get("message", "")
        )

        print(
            "WRONG PASSWORD TEST:",
            "PASS" if success else "FAIL"
        )

        print(
            f"Server response: "
            f"{response.get('message')}"
        )

        return success

    finally:
        client_socket.close()


def authenticate(client_socket, username, password):
    send_json(
        client_socket,
        {
            "type": "login",
            "username": username,
            "password": password
        }
    )

    response = receive_json(
        client_socket
    )

    if response.get("status") != "success":
        raise RuntimeError(
            response.get(
                "message",
                "Authentication failed."
            )
        )

    return response


def test_invalid_recipient(
    username,
    password
):
    client_socket = connect_to_server()

    try:
        authenticate(
            client_socket,
            username,
            password
        )

        send_json(
            client_socket,
            {
                "type": "encrypted_message",
                "sender": username,
                "recipient": "user_that_does_not_exist",
                "encrypted_key": "test",
                "nonce": "test",
                "ciphertext": "test"
            }
        )

        response = receive_json(
            client_socket
        )

        success = (
            response.get("status") == "error"
            and
            "does not exist"
            in response.get("message", "")
        )

        print(
            "INVALID RECIPIENT TEST:",
            "PASS" if success else "FAIL"
        )

        print(
            f"Server response: "
            f"{response.get('message')}"
        )

        return success

    finally:
        client_socket.close()


def test_offline_recipient(
    username,
    password,
    recipient
):
    client_socket = connect_to_server()

    try:
        authenticate(
            client_socket,
            username,
            password
        )

        send_json(
            client_socket,
            {
                "type": "encrypted_message",
                "sender": username,
                "recipient": recipient,
                "encrypted_key": "test",
                "nonce": "test",
                "ciphertext": "test"
            }
        )

        response = receive_json(
            client_socket
        )

        success = (
            response.get("status") == "error"
            and
            "not online"
            in response.get("message", "")
        )

        print(
            "OFFLINE RECIPIENT TEST:",
            "PASS" if success else "FAIL"
        )

        print(
            f"Server response: "
            f"{response.get('message')}"
        )

        return success

    finally:
        client_socket.close()


def test_sender_spoofing(
    username,
    password
):
    client_socket = connect_to_server()

    try:
        authenticate(
            client_socket,
            username,
            password
        )

        send_json(
            client_socket,
            {
                "type": "encrypted_message",
                "sender": "siri",
                "recipient": username,
                "encrypted_key": "test",
                "nonce": "test",
                "ciphertext": "test"
            }
        )

        response = receive_json(
            client_socket
        )

        success = (
            response.get("status") == "error"
            and
            "does not match"
            in response.get("message", "")
        )

        print(
            "SENDER SPOOFING TEST:",
            "PASS" if success else "FAIL"
        )

        print(
            f"Server response: "
            f"{response.get('message')}"
        )

        return success

    finally:
        client_socket.close()


def test_unauthorized_public_key_update(
    username,
    password
):
    client_socket = connect_to_server()

    try:
        authenticate(
            client_socket,
            username,
            password
        )

        send_json(
            client_socket,
            {
                "type": "public_key",
                "username": "siri",
                "public_key": "fake-public-key"
            }
        )

        response = receive_json(
            client_socket
        )

        success = (
            response.get("status") == "error"
            and
            "does not match"
            in response.get("message", "")
        )

        print(
            "UNAUTHORIZED PUBLIC KEY TEST:",
            "PASS" if success else "FAIL"
        )

        print(
            f"Server response: "
            f"{response.get('message')}"
        )

        return success

    finally:
        client_socket.close()


def test_unauthenticated_public_key_update():
    client_socket = connect_to_server()

    try:
        send_json(
            client_socket,
            {
                "type": "public_key",
                "username": "siri",
                "public_key": "fake-public-key"
            }
        )

        response = receive_json(
            client_socket
        )

        success = (
            response.get("status") == "error"
            and
            response.get("message") == "Login is required."
        )

        print(
            "UNAUTHENTICATED KEY TEST:",
            "PASS" if success else "FAIL"
        )

        print(
            f"Server response: "
            f"{response.get('message')}"
        )

        return success

    finally:
        client_socket.close()


def main():
    print()
    print("========================================")
    print("   ENCRYPTED CHAT SECURITY TESTS")
    print("========================================")
    print()

    username = input(
        "Enter test username: "
    ).strip()

    password = input(
        "Enter test password: "
    )

    offline_recipient = input(
        "Enter an existing user who is OFFLINE: "
    ).strip()

    print()
    print("Running security tests...")
    print()

    results = []

    try:
        results.append(
            test_wrong_password(
                username,
                password
            )
        )

        results.append(
            test_invalid_recipient(
                username,
                password
            )
        )

        results.append(
            test_offline_recipient(
                username,
                password,
                offline_recipient
            )
        )

        results.append(
            test_sender_spoofing(
                username,
                password
            )
        )

        results.append(
            test_unauthorized_public_key_update(
                username,
                password
            )
        )

        results.append(
            test_unauthenticated_public_key_update()
        )

    except (
        ConnectionError,
        OSError,
        ValueError,
        RuntimeError
    ) as error:
        print()
        print(
            f"TEST EXECUTION ERROR: {error}"
        )
        return

    print()
    print("========================================")

    if all(results):
        print(
            "SECURITY TEST SUITE: SUCCESS"
        )
        print(
            "All security controls passed."
        )
    else:
        print(
            "SECURITY TEST SUITE: FAILED"
        )
        print(
            "One or more security controls failed."
        )

    print("========================================")


if __name__ == "__main__":
    main()