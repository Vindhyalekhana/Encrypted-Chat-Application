import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from database.database import (
    initialize_database,
    create_user,
    get_user,
    update_public_key
)
from security.auth import verify_password
from security.network_protocol import (
    send_json,
    receive_json
)

HOST = "127.0.0.1"
PORT = 5000

connected_clients = {}
clients_lock = threading.Lock()


def send_response(
    connection,
    request,
    status,
    message,
    **data
):
    response = {
        "type": "response",
        "status": status,
        "message": message
    }

    request_id = request.get("request_id")

    if request_id:
        response["request_id"] = request_id

    response.update(data)

    send_json(
        connection,
        response
    )


def send_error(
    connection,
    request,
    message
):
    send_response(
        connection,
        request,
        "error",
        message
    )


def validate_public_key(public_key_text):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_text.encode("utf-8")
        )

        if not isinstance(
            public_key,
            rsa.RSAPublicKey
        ):
            return False

        if public_key.key_size < 2048:
            return False

        return True

    except (
        ValueError,
        TypeError,
        OSError
    ):
        return False


def handle_register(
    connection,
    request
):
    username = request.get("username")
    password = request.get("password")

    if not username or not password:
        send_error(
            connection,
            request,
            "Username and password are required."
        )
        return

    if get_user(username):
        send_error(
            connection,
            request,
            "Username already exists."
        )
        return

    if create_user(
        username,
        password
    ):
        send_response(
            connection,
            request,
            "success",
            "Registration successful."
        )
    else:
        send_error(
            connection,
            request,
            "Registration failed."
        )


def authenticate_user(
    connection,
    request
):
    username = request.get("username")
    password = request.get("password")

    if not username or not password:
        send_error(
            connection,
            request,
            "Username and password are required."
        )
        return None

    user = get_user(username)

    if not user:
        send_error(
            connection,
            request,
            "Invalid username or password."
        )
        return None

    if not verify_password(
        password,
        user["password_hash"]
    ):
        send_error(
            connection,
            request,
            "Invalid username or password."
        )
        return None

    send_response(
        connection,
        request,
        "success",
        "Login successful.",
        username=username,
        has_public_key=bool(
            user["public_key"]
        )
    )

    return username


def handle_public_key(
    connection,
    request,
    authenticated_username
):
    if not authenticated_username:
        send_error(
            connection,
            request,
            "Authentication is required before registering a public key."
        )
        return

    username = request.get("username")
    public_key = request.get("public_key")

    if not username or not public_key:
        send_error(
            connection,
            request,
            "Username and public key are required."
        )
        return

    if username != authenticated_username:
        send_error(
            connection,
            request,
            "Public key registration does not match the authenticated user."
        )
        return

    if not validate_public_key(public_key):
        send_error(
            connection,
            request,
            "Invalid RSA public key."
        )
        return

    if update_public_key(
        authenticated_username,
        public_key
    ):
        send_response(
            connection,
            request,
            "success",
            "Public key stored successfully."
        )
    else:
        send_error(
            connection,
            request,
            "Failed to store public key."
        )


def handle_get_public_key(
    connection,
    request
):
    username = request.get("username")

    if not username:
        send_error(
            connection,
            request,
            "Username is required."
        )
        return

    user = get_user(username)

    if not user:
        send_error(
            connection,
            request,
            "User not found."
        )
        return

    if not user["public_key"]:
        send_error(
            connection,
            request,
            "Public key is not registered for this user."
        )
        return

    send_response(
        connection,
        request,
        "success",
        "Public key retrieved successfully.",
        username=username,
        public_key=user["public_key"]
    )


def handle_list_users(
    connection,
    request
):
    cursor_users = []

    from database.database import get_connection

    database_connection = get_connection()

    try:
        rows = database_connection.execute(
            """
            SELECT username
            FROM users
            ORDER BY username COLLATE NOCASE
            """
        ).fetchall()

        with clients_lock:
            online_users = set(
                connected_clients.keys()
            )

        for row in rows:
            username = row["username"]

            cursor_users.append(
                {
                    "username": username,
                    "online": username in online_users
                }
            )

    finally:
        database_connection.close()

    send_response(
        connection,
        request,
        "success",
        "User list retrieved successfully.",
        users=cursor_users
    )


def route_encrypted_message(
    request,
    authenticated_username
):
    sender = request.get("sender")
    recipient = request.get("recipient")

    if not sender or not recipient:
        return (
            False,
            "Sender and recipient are required."
        )

    if sender != authenticated_username:
        return (
            False,
            "Sender does not match the authenticated user."
        )

    if sender == recipient:
        return (
            False,
            "Sender and recipient cannot be the same."
        )

    required_fields = [
        "encrypted_key",
        "nonce",
        "ciphertext"
    ]

    for field in required_fields:
        if not request.get(field):
            return (
                False,
                f"Missing encrypted message field: {field}"
            )

    recipient_user = get_user(recipient)

    if not recipient_user:
        return (
            False,
            "Recipient does not exist."
        )

    if not recipient_user["public_key"]:
        return (
            False,
            "Recipient has no registered public key."
        )

    with clients_lock:
        recipient_connection = (
            connected_clients.get(recipient)
        )

    if not recipient_connection:
        return (
            False,
            "Recipient is not online."
        )

    try:
        send_json(
            recipient_connection,
            request
        )

        return (
            True,
            "Encrypted message delivered."
        )

    except (
        ConnectionError,
        OSError
    ):
        with clients_lock:
            if (
                connected_clients.get(recipient)
                == recipient_connection
            ):
                del connected_clients[
                    recipient
                ]

        return (
            False,
            "Failed to deliver encrypted message."
        )


def handle_authenticated_request(
    connection,
    request,
    authenticated_username
):
    request_type = request.get("type")

    if request_type == "public_key":
        handle_public_key(
            connection,
            request,
            authenticated_username
        )

    elif request_type == "get_public_key":
        handle_get_public_key(
            connection,
            request
        )

    elif request_type == "list_users":
        handle_list_users(
            connection,
            request
        )

    elif request_type == "encrypted_message":
        success, message = route_encrypted_message(
            request,
            authenticated_username
        )

        send_response(
            connection,
            request,
            "success" if success else "error",
            message
        )

    else:
        send_error(
            connection,
            request,
            "Unknown request type."
        )


def handle_client(
    connection,
    address
):
    authenticated_username = None

    print(
        f"Client connected: {address}"
    )

    try:
        first_request = receive_json(
            connection
        )

        request_type = first_request.get(
            "type"
        )

        if request_type == "register":
            handle_register(
                connection,
                first_request
            )
            return

        if request_type != "login":
            send_error(
                connection,
                first_request,
                "Login is required."
            )
            return

        authenticated_username = authenticate_user(
            connection,
            first_request
        )

        if not authenticated_username:
            return

        with clients_lock:
            old_connection = connected_clients.get(
                authenticated_username
            )

            if old_connection:
                try:
                    old_connection.shutdown(
                        socket.SHUT_RDWR
                    )
                except OSError:
                    pass

                try:
                    old_connection.close()
                except OSError:
                    pass

            connected_clients[
                authenticated_username
            ] = connection

        print(
            f"User logged in: "
            f"{authenticated_username}"
        )

        while True:
            request = receive_json(
                connection
            )

            handle_authenticated_request(
                connection,
                request,
                authenticated_username
            )

    except (
        ConnectionError,
        ValueError,
        OSError
    ) as error:
        print(
            f"Connection closed for "
            f"{authenticated_username or address}: "
            f"{error}"
        )

    finally:
        if authenticated_username:
            with clients_lock:
                if connected_clients.get(
                    authenticated_username
                ) == connection:
                    del connected_clients[
                        authenticated_username
                    ]

            print(
                f"User disconnected: "
                f"{authenticated_username}"
            )

        try:
            connection.close()
        except OSError:
            pass


def start_server():
    initialize_database()

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind(
        (HOST, PORT)
    )

    server_socket.listen(10)

    print(
        f"Server started on "
        f"{HOST}:{PORT}"
    )

    print(
        "Waiting for clients..."
    )

    try:
        while True:
            connection, address = (
                server_socket.accept()
            )

            client_thread = threading.Thread(
                target=handle_client,
                args=(
                    connection,
                    address
                ),
                daemon=True
            )

            client_thread.start()

    except KeyboardInterrupt:
        print(
            "\nServer stopped."
        )

    finally:
        with clients_lock:
            for connection in connected_clients.values():
                try:
                    connection.shutdown(
                        socket.SHUT_RDWR
                    )
                except OSError:
                    pass

                try:
                    connection.close()
                except OSError:
                    pass

            connected_clients.clear()

        server_socket.close()


if __name__ == "__main__":
    start_server()
