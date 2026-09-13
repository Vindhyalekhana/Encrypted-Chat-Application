import socket
import threading

from network_protocol import send_json, receive_json


def server_test(server_socket):
    connection, address = server_socket.accept()

    try:
        received_data = receive_json(connection)

        print("Server received:")
        print(received_data)

        response = {
            "status": "success",
            "message": "TCP framing works correctly."
        }

        send_json(connection, response)

    finally:
        connection.close()
        server_socket.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)

    port = server_socket.getsockname()[1]

    thread = threading.Thread(
        target=server_test,
        args=(server_socket,)
    )
    thread.start()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", port))

    test_data = {
        "type": "test",
        "username": "vindhya",
        "message": "Hello Siri! TCP framing test."
    }

    print("Client sending:")
    print(test_data)

    send_json(client_socket, test_data)

    response = receive_json(client_socket)

    print("\nClient received:")
    print(response)

    client_socket.close()
    thread.join()

    if (
        response.get("status") == "success"
        and response.get("message") == "TCP framing works correctly."
    ):
        print("\nTCP FRAMING TEST: SUCCESS")
    else:
        print("\nTCP FRAMING TEST: FAILED")


if __name__ == "__main__":
    main()