import json
import struct
import uuid

HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 10 * 1024 * 1024


def create_request(request_type, **data):
    request = {
        "type": request_type,
        "request_id": str(uuid.uuid4())
    }
    request.update(data)
    return request


def send_json(sock, data):
    message = json.dumps(data).encode("utf-8")

    if len(message) > MAX_MESSAGE_SIZE:
        raise ValueError("Message is too large.")

    header = struct.pack("!I", len(message))
    sock.sendall(header + message)


def receive_exact(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Connection closed by the peer."
            )

        data.extend(chunk)

    return bytes(data)


def receive_json(sock):
    header = receive_exact(
        sock,
        HEADER_SIZE
    )

    message_length = struct.unpack(
        "!I",
        header
    )[0]

    if (
        message_length <= 0
        or message_length > MAX_MESSAGE_SIZE
    ):
        raise ValueError(
            "Invalid message size."
        )

    message = receive_exact(
        sock,
        message_length
    )

    return json.loads(
        message.decode("utf-8")
    )
