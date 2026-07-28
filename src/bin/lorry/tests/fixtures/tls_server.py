#!/usr/bin/env python3

import socket
import ssl
import sys


RESPONSES = {
    "success": b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "redirect": (
        b"HTTP/1.1 302 Found\r\nContent-Length: 4\r\n"
        b"Location: /next\r\n\r\nbody"
    ),
    "truncated": b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
    "malformed": b"NOT HTTP\r\n\r\n",
}


def main():
    if len(sys.argv) != 4 or sys.argv[3] not in RESPONSES:
        raise SystemExit("usage: tls_server.py CERT KEY SCENARIO")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[1], sys.argv[2])
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        print(listener.getsockname()[1], flush=True)
        connection, _ = listener.accept()
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                request = bytearray()
                while not request.endswith(b"\r\n\r\n"):
                    chunk = stream.recv(4096)
                    if not chunk or len(request) + len(chunk) > 64 * 1024:
                        return
                    request.extend(chunk)
                stream.sendall(RESPONSES[sys.argv[3]])
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


if __name__ == "__main__":
    main()
