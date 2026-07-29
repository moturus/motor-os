#!/usr/bin/env python3

import socket
import ssl
import sys
import time


RESPONSES = {
    "success": b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "redirect": (
        b"HTTP/1.1 302 Found\r\nContent-Length: 4\r\n"
        b"Location: /next\r\n\r\nbody"
    ),
    "chunked": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"3\r\nabc\r\n2;test=yes\r\nde\r\n0\r\nTrailer: yes\r\n\r\n"
    ),
    "close": b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil close",
    "stall": b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "hostname": b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
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
        print(f"LORRY_TLS_PORT={listener.getsockname()[1]}", flush=True)
        connection, _ = listener.accept()
        try:
            with context.wrap_socket(connection, server_side=True) as stream:
                request = bytearray()
                while not request.endswith(b"\r\n\r\n"):
                    chunk = stream.recv(4096)
                    if not chunk or len(request) + len(chunk) > 64 * 1024:
                        return
                    request.extend(chunk)
                if sys.argv[3] == "stall":
                    time.sleep(2)
                stream.sendall(RESPONSES[sys.argv[3]])
                stream.unwrap().close()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


if __name__ == "__main__":
    main()
