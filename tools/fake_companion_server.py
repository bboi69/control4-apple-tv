#!/usr/bin/env python3
"""Tiny Companion frame recorder for local driver development.

This is not a full Apple TV emulator. It accepts TCP connections, decodes the
Companion 1-byte frame type + 3-byte big-endian length wrapper, and prints each
payload as hex. It is useful before the real fake device exists because it
proves the Lua side writes binary-safe frames correctly.
"""

from __future__ import annotations

import argparse
import socket


def read_exact(conn: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise EOFError("client disconnected")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def serve(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        print(f"fake Companion frame recorder listening on {host}:{port}")

        while True:
            conn, address = server.accept()
            with conn:
                print(f"client connected from {address[0]}:{address[1]}")
                try:
                    while True:
                        header = read_exact(conn, 4)
                        frame_type = header[0]
                        length = int.from_bytes(header[1:4], "big")
                        payload = read_exact(conn, length)
                        print(
                            f"frame type=0x{frame_type:02x} length={length} "
                            f"payload={payload.hex()}"
                        )
                except EOFError:
                    print("client disconnected")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=49153, type=int)
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
