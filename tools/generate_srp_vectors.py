#!/usr/bin/env python3
"""Generate deterministic HAP SRP vectors from pyatv's srptools dependency."""

from __future__ import annotations

import hashlib

from srptools import SRPClientSession, SRPContext, SRPServerSession, constants


def main() -> None:
    pin = "1234"
    salt = "0102030405060708090a0b0c0d0e0f10"
    client_private = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    server_private = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

    context = SRPContext(
        "Pair-Setup",
        pin,
        prime=constants.PRIME_3072,
        generator=constants.PRIME_3072_GEN,
        hash_func=hashlib.sha512,
    )
    password_hash = context.get_common_password_hash(int(salt, 16))
    verifier = context.get_common_password_verifier(password_hash)
    server = SRPServerSession(context, f"{verifier:x}", private=server_private)
    client = SRPClientSession(context, private=client_private)
    client.process(server.public, salt)
    server.process(client.public, salt)

    assert client.verify_proof(client.key_proof_hash)
    assert server.verify_proof(client.key_proof)

    values = {
        "pin": pin,
        "salt": salt,
        "a": client_private,
        "b": server_private,
        "x": f"{password_hash:0128x}",
        "A": client.public.zfill(768),
        "B": server.public.zfill(768),
        "u": f"{context.get_common_secret(int(client.public, 16), int(server.public, 16)):0128x}",
        "K": client.key.decode(),
        "M1": client.key_proof.decode(),
        "M2": client.key_proof_hash.decode(),
    }

    for key, value in values.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
