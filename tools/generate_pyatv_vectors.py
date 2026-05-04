#!/usr/bin/env python3
"""Generate OPACK vectors from the locally cloned pyatv source.

This avoids importing the whole pyatv package and its runtime dependencies.
"""

from __future__ import annotations

import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
OPACK_PATH = ROOT / "pyatv" / "pyatv" / "support" / "opack.py"


def load_opack():
    spec = importlib.util.spec_from_file_location("pyatv_local_opack", OPACK_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {OPACK_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    opack = load_opack()
    fixed_public_key = bytes(range(32))
    fixed_encrypted_data = bytes(range(16))
    vectors = {
        "launch_bundle": {
            "_i": "_launchApp",
            "_t": 2,
            "_c": {"_bundleID": "com.netflix.Netflix"},
            "_x": 1,
        },
        "launch_url": {
            "_i": "_launchApp",
            "_t": 2,
            "_c": {"_urlS": "https://www.netflix.com/title/80234304"},
            "_x": 2,
        },
        "fetch_apps": {
            "_i": "FetchLaunchableApplicationsEvent",
            "_t": 2,
            "_c": {},
            "_x": 3,
        },
        "hid_up_release": {
            "_i": "_hidC",
            "_t": 2,
            "_c": {"_hBtS": 2, "_hidC": 1},
            "_x": 4,
        },
        "session_start": {
            "_i": "_sessionStart",
            "_t": 2,
            "_c": {"_srvT": "com.apple.tvremoteservices", "_sid": 123456},
            "_x": 5,
        },
        "pair_verify_start": {
            "_pd": b"\x06\x01\x01\x03\x20" + fixed_public_key,
            "_auTy": 4,
        },
        "pair_verify_next": {
            "_pd": b"\x06\x01\x03\x05\x10" + fixed_encrypted_data,
        },
    }

    for name, data in vectors.items():
        print(f"{name} {opack.pack(data).hex()}")


if __name__ == "__main__":
    main()
