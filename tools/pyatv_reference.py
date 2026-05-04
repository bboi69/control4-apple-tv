#!/usr/bin/env python3
"""Generate pyatv reference observations for this port.

This script intentionally starts small. It connects with pyatv, prints the
launchable app list, and can launch a supplied bundle id or URL. Use it against
a real Apple TV to capture the behavior our Lua port must match.
"""

from __future__ import annotations

import argparse
import asyncio
import json


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True, help="Apple TV IP address")
    parser.add_argument("--launch", help="Bundle id or URL to launch")
    args = parser.parse_args()

    import pyatv

    configs = await pyatv.scan(hosts=[args.address], timeout=5)
    if not configs:
        raise SystemExit(f"no Apple TV found at {args.address}")

    atv = await pyatv.connect(configs[0])
    try:
        apps = await atv.apps.app_list()
        print(
            json.dumps(
                [{"name": app.name, "identifier": app.identifier} for app in apps],
                indent=2,
                sort_keys=True,
            )
        )
        if args.launch:
            await atv.apps.launch_app(args.launch)
            print(f"launched {args.launch}")
    finally:
        atv.close()


if __name__ == "__main__":
    asyncio.run(main())
