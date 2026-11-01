"""Capture the real device-side upload names for the Find My / identity files.

Runs one protective backup (no photos, no keychain) with a spy around
is_protective_device_file, records every (device_name, keep) decision, then
prints the names matching the identity domains / IdentityServices path.
"""
import asyncio
import json
import re
import time
from pathlib import Path

from pymobiledevice3.lockdown import create_using_usbmux

import goldenrestore.src.protective as P

records: list = []
_orig = P.is_protective_device_file


def _spy(device_name, *args, **kwargs):
    result = _orig(device_name, *args, **kwargs)
    records.append((device_name, bool(result)))
    return result


P.is_protective_device_file = _spy

PATTERNS = re.compile(
    r"findmy|identityservices|fmip|adid|fairplay|systemgroup|SysShared|SysContainer",
    re.I,
)


async def main() -> None:
    lockdown = await create_using_usbmux(connection_type="USB")
    root = f"/tmp/gn_idcap_{int(time.time())}"
    Path(root).mkdir(parents=True, exist_ok=True)
    print(f"Backup root: {root}", flush=True)
    await P.perform_protective_backup(
        lockdown, root,
        progress_callback=lambda x: None,
        include_photos=False,
        include_keychain=False,
    )
    await lockdown.close()

    out = Path(root) / "idcap.jsonl"
    with out.open("w") as fh:
        for name, keep in records:
            fh.write(json.dumps({"device_name": name, "keep": keep}) + "\n")
    print(f"\nRecorded {len(records)} decisions -> {out}", flush=True)

    print("\n--- identity-related device names ---", flush=True)
    for name, keep in records:
        if PATTERNS.search(name):
            print(f"  keep={str(keep):<5} {name}", flush=True)


asyncio.run(main())
