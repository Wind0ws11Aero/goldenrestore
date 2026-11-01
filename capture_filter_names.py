"""Capture the real device-side upload names seen by the protective filter.

Runs one protective backup (no photos, keychain on) with a spy around
is_protective_device_file, records every (device_name, keep) decision, then
prints the names that look like SystemPreferencesDomain files — the ones whose
payloads are missing — plus a digest of everything that was dropped.

Afterwards it disables backup encryption again so the device is left as found.
"""
import asyncio
import json
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


async def main() -> None:
    lockdown = await create_using_usbmux(connection_type="USB")
    root = f"/tmp/gn_filter_capture_{int(time.time())}"
    Path(root).mkdir(parents=True, exist_ok=True)

    print(f"Backup root: {root} (include_photos=False, include_keychain=True)")
    print("Enter the device passcode when prompted.")
    await P.perform_protective_backup(
        lockdown, root,
        progress_callback=lambda x: print(f"\r{str(x)[:60]:<60}", end="", flush=True),
        include_photos=False,
        include_keychain=True,
        backup_password="gnug",
    )
    print("\nBackup done. Disabling encryption again...")
    async with P.ProtectiveBackupService(lockdown) as mb:
        await P.set_will_encrypt(mb, False, root, "gnug")
    print("Encryption disabled.")

    out = Path(root) / "filter_names.jsonl"
    with out.open("w") as fh:
        for name, keep in records:
            fh.write(json.dumps({"device_name": name, "keep": keep}) + "\n")
    print(f"\nRecorded {len(records)} decisions -> {out}")

    kept = sum(1 for _, k in records if k)
    print(f"kept={kept} dropped={len(records) - kept}")

    print("\n--- names containing 'SystemConfig' / 'networkextension' / 'SystemPreferences' ---")
    for name, keep in records:
        low = name.lower()
        if any(s in low for s in ("systemconfig", "networkextension", "systempreferences")):
            print(f"  keep={keep!s:<5} {name}")

    print("\n--- dropped names by first path segment (top 25) ---")
    from collections import Counter
    seg = Counter()
    for name, keep in records:
        if not keep:
            norm = name.replace("\\", "/").lstrip("/")
            seg[norm.split("/", 1)[0]] += 1
    for prefix, count in seg.most_common(25):
        print(f"  {count:5d}  {prefix}")


asyncio.run(main())
