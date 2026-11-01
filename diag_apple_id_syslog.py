"""Live syslog capture from the device, focused on the Apple Account side.

The device refuses com.apple.os_trace_relay while it is locked, so the iPad
has to be unlocked before this can start.

    python diag_apple_id_syslog.py [SECONDS]

Writes every entry to /tmp/gn_syslog.jsonl and prints the ones that mention
the account / identity / setup / activation stack as they arrive.
"""
import asyncio
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, "/Users/jason/Documents")
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.os_trace import OsTraceService

DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 1800.0
OUT = Path("/tmp/gn_syslog.jsonl")

INTERESTING = re.compile(
    r"appleaccount|identityservice|\bids\b|accountd|accounts\b|AKS|fairplay"
    r"|verif|ownership|activat|setupassistant|setup |SBAppleAccount"
    r"|applesignin|itunesstore|amsaccount",
    re.I)


async def connect():
    last = None
    for attempt in range(30):
        try:
            return await create_using_usbmux()
        except Exception as e:  # the device rejects connections while locked
            last = e
            print(f"connect attempt {attempt + 1}: {type(e).__name__}: {e}",
                  flush=True)
            await asyncio.sleep(5)
    raise last


async def main():
    deadline = time.monotonic() + DURATION
    c = await connect()
    print("connected:", c.udid, flush=True)
    hits = 0
    with OUT.open("w") as fh:
        async with OsTraceService(c) as svc:
            try:
                pids = await svc.get_pid_list()
                names = sorted({v.get("ProcessName", "?")
                                for v in (pids.get("Payload") or {}).values()
                                if isinstance(v, dict)})
                print(f"{len(names)} processes running", flush=True)
            except Exception as e:
                print("pid list failed:", e, flush=True)
            async for entry in svc.syslog():
                record = {
                    "t": entry.timestamp.isoformat(),
                    "p": entry.image_name,
                    "l": str(entry.level),
                    "m": entry.message,
                }
                fh.write(json.dumps(record) + "\n")
                fh.flush()
                if INTERESTING.search(entry.image_name or "") or \
                        INTERESTING.search(entry.message or ""):
                    hits += 1
                    print(f"[{record['t']}] {record['p']}: "
                          f"{record['m'][:400]}", flush=True)
                if time.monotonic() > deadline:
                    print("duration reached", flush=True)
                    break
    print(f"done, {hits} interesting lines -> {OUT}", flush=True)
    await c.close()


asyncio.run(main())
