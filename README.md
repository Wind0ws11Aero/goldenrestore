# GoldenRestore

Standalone async Python package for the GoldenNugget iOS restore engine.

It extracts the core of the [GoldenNugget](https://github.com/GoldenNugget) app
into a device-only library: the sparse `Backup` / `perform_restore` primitives
plus the full **six-phase iOS 27 protective-restore flow** (`restore_files`).

## Install

```sh
pip install -r requirements.txt
# or
pip install pymobiledevice3 cryptography packaging
```

`pymobiledevice3` is only needed at runtime (device communication); the pure
backup-building modules are import-free of the device stack.

## Quick start — sparse restore

Build a `Backup` from `FileToRestore` entries and hand it to
`perform_restore`:

```python
import asyncio
from pathlib import Path

from pymobiledevice3.lockdown import create_using_usbmux
from goldennugget import Backup, ConcreteFile, perform_restore

async def main():
    client = await create_using_usbmux()

    backup = Backup(files=[
        ConcreteFile(
            domain="HomeDomain",
            path="Library/Preferences/com.apple.springboard.plist",
            contents=Path("springboard.plist").read_bytes(),
            owner=501, group=501,
        ),
    ], apps=[])

    await perform_restore(backup, reboot=False, lockdown_client=client)

asyncio.run(main())
```

## Full six-phase flow

`restore_files` runs the complete protective backup + sparse + restore pipeline
(Phases 1-6) with the optional cache, AFC media store, and setup-skip:

```python
from goldennugget import (
    FileToRestore, perform_protective_backup, ProtectiveBackupCache,
    restore_files,
)

files = [
    FileToRestore(
        contents=plist_bytes,
        restore_path="com.apple.springboard.plist",
        domain="HomeDomain",
        owner=501, group=501,
    ),
    # ...
]

# Optional: prepare a protective backup root (cached or live) to inject the
# tweaks into instead of sparse-restoring them.
# prepared = ...  # a PreparedBackup

await restore_files(
    files,
    reboot=True,
    lockdown_client=client,
    progress_callback=lambda pct: print(f"{pct:.0f}%"),
    prepared_backup_root=prepared,
    skip_setup=True,
    merge_phases=True,
)
```

## Public API

| Name | Purpose |
|------|---------|
| `perform_restore(backup, reboot, lockdown_client, ...)` | Sparse restore of a `Backup`. |
| `reboot_device(reboot, lockdown_client)` | Reboot the device via Diagnostics. |
| `restore_files(files, ...)` | Full six-phase protective restore flow. |
| `perform_protective_backup(...)` | Build a selective protective backup. |
| `ProtectiveBackupCache` / `peek_cache_info` | Per-device backup cache. |
| `PreparedBackup` | Handle to a prepared/working backup root. |
| `Backup`, `ConcreteFile`, `Directory`, `SymbolicLink`, `AppBundle` | Sparse backup model. |
| `FileToRestore` | A single file the restore agent should install. |
| `RestoreOptions` / `RestoreSession` | Flow configuration & per-apply state. |
| `NuggetException` | Package base exception. |

## Storage locations

Backup/cache/photo-store roots default to `~/.goldennugget` and can be
overridden with the `GOLDENNUGGET_BACKUP_DIR` environment variable.

## License

MIT (see the upstream GoldenNugget project).
