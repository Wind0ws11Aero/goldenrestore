# GoldenRestore

Standalone async Python package for the GoldenNugget iOS restore engine.

It extracts the core of the [GoldenNugget](https://github.com/GoldenNugget-Team) app
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

## Restoring a prebuilt Backup

`restore_files` also accepts a prebuilt `Backup` (the legacy sparse model)
instead of a `FileToRestore` list — it is restored as-is through the sparse
pass, with the rest of the flow (protective backup, restore, setup skip)
running around it:

```python
from goldennugget import Backup, ConcreteFile, restore_files

backup = Backup(files=[
    ConcreteFile(
        domain="HomeDomain",
        path="Library/Preferences/com.apple.springboard.plist",
        contents=plist_bytes,
        owner=501, group=501,
    ),
], apps=[])

await restore_files(backup, reboot=True, lockdown_client=client,
                    progress_callback=lambda pct: print(f"{pct:.0f}%"))
```

## The post-restore "verify your Apple ID" prompt

iOS asks the user to verify the Apple Account when it finds the account on the
device but cannot validate the session that goes with it. The prompt shows up
in **both** flows — with and without `include_keychain` — so neither the
keychain nor the security-recovery wipe explains it on its own. What the two
flows have in common is the Phase 3 restore of the Apple-ID state.

### The scope difference against upstream GoldenNugget

The protective scope here is upstream's **plus** two groups upstream does not
carry:

| group | upstream | here |
|-------|----------|------|
| `HomeDomain/Library/Accounts` (account record) | yes | yes |
| `HomeDomain/Library/IdentityServices/Persistence/*` (IDS token + provisioning cache) | **no** | **yes** |
| `SysContainerDomain-com.apple.icloud.findmydeviced`, `…findmydevice.managed`, `…com.apple.adid` | **no** | **yes** |
| `com.apple.ids*`, `com.apple.identityservices*`, `com.apple.accountsd`, `com.apple.madrid` plists | **no** | **yes** |

Upstream restores the account record *only* — the device keeps its own live
session state. This library additionally restores a **copy** of the
identity-services token cache next to it, which is the state that goes stale
and leaves the device unable to validate the account it just found.

### Two switches

**`include_apple_identity=False` — upstream parity.** Leaves the
identity-services session state (`Library/IdentityServices`, the
identity/IDS/account-daemon preference plists) out of the backup and the
restore. The account record is still restored, so the device stays signed in;
it just keeps using its own session instead of a restored token cache.

```python
await restore_files(files, include_apple_identity=False, lockdown_client=client)
```

**`include_apple_id=False` — no Apple-ID state at all.** Additionally leaves
out the account record (`Library/Accounts`), the Apple-account preference
plists and the Find My / adid containers. Nothing on the device claims an
Apple Account, so the prompt cannot appear. The device ends up **signed out**
of the Apple Account.

```python
await restore_files(files, include_apple_id=False, lockdown_client=client)
```

Find My has to be off for the restore to run at all (the device rejects the
restore otherwise), so no Activation Lock is left behind by either path.

### Why `include_keychain=True` does not remove the prompt

The keychain blob is captured correctly: the device uploads
`KeychainDomain/keychain-backup.plist` as soon as backup encryption is on,
and it rides the protective backup in the manifest (verified on a real backup:
1.2 MB, 723 generic-password items). The gap is on the restore side. Phase 3
is a *selective* mobilebackup2 restore — the device is not erased by it
(`RemoveItemsNotRestored=False`) — and the restore agent does not re-import a
backup keychain onto a device it is not replacing.

`include_keychain=True` also has a side effect that works *against* the
prompt: it forces the classic flow (`merge_phases=False`), so the sparse pass
triggers the security-recovery wipe and the device loses the keychain it was
carrying anyway. The device is then re-paired, which is why its pair record
comes back without an `EscrowBag` (`_Mobilebackup2NoEscrow` exists for that).
Upstream never does this — it only turns `merge_phases` off through the
`GOLDENNUGGET_NO_MERGE_PHASES=1` environment variable.

### Keychain handling in detail

The keychain only rides an **encrypted** backup. If backup encryption is not
enabled on the device, the tool turns it on automatically before Phase 1
(using `backup_password` when given, otherwise the built-in default `gnug`)
and turns it off again after the restore — the device ends in the state the
user left it in, no setup required. If encryption is already on,
`backup_password` is required. That password is used to prune/inject the
encrypted manifest and for the Phase 3 restore.

`include_keychain=True` forces the classic (non-merged) flow: the device
only imports the keychain when restoring onto a wiped system, so the sparse
pass must trigger the security-recovery wipe before the protective restore.
The run takes longer and the device re-pairs mid-flow.

This works in the inject flow too. Injection and the keychain used to be
mutually exclusive — injection only ran on an *unencrypted* manifest, but the
keychain only rides an *encrypted* one. Injected payloads are now encrypted
with a fresh per-file key (wrapped by the manifest keybag and stamped into the
blob's `EncryptionKey` field), so tweaks are injected into an **encrypted**
protective backup and survive the wipe. If the prepared backup is unencrypted
(it therefore has no keychain), the flow takes a fresh encrypted backup in
Phase 1 and injects the tweaks into that. A minimal `crash_on_purpose` sparse
payload is kept so the security-recovery wipe still fires when nothing else
rides the sparse pass.

The same applies to a prepared backup that is encrypted but was taken
*without* `include_keychain` (e.g. a `ProtectiveBackupCache` master refreshed
with the default `include_keychain=False`): it never uploaded `KeychainDomain`,
so restoring it would bring back the Apple ID account record without its
credentials and the verification prompt would appear anyway. `restore_files`
detects this with `backup_contains_keychain()` (a payload-existence probe that
needs no manifest password) and swaps such a backup for a fresh encrypted one
in Phase 1, just like the unencrypted case.

`diag_apple_id_scope.py` prints what each scope drops from a real backup and
checks that the upload-side and prune-side filters still agree on every file
(a disagreement in that direction leaves a manifest row without a payload and
the restore fails with MBErrorDomain/205). `diag_apple_id_restore.py` runs the
decisive experiment on the device (one scope per run, default flow — no
`include_keychain`, so no wipe). `diag_apple_id_syslog.py` streams the device's
own unified log; iOS refuses `com.apple.os_trace_relay` while the device is
locked, so it needs an unlocked iPad.

## Public API

| Name | Purpose |
|------|---------|
| `perform_restore(backup, reboot, lockdown_client, ...)` | Sparse restore of a `Backup`. |
| `reboot_device(reboot, lockdown_client)` | Reboot the device via Diagnostics. |
| `restore_files(files, ...)` | Six-phase protective restore flow; `files` may be a `FileToRestore` list or a prebuilt `Backup`. `include_apple_identity=False` keeps the restored identity-services session state out of the backup; `include_apple_id=False` keeps the whole Apple-ID state out. |
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
