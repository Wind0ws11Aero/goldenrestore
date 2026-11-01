"""Shows what each Apple-ID scope drops from a protective backup, and checks
that the upload-side and the prune-side filter still agree.

The two filters must agree on every file: a file the *upload* filter drops
while the *prune* filter keeps its manifest row leaves a row without a
payload, and the restore agent rejects that backup with MBErrorDomain/205.

The upload-side check uses the real device-side names captured from an iOS
27 backup (``idcap.jsonl``) when it is available, so the comparison runs
against the actual name layout instead of a guess.

    python diag_apple_id_scope.py [BACKUP_DIR] [PASSWORD] [CAPTURE_JSONL]

Scopes:
    full      include_apple_account=True,  include_apple_identity=True   (default)
    identity  include_apple_account=True,  include_apple_identity=False  (upstream parity)
    none      include_apple_account=False, include_apple_identity=False  (no Apple-ID state)
"""
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service  # noqa: E402

from goldenrestore.src.protective import (  # noqa: E402
    _DOMAIN_PREFIXES,
    _TREE_DOMAIN_SEGMENTS,
    _device_relative_path,
    _device_tree_name,
    _identity_container_domain,
    _keep_protective_entry,
    is_protective_device_file,
)

DEFAULT_BACKUP = None
DEFAULT_PASSWORD = "gnug"
DEFAULT_CAPTURE = Path("/tmp/gn_idcap_1793520617/idcap.jsonl")
# The capture files are taken with these settings — the comparison has to use
# the same ones, or every file the capture dropped shows up as "newly kept".
CAPTURE_INCLUDE_PHOTOS = False
CAPTURE_INCLUDE_KEYCHAIN = False

SCOPES = {
    "full": (True, True),
    "identity": (True, False),
    "none": (False, False),
}


def load_rows(device_dir: Path, password: str):
    """Manifest rows as (domain, relativePath, flags), decrypted if needed."""
    manifest_db = device_dir / "Manifest.db"
    if Mobilebackup2Service._is_encrypted_backup(device_dir):
        with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tmp:
            decrypted = Path(tmp.name)
        Mobilebackup2Service._decrypt_backup_manifest_db(device_dir, password, decrypted)
    else:
        decrypted = manifest_db
    con = sqlite3.connect(str(decrypted))
    try:
        return con.execute(
            "SELECT domain, relativePath, flags FROM Files").fetchall()
    finally:
        con.close()


def load_capture(path: Path):
    """(device_name, keep) pairs recorded during a real protective backup."""
    if not path.is_file():
        return []
    out = []
    with path.open() as fh:
        for line in fh:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            out.append((record["device_name"], bool(record["keep"])))
    return out


def upload_domain(device_name: str) -> str:
    """The manifest domain an upload lands in.

    On iOS 27 the HomeDomain tree arrives without a domain prefix
    (``/.b/6/Library/...``) and the system-preference tree arrives as
    ``/.b/7/preferences/...``.
    """
    derived = _identity_container_domain(device_name)
    if derived:
        return derived
    name = _device_tree_name(device_name)
    for domain in _DOMAIN_PREFIXES:
        if name.startswith(domain + "/"):
            return domain
    for segment, domain in _TREE_DOMAIN_SEGMENTS.items():
        if name == segment or name.startswith(segment + "/"):
            return domain
    return "HomeDomain"


def compare(capture_rows, include_apple_account, include_apple_identity):
    """Every upload name, judged by the upload filter and the prune filter.

    Returns ``(fatal, informational)``. A *fatal* disagreement is a file the
    upload filter drops while the prune filter keeps its manifest row: the
    device never uploads it, the row stays, and the restore agent rejects the
    backup with MBErrorDomain/205. The other direction only uploads bytes that
    are pruned away again.
    """
    fatal, informational = [], []
    for device_name, _was_kept in capture_rows:
        domain = upload_domain(device_name)
        relative_path = _device_relative_path(device_name)
        upload_says = is_protective_device_file(
            device_name,
            include_photos=CAPTURE_INCLUDE_PHOTOS,
            include_keychain=CAPTURE_INCLUDE_KEYCHAIN,
            include_apple_account=include_apple_account,
            include_apple_identity=include_apple_identity)
        prune_says = _keep_protective_entry(
            domain, relative_path,
            include_photos=CAPTURE_INCLUDE_PHOTOS,
            include_keychain=CAPTURE_INCLUDE_KEYCHAIN,
            include_apple_account=include_apple_account,
            include_apple_identity=include_apple_identity)
        if upload_says == prune_says:
            continue
        entry = (device_name, domain, relative_path, upload_says, prune_says)
        if not upload_says and prune_says:
            fatal.append(entry)
        else:
            informational.append(entry)
    return fatal, informational


def main() -> int:
    backup = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BACKUP
    password = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PASSWORD
    capture = Path(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_CAPTURE
    if backup is None:
        base = Path.home() / ".goldennugget" / "protective"
        runs = sorted((p for p in base.glob("*/*/device_backup") if p.is_dir()),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        if not runs:
            print("No protective backup found under ~/.goldennugget/protective")
            return 1
        backup = runs[0]
    device_dir = backup
    if not (device_dir / "Manifest.db").exists():
        device_dir = next(p for p in backup.iterdir() if p.is_dir()
                          and (p / "Manifest.db").exists())
    print(f"Backup: {device_dir}")

    rows = load_rows(device_dir, password)
    capture_rows = load_capture(capture)
    if not capture_rows:
        print(f"\n(no capture file at {capture} — upload-side check skipped)")

    failures = 0
    for scope, (include_apple_account, include_apple_identity) in SCOPES.items():
        print(f"\n===== scope {scope} (include_apple_account={include_apple_account}, "
              f"include_apple_identity={include_apple_identity}) =====")
        dropped = []
        for domain, relative_path, flags in rows:
            keep = _keep_protective_entry(domain, relative_path or "",
                                          include_apple_account=True,
                                          include_apple_identity=True)
            keep_off = _keep_protective_entry(domain, relative_path or "",
                                              include_apple_account=include_apple_account,
                                              include_apple_identity=include_apple_identity)
            if keep and not keep_off:
                dropped.append((domain, relative_path, flags))
        print(f"manifest rows dropped ({len(dropped)}):")
        for domain, relative_path, flags in sorted(dropped):
            print(f"  {domain} :: {relative_path}  flags={flags}")

        if not capture_rows:
            continue
        fatal, informational = compare(capture_rows, include_apple_account,
                                       include_apple_identity)
        print(f"\nuploads the filter drops while the prune filter keeps them — "
              f"row without payload, MBErrorDomain/205 (must be 0): {len(fatal)}")
        for name, domain, relative_path, upload_says, prune_says in sorted(fatal):
            print(f"    ! {name}  ->  {domain} :: {relative_path}  "
                  f"upload={upload_says} prune={prune_says}")
        print(f"uploads the prune filter drops while the filter keeps them — "
              f"wasted upload, harmless (informational): {len(informational)}")
        failures += len(fatal)

    print(f"\nfatal disagreements across all scopes: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
