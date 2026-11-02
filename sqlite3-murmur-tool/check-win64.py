#!/usr/bin/env python3
"""Exercise the actual Windows executable, natively or using Wine."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("executable", type=Path)
parser.add_argument("--runner", help="Wine executable on Linux")
parser.add_argument("--linux-cli", type=Path, help="Also check format interoperability")
args = parser.parse_args()
phrase = "Windows encrypted store passphrase — preserved"


def winpath(path):
    path = Path(path).resolve()
    return "Z:" + path.as_posix() if args.runner else str(path)


def execute(store, *commands, secret=phrase, success=True, linux=False):
    launcher = [str(args.linux_cli.resolve())] if linux else (
        ([args.runner] if args.runner else []) + [str(args.executable.resolve())])
    result = subprocess.run(
        launcher + ["-batch", "-noinit", "--passphrase-fd", "0",
                    str(store) if linux else winpath(store), *commands],
        input=secret + "\n", text=True, encoding="utf-8", capture_output=True, timeout=90,
    )
    assert (result.returncode == 0) == success, (commands, result.returncode, result.stdout, result.stderr)
    return result.stdout.replace("\r\n", "\n")


with tempfile.TemporaryDirectory(prefix="murmur-win64-") as tmp:
    root = Path(tmp)
    store = root / "store with spaces"
    assert execute(store, "CREATE TABLE t(v); INSERT INTO t VALUES(42); PRAGMA murmur_kdf;") == "scrypt\n"
    assert execute(store, "SELECT v FROM t;") == "42\n"
    execute(store, "SELECT v FROM t;", secret="wrong passphrase", success=False)
    for command in ("backup", "save", "clone"):
        target = root / command
        execute(store, f'.{command} "{winpath(target)}"')
        assert execute(target, "SELECT v FROM t;") == "42\n"
    target = root / "vacuum"
    execute(store, "VACUUM INTO '" + winpath(target).replace("'", "''") + "';")
    assert execute(target, "SELECT v FROM t;") == "42\n"
    restored = root / "restored"
    execute(restored, f'.restore "{winpath(root / "backup")}"')
    assert execute(restored, "SELECT v FROM t;") == "42\n"
    attached = root / "attached"
    execute(store, f"ATTACH '{winpath(attached)}' AS other; CREATE TABLE other.t(v); INSERT INTO other.t VALUES(8); DETACH other;")
    assert execute(attached, "SELECT v FROM t;") == "8\n"
    assert execute(store, f'.open "{winpath(attached)}"', "SELECT v FROM t;") == "8\n"
    execute(store, f'.open --readonly "{winpath(attached)}"', "INSERT INTO t VALUES(9);", success=False)
    aegis = root / "aegis"
    execute(aegis, "PRAGMA cipher=aes256gcm; PRAGMA compression=zstd9; CREATE TABLE t(v); INSERT INTO t VALUES(55);")
    assert execute(aegis, "PRAGMA cipher; SELECT v FROM t;") == "aes256gcm\n55\n"
    execute(store, "PRAGMA journal_mode=WAL;", success=False)
    missing = root / "missing"
    execute(store, f'.restore "{winpath(missing)}"', success=False)
    assert not missing.exists()
    if args.linux_cli:
        assert execute(store, "SELECT v FROM t;", linux=True) == "42\n"
        native = root / "linux-store"
        execute(native, "CREATE TABLE t(v); INSERT INTO t VALUES(17);", linux=True)
        assert execute(native, "SELECT v FROM t;") == "17\n"
    print("WIN64-CHECK-OK: encrypted creation/reopen, wrong key, copies, ATTACH, .open, read-only, AEGIS, compression, restrictions, format interoperability")
