#!/usr/bin/env python3
"""End-to-end tests using the real shell, native client, and controlling tty."""
import fcntl
import hashlib
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import termios
import time
import unittest

CLI, NATIVE, EXTENSION, FAULT_CLI = [str(Path(arg).resolve()) for arg in sys.argv[1:5]]
sys.argv[1:] = []
PHRASE = "a fairly long test passphrase — with spaces "
MASTER = hashlib.sha256(PHRASE.encode()).hexdigest()


def quote(path):
    return "'" + str(path).replace("'", "''") + "'"


class Terminal:
    def __init__(self, *args):
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)

        def controlling_tty():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen(
            [CLI, "-batch", "-noinit", *map(str, args)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(self.slave,), preexec_fn=controlling_tty,
        )
        self.output = b""

    def expect(self, text):
        marker = text.encode()
        deadline = time.monotonic() + 10
        while marker not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.master], [], [], remaining)[0]:
                raise AssertionError(f"terminal timeout waiting for {text!r}: {self.output!r}")
            chunk = os.read(self.master, 4096)
            if not chunk:
                raise AssertionError(f"terminal EOF: {self.output!r}")
            self.output += chunk

    def send(self, text):
        os.write(self.master, text.encode() + b"\n")

    def finish(self):
        out, err = self.proc.communicate(timeout=15)
        assert termios.tcgetattr(self.slave) == self.original, "terminal settings not restored"
        return self.proc.returncode, out.decode(), err.decode()

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.communicate()
        os.close(self.master)
        os.close(self.slave)


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="murmur-cli-check-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "store"

    def cli(self, *args, phrase=PHRASE, sql_input=None, ok=True, key_fd=True, no_init=True):
        with tempfile.TemporaryFile() as key:
            key.write((phrase + "\n").encode())
            key.seek(0)
            argv = [CLI, "-batch"] + (["-noinit"] if no_init else [])
            if key_fd:
                argv += ["--passphrase-fd", str(key.fileno())]
            result = subprocess.run(
                argv + list(map(str, args)), input=sql_input, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(key.fileno(),) if key_fd else (),
                start_new_session=True, timeout=20,
            )
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn("AddressSanitizer", result.stderr)
        self.assertNotIn("runtime error:", result.stderr)
        return result

    def native(self, store, sql, master=MASTER):
        result = subprocess.run([NATIVE, str(store), master, sql],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def create(self):
        self.cli(self.store, "CREATE TABLE example(id INTEGER PRIMARY KEY, value TEXT);"
                            "INSERT INTO example VALUES(1,'hello');")

    def test_help_version_memory(self):
        self.assertIn("--passphrase-fd", self.cli("--help", key_fd=False).stderr)
        self.assertIn("libmurmur", self.cli("--version", key_fd=False).stdout)
        self.assertEqual(self.cli(":memory:", "SELECT 6*7;", key_fd=False).stdout, "42\n")
        self.assertEqual(self.cli(sql_input="SELECT 7;\n", key_fd=False).stdout, "7\n")

    def test_native_interoperability_and_protection(self):
        payload = "murmur_secret_payload_1234567890_unique"
        result = self.cli(self.store, "CREATE TABLE example(value TEXT);"
                          f"INSERT INTO example VALUES('{payload}');"
                          "PRAGMA cipher; PRAGMA compression; PRAGMA murmur_kdf;")
        self.assertEqual(result.stdout, "aes256gcm\nzstd3\nargon2id\n")
        self.assertTrue((self.store / "CURRENT").is_file())
        self.assertEqual(self.native(self.store, "SELECT value FROM example;"), payload + "\n")
        self.cli(self.store, "SELECT * FROM example;", phrase="wrong passphrase", ok=False)
        self.assertEqual(self.cli(self.store, "SELECT value FROM example;").stdout, payload + "\n")
        for file in self.store.iterdir():
            if file.is_file():
                self.assertNotIn(payload.encode(), file.read_bytes(), str(file))

    def test_existing_native_store_preserved(self):
        self.native(self.store, "CREATE TABLE example(value); INSERT INTO example VALUES(17);")
        self.assertEqual(self.cli(self.store, "SELECT value FROM example;").stdout, "17\n")
        self.assertEqual(self.native(self.store, "PRAGMA murmur_kdf;"), "direct\n")

    def test_raw_hex_convention(self):
        raw = "0123456789abcdef" * 4
        self.cli(self.store, "CREATE TABLE example(value); INSERT INTO example VALUES(18);", phrase=raw)
        self.assertEqual(self.native(self.store, "SELECT value FROM example;", master=raw), "18\n")

    def test_sql_shell_and_scripts(self):
        csv = self.root / "input.csv"
        csv.write_text("2,world\n")
        out = self.root / "export.csv"
        script = self.root / "commands.sql"
        script.write_text(f".import --csv {csv} example\nSELECT count(*) FROM example;\n")
        self.create()
        result = self.cli(self.store, sql_input=f".tables\n.schema example\n.read {script}\n"
                          f".headers on\n.mode csv\n.once {out}\nSELECT * FROM example ORDER BY id;\n")
        self.assertIn("example", result.stdout)
        self.assertIn("CREATE TABLE", result.stdout)
        self.assertIn("2\n", result.stdout)
        self.assertEqual(out.read_text().splitlines(), ["id,value", "1,hello", "2,world"])
        result = self.cli(self.store, sql_input=".parameter init\n.parameter set @id 2\n"
                          "SELECT value FROM example WHERE id=@id;\n.mode json\nSELECT 42 AS answer;\n")
        self.assertIn("world\n", result.stdout)
        self.assertIn('"answer":42', result.stdout)
        dump = self.cli(self.store, ".dump").stdout
        imported = self.root / "imported"
        self.cli(imported, sql_input=dump)
        self.assertEqual(self.cli(imported, "SELECT count(*) FROM example;").stdout, "2\n")
        init = self.root / "init.sql"
        init.write_text(".mode list\nSELECT 'init-ok';\n")
        self.assertIn("init-ok", self.cli("-init", init, self.store, "SELECT 1;", no_init=False).stdout)
        self.cli(self.store, sql_input=".bail on\nSELECT missing;\nSELECT 'unreachable';\n", ok=False)

    def test_transactions_and_features(self):
        self.create()
        self.cli(self.store, "BEGIN; INSERT INTO example VALUES(2,'discard'); ROLLBACK;"
                            "CREATE VIRTUAL TABLE docs USING fts5(body);"
                            "INSERT INTO docs VALUES('searchable text');")
        self.assertEqual(self.cli(self.store, "SELECT count(*) FROM example;"
                                 "SELECT count(*) FROM docs WHERE docs MATCH 'searchable';").stdout, "1\n1\n")
        self.cli(self.store, "BEGIN; INSERT INTO example VALUES(3,'unfinished');")
        self.assertEqual(self.cli(self.store, "SELECT count(*) FROM example;").stdout, "1\n")
        empty = self.root / "aegis"
        self.cli(empty, "PRAGMA cipher='aegis256'; PRAGMA compression='zstd9';"
                        "CREATE TABLE example(value); INSERT INTO example VALUES('aegis');")
        self.assertEqual(self.cli(empty, "PRAGMA cipher; SELECT value FROM example;").stdout, "aegis256\naegis\n")
        self.cli(empty, "PRAGMA compression=none; INSERT INTO example VALUES('uncompressed');")
        self.cli(empty, "PRAGMA compression=zstd22; INSERT INTO example VALUES('compressed');")
        self.assertEqual(self.cli(empty, "SELECT count(*) FROM example;").stdout, "3\n")
        self.cli(empty, "PRAGMA cipher='aes256gcm';", ok=False)

    def test_explicit_exit_flushes(self):
        self.create()
        result = self.cli(self.store, sql_input="INSERT INTO example VALUES(2,'committed');\n.exit 7\n", ok=False)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(self.cli(self.store, "SELECT count(*) FROM example;").stdout, "2\n")
        script = self.root / "exit.sql"
        script.write_text("INSERT INTO example VALUES(3,'nested');\n.exit 8\n")
        result = self.cli(self.store, sql_input=f".read {script}\nINSERT INTO example VALUES(4,'unreachable');\n", ok=False)
        self.assertEqual(result.returncode, 8)
        self.assertEqual(self.cli(self.store, "SELECT count(*) FROM example;").stdout, "3\n")
        script.write_text("INSERT INTO example VALUES(4,'init-committed');\nSELECT missing;\n")
        self.cli("-bail", "-init", script, self.store, "SELECT 'unreachable';", no_init=False, ok=False)
        self.assertEqual(self.cli(self.store, "SELECT count(*) FROM example;").stdout, "4\n")

    def test_flush_failure_exit_status(self):
        self.create()
        for sql in ("SELECT 1;\n", ".exit 0\n"):
            with tempfile.TemporaryFile() as key:
                key.write((PHRASE + "\n").encode())
                key.seek(0)
                result = subprocess.run(
                    [FAULT_CLI, "-batch", "-noinit", "--passphrase-fd", str(key.fileno()), str(self.store)],
                    input=sql, text=True, capture_output=True, pass_fds=(key.fileno(),),
                    env={**os.environ, "MURMUR_CLI_TEST_FLUSH_FAILURE": "1"}, timeout=15,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("close/flush failed", result.stderr)

    def test_multiple_stores(self):
        self.create()
        attached = self.root / "attached"
        self.cli(self.store, f"ATTACH {quote(attached)} AS other;"
                 "CREATE TABLE other.example(value); INSERT INTO other.example VALUES('attached'); DETACH other;")
        self.assertEqual(self.cli(attached, "SELECT value FROM example;").stdout, "attached\n")
        result = self.cli(self.store, sql_input=f".open {attached}\nSELECT value FROM example;\n"
                          f".open --readonly {self.store}\nSELECT value FROM example;\n")
        self.assertEqual(result.stdout, "attached\nhello\n")
        self.cli("-readonly", self.store, "INSERT INTO example VALUES(2,'no');", ok=False)
        self.cli(self.store, sql_input=f".open --readonly {attached}\nINSERT INTO example VALUES('no');\n", ok=False)
        missing = self.root / "missing"
        self.cli(self.store, sql_input=f".open --ifexists {missing}\n", ok=False)
        self.assertFalse(missing.exists())
        other = self.root / "different-key"
        self.cli(other, "CREATE TABLE t(value); INSERT INTO t VALUES(99);", phrase="different phrase")
        self.cli(self.store, f"ATTACH {quote(other)} AS other;", ok=False)
        self.assertEqual(self.cli(other, "SELECT value FROM t;", phrase="different phrase").stdout, "99\n")

    def test_encrypted_copies(self):
        self.create()
        for command in ("backup", "save", "clone"):
            target = self.root / command
            self.cli(self.store, f".{command} {target}")
            self.assertEqual(self.cli(target, "SELECT value FROM example; PRAGMA murmur_kdf;").stdout, "hello\nargon2id\n")
            self.cli(target, "SELECT * FROM example;", phrase="wrong", ok=False)
        self.cli(self.store, f".clone {self.root / 'clone'}", ok=False)
        self.cli(self.store, f".c {self.root / 'clone-abbreviated'}")
        self.assertEqual(self.cli(self.root / "clone-abbreviated", "SELECT value FROM example;").stdout, "hello\n")
        vacuum = self.root / "vacuum"
        self.cli(self.store, f"VACUUM INTO {quote(vacuum)};")
        self.assertEqual(self.cli(vacuum, "SELECT value FROM example;").stdout, "hello\n")
        restored = self.root / "restored"
        self.cli(restored, f".restore {self.root / 'backup'}")
        self.assertEqual(self.cli(restored, "SELECT value FROM example;").stdout, "hello\n")
        # SQLite backup replaces pages, retaining each destination's own keyring.
        self.cli(restored, "INSERT INTO example VALUES(2,'replace me');")
        self.cli(restored, f".restore {self.root / 'backup'}")
        self.assertEqual(self.cli(restored, "SELECT count(*) FROM example;").stdout, "1\n")
        source = self.root / "not-a-source"
        self.cli(self.store, f".restore {source}", ok=False)
        self.assertFalse(source.exists())
        invalid = self.root / "bad-dest"
        invalid.write_text("existing ordinary file")
        self.cli(self.store, f".backup {invalid}", ok=False)
        self.assertEqual(invalid.read_text(), "existing ordinary file")

    def test_rejected_modes_and_paths(self):
        self.create()
        ordinary = self.root / "ordinary.db"
        with sqlite3.connect(ordinary) as db:
            db.execute("CREATE TABLE t(value)")
        self.cli(ordinary, "SELECT 1;", ok=False)
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        (unrelated / "keep").write_text("untouched")
        self.cli(unrelated, "SELECT 1;", ok=False)
        self.assertEqual(list(unrelated.iterdir()), [unrelated / "keep"])
        for mode in ("--new", "--append", "--deserialize", "--hexdb"):
            self.cli(self.store, sql_input=f".open {mode} {self.store}\n", ok=False)
        self.assertEqual(self.cli(self.store, "SELECT value FROM example;").stdout, "hello\n")
        for option in ("--async", "--append"):
            self.cli(self.store, f".backup {option} {self.root / 'rejected'}", ok=False)
        self.assertFalse((self.root / "rejected").exists())
        self.cli("-append", self.store, "SELECT 1;", ok=False)
        self.cli("-vfs", "unix", self.store, "SELECT 1;", ok=False)
        self.cli(self.store, f"ATTACH {quote('file:' + str(ordinary) + '?vfs=unix')} AS other;", ok=False)
        self.cli(self.store, "PRAGMA journal_mode=WAL;", ok=False)
        self.assertEqual(self.cli(self.store, "PRAGMA mmap_size=100000; PRAGMA journal_mode;").stdout, "0\ndelete\n")

    def test_dynamic_extension(self):
        result = self.cli(":memory:", sql_input=f".load {EXTENSION}\nSELECT murmur_extension_check();\n", key_fd=False)
        self.assertEqual(result.stdout, "murmur-extension-ok\n")

    def test_credential_errors(self):
        result = self.cli(self.store, "SELECT 1;", key_fd=False, ok=False)
        self.assertIn("--passphrase-fd", result.stderr)
        self.assertFalse(self.store.exists())
        for phrase in ("", "x" * 4097, "embedded\0nul"):
            self.cli(self.store, "SELECT 1;", phrase=phrase, ok=False)
            self.assertFalse(self.store.exists())
        self.cli("--passphrase-fd", "999999", self.store, ok=False, key_fd=False)
        self.cli("--passphrase-fd", key_fd=False, ok=False)
        self.cli(self.store, "SELECT 1;", phrase=PHRASE + "\r")
        self.assertEqual(self.cli(self.store, "SELECT 2;").stdout, "2\n")

    def test_terminal_prompt_confirmation_and_reopen(self):
        terminal = Terminal(self.store, "CREATE TABLE t(value); INSERT INTO t VALUES(42);")
        self.addCleanup(terminal.close)
        terminal.expect("Passphrase: ")
        self.assertFalse(termios.tcgetattr(terminal.slave)[3] & termios.ECHO)
        terminal.send("a hidden terminal passphrase")
        terminal.expect("Confirm passphrase: ")
        terminal.send("a hidden terminal passphrase")
        self.assertEqual(terminal.finish()[0], 0)
        self.assertNotIn(b"a hidden terminal passphrase", terminal.output)
        terminal2 = Terminal(self.store, "SELECT value FROM t;")
        self.addCleanup(terminal2.close)
        terminal2.expect("Passphrase: ")
        terminal2.send("a hidden terminal passphrase")
        self.assertEqual(terminal2.finish()[:2], (0, "42\n"))
        self.assertNotIn(b"Confirm", terminal2.output)

    def test_terminal_mismatch_and_signals(self):
        for sig in (None, signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig):
                terminal = Terminal(self.store, "SELECT 1;")
                self.addCleanup(terminal.close)
                terminal.expect("Passphrase: ")
                if sig is None:
                    terminal.send("first phrase")
                    terminal.expect("Confirm passphrase: ")
                    terminal.send("different phrase")
                else:
                    os.kill(terminal.proc.pid, sig)
                self.assertNotEqual(terminal.finish()[0], 0)
                self.assertFalse(self.store.exists())

    def test_process_lock(self):
        self.create()
        with tempfile.TemporaryFile() as key:
            key.write((PHRASE + "\n").encode())
            key.seek(0)
            proc = subprocess.Popen([CLI, "-batch", "-noinit", "--passphrase-fd",
                                     str(key.fileno()), str(self.store)],
                                    pass_fds=(key.fileno(),), stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                proc.stdin.write(".print lock-ready\n")
                proc.stdin.flush()
                self.assertTrue(select.select([proc.stdout], [], [], 10)[0])
                self.assertEqual(proc.stdout.readline(), "lock-ready\n")
                result = self.cli(self.store, "SELECT 1;", ok=False)
                self.assertIn("lock", result.stderr)
                proc.stdin.write(".quit\n")
                proc.stdin.flush()
                self.assertEqual(proc.wait(timeout=10), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
