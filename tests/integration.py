"""Black-box tests; run via cargo test, or with PINENTRY_OP_TEST_BINARY set."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
GRIP = "0123456789ABCDEF0123456789ABCDEF01234567"
REFERENCE = "op://vault/item with spaces/password"
PRELUDE = f"OPTION allow-external-password-cache\nSETKEYINFO n/{GRIP}\n"


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = ROOT / "target" / "integration" / str(os.getpid()) / self._testMethodName
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.config = self.scratch / "config.toml"
        self.env = dict(os.environ, TEST_OP_PID=str(self.scratch / "op.pid"),
                        TEST_OP_ARGS=str(self.scratch / "args.json"),
                        TEST_FALLBACK_LOG=str(self.scratch / "fallback.log"))
        self.write_config()

    def tearDown(self):
        shutil.rmtree(self.scratch)

    def write_config(self, grip=GRIP, op_program=ROOT / "tests/fixtures/op.py", extra=""):
        self.config.write_text(
            extra +
            f"op_program = {json.dumps(str(op_program))}\n"
            f"fallback_program = {json.dumps(str(ROOT / 'tests/fixtures/pinentry.py'))}\n"
            'timeout_seconds = 1\naccount = "test-account"\n[keys]\n'
            f'{json.dumps(grip)} = {json.dumps(REFERENCE)}\n')

    def run_session(self, transcript, args=None, **env):
        if args is None:
            args = ["--config", str(self.config)]
        if isinstance(transcript, str):
            transcript = transcript.encode()
        result = subprocess.run(
            [os.environ["PINENTRY_OP_TEST_BINARY"], *args],
            input=transcript, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(self.env, **env), timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return result.stdout.decode(), result.stderr.decode()

    def fallback_log(self):
        return Path(self.env["TEST_FALLBACK_LOG"]).read_text()

    def test_mapping_escaping_and_direct_arguments(self):
        stdout, stderr = self.run_session(PRELUDE + "GETPIN\nBYE\n", TEST_SECRET=" space %\r\n ")
        self.assertIn("S PASSWORD_FROM_CACHE\nD  space %25%0D%0A \nOK\n", stdout)
        self.assertEqual(stderr, "")
        self.assertNotIn("GETPIN", self.fallback_log())
        self.assertEqual(json.loads(Path(self.env["TEST_OP_ARGS"]).read_text()),
                         ["read", "--no-newline", REFERENCE, "--account", "test-account"])

    def test_no_external_cache_permission(self):
        stdout, _ = self.run_session(f"SETKEYINFO n/{GRIP}\nGETPIN\nBYE\n")
        self.assertIn("D manual-passphrase", stdout)
        self.assertFalse(Path(self.env["TEST_OP_PID"]).exists())

    def test_symmetric_unknown_and_new_passphrases(self):
        for setup in (f"SETKEYINFO u/{GRIP}\n", "SETKEYINFO n/" + "F" * 40 + "\n",
                      f"SETKEYINFO n/{GRIP}\nSETREPEAT Again:\n"):
            with self.subTest(setup=setup):
                stdout, _ = self.run_session("OPTION allow-external-password-cache\n" + setup + "GETPIN\nBYE\n")
                self.assertIn("D manual-passphrase", stdout)
                self.assertFalse(Path(self.env["TEST_OP_PID"]).exists())

    def test_rejected_passphrase_uses_fallback_with_state(self):
        stdout, _ = self.run_session(PRELUDE + "SETDESC Original%20prompt\nGETPIN\nSETERROR Bad passphrase\nGETPIN\nBYE\n")
        self.assertEqual(stdout.count("PASSWORD_FROM_CACHE"), 1)
        self.assertIn("D manual-passphrase", stdout)
        self.assertIn("SETDESC Original%20prompt\nSETERROR Bad passphrase\nGETPIN", self.fallback_log())

    def test_second_request_does_not_repeat_lookup(self):
        stdout, _ = self.run_session(PRELUDE + "GETPIN\nGETPIN\nBYE\n")
        self.assertEqual(stdout.count("PASSWORD_FROM_CACHE"), 1)
        self.assertIn("D manual-passphrase", stdout)

    def test_reset_does_not_retry_same_secret(self):
        stdout, _ = self.run_session(PRELUDE + "GETPIN\nRESET\n" + PRELUDE + "GETPIN\nBYE\n")
        self.assertEqual(stdout.count("PASSWORD_FROM_CACHE"), 1)
        self.assertIn("D manual-passphrase", stdout)

    def test_lookup_failure_cancels_without_fallback_or_secret_leak(self):
        stdout, stderr = self.run_session(PRELUDE + "GETPIN\nBYE\n", TEST_OP_MODE="failure")
        self.assertIn("ERR 83886179", stdout)
        self.assertNotIn("SYNTHETIC_SECRET_MUST_NOT_LEAK", stdout + stderr)
        self.assertNotIn("GETPIN", self.fallback_log())

    def test_prompt_policy_falls_back_after_failure_or_timeout(self):
        self.write_config(extra='on_lookup_failure = "prompt"\n')
        for mode in ("failure", "timeout"):
            with self.subTest(mode=mode):
                Path(self.env["TEST_FALLBACK_LOG"]).unlink(missing_ok=True)
                stdout, stderr = self.run_session(PRELUDE + "GETPIN\nBYE\n", TEST_OP_MODE=mode)
                self.assertNotIn("ERR 83886179", stdout)
                self.assertIn("D manual-passphrase", stdout)
                self.assertIn("GETPIN", self.fallback_log())
                self.assertNotIn("SYNTHETIC_SECRET_MUST_NOT_LEAK", stdout + stderr)

    def test_unusable_secret_prompts_manually(self):
        for mode in ("oversized", "nul", "empty"):
            with self.subTest(mode=mode):
                Path(self.env["TEST_FALLBACK_LOG"]).unlink(missing_ok=True)
                stdout, _ = self.run_session(PRELUDE + "GETPIN\nBYE\n", TEST_OP_MODE=mode)
                self.assertNotIn("PASSWORD_FROM_CACHE", stdout)
                self.assertIn("D manual-passphrase", stdout)
                self.assertIn("GETPIN", self.fallback_log())

    def test_missing_cli_prompts_manually(self):
        self.write_config(op_program=self.scratch / "missing-op")
        stdout, _ = self.run_session(PRELUDE + "GETPIN\nBYE\n")
        self.assertIn("D manual-passphrase", stdout)
        self.assertIn("GETPIN", self.fallback_log())

    def test_timeout_kills_and_reaps_cli(self):
        start = time.monotonic()
        stdout, _ = self.run_session(PRELUDE + "GETPIN\nBYE\n", TEST_OP_MODE="timeout")
        self.assertLess(time.monotonic() - start, 5)
        self.assertIn("ERR 83886179", stdout)
        pid = int(Path(self.env["TEST_OP_PID"]).read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_timeout_kills_cli_process_group(self):
        stdout, _ = self.run_session(PRELUDE + "GETPIN\nBYE\n", TEST_OP_MODE="timeout_with_helper")
        self.assertIn("ERR 83886179", stdout)
        helper = int(Path(self.env["TEST_OP_PID"] + ".helper").read_text())
        deadline = time.monotonic() + 2
        while True:
            try:
                os.kill(helper, 0)
            except ProcessLookupError:
                break
            # The killed helper is reparented to init, which reaps it shortly.
            self.assertLess(time.monotonic(), deadline, "helper survived timeout")
            time.sleep(0.05)

    def test_config_equals_form(self):
        stdout, _ = self.run_session(PRELUDE + "GETPIN\nBYE\n", args=[f"--config={self.config}"])
        self.assertIn("PASSWORD_FROM_CACHE", stdout)
        self.assertNotIn("--config", Path(self.env["TEST_FALLBACK_LOG"]).read_text())

    def test_non_utf8_lines_pass_through(self):
        stdout, _ = self.run_session(b"SETDESC caf\xe9\n" + PRELUDE.encode() + b"GETPIN\nBYE\n")
        self.assertIn("PASSWORD_FROM_CACHE", stdout)
        self.assertIn(b"SETDESC caf\xe9", Path(self.env["TEST_FALLBACK_LOG"]).read_bytes())

    def test_bare_err_ends_transaction(self):
        stdout, _ = self.run_session("BAREERR\nBYE\n")
        self.assertIn("ERR\nOK", stdout)

    def test_confirmation_is_not_automatically_approved(self):
        stdout, _ = self.run_session("CONFIRM\nBYE\n")
        self.assertIn("ERR 83886179", stdout)
        self.assertIn("CONFIRM", self.fallback_log())

    def test_inquiry_roundtrip(self):
        stdout, _ = self.run_session("MESSAGE\nD 100\nEND\nBYE\n")
        self.assertIn("INQUIRE QUALITY synthetic\nOK", stdout)

    def test_unknown_options_and_commands_are_not_silently_accepted(self):
        stdout, _ = self.run_session("OPTION unsupported\nUNKNOWN\nBYE\n")
        self.assertIn("ERR 83886254", stdout)
        self.assertIn("ERR 83886275", stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
