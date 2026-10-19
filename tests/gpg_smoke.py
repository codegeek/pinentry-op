"""Real GnuPG signing and decryption using disposable keys and a fake 1Password CLI.

Run after cargo build: python3 tests/gpg_smoke.py
No user keyring or real 1Password account is accessed.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    binary = Path(os.environ.get("PINENTRY_OP_TEST_BINARY", ROOT / "target/debug/pinentry-op")).resolve()
    if not binary.is_file():
        raise SystemExit("Build pinentry-op first with cargo build")
    if not shutil.which("gpg") or not shutil.which("gpgconf"):
        raise SystemExit("gpg and gpgconf are required")
    # A short path avoids the Unix-domain socket path limit. This directory
    # contains only disposable test data; all test code stays in the worktree.
    with tempfile.TemporaryDirectory(prefix="piop-gpg-") as directory:
        home = Path(directory)
        home.chmod(0o700)
        env = dict(os.environ, GNUPGHOME=str(home),
                   PINENTRY_OP_CONFIG=str(home / "config.toml"),
                   TEST_OP_PID=str(home / "op.pid"), TEST_OP_ARGS=str(home / "args.json"),
                   TEST_FALLBACK_LOG=str(home / "fallback.log"), TEST_SECRET="test-passphrase")

        def gpg(*args, input=None):
            return subprocess.run(["gpg", "--homedir", str(home), *args], input=input,
                                  env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  check=True, timeout=60).stdout

        def stop_agent():
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                           env=env, check=True, timeout=15)

        try:
            gpg("--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                "--quick-generate-key", "pinentry-op test <test@example.invalid>",
                "ed25519", "default", "1d", input=b"test-passphrase\n")
            listing = gpg("--batch", "--with-colons", "--with-keygrip", "--list-secret-keys").decode()
            fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            gpg("--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0",
                "--quick-add-key", fingerprint, "cv25519", "encrypt", "1d", input=b"test-passphrase\n")
            listing = gpg("--batch", "--with-colons", "--with-keygrip", "--list-secret-keys").decode()
            # Each grp: record follows the sec: (primary) or ssb: (subkey) record it belongs to.
            grips, owner = {}, None
            for line in listing.splitlines():
                fields = line.split(":")
                if fields[0] in ("sec", "ssb"):
                    owner = fields[0]
                elif fields[0] == "grp":
                    grips[owner] = fields[9]
            assert grips.keys() == {"sec", "ssb"} and grips["sec"] != grips["ssb"], grips
            # Distinct references prove each operation looked up its own keygrip.
            # The fake CLI returns the same passphrase for both.
            sign_ref = "op://test-vault/signing-item/password"
            decrypt_ref = "op://test-vault/encryption-item/password"
            config = (
                f'op_program = {json.dumps(str(ROOT / "tests/fixtures/op.py"))}\n'
                f'fallback_program = {json.dumps(str(ROOT / "tests/fixtures/pinentry.py"))}\n'
                "timeout_seconds = 10\n[keys]\n"
                f'{json.dumps(grips["sec"])} = {json.dumps(sign_ref)}\n'
                f'{json.dumps(grips["ssb"])} = {json.dumps(decrypt_ref)}\n')
            (home / "config.toml").write_text(config)
            (home / "gpg-agent.conf").write_text(f"pinentry-program {binary}\n")
            payload = b"pinentry-op roundtrip\nBinary payload: \x00\xff\n"

            def looked_up():
                assert (home / "op.pid").exists(), "operation did not invoke op"
                log = home / "fallback.log"
                assert not log.exists() or "GETPIN" not in log.read_text(errors="replace"), \
                    "fallback prompted instead of op"
                reference = json.loads((home / "args.json").read_text())[2]
                (home / "op.pid").unlink()
                return reference

            stop_agent()
            signature = gpg("--batch", "--local-user", fingerprint, "--detach-sign", input=payload)
            assert looked_up() == sign_ref, "signing did not use the signing keygrip"
            signature_file = home / "payload.sig"
            signature_file.write_bytes(signature)
            subprocess.run(["gpg", "--homedir", str(home), "--batch", "--verify",
                            str(signature_file), "-"], input=payload, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60)

            encrypted = gpg("--batch", "--yes", "--trust-model", "always", "--recipient", fingerprint,
                            "--encrypt", input=payload)
            stop_agent()
            decrypted = gpg("--decrypt", input=encrypted)
            assert decrypted == payload, "decrypted payload differs"
            assert looked_up() == decrypt_ref, "decryption did not use the encryption keygrip"
            print("PASS: real GPG signed and decrypted a binary payload through pinentry-op")
        except subprocess.CalledProcessError as error:
            raise SystemExit(f"GPG smoke test failed: {error.stderr.decode() if error.stderr else error}") from error
        finally:
            stop_agent()


if __name__ == "__main__":
    main()
