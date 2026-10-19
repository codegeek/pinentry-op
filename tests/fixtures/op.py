#!/usr/bin/env python3
"""Fake op CLI. Used only with synthetic test secrets."""
import json
import os
from pathlib import Path
import sys
import subprocess
import time

Path(os.environ["TEST_OP_PID"]).write_text(str(os.getpid()))
Path(os.environ["TEST_OP_ARGS"]).write_text(json.dumps(sys.argv[1:]))
mode = os.environ.get("TEST_OP_MODE", "success")
if mode == "timeout":
    time.sleep(30)
if mode == "timeout_with_helper":
    # A helper in the same process group must die with the CLI on timeout.
    helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    Path(os.environ["TEST_OP_PID"] + ".helper").write_text(str(helper.pid))
    time.sleep(30)
if mode == "failure":
    sys.stderr.write("SYNTHETIC_SECRET_MUST_NOT_LEAK")
    sys.exit(1)
if mode == "oversized":
    sys.stdout.buffer.write(b"x" * 65537)
elif mode == "empty":
    pass
elif mode == "nul":
    sys.stdout.buffer.write(b"bad\x00secret")
else:
    sys.stdout.buffer.write(os.environ.get("TEST_SECRET", "test-passphrase").encode())
