#!/usr/bin/env python3
"""Deterministic fallback implementing UI responses without opening windows."""
import os
from pathlib import Path
import sys

def emit(text):
    print(text, flush=True)

emit("OK test fallback")
for line in sys.stdin:
    line = line.rstrip("\r\n")
    with Path(os.environ["TEST_FALLBACK_LOG"]).open("a") as log:
        log.write(line + "\n")
    command = line.split(" ", 1)[0]
    if command == "GETPIN":
        emit("D manual-passphrase")
    elif command == "CONFIRM":
        emit("ERR 83886179 Operation cancelled")
        continue
    elif command == "MESSAGE":
        emit("INQUIRE QUALITY synthetic")
        while True:
            reply = sys.stdin.readline().rstrip("\r\n")
            if reply in ("END", "CAN"):
                break
            if not reply:
                sys.exit(2)
    elif command == "OPTION" and line.endswith("unsupported"):
        emit("ERR 83886254 Unknown option")
        continue
    elif command == "UNKNOWN":
        emit("ERR 83886275 Unknown command")
        continue
    emit("OK")
    if command == "BYE":
        break
