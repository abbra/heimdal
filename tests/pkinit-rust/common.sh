#!/bin/bash
#
# Shared helpers for the pkinit-rust test scripts.
#
# Sourced (not executed) by check-interop.sh, check-pkinit-rust.sh, and
# run.sh after they set SCRIPT_DIR. Callers are expected to define
# WORKDIR and $ec before invoking testfailed()/check_kdc_log()-style
# helpers that read them.
#

free_port() {
    python3 -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
' 2>/dev/null || echo 48888
}

testsuccess() {
    echo "  [PASS] $1"
}

testfailed() {
    echo "  [FAIL] $1"
    ec=1
    if [ "${VERBOSE:-0}" = "1" ] && [ -f "${WORKDIR:-}/kdc.log" ]; then
        echo "--- KDC log tail ---"
        tail -20 "$WORKDIR/kdc.log"
        echo "---"
    fi
}

testskip() {
    echo "  [SKIP] $1"
}
