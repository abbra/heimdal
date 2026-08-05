#!/bin/bash
#
# Integration test for the Rust PKINIT adapter.
#
# Prerequisites:
#   - Heimdal built with --enable-pkinit-rust
#   - KDC binaries in $HEIMDAL_PREFIX/libexec or PATH
#   - openssl in PATH
#
# This script:
#   1. Generates a test PKI (CA + KDC cert + client cert)
#   2. Creates a temporary krb5.conf and KDC database
#   3. Starts a KDC on a random port
#   4. Runs kinit with PKINIT against it
#   5. Verifies the ticket was obtained
#   6. Cleans up
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
WORKDIR="$(mktemp -d /tmp/heimdal-pkinit-test.XXXXXX)"
export REALM="PKINIT-TEST.EXAMPLE.COM"
CLIENT="testuser"
HEIMDAL_PREFIX="${HEIMDAL_PREFIX:-/usr/local/heimdal}"
KDC_PORT="${KDC_PORT:-0}"

cleanup() {
    if [ -n "${KDC_PID:-}" ]; then
        kill "$KDC_PID" 2>/dev/null || true
        wait "$KDC_PID" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

echo "=== Working directory: $WORKDIR ==="

# ── Step 1: Generate PKI ──────────────────────────────────────────────

echo "--- Generating test PKI ---"
bash "$SCRIPT_DIR/setup-pki.sh" "$WORKDIR/pki"

# ── Step 2: Create krb5.conf ──────────────────────────────────────────

# Find a free port
KDC_PORT=$(free_port)

cat > "$WORKDIR/krb5.conf" <<EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    pkinit_anchors = FILE:${WORKDIR}/pki/ca.pem

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }

[kdc]
    enable-pkinit = true
    pkinit_identity = FILE:${WORKDIR}/pki/kdc.pem,${WORKDIR}/pki/kdc.key
    pkinit_anchors = FILE:${WORKDIR}/pki/ca.pem
    pkinit_principal_in_certificate = true
    pkinit_dh_min_bits = 0
    # PQC config (will be used if pkinit-core supports it)
    # pkinit_pqc_min_algorithm = ML-KEM-768

[logging]
    kdc = FILE:${WORKDIR}/kdc.log
EOF

export KRB5_CONFIG="$WORKDIR/krb5.conf"

echo "--- krb5.conf written (KDC port: $KDC_PORT) ---"

# ── Step 3: Initialize KDC database ──────────────────────────────────

echo "--- Initializing KDC database ---"

KDC_DB="$WORKDIR/kdc-db"
mkdir -p "$KDC_DB"

KADMIN="${HEIMDAL_PREFIX}/sbin/kadmin"
KDC="${HEIMDAL_PREFIX}/libexec/kdc"
KINIT="${HEIMDAL_PREFIX}/bin/kinit"
KLIST="${HEIMDAL_PREFIX}/bin/klist"

# Check that binaries exist
for bin in "$KDC" "$KINIT"; do
    if [ ! -x "$bin" ]; then
        echo "ERROR: $bin not found. Set HEIMDAL_PREFIX to Heimdal install dir."
        exit 1
    fi
done

# Create the database
"${HEIMDAL_PREFIX}/sbin/kadmin" -l \
    init --realm-max-ticket-life=1d --realm-max-renewable-life=7d "$REALM" \
    2>"$WORKDIR/kadmin-init.log" || {
    echo "ERROR: kadmin init failed"
    cat "$WORKDIR/kadmin-init.log"
    exit 1
}

# Add test principal (no password needed for PKINIT)
"${HEIMDAL_PREFIX}/sbin/kadmin" -l \
    add --random-password --use-defaults "${CLIENT}@${REALM}" \
    2>>"$WORKDIR/kadmin-init.log" || true

echo "--- Database initialized ---"

# ── Step 4: Start KDC ────────────────────────────────────────────────

echo "--- Starting KDC ---"
"$KDC" --addresses=127.0.0.1 --ports="$KDC_PORT" \
    --config-file="$WORKDIR/krb5.conf" \
    --detach \
    --pid-file="$WORKDIR/kdc.pid" \
    2>"$WORKDIR/kdc-startup.log" || {
    echo "ERROR: KDC failed to start"
    cat "$WORKDIR/kdc-startup.log"
    cat "$WORKDIR/kdc.log" 2>/dev/null
    exit 1
}

KDC_PID="$(cat "$WORKDIR/kdc.pid" 2>/dev/null || true)"
echo "    KDC PID: ${KDC_PID:-unknown}"

# Wait for KDC to be ready
sleep 1

# ── Step 5: Run kinit with PKINIT ────────────────────────────────────

echo "--- Running kinit with PKINIT ---"

CCACHE="$WORKDIR/ccache"
export KRB5CCNAME="FILE:$CCACHE"

"$KINIT" \
    -C "FILE:${WORKDIR}/pki/client.pem,${WORKDIR}/pki/client.key" \
    --x509-anchors="FILE:${WORKDIR}/pki/ca.pem" \
    "${CLIENT}@${REALM}" \
    2>"$WORKDIR/kinit.log" && {
    echo "    kinit SUCCEEDED"
} || {
    echo "    kinit FAILED (exit code: $?)"
    cat "$WORKDIR/kinit.log"
    echo "--- KDC log ---"
    cat "$WORKDIR/kdc.log" 2>/dev/null
    exit 1
}

# ── Step 6: Verify ticket ────────────────────────────────────────────

echo "--- Verifying ticket ---"
"$KLIST" -c "$CCACHE" 2>"$WORKDIR/klist.log" && {
    "$KLIST" -c "$CCACHE"
    echo ""
    echo "=== PKINIT integration test PASSED ==="
} || {
    echo "    klist FAILED"
    cat "$WORKDIR/klist.log"
    exit 1
}
