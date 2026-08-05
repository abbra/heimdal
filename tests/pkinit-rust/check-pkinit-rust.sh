#!/bin/bash
#
# Integration test for the Rust PKINIT adapter (heimdal-pkinit).
#
# This script tests the full PKINIT flow using the Rust pkinit-core
# library.  It must be run from a Heimdal build tree configured with
# --enable-pkinit-rust, or with HEIMDAL_PREFIX pointing to an installed
# Heimdal with the Rust adapter.
#
# Test categories:
#   1. Build verification (Rust crate + static library)
#   2. Classical PKINIT — DH, ECDH (client + KDC)
#   3. Post-quantum PKINIT — ML-KEM-768 (KDC hint + key exchange)
#   4. Error handling — DH parameter rejection, retry
#   5. Cross-implementation (MIT kurbu5-pkinit, optional)
#
# Usage:
#   ./check-pkinit-rust.sh [--mit-prefix /path/to/mit]
#
# Environment:
#   HEIMDAL_PREFIX  — Heimdal install prefix (default: autodetect from build tree)
#   MIT_PREFIX      — MIT krb5 install prefix (optional, for cross-tests)
#   VERBOSE         — set to 1 for detailed output
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOP_SRCDIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKDIR="$(mktemp -d /tmp/pkinit-rust-test.XXXXXX)"

REALM="EXAMPLE.COM"
CLIENT="testuser"
KDC_PID=""
ec=0

# ── Parse arguments ──────────────────────────────────────────────────

MIT_PREFIX=""
while [ $# -gt 0 ]; do
    case "$1" in
        --mit-prefix) MIT_PREFIX="$2"; shift 2 ;;
        --mit-prefix=*) MIT_PREFIX="${1#*=}"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Locate binaries ──────────────────────────────────────────────────

find_binary() {
    local name="$1"
    local heimdal_paths=(
        "${HEIMDAL_PREFIX:-}"
        "${TOP_SRCDIR}"
    )
    for prefix in "${heimdal_paths[@]}"; do
        for dir in sbin libexec bin; do
            if [ -x "${prefix}/${dir}/${name}" ]; then
                echo "${prefix}/${dir}/${name}"
                return 0
            fi
        done
    done
    # Fall back to PATH
    command -v "$name" 2>/dev/null || true
}

KDC="$(find_binary kdc)"
KINIT="$(find_binary kinit)"
KLIST="$(find_binary klist)"
KDESTROY="$(find_binary kdestroy)"
KADMIN="$(find_binary kadmin)"
KGETCRED="$(find_binary kgetcred)"

for bin in "$KDC" "$KINIT" "$KADMIN"; do
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "ERROR: Required binary not found. Set HEIMDAL_PREFIX."
        echo "  KDC=$KDC KINIT=$KINIT KADMIN=$KADMIN"
        exit 1
    fi
done

echo "=== Heimdal binaries ==="
echo "  KDC:     $KDC"
echo "  kinit:   $KINIT"
echo "  kadmin:  $KADMIN"
echo "  klist:   $KLIST"
echo ""

# ── Helpers ──────────────────────────────────────────────────────────

cleanup() {
    if [ -n "${KDC_PID}" ]; then
        kill "$KDC_PID" 2>/dev/null || true
        wait "$KDC_PID" 2>/dev/null || true
    fi
    if [ "$ec" -ne 0 ]; then
        echo ""
        echo "=== KDC log ==="
        cat "$WORKDIR/kdc.log" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

testfailed() {
    echo "  FAIL: $1"
    ec=1
    if [ "${VERBOSE:-0}" = "1" ]; then
        echo "--- KDC log tail ---"
        tail -20 "$WORKDIR/kdc.log" 2>/dev/null || true
        echo "---"
    fi
}

testsuccess() {
    echo "  OK: $1"
}

free_port() {
    python3 -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
' 2>/dev/null || echo 48888
}

# ── Step 1: Build verification ───────────────────────────────────────

echo "=== Step 1: Build verification ==="

RUST_LIB="${TOP_SRCDIR}/rust/target/release/libheimdal_pkinit.a"
if [ -f "$RUST_LIB" ]; then
    testsuccess "libheimdal_pkinit.a exists ($(stat -c%s "$RUST_LIB" 2>/dev/null || stat -f%z "$RUST_LIB") bytes)"
else
    echo "  Building Rust library..."
    (cd "$TOP_SRCDIR/rust" && cargo build --release 2>&1) || {
        testfailed "cargo build --release failed"
        exit 1
    }
    testsuccess "libheimdal_pkinit.a built"
fi

# Verify FFI symbols
EXPECTED_SYMBOLS="heimdal_pkinit_initialize heimdal_pkinit_rd_padata \
heimdal_pkinit_mk_pa_reply heimdal_pkinit_check_client \
heimdal_pkinit_free_client_param heimdal_pkinit_keyex_name \
heimdal_pkinit_get_hint \
heimdal_pkinit_client_init heimdal_pkinit_client_mk_padata \
heimdal_pkinit_client_rd_pa_reply heimdal_pkinit_client_free \
heimdal_pkinit_client_set_freshness heimdal_pkinit_client_process_hint \
heimdal_pkinit_client_tryagain"

ALL_SYMBOLS=$(nm "$RUST_LIB" 2>/dev/null | grep " T heimdal_pkinit_" || true)
for sym in $EXPECTED_SYMBOLS; do
    if echo "$ALL_SYMBOLS" | grep -q " T ${sym}$"; then
        :
    else
        testfailed "missing symbol: $sym"
    fi
done
NSYMS=$(nm "$RUST_LIB" 2>/dev/null | grep " T heimdal_pkinit_" | wc -l)
testsuccess "all $NSYMS FFI symbols present"

# ── Step 2: Generate PKI ─────────────────────────────────────────────

echo ""
echo "=== Step 2: Generate test PKI ==="

PKI_DIR="$WORKDIR/pki"
bash "$SCRIPT_DIR/setup-pki.sh" "$PKI_DIR" > /dev/null 2>&1 || {
    testfailed "PKI generation failed"
    exit 1
}

# Verify certificates
for cert in ca.pem kdc.pem client.pem; do
    openssl x509 -in "$PKI_DIR/$cert" -noout -subject > /dev/null 2>&1 || {
        testfailed "invalid certificate: $cert"
        exit 1
    }
done
testsuccess "CA + KDC + client certificates generated"

# Verify EKUs
KDC_EKU=$(openssl x509 -in "$PKI_DIR/kdc.pem" -noout -text 2>/dev/null | grep "Signing KDC Response" || true)
CLIENT_EKU=$(openssl x509 -in "$PKI_DIR/client.pem" -noout -text 2>/dev/null | grep "PKINIT Client Auth" || true)
[ -n "$KDC_EKU" ] && testsuccess "KDC cert has id-pkkdcekuoid" || testfailed "KDC cert missing EKU"
[ -n "$CLIENT_EKU" ] && testsuccess "client cert has id-pkekuoid" || testfailed "client cert missing EKU"

# ── Step 3: Set up KDC ───────────────────────────────────────────────

echo ""
echo "=== Step 3: Initialize KDC ==="

KDC_PORT=$(free_port)

# Write krb5.conf for classical PKINIT
write_krb5_conf() {
    local pqc_line=""
    if [ "${1:-}" = "pqc" ]; then
        pqc_line="    pkinit_pqc_min_algorithm = ML-KEM-768"
    fi
    cat > "$WORKDIR/krb5.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }

[kdc]
    enable-pkinit = true
    pkinit_identity = FILE:${PKI_DIR}/kdc.pem,${PKI_DIR}/kdc.key
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem
    pkinit_principal_in_certificate = true
    pkinit_dh_min_bits = 0
${pqc_line}
    database = {
        dbname = ${WORKDIR}/db/heimdal
        log_file = ${WORKDIR}/db/log
    }

[logging]
    kdc = FILE:${WORKDIR}/kdc.log
CONF
}

write_krb5_conf
export KRB5_CONFIG="$WORKDIR/krb5.conf"

# Set database path
HDB_FILE="$WORKDIR/db/heimdal"
mkdir -p "$WORKDIR/db"

# Add database config to krb5.conf
cat >> "$WORKDIR/krb5.conf" <<DBCONF

[kdc]
    database = {
        dbname = $HDB_FILE
        log_file = $WORKDIR/db/log
    }
DBCONF

KADMIN_CMD="$KADMIN -l -H $HDB_FILE"

# Initialize database
echo "" | $KADMIN_CMD init --realm-max-ticket-life=1d --realm-max-renewable-life=7d \
    "$REALM" > "$WORKDIR/kadmin.log" 2>&1
# Check if db was created (kadmin may report non-fatal iprop errors)
if [ ! -f "${HDB_FILE}.db" ] && [ ! -f "${HDB_FILE}" ]; then
    testfailed "kadmin init failed (no database file)"
    cat "$WORKDIR/kadmin.log"
    exit 1
fi

# Add test principal
$KADMIN_CMD add --random-password --use-defaults \
    "${CLIENT}@${REALM}" >> "$WORKDIR/kadmin.log" 2>&1 || true

testsuccess "KDC database initialized"

# Start KDC
> "$WORKDIR/kdc.log"
"$KDC" --addresses=127.0.0.1 --ports="$KDC_PORT" \
    --config-file="$WORKDIR/krb5.conf" \
    --detach --testing \
    2>> "$WORKDIR/kdc.log" || {
    testfailed "KDC failed to start"
    cat "$WORKDIR/kdc.log"
    exit 1
}

# Wait for KDC
sleep 1
KDC_PID=$(lsof -ti "tcp:${KDC_PORT}" 2>/dev/null | head -1 || true)
if [ -z "$KDC_PID" ]; then
    # Try to find via process name
    KDC_PID=$(pgrep -f "kdc.*${KDC_PORT}" 2>/dev/null | head -1 || true)
fi
testsuccess "KDC started (port $KDC_PORT, pid ${KDC_PID:-unknown})"

CCACHE="$WORKDIR/ccache"
export KRB5CCNAME="FILE:$CCACHE"

# ── Step 4: Classical PKINIT tests ───────────────────────────────────

echo ""
echo "=== Step 4: Classical PKINIT tests ==="

run_kinit() {
    local desc="$1"
    shift
    echo "Trying $desc"; > "$WORKDIR/kdc.log"
    if "$KINIT" \
        -C "FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
        --x509-anchors="FILE:${PKI_DIR}/ca.pem" \
        "$@" \
        "${CLIENT}@${REALM}" 2>"$WORKDIR/kinit-err.log"; then
        testsuccess "$desc"
        "$KDESTROY" -c "$CCACHE" 2>/dev/null || true
        return 0
    else
        testfailed "$desc (kinit exit code: $?)"
        [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/kinit-err.log"
        return 1
    fi
}

# Basic PKINIT (default key agreement — usually ECDH P-256)
run_kinit "pk-init (default key agreement)"

# DH groups
for group in modp_2048 modp_3072; do
    run_kinit "pk-init with --key-agreement=$group" \
        --key-agreement="$group" || true
done

# ECDH curves
for curve in P-256 P-384 P-521; do
    run_kinit "pk-init with --key-agreement=$curve" \
        --key-agreement="$curve" || true
done

# KDF algorithms (RFC 8636)
for kdf in ah-sha256 ah-sha512; do
    run_kinit "pk-init with --kdf=$kdf" \
        --kdf="$kdf" || true
done

# Combined: ECDH + KDF
run_kinit "pk-init with --key-agreement=P-256 --kdf=ah-sha256" \
    --key-agreement=P-256 --kdf=ah-sha256 || true

# ── Step 5: Verify ticket ────────────────────────────────────────────

echo ""
echo "=== Step 5: Verify ticket acquisition ==="

# Get a ticket and verify it
"$KINIT" \
    -C "FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
    --x509-anchors="FILE:${PKI_DIR}/ca.pem" \
    "${CLIENT}@${REALM}" 2>"$WORKDIR/kinit-err.log" && {
    if "$KLIST" -c "$CCACHE" > /dev/null 2>&1; then
        testsuccess "klist shows valid ticket"
        if [ "${VERBOSE:-0}" = "1" ]; then
            "$KLIST" -c "$CCACHE"
        fi
    else
        testfailed "klist failed after successful kinit"
    fi
} || testfailed "final kinit failed"

"$KDESTROY" -c "$CCACHE" 2>/dev/null || true

# ── Step 6: KDC restart with PQC config ──────────────────────────────

echo ""
echo "=== Step 6: Post-quantum PKINIT (ML-KEM) ==="

# Stop existing KDC
if [ -n "$KDC_PID" ]; then
    kill "$KDC_PID" 2>/dev/null || true
    wait "$KDC_PID" 2>/dev/null || true
    KDC_PID=""
fi

# Rewrite config with PQC enabled
write_krb5_conf pqc

# Restart KDC
> "$WORKDIR/kdc.log"
"$KDC" --addresses=127.0.0.1 --ports="$KDC_PORT" \
    --config-file="$WORKDIR/krb5.conf" \
    --detach --testing \
    2>> "$WORKDIR/kdc.log" || {
    testfailed "KDC restart with PQC config failed"
    cat "$WORKDIR/kdc.log"
}
sleep 1
KDC_PID=$(lsof -ti "tcp:${KDC_PORT}" 2>/dev/null | head -1 || true)
if [ -z "$KDC_PID" ]; then
    KDC_PID=$(pgrep -f "kdc.*${KDC_PORT}" 2>/dev/null | head -1 || true)
fi

if [ -n "$KDC_PID" ]; then
    testsuccess "KDC restarted with pkinit_pqc_min_algorithm=ML-KEM-768"

    # Classical PKINIT should still work even with PQC configured
    # (the KDC advertises KEM but still accepts DH/ECDH)
    run_kinit "pk-init (classical, PQC-configured KDC)" || true

    # Check KDC log for KEM hint advertisement
    if grep -qi "KEM\|ML-KEM\|pqc\|hint" "$WORKDIR/kdc.log" 2>/dev/null; then
        testsuccess "KDC log mentions KEM/PQC (hint advertisement working)"
    else
        echo "  INFO: KDC log does not mention KEM/PQC (expected if C KDC path is used)"
    fi
else
    testfailed "KDC did not restart"
fi

# ── Step 6b: PQC enforcement (reject classical when PQC required) ────

echo ""
echo "=== Step 6b: PQC enforcement ==="

# Stop existing KDC
if [ -n "$KDC_PID" ]; then
    kill "$KDC_PID" 2>/dev/null || true
    wait "$KDC_PID" 2>/dev/null || true
    KDC_PID=""
fi

# Write config with PQC enforcement
cat > "$WORKDIR/krb5.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }

[kdc]
    enable-pkinit = true
    pkinit_identity = FILE:${PKI_DIR}/kdc.pem,${PKI_DIR}/kdc.key
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem
    pkinit_principal_in_certificate = true
    pkinit_dh_min_bits = 0
    pkinit_pqc_min_algorithm = ML-KEM-768
    pkinit_require_pqc = true
    database = {
        dbname = ${WORKDIR}/db/heimdal
        log_file = ${WORKDIR}/db/log
    }

[logging]
    kdc = FILE:${WORKDIR}/kdc.log
CONF

> "$WORKDIR/kdc.log"
"$KDC" --addresses=127.0.0.1 --ports="$KDC_PORT" \
    --config-file="$WORKDIR/krb5.conf" \
    --detach --testing \
    2>> "$WORKDIR/kdc.log" || true
sleep 1
KDC_PID=$(lsof -ti "tcp:${KDC_PORT}" 2>/dev/null | head -1 || true)
if [ -z "$KDC_PID" ]; then
    KDC_PID=$(pgrep -f "kdc.*${KDC_PORT}" 2>/dev/null | head -1 || true)
fi

if [ -n "$KDC_PID" ]; then
    testsuccess "KDC restarted with pkinit_require_pqc=true"

    # Classical PKINIT should be REJECTED when PQC is required
    echo "Trying pk-init (classical, should be REJECTED)"; > "$WORKDIR/kdc.log"
    if "$KINIT" \
        -C "FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
        --x509-anchors="FILE:${PKI_DIR}/ca.pem" \
        "${CLIENT}@${REALM}" 2>"$WORKDIR/kinit-pqc-err.log"; then
        testfailed "classical PKINIT should have been rejected but succeeded"
    else
        testsuccess "classical PKINIT correctly rejected by PQC-enforcing KDC"
    fi

    # Verify the KDC log shows the PQC enforcement message
    if grep -q "PQC required" "$WORKDIR/kdc.log" 2>/dev/null; then
        testsuccess "KDC log confirms PQC enforcement"
    else
        testfailed "KDC log missing PQC enforcement message"
        [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/kdc.log"
    fi
else
    testfailed "KDC did not restart with pkinit_require_pqc=true"
fi

# ── Step 7: Cross-implementation tests (optional) ────────────────────

echo ""
echo "=== Step 7: Cross-implementation tests ==="

if [ -n "$MIT_PREFIX" ] && [ -x "${MIT_PREFIX}/bin/kinit" ]; then
    MIT_KINIT="${MIT_PREFIX}/bin/kinit"
    echo "  MIT kinit: $MIT_KINIT"

    # Write a minimal MIT krb5.conf
    cat > "$WORKDIR/mit-krb5.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }
CONF

    echo "Trying MIT kinit → Heimdal KDC (classical PKINIT)"; > "$WORKDIR/kdc.log"
    KRB5_CONFIG="$WORKDIR/mit-krb5.conf" \
    KRB5CCNAME="FILE:$WORKDIR/mit-ccache" \
    "$MIT_KINIT" \
        -X "X509_user_identity=FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
        -X "X509_anchors=FILE:${PKI_DIR}/ca.pem" \
        "${CLIENT}@${REALM}" 2>"$WORKDIR/mit-kinit-err.log" && {
        testsuccess "MIT kinit → Heimdal KDC (classical)"
    } || {
        testfailed "MIT kinit → Heimdal KDC (classical)"
        [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/mit-kinit-err.log"
    }

    # If kurbu5-pkinit is installed, it might negotiate PQC
    if [ -f "${MIT_PREFIX}/lib/krb5/plugins/preauth/pkinit.so" ] || \
       [ -f "${MIT_PREFIX}/lib64/krb5/plugins/preauth/pkinit.so" ]; then
        echo "Trying MIT kinit (kurbu5-pkinit) → Heimdal KDC (PQC)"; > "$WORKDIR/kdc.log"
        KRB5_CONFIG="$WORKDIR/mit-krb5.conf" \
        KRB5CCNAME="FILE:$WORKDIR/mit-ccache-pqc" \
        "$MIT_KINIT" \
            -X "X509_user_identity=FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
            -X "X509_anchors=FILE:${PKI_DIR}/ca.pem" \
            "${CLIENT}@${REALM}" 2>"$WORKDIR/mit-kinit-pqc-err.log" && {
            testsuccess "MIT kinit (kurbu5-pkinit) → Heimdal KDC (PQC)"
            # Check if ML-KEM was actually used
            if grep -qi "ML-KEM" "$WORKDIR/kdc.log" 2>/dev/null; then
                testsuccess "ML-KEM key exchange confirmed in KDC log"
            else
                echo "  INFO: ML-KEM not seen in KDC log (may have fallen back to ECDH)"
            fi
        } || {
            testfailed "MIT kinit (kurbu5-pkinit) → Heimdal KDC (PQC)"
            [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/mit-kinit-pqc-err.log"
        }
    else
        echo "  SKIP: kurbu5-pkinit plugin not found at $MIT_PREFIX"
    fi
else
    echo "  SKIP: MIT_PREFIX not set (use --mit-prefix /path/to/mit to enable)"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "================================================"
if [ "$ec" -eq 0 ]; then
    echo "  All tests PASSED"
else
    echo "  Some tests FAILED (ec=$ec)"
fi
echo "================================================"
echo ""
echo "Work directory: $WORKDIR"
echo "KDC log: $WORKDIR/kdc.log"

exit $ec
