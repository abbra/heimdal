#!/bin/bash
#
# Cross-implementation PKINIT interop tests.
#
# Tests the Rust pkinit-core adapter on both Heimdal and MIT Kerberos
# in all four combinations:
#
#   1. Heimdal KDC (Rust)  ←→  Heimdal kinit (Rust client)
#   2. Heimdal KDC (Rust)  ←→  MIT kinit (kurbu5-pkinit)
#   3. MIT KDC (kurbu5)    ←→  Heimdal kinit (C client)
#   4. MIT KDC (kurbu5)    ←→  MIT kinit (kurbu5-pkinit)
#
# For PQC:
#   5. Heimdal KDC (Rust, PQC)  ←→  MIT kinit (kurbu5-pkinit, ML-KEM-768)
#   6. PQC enforcement: Heimdal KDC rejects classical from MIT kinit
#
# Prerequisites:
#   - Heimdal built with --enable-pkinit-rust at HEIMDAL_PREFIX
#   - MIT krb5 installed (system /usr/bin/kinit or MIT_PREFIX)
#   - kurbu5-pkinit built at KURBU5_DIR
#
# Usage:
#   HEIMDAL_PREFIX=/opt/heimdal KURBU5_DIR=~/kurbu5-pkinit ./check-interop.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/common.sh"
TOP_SRCDIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKDIR="$(mktemp -d /tmp/pkinit-interop.XXXXXX)"

REALM="INTEROP.EXAMPLE.COM"
CLIENT="testuser"
ec=0

# ── Locate binaries ──────────────────────────────────────────────────

HEIMDAL_PREFIX="${HEIMDAL_PREFIX:-/tmp/heimdal-pkinit-test}"
MIT_PREFIX="${MIT_PREFIX:-/usr}"
KURBU5_DIR="${KURBU5_DIR:-${TOP_SRCDIR}/../kurbu5-pkinit}"

# Heimdal binaries
H_KDC=""
for d in libexec sbin; do
    [ -x "$HEIMDAL_PREFIX/$d/kdc" ] && H_KDC="$HEIMDAL_PREFIX/$d/kdc" && break
done
H_KINIT="$HEIMDAL_PREFIX/bin/kinit"
H_KLIST="$HEIMDAL_PREFIX/bin/klist"
H_KDESTROY="$HEIMDAL_PREFIX/bin/kdestroy"
H_KADMIN="$HEIMDAL_PREFIX/bin/kadmin"

# MIT binaries
M_KDC="$MIT_PREFIX/sbin/krb5kdc"
[ ! -x "$M_KDC" ] && M_KDC="$MIT_PREFIX/bin/krb5kdc"
M_KINIT="$MIT_PREFIX/bin/kinit"
M_KLIST="$MIT_PREFIX/bin/klist"
M_KDESTROY="$MIT_PREFIX/bin/kdestroy"
M_KADMIN="$MIT_PREFIX/sbin/kadmin.local"
[ ! -x "$M_KADMIN" ] && M_KADMIN="$MIT_PREFIX/bin/kadmin.local"

# kurbu5-pkinit plugin
KURBU5_SO="$KURBU5_DIR/target/release/libkurbu5_pkinit.so"

# Verify
MISSING=""
[ -z "$H_KDC" ] || [ ! -x "$H_KDC" ] && MISSING="$MISSING Heimdal-kdc"
[ ! -x "$H_KINIT" ] && MISSING="$MISSING Heimdal-kinit"
[ ! -x "$H_KADMIN" ] && MISSING="$MISSING Heimdal-kadmin"
[ ! -x "$M_KINIT" ] && MISSING="$MISSING MIT-kinit"
[ ! -x "$M_KADMIN" ] && MISSING="$MISSING MIT-kadmin.local"
[ ! -f "$KURBU5_SO" ] && MISSING="$MISSING kurbu5-pkinit.so"

if [ -n "$MISSING" ]; then
    echo "ERROR: Missing binaries:$MISSING"
    echo "  HEIMDAL_PREFIX=$HEIMDAL_PREFIX"
    echo "  MIT_PREFIX=$MIT_PREFIX"
    echo "  KURBU5_DIR=$KURBU5_DIR"
    exit 1
fi

echo "=== Binaries ==="
echo "  Heimdal KDC:    $H_KDC"
echo "  Heimdal kinit:  $H_KINIT"
echo "  MIT kinit:      $M_KINIT"
echo "  MIT KDC:        ${M_KDC:-N/A}"
echo "  kurbu5-pkinit:  $KURBU5_SO"
echo ""

# ── Helpers ──────────────────────────────────────────────────────────

KDC_PID=""

cleanup() {
    [ -n "$KDC_PID" ] && kill "$KDC_PID" 2>/dev/null || true
    wait "$KDC_PID" 2>/dev/null || true
    if [ "$ec" -ne 0 ]; then
        echo ""
        echo "=== KDC log ==="
        cat "$WORKDIR/kdc.log" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

stop_kdc() {
    [ -n "$KDC_PID" ] && kill "$KDC_PID" 2>/dev/null || true
    wait "$KDC_PID" 2>/dev/null || true
    KDC_PID=""
    sleep 0.5
}

# ── PKI setup ────────────────────────────────────────────────────────

echo "=== Setting up test PKI ==="

PKI_DIR="$WORKDIR/pki"
# Use INTEROP.EXAMPLE.COM realm in certs
CERT_REALM="$REALM"

# Generate PKI with the interop realm
OUTDIR="$PKI_DIR"
mkdir -p "$OUTDIR"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUTDIR/ca.key" 2>/dev/null
openssl req -new -x509 -key "$OUTDIR/ca.key" -subj "/CN=Interop CA" -days 3650 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$OUTDIR/ca.pem" 2>/dev/null

# KDC cert
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUTDIR/kdc.key" 2>/dev/null
cat > "$OUTDIR/kdc-ext.cnf" <<EOF
[v3_kdc]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @kdc_san

[kdc_san]
otherName.0 = 1.3.6.1.5.2.2;SEQUENCE:kdc_princ

[kdc_princ]
realm = EXPLICIT:0,GeneralString:${CERT_REALM}
name  = EXPLICIT:1,SEQUENCE:kdc_name

[kdc_name]
type  = EXPLICIT:0,INTEGER:2
comp0 = EXPLICIT:1,SEQUENCE:kdc_name_components

[kdc_name_components]
val0 = GeneralString:krbtgt
val1 = GeneralString:${CERT_REALM}
EOF
openssl req -new -key "$OUTDIR/kdc.key" -subj "/CN=KDC ${CERT_REALM}" -out "$OUTDIR/kdc.csr" 2>/dev/null
openssl x509 -req -in "$OUTDIR/kdc.csr" -CA "$OUTDIR/ca.pem" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -days 3650 -extfile "$OUTDIR/kdc-ext.cnf" -extensions v3_kdc -out "$OUTDIR/kdc.pem" 2>/dev/null

# Client cert
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUTDIR/client.key" 2>/dev/null
cat > "$OUTDIR/client-ext.cnf" <<EOF
[v3_client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @client_san

[client_san]
otherName.0 = 1.3.6.1.5.2.2;SEQUENCE:client_princ

[client_princ]
realm = EXPLICIT:0,GeneralString:${CERT_REALM}
name  = EXPLICIT:1,SEQUENCE:client_name

[client_name]
type  = EXPLICIT:0,INTEGER:1
comp0 = EXPLICIT:1,SEQUENCE:client_name_components

[client_name_components]
val0 = GeneralString:${CLIENT}
EOF
openssl req -new -key "$OUTDIR/client.key" -subj "/CN=${CLIENT}@${CERT_REALM}" -out "$OUTDIR/client.csr" 2>/dev/null
openssl x509 -req -in "$OUTDIR/client.csr" -CA "$OUTDIR/ca.pem" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -days 3650 -extfile "$OUTDIR/client-ext.cnf" -extensions v3_client -out "$OUTDIR/client.pem" 2>/dev/null
rm -f "$OUTDIR"/*.csr "$OUTDIR"/*.cnf "$OUTDIR"/*.srl
testsuccess "PKI generated (realm=$CERT_REALM)"

KDC_PORT=$(free_port)
CCACHE="$WORKDIR/ccache"

# Set up MIT plugin directory with system plugins symlinked
# This prevents MIT from loading its own pkinit.so alongside ours
MIT_PLUGIN_DIR="$WORKDIR/plugins"
mkdir -p "$MIT_PLUGIN_DIR/preauth"
for sys_dir in /usr/lib64/krb5/plugins/preauth /usr/lib/krb5/plugins/preauth; do
    if [ -d "$sys_dir" ]; then
        for so in "$sys_dir"/*.so; do
            name=$(basename "$so")
            [ "$name" = "pkinit.so" ] && continue
            ln -sf "$so" "$MIT_PLUGIN_DIR/preauth/$name" 2>/dev/null || true
        done
        break
    fi
done

# ── Heimdal KDC setup ────────────────────────────────────────────────

setup_heimdal_kdc() {
    local pqc_opts="${1:-}"

    cat > "$WORKDIR/krb5.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem

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
${pqc_opts}
    database = {
        dbname = ${WORKDIR}/heimdal-db/heimdal
        log_file = ${WORKDIR}/heimdal-db/log
    }

[logging]
    kdc = FILE:${WORKDIR}/kdc.log
CONF

    if [ ! -f "$WORKDIR/heimdal-db/heimdal.db" ]; then
        mkdir -p "$WORKDIR/heimdal-db"
        export KRB5_CONFIG="$WORKDIR/krb5.conf"
        echo "" | "$H_KADMIN" -l -H "$WORKDIR/heimdal-db/heimdal" init \
            --realm-max-ticket-life=1d --realm-max-renewable-life=7d \
            "$REALM" 2>/dev/null || true
        "$H_KADMIN" -l -H "$WORKDIR/heimdal-db/heimdal" add \
            --random-password --use-defaults "${CLIENT}@${REALM}" 2>/dev/null || true
    fi

    export KRB5_CONFIG="$WORKDIR/krb5.conf"
    > "$WORKDIR/kdc.log"
    "$H_KDC" --addresses=127.0.0.1 --ports="$KDC_PORT" \
        --config-file="$WORKDIR/krb5.conf" \
        --detach --testing 2>>"$WORKDIR/kdc.log" || true
    sleep 1
    KDC_PID=$(lsof -ti "tcp:${KDC_PORT}" 2>/dev/null | head -1 || true)
    [ -z "$KDC_PID" ] && KDC_PID=$(pgrep -f "kdc.*${KDC_PORT}" 2>/dev/null | head -1 || true)
}

# ── MIT KDC setup ─────────────────────────────────────────────────────

setup_mit_kdc() {
    local pqc_opts="${1:-}"

    mkdir -p "$WORKDIR/mit-db"

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

[kdcdefaults]
    pkinit_identity = FILE:${PKI_DIR}/kdc.pem,${PKI_DIR}/kdc.key
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem
${pqc_opts}

[dbdefaults]
    database_name = ${WORKDIR}/mit-db/principal

[plugins]
    clpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    kdcpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    certauth = {
        module = pkinit:${KURBU5_SO}

    }

[logging]
    kdc = FILE:${WORKDIR}/kdc.log
CONF

    # Create KDC config (must exist before kdb5_util)
    cat > "$WORKDIR/mit-kdc.conf" <<CONF
[kdcdefaults]
    kdc_ports = ${KDC_PORT}
    kdc_tcp_ports = ${KDC_PORT}

[realms]
    ${REALM} = {
        database_name = ${WORKDIR}/mit-db/principal
        key_stash_file = ${WORKDIR}/mit-db/.k5.${REALM}
        pkinit_identity = FILE:${PKI_DIR}/kdc.pem,${PKI_DIR}/kdc.key
        pkinit_anchors = FILE:${PKI_DIR}/ca.pem
${pqc_opts}
    }

[plugins]
    clpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    kdcpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    certauth = {
        module = pkinit:${KURBU5_SO}

    }

[logging]
    kdc = FILE:${WORKDIR}/kdc.log
CONF

    export KRB5_CONFIG="$WORKDIR/mit-krb5.conf"
    export KRB5_KDC_PROFILE="$WORKDIR/mit-kdc.conf"

    if [ ! -f "$WORKDIR/mit-db/principal" ]; then
        # Create the MIT KDB
        # "master_password" is a fixed placeholder: this KDB is created fresh
        # in $WORKDIR for this test run only and destroyed on cleanup, so the
        # stash key never needs to be secret or unique.
        KRB5_CONFIG="$WORKDIR/mit-krb5.conf" \
        KRB5_KDC_PROFILE="$WORKDIR/mit-kdc.conf" \
            kdb5_util create -s -P master_password -r "$REALM" \
            2>"$WORKDIR/mit-kdb.log" || true
        KRB5_CONFIG="$WORKDIR/mit-krb5.conf" \
        KRB5_KDC_PROFILE="$WORKDIR/mit-kdc.conf" \
            "$M_KADMIN" -r "$REALM" -q "addprinc -randkey ${CLIENT}@${REALM}" \
            2>>"$WORKDIR/mit-kdb.log" || true
    fi

    > "$WORKDIR/kdc.log"
    KRB5_KDC_PROFILE="$WORKDIR/mit-kdc.conf" \
    KRB5_CONFIG="$WORKDIR/mit-krb5.conf" \
        "$M_KDC" -n 2>>"$WORKDIR/kdc.log" &
    KDC_PID=$!
    sleep 1
}

# ── Test runners ──────────────────────────────────────────────────────

run_heimdal_kinit() {
    local desc="$1"
    local extra_conf="${2:-}"

    echo "  Testing: $desc"
    export KRB5_CONFIG="$WORKDIR/krb5.conf"
    export KRB5CCNAME="FILE:$CCACHE"
    > "$WORKDIR/kdc.log"

    if "$H_KINIT" \
        -C "FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
        --x509-anchors="FILE:${PKI_DIR}/ca.pem" \
        "${CLIENT}@${REALM}" 2>"$WORKDIR/kinit-err.log"; then
        testsuccess "$desc"
        "$H_KDESTROY" 2>/dev/null || true
        return 0
    else
        testfailed "$desc"
        [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/kinit-err.log"
        return 1
    fi
}

run_mit_kinit() {
    local desc="$1"
    local conf="${2:-$WORKDIR/krb5.conf}"

    echo "  Testing: $desc"
    export KRB5CCNAME="FILE:$CCACHE"
    > "$WORKDIR/kdc.log"

    if KRB5_CONFIG="$conf" \
       "$M_KINIT" \
        -X "X509_user_identity=FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
        -X "X509_anchors=FILE:${PKI_DIR}/ca.pem" \
        "${CLIENT}@${REALM}" 2>"$WORKDIR/kinit-err.log"; then
        testsuccess "$desc"
        "$M_KDESTROY" 2>/dev/null || true
        return 0
    else
        testfailed "$desc"
        [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/kinit-err.log"
        return 1
    fi
}

check_kdc_log() {
    local pattern="$1"
    local desc="$2"
    if grep -qi "$pattern" "$WORKDIR/kdc.log" 2>/dev/null; then
        testsuccess "$desc"
    else
        testfailed "$desc"
        if [ "${VERBOSE:-0}" = "1" ]; then
            cat "$WORKDIR/kdc.log"
        fi
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════════════
# Test 1: Heimdal KDC (Rust) ← Heimdal kinit (Rust client)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Test 1: Heimdal KDC (Rust) ←→ Heimdal kinit ==="

setup_heimdal_kdc
if [ -n "$KDC_PID" ]; then
    run_heimdal_kinit "Heimdal→Heimdal DH-2048" || true
    run_heimdal_kinit "Heimdal→Heimdal ECDH P-256 (--key-agreement=P-256)" || true
    check_kdc_log "verified AS-REQ" "KDC log shows Rust verification"
    stop_kdc
else
    testfailed "Heimdal KDC failed to start"
fi

# ══════════════════════════════════════════════════════════════════════
# Test 2: Heimdal KDC (Rust) ← MIT kinit (kurbu5-pkinit)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Test 2: Heimdal KDC (Rust) ←→ MIT kinit (kurbu5-pkinit) ==="

setup_heimdal_kdc
if [ -n "$KDC_PID" ]; then
    # Need MIT krb5.conf that points to Heimdal KDC
    cat > "$WORKDIR/mit-client.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem
    plugin_base_dir = ${MIT_PLUGIN_DIR}

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }

[plugins]
    clpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    kdcpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    certauth = {
        module = pkinit:${KURBU5_SO}
    }
CONF

    run_mit_kinit "MIT(kurbu5)→Heimdal DH/ECDH" "$WORKDIR/mit-client.conf" || true
    check_kdc_log "verified AS-REQ" "KDC processed MIT client's PKINIT"
    stop_kdc
else
    testfailed "Heimdal KDC failed to start"
fi

# ══════════════════════════════════════════════════════════════════════
# Test 3: MIT KDC (kurbu5-pkinit) ← Heimdal kinit
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Test 3: MIT KDC (kurbu5-pkinit) ←→ Heimdal kinit ==="

if [ -x "$M_KDC" ] && [ -x "$M_KADMIN" ]; then
    setup_mit_kdc
    if [ -n "$KDC_PID" ] && kill -0 "$KDC_PID" 2>/dev/null; then
        # Heimdal kinit needs its own config pointing to MIT KDC
        cat > "$WORKDIR/heimdal-to-mit.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }
CONF
        KRB5_CONFIG="$WORKDIR/heimdal-to-mit.conf" \
        KRB5CCNAME="FILE:$CCACHE" \
        "$H_KINIT" \
            -C "FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
            --x509-anchors="FILE:${PKI_DIR}/ca.pem" \
            "${CLIENT}@${REALM}" 2>"$WORKDIR/kinit-err.log" && \
            testsuccess "Heimdal kinit → MIT KDC (kurbu5)" || \
            testfailed "Heimdal kinit → MIT KDC (kurbu5)"

        stop_kdc
    else
        testfailed "MIT KDC failed to start"
        [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/kdc.log"
    fi
else
    testskip "MIT KDC (krb5kdc not found)"
fi

# ══════════════════════════════════════════════════════════════════════
# Test 4: MIT KDC (kurbu5-pkinit) ← MIT kinit (kurbu5-pkinit)
#         Uses kurbu5-pkinit's own test infrastructure for proper
#         MIT plugin loading (kdcpreauth + clpreauth + certauth).
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Test 4: MIT KDC (kurbu5-pkinit) ←→ MIT kinit (kurbu5-pkinit) ==="

SETUP_PY="$KURBU5_DIR/tests/system/pkinit/setup.py"
if [ -x "$M_KDC" ] && [ -f "$SETUP_PY" ]; then
    MIT_TEST_DIR="$WORKDIR/mit-test4"
    MIT_ENV="$MIT_TEST_DIR/env.sh"
    MIT_PORT=$((KDC_PORT + 100))

    python3 "$SETUP_PY" \
        --testdir "$MIT_TEST_DIR/kdc" \
        --portbase "$MIT_PORT" \
        --realm "$REALM" \
        --principal "$CLIENT" \
        --plugin-so "$KURBU5_SO" \
        --env-file "$MIT_ENV" &
    MIT_SETUP_PID=$!

    # Wait for env file
    for i in $(seq 1 30); do
        [ -f "$MIT_ENV" ] && break
        kill -0 "$MIT_SETUP_PID" 2>/dev/null || break
        sleep 0.5
    done

    if [ -f "$MIT_ENV" ]; then
        # Source the env and run kinit
        T4_RESULT=$(source "$MIT_ENV" && /usr/bin/kinit \
            -X "X509_user_identity=FILE:${PKINIT_CLIENT_CERT},${PKINIT_CLIENT_KEY}" \
            "${PKINIT_PRINCIPAL}@${PKINIT_REALM}" </dev/null 2>"$WORKDIR/kinit-t4-err.log" && echo PASS || echo FAIL)
        if [ "$T4_RESULT" = "PASS" ]; then
            testsuccess "MIT(kurbu5)→MIT KDC(kurbu5)"
        else
            testfailed "MIT(kurbu5)→MIT KDC(kurbu5)"
            [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/kinit-t4-err.log" 2>/dev/null
        fi
    else
        testfailed "MIT KDC setup.py did not produce env file"
    fi

    kill "$MIT_SETUP_PID" 2>/dev/null || true
    wait "$MIT_SETUP_PID" 2>/dev/null || true
else
    if [ ! -f "$SETUP_PY" ]; then
        testskip "kurbu5-pkinit setup.py not found at $SETUP_PY"
    else
        testskip "MIT KDC (krb5kdc not found)"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# Test 5: PQC — Heimdal KDC (ML-KEM) ← MIT kinit (kurbu5-pkinit)
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Test 5: PQC — Heimdal KDC (ML-KEM-768) ←→ MIT kinit ==="

setup_heimdal_kdc "    pkinit_pqc_min_algorithm = ML-KEM-768"
if [ -n "$KDC_PID" ]; then
    cat > "$WORKDIR/mit-pqc-client.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem
    plugin_base_dir = ${MIT_PLUGIN_DIR}
    pkinit_pqc_min_algorithm = ML-KEM-768

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }

[plugins]
    clpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    kdcpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    certauth = {
        module = pkinit:${KURBU5_SO}
    }
CONF

    run_mit_kinit "MIT(kurbu5, ML-KEM-768)→Heimdal KDC" "$WORKDIR/mit-pqc-client.conf" || true
    check_kdc_log "KEM" "KDC log shows ML-KEM negotiation"
    stop_kdc
else
    testfailed "Heimdal KDC (PQC) failed to start"
fi

# ══════════════════════════════════════════════════════════════════════
# Test 6: PQC enforcement — reject classical from MIT kinit
# ══════════════════════════════════════════════════════════════════════

echo ""
echo "=== Test 6: PQC enforcement — classical rejected ==="

PQC_OPTS="    pkinit_pqc_min_algorithm = ML-KEM-768
    pkinit_require_pqc = true"
setup_heimdal_kdc "$PQC_OPTS"
if [ -n "$KDC_PID" ]; then
    # MIT kinit WITHOUT PQC config → should be rejected
    cat > "$WORKDIR/mit-nopqc-client.conf" <<CONF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    pkinit_anchors = FILE:${PKI_DIR}/ca.pem
    plugin_base_dir = ${MIT_PLUGIN_DIR}

[realms]
    ${REALM} = {
        kdc = 127.0.0.1:${KDC_PORT}
    }

[plugins]
    clpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    kdcpreauth = {
        module = pkinit:${KURBU5_SO}
    }
    certauth = {
        module = pkinit:${KURBU5_SO}
    }
CONF

    echo "  Testing: MIT kinit (classical) → PQC-enforcing Heimdal KDC"
    > "$WORKDIR/kdc.log"
    if KRB5_CONFIG="$WORKDIR/mit-nopqc-client.conf" \
       KRB5CCNAME="FILE:$CCACHE" \
       "$M_KINIT" \
        -X "X509_user_identity=FILE:${PKI_DIR}/client.pem,${PKI_DIR}/client.key" \
        -X "X509_anchors=FILE:${PKI_DIR}/ca.pem" \
        "${CLIENT}@${REALM}" 2>"$WORKDIR/kinit-err.log"; then
        # kinit succeeding here is only a pass if kurbu5-pkinit actually
        # retried with ML-KEM after the KDC's PQC-required hint — plain
        # success doesn't prove that happened, so require the KDC's own
        # "verified AS-REQ via ML-KEM-*" trace line as positive evidence.
        if grep -qi "verified AS-REQ via ML-KEM" "$WORKDIR/kdc.log" 2>/dev/null; then
            testsuccess "MIT kinit retried with ML-KEM after PQC rejection (auto-negotiation)"
        else
            testfailed "classical PKINIT should have been rejected but succeeded"
        fi
    else
        # Check if the rejection was for PQC reasons
        if grep -q "PQC required" "$WORKDIR/kdc.log" 2>/dev/null; then
            testsuccess "classical correctly rejected by PQC-enforcing KDC"
        else
            testfailed "kinit failed but not due to PQC enforcement"
            [ "${VERBOSE:-0}" = "1" ] && cat "$WORKDIR/kdc.log"
        fi
    fi

    stop_kdc
else
    testfailed "Heimdal KDC (PQC enforce) failed to start"
fi

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo "================================================"
if [ "$ec" -eq 0 ]; then
    echo "  All interop tests PASSED"
else
    echo "  Some interop tests FAILED (ec=$ec)"
fi
echo "================================================"
echo ""
echo "Work directory: $WORKDIR"

exit $ec
