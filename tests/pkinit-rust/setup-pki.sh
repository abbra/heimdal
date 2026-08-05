#!/bin/bash
#
# Generate a test PKI for PKINIT integration testing.
#
# Creates a CA, a KDC certificate, and a client certificate
# suitable for use with Heimdal's PKINIT.
#
# Usage: ./setup-pki.sh <output-dir>
#
set -euo pipefail

OUTDIR="${1:-.}"
REALM="EXAMPLE.COM"
KDC_PRINCIPAL="krbtgt/${REALM}"
CLIENT_PRINCIPAL="testuser"

mkdir -p "$OUTDIR"

# ── CA ────────────────────────────────────────────────────────────────

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUTDIR/ca.key" 2>/dev/null

openssl req -new -x509 -key "$OUTDIR/ca.key" \
    -subj "/CN=Test PKINIT CA" \
    -days 3650 \
    -out "$OUTDIR/ca.pem" 2>/dev/null

# ── KDC certificate ──────────────────────────────────────────────────

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUTDIR/kdc.key" 2>/dev/null

cat > "$OUTDIR/kdc-ext.cnf" <<EOF
[v3_kdc]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectAltName = @kdc_san

[kdc_san]
otherName.0 = 1.3.6.1.5.2.2;SEQUENCE:kdc_princ

[kdc_princ]
realm = EXPLICIT:0,GeneralString:${REALM}
name  = EXPLICIT:1,SEQUENCE:kdc_name

[kdc_name]
type  = EXPLICIT:0,INTEGER:2
comp0 = EXPLICIT:1,SEQUENCE:kdc_name_components

[kdc_name_components]
val0 = GeneralString:krbtgt
val1 = GeneralString:${REALM}
EOF

openssl req -new -key "$OUTDIR/kdc.key" \
    -subj "/CN=KDC ${REALM}" \
    -out "$OUTDIR/kdc.csr" 2>/dev/null

openssl x509 -req -in "$OUTDIR/kdc.csr" \
    -CA "$OUTDIR/ca.pem" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -days 3650 \
    -extfile "$OUTDIR/kdc-ext.cnf" -extensions v3_kdc \
    -out "$OUTDIR/kdc.pem" 2>/dev/null

# ── Client certificate ───────────────────────────────────────────────

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUTDIR/client.key" 2>/dev/null

cat > "$OUTDIR/client-ext.cnf" <<EOF
[v3_client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectAltName = @client_san

[client_san]
otherName.0 = 1.3.6.1.5.2.2;SEQUENCE:client_princ

[client_princ]
realm = EXPLICIT:0,GeneralString:${REALM}
name  = EXPLICIT:1,SEQUENCE:client_name

[client_name]
type  = EXPLICIT:0,INTEGER:1
comp0 = EXPLICIT:1,SEQUENCE:client_name_components

[client_name_components]
val0 = GeneralString:${CLIENT_PRINCIPAL}
EOF

openssl req -new -key "$OUTDIR/client.key" \
    -subj "/CN=${CLIENT_PRINCIPAL}@${REALM}" \
    -out "$OUTDIR/client.csr" 2>/dev/null

openssl x509 -req -in "$OUTDIR/client.csr" \
    -CA "$OUTDIR/ca.pem" -CAkey "$OUTDIR/ca.key" -CAcreateserial \
    -days 3650 \
    -extfile "$OUTDIR/client-ext.cnf" -extensions v3_client \
    -out "$OUTDIR/client.pem" 2>/dev/null

# ── Cleanup temp files ────────────────────────────────────────────────
rm -f "$OUTDIR"/*.csr "$OUTDIR"/*.cnf "$OUTDIR"/*.srl

echo "PKI generated in $OUTDIR:"
echo "  CA:     $OUTDIR/ca.pem"
echo "  KDC:    $OUTDIR/kdc.pem + $OUTDIR/kdc.key"
echo "  Client: $OUTDIR/client.pem + $OUTDIR/client.key"
