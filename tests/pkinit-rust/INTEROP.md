# Cross-Implementation PKINIT Interop Testing

## Overview

This document describes how to test the Rust PKINIT adapter against both
Heimdal's own client and MIT Kerberos with the `kurbu5-pkinit` plugin.

## Test Matrix

| KDC | Client | Key Exchange | Expected |
|-----|--------|-------------|----------|
| Heimdal+Rust | Heimdal `kinit` | ECDH P-256 | ✅ |
| Heimdal+Rust | Heimdal `kinit` | DH-2048 | ✅ |
| Heimdal+Rust | MIT `kinit` + `kurbu5-pkinit` | ECDH P-256 | ✅ |
| Heimdal+Rust | MIT `kinit` + `kurbu5-pkinit` | ML-KEM-768 | ✅ |
| MIT KDC + `kurbu5-pkinit` | Heimdal `kinit` (C) | ECDH P-256 | ✅ |
| Heimdal+Rust | MIT `kinit` + `kurbu5-pkinit` | ML-KEM-768-X25519 | ✅ |

## Prerequisites

### Heimdal with Rust PKINIT

```sh
cd ~/workspace/heimdal-pkinit
cd rust && cargo build --release && cd ..
autoreconf -fi
./configure --prefix=/opt/heimdal-test \
    --enable-pkinit-rust \
    --with-openssl
make && make install
```

### MIT Kerberos with kurbu5-pkinit

```sh
# Build MIT krb5
cd ~/workspace/mit-krb5/src
./configure --prefix=/opt/mit-test
make && make install

# Build kurbu5-pkinit
cd ~/workspace/kurbu5-pkinit
cargo build --release
install -m 755 target/release/libkurbu5_pkinit.so \
    /opt/mit-test/lib/krb5/plugins/preauth/pkinit.so
```

## Test Setup

### Shared PKI

Both implementations must use the same CA, KDC certificate, and client
certificate. Use `setup-pki.sh` to generate them:

```sh
./tests/pkinit-rust/setup-pki.sh /tmp/pkinit-pki
```

### Heimdal KDC Configuration (krb5.conf)

```ini
[kdc]
    enable-pkinit = true
    pkinit_identity = FILE:/tmp/pkinit-pki/kdc.pem,/tmp/pkinit-pki/kdc.key
    pkinit_anchors = FILE:/tmp/pkinit-pki/ca.pem
    pkinit_principal_in_certificate = true
    # Enable PQC:
    pkinit_pqc_min_algorithm = ML-KEM-768
```

### MIT KDC Configuration (kdc.conf)

```ini
[kdcdefaults]
    pkinit_identity = FILE:/tmp/pkinit-pki/kdc.pem,/tmp/pkinit-pki/kdc.key
    pkinit_anchors = FILE:/tmp/pkinit-pki/ca.pem
    pkinit_pqc_min_algorithm = ML-KEM-768
```

## Running Cross-Tests

### Test 1: Heimdal KDC (Rust) ↔ Heimdal kinit

```sh
export KRB5_CONFIG=/path/to/heimdal/krb5.conf
/opt/heimdal-test/bin/kinit \
    -C FILE:/tmp/pkinit-pki/client.pem,/tmp/pkinit-pki/client.key \
    --x509-anchors=FILE:/tmp/pkinit-pki/ca.pem \
    testuser@EXAMPLE.COM
```

### Test 2: Heimdal KDC (Rust) ↔ MIT kinit (kurbu5-pkinit, classical)

```sh
export KRB5_CONFIG=/path/to/mit/krb5.conf
/opt/mit-test/bin/kinit \
    -X X509_user_identity=FILE:/tmp/pkinit-pki/client.pem,/tmp/pkinit-pki/client.key \
    -X X509_anchors=FILE:/tmp/pkinit-pki/ca.pem \
    testuser@EXAMPLE.COM
```

### Test 3: Heimdal KDC (Rust) ↔ MIT kinit (kurbu5-pkinit, ML-KEM-768)

```sh
# krb5.conf must have: pkinit_pqc_min_algorithm = ML-KEM-768
export KRB5_CONFIG=/path/to/mit/krb5.conf
/opt/mit-test/bin/kinit \
    -X X509_user_identity=FILE:/tmp/pkinit-pki/client.pem,/tmp/pkinit-pki/client.key \
    -X X509_anchors=FILE:/tmp/pkinit-pki/ca.pem \
    testuser@EXAMPLE.COM
# The KDC log should show: "PKINIT: verified AS-REQ via ML-KEM-768"
```

### Test 4: MIT KDC (kurbu5-pkinit) ↔ Heimdal kinit

```sh
# Start MIT KDC with kurbu5-pkinit plugin
export KRB5_CONFIG=/path/to/heimdal/krb5.conf
/opt/heimdal-test/bin/kinit \
    -C FILE:/tmp/pkinit-pki/client.pem,/tmp/pkinit-pki/client.key \
    --x509-anchors=FILE:/tmp/pkinit-pki/ca.pem \
    testuser@EXAMPLE.COM
```

## Verifying PQC Key Exchange

When `pkinit_pqc_min_algorithm` is set, check the KDC log for evidence
of ML-KEM negotiation:

```
# Heimdal KDC (Rust):
PKINIT: verified AS-REQ via ML-KEM-768
PKINIT: built AS-REP via ML-KEM-768

# MIT KDC (kurbu5-pkinit):
PKINIT client selected ML-KEM-768
PKINIT client verified AS-REP via ML-KEM-768
```

## Known Limitations

- **Freshness tokens (RFC 8070)**: `pkinit-core` supports them at the
  protocol level, but Heimdal's KDC doesn't have the infrastructure to
  generate/validate freshness tokens. The feature works with MIT's KDC
  (which has freshness support in its FAST framework).

- **Win2k PKINIT**: The Rust adapter does not support Win2k-era PKINIT.
  When `PKINIT_RUST` is enabled, Win2k PKINIT requests will fall through
  to the original C code path (since `pa_pkinit_validate` handles both
  in the C path, and the Rust path only handles IETF PKINIT).

- **Anonymous PKINIT**: Supported by `pkinit-core` but the Heimdal
  adapter doesn't yet wire PA-PKINIT-KX (RFC 6112) for the anonymous
  session key derivation. Classical anonymous PKINIT works.
