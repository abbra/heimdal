# Cross-Implementation PKINIT Interop Testing

## Overview

This document describes how to test the Rust PKINIT adapter against both
Heimdal's own client and MIT Kerberos with the `kurbu5-pkinit` plugin.

## Verified Test Matrix

All combinations below have been verified by `check-interop.sh`:

| # | KDC | Client | Key Exchange | Status |
|---|-----|--------|-------------|--------|
| 1a | Heimdal+Rust | Heimdal `kinit` (Rust client) | DH-2048 | ✅ Verified |
| 1b | Heimdal+Rust | Heimdal `kinit` (Rust client) | ECDH P-256 | ✅ Verified |
| 1c | Heimdal+Rust | Heimdal `kinit` (Rust client) | ECDH P-384 | ✅ Verified |
| 1d | Heimdal+Rust | Heimdal `kinit` (Rust client) | ECDH P-521 | ✅ Verified |
| 1e | Heimdal+Rust | Heimdal `kinit` (Rust client) | KDF ah-sha256 | ✅ Verified |
| 1f | Heimdal+Rust | Heimdal `kinit` (Rust client) | KDF ah-sha512 | ✅ Verified |
| 2 | Heimdal+Rust | MIT `kinit` + `kurbu5-pkinit` | ECDH P-256 | ✅ Verified |
| 3 | MIT KDC + `kurbu5-pkinit` | Heimdal `kinit` | ECDH P-256 | ✅ Verified |
| 4 | MIT KDC + `kurbu5-pkinit` | MIT `kinit` + `kurbu5-pkinit` | ECDH P-256 | ✅ Verified |
| 5 | Heimdal+Rust (PQC) | MIT `kinit` + `kurbu5-pkinit` | **ML-KEM-768** | ✅ Verified |
| 6a | Heimdal+Rust (PQC enforce) | MIT `kinit` + `kurbu5-pkinit` | DH rejected | ✅ Verified |
| 6b | Heimdal+Rust (PQC enforce) | MIT `kinit` + `kurbu5-pkinit` | **ML-KEM-768 auto-retry** | ✅ Verified |

### ML-KEM-768 KDC Log (Test 5)

```
PKINIT: KDC initialized (Rust pkinit-core), KEM hint 32 bytes
PKINIT: get_hint returning 32 bytes of KEM algorithm hint
PKINIT: verified AS-REQ via ML-KEM-768
PKINIT pre-authentication succeeded -- testuser using ML-KEM-768
PKINIT: built AS-REP via ML-KEM-768
AS-REQ SUCCESS
```

## Running the Tests

### Automated (recommended)

```sh
# Full interop test suite
HEIMDAL_PREFIX=/opt/heimdal-test \
KURBU5_DIR=~/workspace/kurbu5-pkinit \
    tests/pkinit-rust/check-interop.sh

# With verbose output
VERBOSE=1 HEIMDAL_PREFIX=/opt/heimdal-test \
KURBU5_DIR=~/workspace/kurbu5-pkinit \
    tests/pkinit-rust/check-interop.sh
```

### Full build + test pipeline

```sh
tests/pkinit-rust/build-and-test.sh \
    --prefix /opt/heimdal-test
```

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

### MIT Kerberos + kurbu5-pkinit

The system MIT krb5 (`krb5-workstation`, `krb5-server` packages) works.
Only `kurbu5-pkinit` needs to be built from source:

```sh
cd ~/workspace/kurbu5-pkinit
cargo build --release
# The plugin is: target/release/libkurbu5_pkinit.so
```

The test scripts load `kurbu5-pkinit` via MIT's `[plugins]` config
sections and `plugin_base_dir` redirection, so no system files need
to be modified.

## MIT Plugin Loading

MIT krb5 uses separate plugin interfaces for KDC and client:

```ini
[libdefaults]
    # Redirect plugin search away from /usr/lib64/krb5/plugins/
    # to avoid loading the system pkinit.so alongside ours
    plugin_base_dir = /path/to/test/plugins

[plugins]
    clpreauth = {
        module = pkinit:/path/to/libkurbu5_pkinit.so
    }
    kdcpreauth = {
        module = pkinit:/path/to/libkurbu5_pkinit.so
    }
    certauth = {
        module = pkinit:/path/to/libkurbu5_pkinit.so
    }
```

**Important**: the old `[plugins] preauth = { ... }` syntax does NOT
work for loading `kurbu5-pkinit`. MIT krb5 requires the interface-
specific section names (`clpreauth`, `kdcpreauth`, `certauth`).

Non-PKINIT system plugins (spake.so, otp.so) must be symlinked into
the `plugin_base_dir/preauth/` directory to avoid "unable to load
plugin" errors.

## KDC Configuration

### Heimdal KDC (krb5.conf)

```ini
[kdc]
    enable-pkinit = true
    pkinit_identity = FILE:/path/to/kdc.pem,/path/to/kdc.key
    pkinit_anchors = FILE:/path/to/ca.pem
    pkinit_principal_in_certificate = true

    # Post-quantum: advertise ML-KEM-768 and ML-KEM-1024
    pkinit_pqc_min_algorithm = ML-KEM-768

    # Optional: reject classical DH/ECDH entirely
    pkinit_require_pqc = true
```

### MIT KDC (kdc.conf, using kurbu5-pkinit)

```ini
[realms]
    EXAMPLE.COM = {
        pkinit_identity = FILE:/path/to/kdc.pem,/path/to/kdc.key
        pkinit_anchors = FILE:/path/to/ca.pem
        pkinit_pqc_min_algorithm = ML-KEM-768
    }
```

## PQC Behavior

### Hint advertisement

When `pkinit_pqc_min_algorithm` is configured, the Heimdal KDC includes
a `PA-PK-AS-REQ-Hint` in the `ERR_PREAUTH_REQUIRED` response listing
the supported ML-KEM algorithms. A PQC-capable client (kurbu5-pkinit)
parses this hint and selects ML-KEM for its AS-REQ.

### Enforcement

When `pkinit_require_pqc = true`, the KDC:
1. Accepts the AS-REQ and verifies the CMS signature
2. Detects the key exchange is classical DH/ECDH
3. Returns `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` (error 65)
4. Includes the acceptable KEM algorithms in the error data
5. A PQC-capable client retries with ML-KEM and succeeds

### Auto-negotiation (verified)

When `pkinit_require_pqc = true` and the client is kurbu5-pkinit:
1. Client sends AS-REQ with ECDH P-256
2. KDC rejects with error 65 + KEM algorithm list
3. Client's `handle_tryagain()` selects ML-KEM-768
4. Client sends new AS-REQ with ML-KEM-768 public key
5. KDC encapsulates, derives key via HKDF-SHA-512
6. Ticket issued successfully

## Supported Algorithms

### Key exchange (via pkinit-core)

| Algorithm | Type | Status |
|-----------|------|--------|
| MODP DH 2048 | Classical | ✅ |
| MODP DH 4096 | Classical | ✅ |
| ECDH P-256 | Classical | ✅ |
| ECDH P-384 | Classical | ✅ |
| ECDH P-521 | Classical | ✅ |
| ML-KEM-512 | Post-quantum | ✅ (supported, untested) |
| ML-KEM-768 | Post-quantum | ✅ Verified |
| ML-KEM-1024 | Post-quantum | ✅ (supported, untested) |
| ML-KEM-768-X25519 | Composite | ✅ (supported, untested) |
| ML-KEM-768-ECDH-P256 | Composite | ✅ (supported, untested) |
| ML-KEM-1024-ECDH-P384 | Composite | ✅ (supported, untested) |

### KDF algorithms (RFC 8636)

| Algorithm | Status |
|-----------|--------|
| SP800-56A SHA-256 (`ah-sha256`) | ✅ Verified |
| SP800-56A SHA-512 (`ah-sha512`) | ✅ Verified |
| SP800-56A SHA-1 (`ah-sha1`) | ✅ (supported) |
| HKDF-SHA-512 (KEM path) | ✅ Verified (with ML-KEM) |
| Legacy `octetstring2key` | ✅ Verified (default DH) |

## Known Limitations

### Freshness tokens (RFC 8070)

`pkinit-core` supports freshness tokens at the protocol level:
- `PkinitClientState::set_freshness_token()` stores a received token
- `PKAuthenticator.freshness_token` is included in the AS-REQ
- The Heimdal adapter exposes `heimdal_pkinit_client_set_freshness()`

However, Heimdal's KDC does not have the infrastructure to **generate**
freshness tokens (which requires an encrypted timestamp mechanism in the
KDC's pre-auth framework). This is a Heimdal limitation, not a
pkinit-core limitation. The feature works with MIT's KDC (which has
freshness support via its FAST framework).

**Workaround**: When interoperating with an MIT KDC that sends
`PA-AS-FRESHNESS`, kurbu5-pkinit (on the client side) handles it
correctly. The Heimdal KDC simply never sends `PA-AS-FRESHNESS`.

### Win2k PKINIT and RSA key transport — Deprecated

Win2k PKINIT (PA type 15) uses RSA key transport, which is being
formally deprecated by
[draft-rische-kitten-pkinit-crypto-deprec](https://datatracker.ietf.org/doc/draft-rische-kitten-pkinit-crypto-deprec/).
The `pkinit-core` library deliberately does not implement RSA key
transport (`PaPkAsRep::EncKeyPack` returns `Unsupported`).

**Current behavior**: When `PKINIT_RUST` is enabled, the KDC
automatically routes Win2k requests (PA type 15) to Heimdal's
original C code path. IETF PKINIT (PA type 16) goes through
the Rust pkinit-core path. This provides backward compatibility
without requiring pkinit-core to implement a deprecated mechanism.

**Practical impact**: Win2k PKINIT is only used by Windows 2000
and early Windows XP clients (pre-SP2). All modern Windows
versions (XP SP2+, Vista, 7, 8, 10, 11, Server 2003+) use
IETF PKINIT (PA type 16). New deployments should not need
Win2k support.

### Anonymous PKINIT (RFC 6112, RFC 8062) — Fixed

Anonymous PKINIT is fully supported:
- Unsigned CMS data (no client certificate) via `pkinit-core`
- `WELLKNOWN/ANONYMOUS` principal detection
- **PA-PKINIT-KX** session key strengthening via `krb5_crypto_fx_cf2`

The PA-PKINIT-KX mechanism is generated in the C code after
`heimdal_pkinit_mk_pa_reply` returns, using Heimdal's native
`krb5_crypto_fx_cf2` and `krb5_encrypt_EncryptedData`. It:
1. Generates a random KDC contribution key
2. Derives `session_key = FX-CF2(contribution, reply_key, "PKINIT", "KEYEXCHANGE")`
3. Encrypts the contribution and sends it as PA-PKINIT-KX padata

PA-PKINIT-KX is generated for **all** DH/ECDH/KEM exchanges, not just
anonymous ones, matching the behavior of Heimdal's original C code.

Verified with both Heimdal `kinit -n` and MIT `kinit -n` (kurbu5-pkinit).

## Test Scripts

| Script | Purpose | Tests |
|--------|---------|-------|
| `check-interop.sh` | Cross-implementation interop | 8 scenarios (Heimdal↔MIT, PQC) |
| `check-pkinit-rust.sh` | Heimdal-only comprehensive | 16 tests (DH, ECDH, KDF, PQC) |
| `build-and-test.sh` | Full build + test pipeline | Build + all tests |
| `setup-pki.sh` | PKI generator | CA + KDC cert + client cert |

## References

- [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) — PKINIT
- [RFC 6112](https://www.rfc-editor.org/rfc/rfc6112) — Anonymous PKINIT
- [RFC 8062](https://www.rfc-editor.org/rfc/rfc8062) — Anonymous Kerberos
- [RFC 8070](https://www.rfc-editor.org/rfc/rfc8070) — Freshness Tokens
- [RFC 8636](https://www.rfc-editor.org/rfc/rfc8636) — PKINIT Algorithm Agility
- [draft-bokovoy-kitten-pkinit-pqc](https://datatracker.ietf.org/doc/draft-bokovoy-kitten-pkinit-pqc/) — Post-quantum PKINIT
- [draft-rische-kitten-pkinit-crypto-deprec](https://datatracker.ietf.org/doc/draft-rische-kitten-pkinit-crypto-deprec/) — PKINIT crypto deprecation (RSA key transport)
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM
