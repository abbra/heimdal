# Heimdal PKINIT Post-Quantum Plugin — Feasibility Analysis

## Executive Summary

The `kurbu5-pkinit` workspace is deliberately split into two crates:

- **`pkinit-core`** — a pure Rust library implementing the entire PKINIT
  protocol: ASN.1 encoding/decoding, CMS signing/verification, DH/ECDH/KEM
  key exchange, KDF, certificate verification, and client authorization.
  It has **zero dependency** on MIT Kerberos.

- **`kurbu5-pkinit`** — a thin `cdylib` adapter that wires `pkinit-core`
  into MIT krb5's `clpreauth`, `kdcpreauth`, and `certauth` plugin
  interfaces via the `kurbu5-rs` bindings.

This architecture makes it feasible to **reuse `pkinit-core` as-is** and
write only a new Heimdal-specific adapter crate (`heimdal-pkinit`) that
maps Heimdal's APIs to the same `pkinit-core` state machines.

---

## 1. Architectural Comparison

### 1.1 MIT Kerberos PKINIT Plugin Model

MIT krb5 uses a **loadable plugin** architecture. PKINIT is implemented as a
shared object (`pkinit.so`) placed into `plugins/preauth/`. The KDC and
`kinit` each discover and load it at runtime via the `clpreauth_<name>_initvt`
/ `kdcpreauth_<name>_initvt` / `certauth_<name>_initvt` symbol conventions.
The plugin interacts with krb5 through well-defined vtable callbacks:

| Plugin interface      | Purpose |
|-----------------------|---------|
| `ClpreauthModule`     | Client-side pre-auth: build AS-REQ, process AS-REP |
| `KdcpreauthModule`    | KDC-side pre-auth: verify request, build reply |
| `CertauthModule`      | Certificate-to-principal authorization |

The plugin owns all PKINIT logic and uses krb5 only for:
- `krb5_c_random_to_key` / `krb5_c_keylengths` (via the `OctetString2Key` trait)
- `krb5int_trace` (tracing)
- `krb5_config_get_*` (reading `krb5.conf`)
- `krb5_unparse_name` (principal formatting)
- FAST-related crypto (`krb5_crypto_fx_cf2`)

### 1.2 Heimdal PKINIT Model

Heimdal's PKINIT is **compiled directly into `libkdc` and `libkrb5`** — it
is not a loadable plugin. The code lives in:

| File                        | Role |
|-----------------------------|------|
| `kdc/pkinit.c`              | KDC-side: `_kdc_pk_rd_padata`, `_kdc_pk_mk_pa_reply`, `_kdc_pk_check_client` |
| `kdc/pkinit-ec.c`           | KDC-side ECDH key agreement (OpenSSL-specific) |
| `lib/krb5/pkinit.c`         | Client-side: `_krb5_pk_mk_padata`, `_krb5_pk_rd_pa_reply` |
| `lib/krb5/pkinit-ec.c`      | Client-side ECDH key agreement |
| `lib/asn1/pkinit.asn1`      | ASN.1 module compiled by Heimdal's ASN.1 compiler |

Key differences from MIT:

1. **No plugin interface for PKINIT.** The KDC main loop calls `_kdc_pk_rd_padata`
   and `_kdc_pk_mk_pa_reply` directly via internal (underscore-prefixed) symbols.
   There is no vtable or `initvt` mechanism.

2. **Heimdal uses its own ASN.1 compiler** (generating C encode/decode functions)
   rather than an ASN.1 library. The generated types (`AuthPack`, `PA_PK_AS_REQ`,
   `PA_PK_AS_REP`, etc.) are exported in `pkinit_asn1.h`.

3. **Heimdal uses `hx509`** (its own X.509/CMS library) for all certificate
   operations, CMS signing/verification, and PKCS#11 access. There is no
   separate "identity loader" — `hx509_certs` handles everything.

4. **The KDC configuration** is stored in `krb5_kdc_configuration`, a struct
   that includes PKINIT fields directly (`enable_pkinit`,
   `pkinit_kdc_identity`, `pkinit_kdc_anchors`, `pkinit_dh_min_bits`, etc.)

5. **`octetstring2key`** is provided by `_krb5_pk_octetstring2key` (an internal
   function in `lib/krb5/`), not a plugin callback. Heimdal's equivalent of
   MIT's `krb5_c_random_to_key` is `krb5_random_to_key`.

6. **Anonymous PKINIT / PA-PKINIT-KX** is handled inline in
   `_kdc_pk_mk_pa_reply` using `krb5_crypto_fx_cf2` directly.

### 1.3 What Heimdal Lacks Compared to `pkinit-core`

Heimdal 7.8.0's PKINIT is missing several features that `pkinit-core`
implements:

| Feature | `pkinit-core` | Heimdal 7.8.0 | Heimdal+Rust |
|---------|:---:|:---:|:---:|
| DH (MODP 2048/4096) | ✅ | ✅ | ✅ Verified |
| ECDH (P-256) | ✅ | ✅ | ✅ Verified |
| ECDH (P-384, P-521) | ✅ | ❌ | ✅ Verified |
| RSA key transport | ✅ (server) | ✅ | ❌ (Rust path) |
| RFC 8636 algorithm-agile KDF | ✅ | ❌ | ✅ Verified |
| RFC 6112 / RFC 8062 Anonymous PKINIT | ✅ | ✅ | ⚠️ Partial |
| RFC 8070 Freshness tokens | ✅ | ❌ | ⚠️ Client only |
| `paChecksum2` (SHA-256) | ✅ | ❌ | ✅ (via pkinit-core) |
| ML-KEM-512/768/1024 (draft-pkinit-pqc) | ✅ | ❌ | ✅ ML-KEM-768 verified |
| Composite ML-KEM (ML-KEM-768-X25519, etc.) | ✅ | ❌ | ✅ (supported) |
| ML-DSA downgrade prevention | ✅ | ❌ | ✅ (via pkinit-core) |
| HKDF-SHA-512 KDF for KEM path | ✅ | ❌ | ✅ Verified |
| `PA-PK-AS-REQ-Hint` (KEM algorithm advertisement) | ✅ | ❌ | ✅ Verified |
| PQC enforcement (`pkinit_require_pqc`) | ✅ | ❌ | ✅ Verified |
| Win2k PKINIT compatibility | ❌ | ✅ | Falls back to C |
| Apple BTMM PKINIT compatibility | ❌ | ✅ | Falls back to C |

---

## 2. Integration Strategy

### 2.1 Recommended Approach: Heimdal Source Patch + `pkinit-core`

Since Heimdal has **no loadable plugin interface for PKINIT**, the adapter
cannot be a drop-in `.so` like `kurbu5-pkinit` is for MIT. Instead, the
integration must take one of these forms:

#### Option A: In-tree replacement (recommended for Heimdal forks / distributions)

Replace the C PKINIT implementation (`kdc/pkinit.c`, `kdc/pkinit-ec.c`,
`lib/krb5/pkinit.c`, `lib/krb5/pkinit-ec.c`) with thin C shims that call
into a Rust static library built from `pkinit-core` plus a new
`heimdal-pkinit` adapter crate.

The C shims would:
- Implement the existing `_kdc_pk_*` / `_krb5_pk_*` internal API surface
- Translate Heimdal's `krb5_context`, `krb5_kdc_configuration`,
  `hdb_entry_ex`, etc. into calls to `pkinit-core`'s Rust state machines
- Link as a static archive (`staticlib`) into `libkdc.so` and `libkrb5.so`

#### Option B: `windc_plugin` hook (limited — KDC side only, not sufficient)

Heimdal's `windc_plugin` provides hooks for PAC generation and client access
checks, but it does **not** provide hooks for pre-authentication processing.
The `client_access` callback runs too late — after PKINIT has already been
processed. This route is **not viable** for replacing PKINIT.

#### Option C: Patch Heimdal to add a pre-auth plugin interface

Add a proper loadable pre-auth plugin interface to Heimdal (similar to MIT's)
and then write `heimdal-pkinit` as a loadable `.so`. This is the cleanest
long-term approach but requires significant Heimdal upstream work.

### 2.2 Adapter Crate Structure

```
heimdal-pkinit/
├── Cargo.toml              # depends on pkinit-core, libc
├── build.rs                # bindgen against Heimdal headers
├── src/
│   ├── lib.rs              # crate root
│   ├── ffi.rs              # C-callable functions exposed to Heimdal
│   ├── kdc.rs              # KDC-side adapter (_kdc_pk_rd_padata etc.)
│   ├── client.rs           # Client-side adapter (_krb5_pk_* wrappers)
│   ├── o2k.rs              # OctetString2Key using krb5_random_to_key
│   ├── config.rs           # Map krb5_kdc_configuration → PkinitKdcConfig
│   └── hx509_bridge.rs     # Bridge hx509 cert objects ↔ pkinit-core DER
```

### 2.3 Mapping of Key Interfaces

#### 2.3.1 `OctetString2Key` Implementation

MIT's `kurbu5-pkinit` implements `OctetString2Key` by calling
`krb5_c_random_to_key` / `krb5_c_keylengths`. The Heimdal equivalent:

```rust
// MIT version (kurbu5-pkinit/src/o2k.rs)
unsafe { krb5_c_random_to_key(self.ctx, enctype, &seed, &mut keyblock) }
unsafe { krb5_c_keylengths(self.ctx, enctype, &mut keybytes, &mut keylength) }

// Heimdal equivalent
unsafe { krb5_random_to_key(self.ctx, enctype, data, size, &mut keyblock) }
unsafe { krb5_c_keylengths(self.ctx, enctype, &mut ilen, &mut keylen) }
// Note: Heimdal also provides krb5_c_keylengths for MIT compat
```

Both functions exist in Heimdal with compatible semantics, so `o2k.rs`
requires minimal changes.

#### 2.3.2 KDC-Side Adapter

The KDC adapter must implement these Heimdal-internal functions:

| Heimdal function | Maps to `pkinit-core` |
|---|---|
| `_kdc_pk_rd_padata(context, config, req, pa, client, &cp)` | `PkinitKdcState::verify_as_req()` |
| `_kdc_pk_mk_pa_reply(context, config, cp, client, enctype, req, req_buffer, reply_key, sessionkey, md)` | `PkinitKdcState::build_as_rep()` |
| `_kdc_pk_check_client(context, config, clientdb, client, cp, &subject_name)` | `pkinit_core::certauth::verify_client_san()` |
| `_kdc_pk_free_client_param(context, cp)` | Drop the Rust state |
| `krb5_kdc_pk_initialize(context, config, ...)` | `PkinitKdcState::new()` |

The main translation challenge is that Heimdal's `_kdc_pk_rd_padata` receives
a `PA_DATA *pa` (already parsed by Heimdal's main loop) and an `hdb_entry_ex *client`
(the HDB database entry), whereas `pkinit-core`'s `verify_as_req` works with
raw DER bytes. The adapter must:

1. Extract `pa->padata_value.data` / `pa->padata_value.length` → pass to
   `verify_as_req` as `pa_req_der`
2. Extract the KDC request body → encode it via `encode_KDC_REQ_BODY` and
   pass as `req_body_der`
3. Read clock skew from `context->max_skew`
4. Store the resulting `VerifiedRequest` in a `pk_client_params` opaque
   struct that gets passed through to `_kdc_pk_mk_pa_reply`

#### 2.3.3 Client-Side Adapter

The client adapter replaces Heimdal's `_krb5_pk_mk_padata` and
`_krb5_pk_rd_pa_reply`:

| Heimdal function | Maps to `pkinit-core` |
|---|---|
| `_krb5_pk_mk_padata(context, ctx, req_body, nonce, md)` | `PkinitClientState::build_as_req()` |
| `_krb5_pk_rd_pa_reply(context, realm, ctx, etype, hi, nonce, req_buffer, pa, key)` | `PkinitClientState::process_as_rep()` |
| `_krb5_pk_load_id(context, &id, ...)` | `PkinitIdentity::load()` |

The client side in Heimdal is invoked from `lib/krb5/init_creds_pw.c` during
`krb5_get_init_creds_password()`. The PKINIT context is set up via
`krb5_get_init_creds_opt_set_pkinit()`.

#### 2.3.4 Certificate Handling Bridge

Heimdal uses `hx509_cert` objects internally, while `pkinit-core` operates
on raw DER byte slices. The bridge must:

```rust
// Heimdal hx509_cert → DER bytes for pkinit-core
fn cert_to_der(cert: *mut hx509_cert) -> Vec<u8> {
    // hx509_cert_binary(context, cert, &data) extracts DER
}

// pkinit-core verified cert DER → Heimdal hx509_cert (for _kdc_pk_check_client)
fn der_to_cert(context: hx509_context, der: &[u8]) -> *mut hx509_cert {
    // hx509_cert_init_data(context, der.as_ptr(), der.len(), NULL)
}
```

### 2.4 ASN.1 Considerations

Heimdal's `pkinit.asn1` **does not define** the post-quantum types:
- `KEMRepInfo`
- `KDCKEMInfo`
- `PkinitKEMSuppPubInfo`
- `PA-PK-AS-REQ-Hint`

These are all defined and handled entirely within `pkinit-core` using the
`synta` ASN.1 library in Rust. Since `pkinit-core` does its own ASN.1
encoding/decoding for all PKINIT types (not just the PQC extensions), the
Heimdal adapter **does not need to modify `pkinit.asn1`**. The adapter
receives raw DER from Heimdal and passes it to `pkinit-core`, which handles
all parsing internally.

Heimdal's `PKAuthenticator` is also missing the RFC 8070 `freshness_token`
field and the `paChecksum2` field. Since `pkinit-core` parses `AuthPack`
itself from DER, this is not an issue for the Rust code path. However, if
Heimdal's own codec parses the `AuthPack` before passing it to the adapter,
the fields will be silently dropped — the adapter must receive the **raw**
`signedAuthPack` content, not a pre-decoded `AuthPack` struct.

### 2.5 Configuration Mapping

| Heimdal config field (`krb5_kdc_configuration`) | `PkinitKdcConfig` field |
|---|---|
| `enable_pkinit` | (gate: skip if false) |
| `pkinit_kdc_identity` | `identity` |
| `pkinit_kdc_anchors` | `anchors` |
| `pkinit_kdc_cert_pool` | `intermediates` |
| `pkinit_kdc_revoke` | `crls` |
| `pkinit_dh_min_bits` | `dh_min_bits` |
| `pkinit_princ_in_cert` | (mapped to certauth behavior) |
| `pkinit_allow_proxy_certs` | (handled by hx509 verify context) |
| `pkinit_require_binding` | (Win2k compat, not relevant for PQC) |

New PQC configuration options would need to be added to
`krb5_kdc_configuration` or read directly from `krb5.conf`:

```c
// Proposed additions to krb5_kdc_configuration:
const char *pkinit_pqc_min_algorithm;      // "ML-KEM-768"
char **pkinit_pqc_composite_algorithms;    // {"ML-KEM-768-X25519", ...}
krb5_boolean pkinit_require_freshness;
```

Client-side PQC config would be read from `[libdefaults]` and `[realms]`
sections, identically to how `kurbu5-pkinit/src/profile.rs` reads MIT's
`krb5.conf`.

---

## 3. Build Integration

### 3.1 Cargo Build

```toml
[package]
name = "heimdal-pkinit"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["staticlib"]   # Link into libkdc.so / libkrb5.so

[dependencies]
pkinit-core = { path = "../pkinit-core" }
libc = "0.2"
native-ossl = "0.2"

[build-dependencies]
bindgen = "0.71"
```

### 3.2 Bindgen Configuration

```rust
// build.rs
fn main() {
    println!("cargo:rustc-link-lib=heimdal-krb5");
    println!("cargo:rustc-link-lib=hx509");

    let bindings = bindgen::Builder::default()
        .header("/usr/include/heimdal/krb5.h")
        .header("/usr/include/heimdal/hx509.h")
        .header("/usr/include/heimdal/kdc.h")
        .header("/usr/include/heimdal/pkinit_asn1.h")
        .clang_arg("-I/usr/include/heimdal")
        .allowlist_function("krb5_.*")
        .allowlist_function("hx509_.*")
        .allowlist_function("kdc_.*")
        .allowlist_type("krb5_.*")
        .allowlist_type("hx509_.*")
        .allowlist_type("krb5_kdc_configuration")
        .generate()
        .expect("bindgen");

    bindings.write_to_file("src/bindings.rs").unwrap();
}
```

### 3.3 Heimdal Build System Integration

Heimdal uses autotools. The Rust static library would be integrated via:

```makefile
# kdc/Makefile.am additions
libkdc_la_LIBADD += $(top_builddir)/rust/target/release/libheimdal_pkinit.a
libkdc_la_LIBADD += -lpthread -ldl -lm  # Rust runtime deps
```

---

## 4. Key Challenges and Risks

### 4.1 Internal API Stability

Heimdal's `_kdc_pk_*` functions are internal (underscore-prefixed) and not
part of any stable ABI. Their signatures, the `pk_client_params` struct, and
the `krb5_kdc_configuration` layout can change between Heimdal releases.
The adapter would need to be maintained against specific Heimdal versions.

### 4.2 `hx509` vs. `pkinit-core` Certificate Handling

`pkinit-core` uses `synta-certificate` + `synta-x509-verification` for
certificate chain validation, while Heimdal uses `hx509`. There are two
options:

- **Option A: Use `pkinit-core`'s chain validation** — simpler, but
  duplicates trust store loading and may diverge from Heimdal's validation
  behavior (OCSP, proxy certs, etc.)

- **Option B: Bridge back to `hx509`** — extract the signer cert DER from
  `pkinit-core`'s CMS verification, then pass it to `hx509_verify_path` for
  chain validation. More complex but consistent with Heimdal's existing
  trust model.

Option A is recommended for initial implementation; Option B can be added
later if needed.

### 4.3 Win2k / BTMM Compatibility

Heimdal's PKINIT supports Win2k-era PKINIT (different ASN.1 types) and
Apple's Back to My Mac (BTMM) variant. `pkinit-core` does not implement
these. The adapter must either:

- Keep Heimdal's existing C code for Win2k/BTMM paths and only redirect
  the RFC 4556/RFC 8636/PQC paths to Rust, or
- Accept that Win2k/BTMM support is dropped (acceptable for deployments
  that don't need it)

### 4.4 Thread Safety

Heimdal's KDC is multi-threaded. `pkinit-core`'s `PkinitKdcState` is
designed to be shared (it takes `&self` for `verify_as_req` and
`build_as_rep`), so this is compatible. The current Heimdal C code uses
static globals (`kdc_identity`, `principal_mappings`, `moduli`) which would
need to be wrapped in the Rust adapter.

---

## 5. Implementation Roadmap

### Phase 1: KDC-side classical PKINIT (DH + ECDH)

1. ✅ Create `heimdal-pkinit` crate with bindgen for Heimdal headers
2. ✅ Implement `HeimdalOctetString2Key` (wrapping `krb5_random_to_key`)
3. ✅ Implement C-callable `heimdal_pkinit_rd_padata` → `PkinitKdcState::verify_as_req`
4. ✅ Implement C-callable `heimdal_pkinit_mk_pa_reply` → `PkinitKdcState::build_as_rep`
5. ✅ Implement `heimdal_pkinit_check_client` → `pkinit-core::certauth`
6. Patch Heimdal `kdc/kerberos5.c` to call Rust FFI + wire into build system
7. Interop test against Heimdal's `kinit` (client stays C)

### Phase 2: Client-side classical PKINIT

8. ✅ Implement C-callable `heimdal_pkinit_client_mk_padata` → `PkinitClientState::build_as_req`
9. ✅ Implement C-callable `heimdal_pkinit_client_rd_pa_reply` → `PkinitClientState::process_as_rep`
10. ✅ Implement `heimdal_pkinit_client_tryagain` for retry handling
11. Patch Heimdal `lib/krb5/pkinit.c` to call Rust FFI
12. Cross-test: Rust client ↔ Rust KDC, Rust client ↔ C KDC

### Phase 3: Post-quantum extensions ✅ Complete

10. ✅ PQC config: `pkinit_pqc_min_algorithm` and `pkinit_require_pqc` in `[kdc]`
11. ✅ `PA-PK-AS-REQ-Hint` advertisement (32 bytes for ML-KEM-768 + ML-KEM-1024)
12. ✅ ML-KEM-768 negotiation verified end-to-end (Heimdal KDC ↔ MIT kurbu5-pkinit)
13. ✅ HKDF-SHA-512 KDF for KEM path (via pkinit-core)
14. ✅ ML-DSA downgrade prevention (via pkinit-core)
15. ✅ Cross-tested: Heimdal KDC ↔ MIT kurbu5-pkinit (both directions)
16. ✅ PQC enforcement: `pkinit_require_pqc = true` rejects classical, auto-retry works

### Phase 4: RFC 8636 + RFC 8070 ✅ Complete (via pkinit-core)

17. ✅ Algorithm-agile KDF: `ah-sha256`, `ah-sha512` verified
18. ⚠️ Freshness tokens: client-side support wired, KDC token generation requires Heimdal framework changes
19. ✅ `paChecksum2` (SHA-256): handled by pkinit-core automatically

---

## 6. Reuse Summary

| Component | Reusable from kurbu5-pkinit? | Notes |
|---|:---:|---|
| `pkinit-core` (entire crate) | ✅ | Zero changes needed |
| `synta` / `synta-krb5` / `synta-certificate` | ✅ | ASN.1 codec crates |
| `native-ossl` | ✅ | Crypto primitives |
| `kurbu5-pkinit/src/client_plugin.rs` | ❌ | MIT-specific plugin glue |
| `kurbu5-pkinit/src/kdc_plugin.rs` | ❌ | MIT-specific plugin glue |
| `kurbu5-pkinit/src/o2k.rs` | 🔄 | Needs rewrite for Heimdal API |
| `kurbu5-pkinit/src/profile.rs` | 🔄 | Config reading differs |
| `kurbu5-pkinit/src/trace.rs` | 🔄 | Heimdal uses `kdc_log` not `krb5int_trace` |
| `kurbu5-pkinit/src/principal.rs` | 🔄 | Heimdal principal API differs |
| Test infrastructure (`protocol_integration.rs`) | ✅ | Pure `pkinit-core` tests |
