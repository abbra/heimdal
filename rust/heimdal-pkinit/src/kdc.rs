//! KDC-side PKINIT adapter.
//!
//! This module implements the Heimdal KDC's internal PKINIT API surface
//! (`_kdc_pk_rd_padata`, `_kdc_pk_mk_pa_reply`, etc.) by delegating to
//! `pkinit-core`'s `PkinitKdcState`.

use std::sync::Mutex;

use pkinit_core::config::PkinitKdcConfig;
use pkinit_core::identity::{PkinitIdentity, TrustStore};
use pkinit_core::server::{BuildAsRepParams, PkinitKdcState, VerifiedRequest};

use crate::bindings;
use crate::o2k::HeimdalOctetString2Key;
use crate::trace::pkinit_trace;


/// Opaque state passed between `_kdc_pk_rd_padata` and `_kdc_pk_mk_pa_reply`.
///
/// In Heimdal's C code this is `pk_client_params`.  We replace it with a
/// struct that holds the `pkinit-core` verified request plus the client
/// certificate DER (needed for `_kdc_pk_check_client`).
pub struct PkClientParams {
    pub verified: VerifiedRequest,
    pub subject_name: Option<String>,
}

/// Global KDC PKINIT state, initialized once by `_kdc_pk_initialize`.
///
/// Heimdal's original code uses file-level statics (`kdc_identity`,
/// `moduli`, `principal_mappings`).  We mirror that pattern with a
/// `Mutex`-protected option.
pub(crate) static KDC_STATE: Mutex<Option<PkinitKdcState>> = Mutex::new(None);

/// Initialize the KDC PKINIT subsystem.
///
/// Called from Heimdal's `krb5_kdc_pk_initialize`.  Loads the KDC identity
/// (certificate + key), trust anchors, and configuration, then creates
/// the `PkinitKdcState` that will be used for all subsequent requests.
///
/// # Safety
///
/// `context` and `config` must be valid Heimdal pointers.
pub(crate) unsafe fn initialize(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
) -> bindings::krb5_error_code {
    let kdc_config = unsafe { crate::config::read_kdc_config(context, config) };

    let identity_str = match kdc_config.identity.as_deref() {
        Some(s) => s,
        None => {
            pkinit_trace!(context, config, "PKINIT: no KDC identity configured");
            return libc::EINVAL as _;
        }
    };

    let source = match pkinit_core::identity::IdentitySource::parse(identity_str) {
        Ok(s) => s,
        Err(e) => {
            pkinit_trace!(
                context, config,
                "PKINIT: failed to parse KDC identity '{}': {}", identity_str, e
            );
            return libc::EINVAL as _;
        }
    };

    let identity = match PkinitIdentity::load(&source) {
        Ok(id) => id,
        Err(e) => {
            pkinit_trace!(
                context, config,
                "PKINIT: failed to load KDC identity: {}", e
            );
            return libc::EINVAL as _;
        }
    };

    let mut trust_store = TrustStore::new();
    for anchor in &kdc_config.anchors {
        if let Err(e) = trust_store.load_from_path(anchor) {
            pkinit_trace!(
                context, config,
                "PKINIT: failed to load trust anchor '{}': {}", anchor, e
            );
            return libc::EINVAL as _;
        }
    }
    for revoke_source in &kdc_config.crls {
        if let Err(e) = trust_store.load_from_path(revoke_source) {
            pkinit_trace!(
                context, config,
                "PKINIT: failed to load pkinit_revoke source '{}': {}", revoke_source, e
            );
            return libc::EINVAL as _;
        }
    }
    if kdc_config.require_crl_checking {
        pkinit_trace!(
            context, config,
            "PKINIT: CRL checking enabled ({} pkinit_revoke source(s) loaded)",
            kdc_config.crls.len()
        );
    }
    // NOTE: pkinit_kdc_ocsp is intentionally not read here — pkinit-core's
    // RevocationChecks only supports CRL-based revocation today, not OCSP.

    let state = match PkinitKdcState::new(identity, trust_store, kdc_config) {
        Ok(s) => s,
        Err(e) => {
            pkinit_trace!(context, config, "PKINIT: KDC state init failed: {}", e);
            return libc::EINVAL as _;
        }
    };

    // Log the KEM algorithms configured
    let kem_hint_len = state.build_supported_algorithms_hint().len();

    let mut guard = KDC_STATE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(state);
    drop(guard);

    pkinit_trace!(
        context, config,
        "PKINIT: KDC initialized (Rust pkinit-core), KEM hint {} bytes",
        kem_hint_len
    );
    0
}

/// Verify an incoming PA-PK-AS-REQ.
///
/// This replaces Heimdal's `_kdc_pk_rd_padata`.  It receives the raw
/// PA-DATA value, verifies the CMS signature, checks the PKAuthenticator,
/// and returns an opaque `PkClientParams` pointer for use in
/// `_kdc_pk_mk_pa_reply`.
///
/// # Safety
///
/// All pointer arguments must be valid.
pub(crate) unsafe fn verify_padata(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
    pa_data: *const u8,
    pa_data_len: usize,
    max_skew: i64,
    current_time: i64,
    require_pqc: bool,
) -> Result<Box<PkClientParams>, bindings::krb5_error_code> {
    let guard = KDC_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.as_ref().ok_or(libc::EINVAL as bindings::krb5_error_code)?;

    let pa_slice = if pa_data.is_null() || pa_data_len == 0 {
        return Err(libc::EINVAL as _);
    } else {
        unsafe { std::slice::from_raw_parts(pa_data, pa_data_len) }
    };

    match state.verify_as_req(pa_slice, None, max_skew, current_time) {
        Ok(verified) => {
            pkinit_trace!(
                context, config,
                "PKINIT: verified AS-REQ via {}", verified.key_exchange
            );

            // PQC enforcement: reject classical key exchange when PQC
            // is required.  This is a local policy check — pkinit-core
            // accepts both DH and KEM when KEM algorithms are configured.
            if require_pqc {
                match verified.key_exchange {
                    pkinit_core::server::KeyExchangeType::Dh(_) => {
                        pkinit_trace!(
                            context, config,
                            "PKINIT: rejecting classical DH — PQC required"
                        );
                        return Err(bindings::KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED
                            as bindings::krb5_error_code);
                    }
                    pkinit_core::server::KeyExchangeType::Kem(_) => {
                        // KEM is acceptable
                    }
                }
            }

            Ok(Box::new(PkClientParams {
                verified,
                subject_name: None,
            }))
        }
        Err(e) => {
            pkinit_trace!(
                context, config,
                "PKINIT: AS-REQ verification failed: {}", e
            );
            use pkinit_core::error::KemErrorClass;
            let code = match e.kem_error_class() {
                KemErrorClass::EphemeralKeyParamsNotAccepted => {
                    bindings::KRB5_KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED
                }
                KemErrorClass::NoAcceptableKdf => bindings::KRB5_KDC_ERR_NO_ACCEPTABLE_KDF,
                KemErrorClass::PreauthFailed => bindings::KRB5KDC_ERR_PREAUTH_FAILED,
                KemErrorClass::Other => libc::EINVAL,
            };
            Err(code as bindings::krb5_error_code)
        }
    }
}

/// Build the PA-PK-AS-REP response and derive the reply key.
///
/// This replaces Heimdal's `_kdc_pk_mk_pa_reply`.  It takes the verified
/// request from `verify_padata`, builds the KDC's DH or KEM response,
/// derives the reply key, and returns the encoded PA-DATA and key.
///
/// # Safety
///
/// All pointer arguments must be valid.  `cp` must have been created by
/// `verify_padata`.
pub(crate) unsafe fn build_reply(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
    cp: &PkClientParams,
    nonce: i32,
    enctype: i32,
    as_req_der: &[u8],
    client_name: &str,
    server_name: &str,
) -> Result<(Vec<u8>, pkinit_core::crypto::kdf::DerivedKey), bindings::krb5_error_code> {
    let guard = KDC_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.as_ref().ok_or(libc::EINVAL as bindings::krb5_error_code)?;

    let o2k = unsafe { HeimdalOctetString2Key::new(context) };

    // If nonce is 0, use the nonce from the verified request
    // (the KDC C shim may not have access to it directly)
    let effective_nonce = if nonce == 0 {
        cp.verified.nonce
    } else {
        nonce
    };

    match state.build_as_rep(
        &cp.verified,
        &BuildAsRepParams {
            nonce: effective_nonce,
            enctype,
            as_req_der,
            client_name,
            server_name,
        },
        &o2k,
    ) {
        Ok((pa_rep_der, derived_key)) => {
            pkinit_trace!(
                context, config,
                "PKINIT: built AS-REP via {}", cp.verified.key_exchange
            );
            Ok((pa_rep_der, derived_key))
        }
        Err(e) => {
            pkinit_trace!(
                context, config,
                "PKINIT: failed to build AS-REP: {}", e
            );
            Err(libc::EINVAL as _)
        }
    }
}

/// Check whether a client certificate is authorized for a given principal.
///
/// This replaces Heimdal's `_kdc_pk_check_client`. The implementation
/// delegates to `pkinit-core`'s `certauth` module.
///
/// `princ_in_cert` mirrors Heimdal's `pkinit_princ_in_cert` config knob: the
/// C implementation this replaces (`_kdc_pk_check_client` in
/// `kdc/pkinit.c`) only attempts SAN/UPN authorization when it is true;
/// when false it falls back to HDB certificate pinning / PKINIT ACLs, which
/// are not yet implemented on this path (see the `Err` branch below).
///
/// `is_client_anonymous_principal` must be true only when the KDC has
/// independently verified (via `_kdc_is_anonymous()`/
/// `krb5_principal_is_anonymous()`, NOT a string compare) that the
/// requested principal is the well-known anonymous principal, or that
/// `historical_anon_realm` compatibility applies. This function does not
/// and cannot verify that itself — it only sees the request-scoped
/// verified data, not the KDC's realm/anonymous-principal policy — so
/// trusting an unauthenticated caller-supplied flag here would reintroduce
/// the same bypass.
pub(crate) enum CheckClientError {
    /// `krb5_error_code` to return, plus an optional human-readable reason
    /// (SAN mismatch detail, etc.) for the caller to log / surface via
    /// `_kdc_set_e_text`.
    Code(bindings::krb5_error_code, Option<String>),
}

pub(crate) fn check_client(
    cp: &PkClientParams,
    client_principal: &str,
    princ_in_cert: bool,
    is_client_anonymous_principal: bool,
) -> Result<String, CheckClientError> {
    if cp.verified.client_cert_der.is_empty() {
        if !cp.verified.is_anonymous || !is_client_anonymous_principal {
            // No certificate was presented, but either pkinit-core did not
            // classify this as an anonymous exchange, or the *requested*
            // principal is not actually the anonymous principal. Refuse —
            // matching kdc/pkinit.c::_kdc_pk_check_client()'s
            // `KRB5KDC_ERR_BADOPTION` on the same condition.
            return Err(CheckClientError::Code(
                libc::EACCES as bindings::krb5_error_code,
                Some("certless request for a non-anonymous principal".into()),
            ));
        }
        return Ok("<unauthenticated anonymous client>".to_string());
    }

    if !princ_in_cert {
        // pkinit_princ_in_cert = no: the C path falls back to HDB exact
        // certificate pinning / PKINIT ACLs (hdb_entry_get_pkinit_cert /
        // hdb_entry_get_pkinit_acl), neither of which is implemented on
        // this Rust path yet. Fail closed rather than silently ignore the
        // administrator's setting.
        return Err(CheckClientError::Code(
            libc::EACCES as bindings::krb5_error_code,
            Some(
                "pkinit_princ_in_cert=no and HDB certificate pinning / PKINIT ACLs \
                 are not implemented on the Rust PKINIT path"
                    .into(),
            ),
        ));
    }

    let result = pkinit_core::certauth::verify_client_san(
        &cp.verified.client_cert_der,
        client_principal,
        true, // once princ_in_cert gating passes, also accept MS UPN SAN,
              // matching _kdc_pk_check_client()'s unconditional UPN fallback
    )
    .map_err(|e| {
        CheckClientError::Code(libc::EINVAL as bindings::krb5_error_code, Some(e.to_string()))
    })?;

    match result {
        pkinit_core::certauth::CertauthResult::Authorized => {
            // TODO(follow-up): extract the real certificate subject DN for
            // audit fidelity. Doing so today would require dereferencing
            // krb5_context_data.hx509ctx, an internal struct whose layout
            // is not guaranteed to match what bindgen generates from the
            // *installed* Heimdal headers (see config.rs's comment on the
            // same risk for krb5_kdc_configuration) until build.rs is
            // pointed at the in-tree headers.
            Ok(format!("PKINIT:{}", client_principal))
        }
        pkinit_core::certauth::CertauthResult::Rejected(reason) => Err(CheckClientError::Code(
            libc::EACCES as bindings::krb5_error_code,
            Some(reason),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkinit_core::server::{KeyExchangeType, VerifiedRequest};

    fn anon_verified_request() -> VerifiedRequest {
        VerifiedRequest {
            client_cert_der: vec![],
            client_dh_public: vec![],
            nonce: 1,
            supported_kdfs: vec![],
            client_dh_nonce: None,
            is_anonymous: true,
            key_exchange: KeyExchangeType::Dh(pkinit_core::constants::DhGroup::Oakley2048),
        }
    }

    #[test]
    fn check_client_rejects_certless_request_for_non_anonymous_principal() {
        let cp = PkClientParams {
            verified: anon_verified_request(),
            subject_name: None,
        };
        // Attacker asks for "administrator@EXAMPLE.COM" with no cert at all.
        // Without the anonymous-principal check this incorrectly succeeds.
        let result = check_client(&cp, "administrator@EXAMPLE.COM", true, false);
        assert!(
            result.is_err(),
            "certless request for a non-anonymous principal must be rejected"
        );
    }

    #[test]
    fn check_client_allows_certless_request_for_true_anonymous_principal() {
        let cp = PkClientParams {
            verified: anon_verified_request(),
            subject_name: None,
        };
        let result = check_client(
            &cp,
            "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS",
            true,
            true, // caller confirms the requested principal IS the anonymous principal
        );
        assert!(result.is_ok());
    }
}
