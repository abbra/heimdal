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
static KDC_STATE: Mutex<Option<PkinitKdcState>> = Mutex::new(None);

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

    let state = match PkinitKdcState::new(identity, trust_store, kdc_config) {
        Ok(s) => s,
        Err(e) => {
            pkinit_trace!(context, config, "PKINIT: KDC state init failed: {}", e);
            return libc::EINVAL as _;
        }
    };

    let mut guard = KDC_STATE.lock().unwrap();
    *guard = Some(state);

    pkinit_trace!(context, config, "PKINIT: KDC initialized successfully (Rust pkinit-core)");
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
) -> Result<Box<PkClientParams>, bindings::krb5_error_code> {
    let guard = KDC_STATE.lock().unwrap();
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
            Err(libc::EINVAL as _)
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
    let guard = KDC_STATE.lock().unwrap();
    let state = guard.as_ref().ok_or(libc::EINVAL as bindings::krb5_error_code)?;

    let o2k = unsafe { HeimdalOctetString2Key::new(context) };

    match state.build_as_rep(
        &cp.verified,
        &BuildAsRepParams {
            nonce,
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
/// This replaces Heimdal's `_kdc_pk_check_client`.  The implementation
/// delegates to `pkinit-core`'s `certauth` module.
pub(crate) fn check_client(
    cp: &PkClientParams,
    client_principal: &str,
    allow_upn: bool,
) -> Result<String, bindings::krb5_error_code> {
    if cp.verified.client_cert_der.is_empty() {
        // Anonymous PKINIT — no cert to check
        return Ok("<unauthenticated anonymous client>".to_string());
    }

    let result = pkinit_core::certauth::verify_client_san(
        &cp.verified.client_cert_der,
        client_principal,
        allow_upn,
    )
    .map_err(|_| libc::EINVAL as bindings::krb5_error_code)?;

    match result {
        pkinit_core::certauth::CertauthResult::Authorized => {
            // TODO: extract actual subject name from cert
            Ok(format!("PKINIT:{}", client_principal))
        }
        pkinit_core::certauth::CertauthResult::Rejected(reason) => {
            let _ = reason; // logged by caller
            Err(libc::EACCES as bindings::krb5_error_code)
        }
    }
}
