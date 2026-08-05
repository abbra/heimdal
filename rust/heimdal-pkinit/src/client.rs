// Copyright (c) 2025 Red Hat, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// accompanying LICENSE file are met.

//! Client-side PKINIT adapter.
//!
//! This module implements the Heimdal client's internal PKINIT API surface
//! (`_krb5_pk_mk_padata`, `_krb5_pk_rd_pa_reply`) by delegating to
//! `pkinit-core`'s `PkinitClientState`.

use pkinit_core::client::{AsRepParams, PkinitClientState};
use pkinit_core::config::PkinitClientConfig;
use pkinit_core::identity::{IdentitySource, PkinitIdentity, TrustStore};

use crate::bindings;
use crate::o2k::HeimdalOctetString2Key;

/// Opaque client-side PKINIT context, replaces `krb5_pk_init_ctx_data`.
pub struct PkinitClientCtx {
    state: PkinitClientState,
}

impl PkinitClientCtx {
    /// Create a new client PKINIT context.
    pub fn new(
        identity: PkinitIdentity,
        trust_store: TrustStore,
        config: PkinitClientConfig,
    ) -> Self {
        let state = PkinitClientState::new(identity, trust_store, config);
        Self { state }
    }

    /// Set the KDC principal and optional hostname for SAN verification.
    pub fn set_kdc_identity(&mut self, principal: String, hostname: Option<String>) {
        self.state.set_kdc_identity(principal, hostname);
    }

    /// Set the freshness token received from the KDC.
    pub fn set_freshness_token(&mut self, token: Vec<u8>) {
        self.state.set_freshness_token(token);
    }

    /// Process a PKINIT hint from the KDC (KEM algorithm advertisement).
    pub fn process_hint(&mut self, hint_der: &[u8]) {
        let _ = self.state.process_pkinit_hint(hint_der);
    }

    /// Build the PA-PK-AS-REQ PA-DATA.
    pub fn build_as_req(
        &mut self,
        nonce: i32,
        ctime: i64,
        cusec: i32,
        req_body_der: &[u8],
    ) -> Result<Vec<u8>, pkinit_core::error::PkinitError> {
        let pa_req = self.state.build_as_req(nonce, ctime, cusec, req_body_der)?;
        Ok(pa_req)
    }

    /// Process the KDC's PA-PK-AS-REP and derive the reply key.
    ///
    /// `params.as_req_der` is the full DER-encoded AS-REQ that was sent;
    /// `params.pa_rep_raw` is the PA-PK-AS-REP being processed.
    pub fn process_as_rep(
        &mut self,
        context: bindings::krb5_context,
        params: &AsRepParams,
    ) -> Result<pkinit_core::crypto::kdf::DerivedKey, pkinit_core::error::PkinitError> {
        let o2k = unsafe { HeimdalOctetString2Key::new(context) };
        self.state.process_as_rep(params.pa_rep_raw, params, &o2k)
    }

    /// Handle a KDC error response with retry hints.
    pub fn handle_tryagain(
        &mut self,
        error_padata_der: &[u8],
    ) -> Result<pkinit_core::client::RetryAction, pkinit_core::error::PkinitError> {
        self.state.handle_tryagain(error_padata_der)
    }
}

/// Initialize a client PKINIT context from identity and anchor paths.
///
/// # Safety
///
/// `context` must be a valid Heimdal krb5 context.
pub(crate) unsafe fn init_client_ctx(
    context: bindings::krb5_context,
    identity_str: &str,
    anchor_paths: &[&str],
    anonymous: bool,
    server_principal: Option<&str>,
) -> Result<Box<PkinitClientCtx>, bindings::krb5_error_code> {
    let config = unsafe { crate::config::read_client_config(context) };

    let identity = if anonymous {
        PkinitIdentity {
            cert_der: vec![],
            key_pkcs8_der: vec![],
            chain: vec![],
        }
    } else {
        let source = IdentitySource::parse(identity_str)
            .map_err(|_| libc::EINVAL as bindings::krb5_error_code)?;
        PkinitIdentity::load(&source)
            .map_err(|_| libc::EINVAL as bindings::krb5_error_code)?
    };

    let mut trust_store = TrustStore::new();
    for anchor in anchor_paths {
        trust_store
            .load_from_path(anchor)
            .map_err(|_| libc::EINVAL as bindings::krb5_error_code)?;
    }

    let mut ctx = PkinitClientCtx::new(identity, trust_store, config);

    if let Some(princ) = server_principal {
        ctx.set_kdc_identity(princ.to_string(), None);
    }

    Ok(Box::new(ctx))
}
