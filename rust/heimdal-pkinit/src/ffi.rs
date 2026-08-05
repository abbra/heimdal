//! C-callable FFI functions exposed to Heimdal.
//!
//! These functions provide the interface that Heimdal's KDC main loop
//! calls for PKINIT processing.  They replace the existing C functions
//! in `kdc/pkinit.c`.
//!
//! The function names are prefixed with `heimdal_pkinit_` rather than
//! `_kdc_pk_` to avoid symbol conflicts during the transition period.
//! Heimdal's C code would be patched to call these instead.

use std::ffi::c_void;
use std::os::raw::c_char;

use crate::bindings;
use crate::client::PkinitClientCtx;
use crate::kdc::{self, PkClientParams};

/// Run `f`, converting any panic into `on_panic` instead of letting it
/// unwind across the `extern "C"` boundary (undefined behavior per the
/// Rustonomicon: "unwinding into a foreign function is undefined
/// behavior"). Used by every exported entry point that can transitively
/// reach a poisoned-mutex panic or a pkinit-core panic while processing
/// attacker-controlled input.
fn catch_ffi_panic<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe, on_panic: T) -> T {
    std::panic::catch_unwind(f).unwrap_or(on_panic)
}

/// Copy `data` into a freshly `libc::malloc`'d buffer suitable for
/// returning across the FFI boundary (the C caller frees it with
/// `free()`). Returns `None` on allocation failure. Centralizing this
/// pattern (it previously appeared six times, hand-written, with one copy
/// missing the out-param reset on the failure path) means this class of
/// bug can now only be introduced once.
fn to_c_buffer(data: &[u8]) -> Option<(*mut u8, usize)> {
    let len = data.len();
    // malloc(0) is implementation-defined (may return NULL or a unique
    // non-dereferenceable pointer); request at least 1 byte so a NULL
    // return always means "allocation failed", never "zero-length buffer".
    let buf = unsafe { libc::malloc(len.max(1)) as *mut u8 };
    if buf.is_null() {
        return None;
    }
    if len > 0 {
        // SAFETY: buf was just allocated with at least `len` bytes and is
        // non-null; data.as_ptr() is valid for `len` bytes per the slice
        // contract.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf, len) };
    }
    Some((buf, len))
}

/// Register the trace/logging callback.  Called from the KDC's
/// `pkinit-rust.c` during initialization.
///
/// # Safety
///
/// `f` must be a valid function pointer with `extern "C"` ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_set_trace(
    f: unsafe extern "C" fn(
        bindings::krb5_context,
        *mut bindings::krb5_kdc_configuration,
        std::ffi::c_int,
        *const std::ffi::c_char,
    ),
) {
    crate::trace::set_trace_fn(f);
}

/// Initialize the PKINIT subsystem.
///
/// Replaces `krb5_kdc_pk_initialize`.  Should be called once during KDC
/// startup.
///
/// # Safety
///
/// `context` and `config` must be valid Heimdal pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_initialize(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
) -> bindings::krb5_error_code {
    let context_addr = context as usize;
    let config_addr = config as usize;
    catch_ffi_panic(
        move || {
            let context = context_addr as bindings::krb5_context;
            let config = config_addr as *mut bindings::krb5_kdc_configuration;
            unsafe { kdc::initialize(context, config) }
        },
        libc::EINVAL as _,
    )
}

/// Process an incoming PA-PK-AS-REQ.
///
/// Replaces `_kdc_pk_rd_padata`.  On success, `*out_params` is set to an
/// opaque pointer that must be passed to `heimdal_pkinit_mk_pa_reply`
/// and eventually freed with `heimdal_pkinit_free_client_param`.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_rd_padata(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
    pa_data: *const u8,
    pa_data_len: usize,
    out_params: *mut *mut c_void,
) -> bindings::krb5_error_code {
    if out_params.is_null() {
        return libc::EINVAL as _;
    }
    unsafe { *out_params = std::ptr::null_mut() };

    // SAFETY: context/config/pa_data are the caller's responsibility per
    // this function's documented contract; the pointers themselves are
    // only dereferenced within the closure, not held across the
    // catch_unwind call, so round-tripping them through usize to satisfy
    // UnwindSafe is sound.
    let context_addr = context as usize;
    let config_addr = config as usize;
    let pa_data_addr = pa_data as usize;

    catch_ffi_panic(
        move || {
            let context = context_addr as bindings::krb5_context;
            let config = config_addr as *mut bindings::krb5_kdc_configuration;
            let pa_data = pa_data_addr as *const u8;

            let max_skew = unsafe { bindings::krb5_get_max_time_skew(context) as i64 };
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            // Check if PQC is required
            let require_pqc = unsafe {
                crate::config::read_config_bool(context, &["kdc", "pkinit_require_pqc"], false)
            };

            match unsafe {
                kdc::verify_padata(
                    context, config, pa_data, pa_data_len, max_skew, current_time, require_pqc,
                )
            } {
                Ok(cp) => {
                    unsafe { *out_params = Box::into_raw(cp) as *mut c_void };
                    0
                }
                Err(code) => code,
            }
        },
        libc::EINVAL as _,
    )
}

/// Build the PA-PK-AS-REP response.
///
/// Replaces `_kdc_pk_mk_pa_reply`.  `params` must be the pointer returned
/// by `heimdal_pkinit_rd_padata`.  On success, `*out_pa_data` and
/// `*out_pa_len` are set to the encoded PA-DATA value (caller must free
/// with `free()`), and `reply_key` is filled with the derived key.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_mk_pa_reply(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
    params: *const c_void,
    nonce: i32,
    enctype: i32,
    as_req_data: *const u8,
    as_req_len: usize,
    client_name: *const c_char,
    server_name: *const c_char,
    out_pa_data: *mut *mut u8,
    out_pa_len: *mut usize,
    reply_key: *mut bindings::krb5_keyblock,
) -> bindings::krb5_error_code {
    if params.is_null() || out_pa_data.is_null() || out_pa_len.is_null() || reply_key.is_null() {
        return libc::EINVAL as _;
    }
    unsafe {
        *out_pa_data = std::ptr::null_mut();
        *out_pa_len = 0;
    }

    let context_addr = context as usize;
    let config_addr = config as usize;
    let params_addr = params as usize;
    let as_req_data_addr = as_req_data as usize;
    let client_name_addr = client_name as usize;
    let server_name_addr = server_name as usize;
    let out_pa_data_addr = out_pa_data as usize;
    let out_pa_len_addr = out_pa_len as usize;
    let reply_key_addr = reply_key as usize;

    catch_ffi_panic(
        move || {
            let context = context_addr as bindings::krb5_context;
            let config = config_addr as *mut bindings::krb5_kdc_configuration;
            let params = params_addr as *const c_void;
            let as_req_data = as_req_data_addr as *const u8;
            let client_name = client_name_addr as *const c_char;
            let server_name = server_name_addr as *const c_char;
            let out_pa_data = out_pa_data_addr as *mut *mut u8;
            let out_pa_len = out_pa_len_addr as *mut usize;
            let reply_key = reply_key_addr as *mut bindings::krb5_keyblock;

            let cp = unsafe { &*(params as *const PkClientParams) };

            let as_req_der = if as_req_data.is_null() || as_req_len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(as_req_data, as_req_len) }
            };

            let c_client = if client_name.is_null() {
                return libc::EINVAL as _;
            } else {
                unsafe { std::ffi::CStr::from_ptr(client_name) }
            };
            let c_server = if server_name.is_null() {
                return libc::EINVAL as _;
            } else {
                unsafe { std::ffi::CStr::from_ptr(server_name) }
            };

            let client_str = c_client.to_str().unwrap_or("");
            let server_str = c_server.to_str().unwrap_or("");

            match unsafe {
                kdc::build_reply(
                    context, config, cp, nonce, enctype, as_req_der, client_str, server_str,
                )
            } {
                Ok((pa_rep_der, derived)) => {
                    let Some((buf, buf_len)) = to_c_buffer(&pa_rep_der) else {
                        return libc::ENOMEM as _;
                    };

                    let key_bytes = derived.key_data.as_ref();
                    let Some((key_buf, key_len)) = to_c_buffer(key_bytes) else {
                        unsafe { libc::free(buf as *mut _) };
                        // out_pa_data/out_pa_len were already zeroed at
                        // function entry and are never written before both
                        // allocations succeed, so no reset is needed here.
                        return libc::ENOMEM as _;
                    };

                    unsafe {
                        *out_pa_data = buf;
                        *out_pa_len = buf_len;
                        (*reply_key).keytype = derived.enctype as _;
                        (*reply_key).keyvalue.data = key_buf as *mut _;
                        (*reply_key).keyvalue.length = key_len;
                    }

                    0
                }
                Err(code) => code,
            }
        },
        libc::EINVAL as _,
    )
}

/// Check client certificate authorization.
///
/// Replaces `_kdc_pk_check_client`.  On success, `*out_subject` is set to
/// a malloc'd string with the subject name (caller must free).
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_check_client(
    params: *const c_void,
    client_principal: *const c_char,
    princ_in_cert: i32,
    is_client_anonymous_principal: i32,
    out_subject: *mut *mut c_char,
    out_reject_reason: *mut *mut c_char,
) -> bindings::krb5_error_code {
    if params.is_null()
        || client_principal.is_null()
        || out_subject.is_null()
        || out_reject_reason.is_null()
    {
        return libc::EINVAL as _;
    }
    // SAFETY: both out-params were just checked non-null above; zeroing
    // them here means every error path below leaves them well-defined
    // even if the caller forgot to pre-initialize them.
    unsafe {
        *out_subject = std::ptr::null_mut();
        *out_reject_reason = std::ptr::null_mut();
    }

    let cp = unsafe { &*(params as *const PkClientParams) };
    let princ_str = unsafe { std::ffi::CStr::from_ptr(client_principal) }
        .to_str()
        .unwrap_or("");

    match kdc::check_client(
        cp,
        princ_str,
        princ_in_cert != 0,
        is_client_anonymous_principal != 0,
    ) {
        Ok(subject) => {
            let c_subject = match std::ffi::CString::new(subject) {
                Ok(s) => s,
                Err(_) => return libc::EINVAL as _,
            };
            let Some((buf, _len)) = to_c_buffer(c_subject.as_bytes_with_nul()) else {
                return libc::ENOMEM as _;
            };
            unsafe { *out_subject = buf as *mut c_char };
            0
        }
        Err(kdc::CheckClientError::Code(code, reason)) => {
            if let Some(reason) = reason
                && let Ok(c_reason) = std::ffi::CString::new(reason)
                && let Some((buf, _len)) = to_c_buffer(c_reason.as_bytes_with_nul())
            {
                unsafe { *out_reject_reason = buf as *mut c_char };
            }
            code
        }
    }
}

/// Free the opaque client params allocated by `heimdal_pkinit_rd_padata`.
///
/// Replaces `_kdc_pk_free_client_param`.
///
/// # Safety
///
/// `params` must be a pointer returned by `heimdal_pkinit_rd_padata`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_free_client_param(
    params: *mut c_void,
) {
    if !params.is_null() {
        drop(unsafe { Box::from_raw(params as *mut PkClientParams) });
    }
}

/// Return the key exchange type name for a verified request (for logging).
///
/// The returned string is valid until `heimdal_pkinit_free_client_param`
/// is called.  Returns null if `params` is null.
///
/// # Safety
///
/// `params` must be a valid pointer from `heimdal_pkinit_rd_padata` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_keyex_name(
    params: *const c_void,
    out_name: *mut *const c_char,
) {
    if params.is_null() || out_name.is_null() {
        return;
    }
    let cp = unsafe { &*(params as *const PkClientParams) };
    // Use a static mapping for the display names to avoid allocations
    let name: &'static [u8] = match cp.verified.key_exchange {
        pkinit_core::server::KeyExchangeType::Dh(group) => match group {
            pkinit_core::constants::DhGroup::Oakley2048 => b"DH-2048\0",
            pkinit_core::constants::DhGroup::Oakley4096 => b"DH-4096\0",
            pkinit_core::constants::DhGroup::EcP256 => b"ECDH-P256\0",
            pkinit_core::constants::DhGroup::EcP384 => b"ECDH-P384\0",
            pkinit_core::constants::DhGroup::EcP521 => b"ECDH-P521\0",
        },
        pkinit_core::server::KeyExchangeType::Kem(alg) => match alg {
            pkinit_core::constants::KemAlgorithm::MlKem512 => b"ML-KEM-512\0",
            pkinit_core::constants::KemAlgorithm::MlKem768 => b"ML-KEM-768\0",
            pkinit_core::constants::KemAlgorithm::MlKem1024 => b"ML-KEM-1024\0",
            pkinit_core::constants::KemAlgorithm::MlKem768X25519 => b"ML-KEM-768-X25519\0",
            pkinit_core::constants::KemAlgorithm::MlKem768EcdhP256 => b"ML-KEM-768-ECDH-P256\0",
            pkinit_core::constants::KemAlgorithm::MlKem1024EcdhP384 => b"ML-KEM-1024-ECDH-P384\0",
        },
    };
    unsafe { *out_name = name.as_ptr() as *const c_char };
}

/// Return the KEM algorithm hint (PA-PK-AS-REQ-Hint) for proactive
/// advertisement.
///
/// On success, `*out_data` / `*out_len` are set to a malloc'd buffer
/// containing the DER-encoded hint.  Returns empty if no KEM algorithms
/// are configured.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_get_hint(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) {
    if out_data.is_null() || out_len.is_null() {
        return;
    }
    unsafe {
        *out_data = std::ptr::null_mut();
        *out_len = 0;
    }

    let context_addr = context as usize;
    let config_addr = config as usize;
    let out_data_addr = out_data as usize;
    let out_len_addr = out_len as usize;

    catch_ffi_panic(
        move || {
            let context = context_addr as bindings::krb5_context;
            let config = config_addr as *mut bindings::krb5_kdc_configuration;
            let out_data = out_data_addr as *mut *mut u8;
            let out_len = out_len_addr as *mut usize;

            let guard = crate::kdc::KDC_STATE.lock().unwrap_or_else(|e| e.into_inner());
            let state = match guard.as_ref() {
                Some(s) => s,
                None => {
                    crate::trace::pkinit_trace!(
                        context, config,
                        "PKINIT: get_hint called but KDC state not initialized"
                    );
                    return;
                }
            };

            let hint_der = state.build_supported_algorithms_hint();
            if hint_der.is_empty() {
                crate::trace::pkinit_trace!(
                    context, config,
                    "PKINIT: get_hint returned empty (no KEM algorithms configured)"
                );
                return;
            }

            let Some((buf, len)) = to_c_buffer(&hint_der) else {
                return;
            };
            unsafe {
                *out_data = buf;
                *out_len = len;
            }
            crate::trace::pkinit_trace!(
                context, config,
                "PKINIT: get_hint returning {} bytes of KEM algorithm hint",
                hint_der.len()
            );
        },
        (),
    )
}

/// Check whether the verified request is anonymous PKINIT.
///
/// Returns 1 if anonymous, 0 otherwise.
///
/// # Safety
///
/// `params` must be a valid pointer from `heimdal_pkinit_rd_padata`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_is_anonymous(
    params: *const c_void,
) -> i32 {
    if params.is_null() {
        return 0;
    }
    let cp = unsafe { &*(params as *const PkClientParams) };
    if cp.verified.is_anonymous { 1 } else { 0 }
}

// ─── Client-side FFI ─────────────────────────────────────────────────────

/// Create a new client PKINIT context.
///
/// Replaces `_krb5_pk_set_user_id` + identity loading.  On success,
/// `*out_ctx` is set to an opaque pointer that must be passed to the
/// other `heimdal_pkinit_client_*` functions and eventually freed with
/// `heimdal_pkinit_client_free`.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_client_init(
    context: bindings::krb5_context,
    identity: *const c_char,
    anchors: *const *const c_char,
    anchors_len: usize,
    anonymous: i32,
    server_principal: *const c_char,
    out_ctx: *mut *mut c_void,
) -> bindings::krb5_error_code {
    if out_ctx.is_null() {
        return libc::EINVAL as _;
    }
    unsafe { *out_ctx = std::ptr::null_mut() };

    let identity_str = if identity.is_null() {
        ""
    } else {
        match unsafe { std::ffi::CStr::from_ptr(identity) }.to_str() {
            Ok(s) => s,
            Err(_) => return libc::EINVAL as _,
        }
    };

    let anchor_strs: Vec<&str> = if anchors.is_null() || anchors_len == 0 {
        vec![]
    } else {
        let slice = unsafe { std::slice::from_raw_parts(anchors, anchors_len) };
        slice
            .iter()
            .filter_map(|&p| {
                if p.is_null() {
                    None
                } else {
                    unsafe { std::ffi::CStr::from_ptr(p) }.to_str().ok()
                }
            })
            .collect()
    };

    let server_str = if server_principal.is_null() {
        None
    } else {
        unsafe { std::ffi::CStr::from_ptr(server_principal) }
            .to_str()
            .ok()
    };

    match unsafe {
        crate::client::init_client_ctx(
            context,
            identity_str,
            &anchor_strs,
            anonymous != 0,
            server_str,
        )
    } {
        Ok(ctx) => {
            unsafe { *out_ctx = Box::into_raw(ctx) as *mut c_void };
            0
        }
        Err(code) => code,
    }
}

/// Set the freshness token on a client context.
///
/// # Safety
///
/// `ctx` must be a valid pointer from `heimdal_pkinit_client_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_client_set_freshness(
    ctx: *mut c_void,
    token: *const u8,
    token_len: usize,
) {
    if ctx.is_null() || token.is_null() || token_len == 0 {
        return;
    }
    let client = unsafe { &mut *(ctx as *mut PkinitClientCtx) };
    let data = unsafe { std::slice::from_raw_parts(token, token_len) }.to_vec();
    client.set_freshness_token(data);
}

/// Process a PKINIT hint (KEM algorithm advertisement) from the KDC.
///
/// # Safety
///
/// `ctx` must be a valid pointer from `heimdal_pkinit_client_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_client_process_hint(
    ctx: *mut c_void,
    hint_data: *const u8,
    hint_len: usize,
) {
    if ctx.is_null() || hint_data.is_null() || hint_len == 0 {
        return;
    }
    let client = unsafe { &mut *(ctx as *mut PkinitClientCtx) };
    let hint = unsafe { std::slice::from_raw_parts(hint_data, hint_len) };
    client.process_hint(hint);
}

/// Build the PA-PK-AS-REQ PA-DATA value.
///
/// On success, `*out_data` and `*out_len` are set to the DER-encoded
/// PA-PK-AS-REQ (caller must free with `free()`).
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_client_mk_padata(
    ctx: *mut c_void,
    nonce: i32,
    ctime: i64,
    cusec: i32,
    req_body_data: *const u8,
    req_body_len: usize,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> bindings::krb5_error_code {
    if ctx.is_null() || out_data.is_null() || out_len.is_null() {
        return libc::EINVAL as _;
    }
    unsafe {
        *out_data = std::ptr::null_mut();
        *out_len = 0;
    }

    let client = unsafe { &mut *(ctx as *mut PkinitClientCtx) };
    let req_body = if req_body_data.is_null() || req_body_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(req_body_data, req_body_len) }
    };

    match client.build_as_req(nonce, ctime, cusec, req_body) {
        Ok(pa_req_der) => {
            let Some((buf, len)) = to_c_buffer(&pa_req_der) else {
                return libc::ENOMEM as _;
            };
            unsafe {
                *out_data = buf;
                *out_len = len;
            }
            0
        }
        Err(_) => libc::EINVAL as _,
    }
}

/// Process the KDC's PA-PK-AS-REP and derive the reply key.
///
/// On success, `reply_key` is filled with the derived key.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_client_rd_pa_reply(
    context: bindings::krb5_context,
    ctx: *mut c_void,
    pa_data: *const u8,
    pa_len: usize,
    nonce: i32,
    enctype: i32,
    as_req_data: *const u8,
    as_req_len: usize,
    client_name: *const c_char,
    server_name: *const c_char,
    reply_key: *mut bindings::krb5_keyblock,
) -> bindings::krb5_error_code {
    if ctx.is_null() || pa_data.is_null() || reply_key.is_null() {
        return libc::EINVAL as _;
    }

    let client = unsafe { &mut *(ctx as *mut PkinitClientCtx) };
    let pa_slice = unsafe { std::slice::from_raw_parts(pa_data, pa_len) };
    let as_req_der = if as_req_data.is_null() || as_req_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(as_req_data, as_req_len) }
    };

    let client_str = if client_name.is_null() {
        ""
    } else {
        unsafe { std::ffi::CStr::from_ptr(client_name) }
            .to_str()
            .unwrap_or("")
    };
    let server_str = if server_name.is_null() {
        ""
    } else {
        unsafe { std::ffi::CStr::from_ptr(server_name) }
            .to_str()
            .unwrap_or("")
    };

    match client.process_as_rep(
        context, pa_slice, nonce, enctype, as_req_der, client_str, server_str,
    ) {
        Ok(derived) => {
            let key_bytes = derived.key_data.as_ref();
            let Some((key_buf, key_len)) = to_c_buffer(key_bytes) else {
                return libc::ENOMEM as _;
            };
            unsafe {
                (*reply_key).keytype = derived.enctype as _;
                (*reply_key).keyvalue.data = key_buf as *mut _;
                (*reply_key).keyvalue.length = key_len;
            }
            0
        }
        Err(_) => libc::EINVAL as _,
    }
}

/// Handle a KDC error with retry hints (TD-DH-PARAMETERS etc.).
///
/// Returns 0 if a retry is possible (the context has been updated),
/// or an error code if no retry is possible.
///
/// # Safety
///
/// `ctx` must be a valid pointer from `heimdal_pkinit_client_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_client_tryagain(
    ctx: *mut c_void,
    error_padata: *const u8,
    error_padata_len: usize,
) -> bindings::krb5_error_code {
    if ctx.is_null() || error_padata.is_null() || error_padata_len == 0 {
        return libc::EINVAL as _;
    }
    let client = unsafe { &mut *(ctx as *mut PkinitClientCtx) };
    let data = unsafe { std::slice::from_raw_parts(error_padata, error_padata_len) };

    match client.handle_tryagain(data) {
        Ok(action) => {
            use pkinit_core::client::RetryAction;
            match action {
                RetryAction::NoRetry => libc::EINVAL as _,
                _ => 0, // retry is possible
            }
        }
        Err(_) => libc::EINVAL as _,
    }
}

/// Free a client PKINIT context.
///
/// # Safety
///
/// `ctx` must be a pointer from `heimdal_pkinit_client_init`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn heimdal_pkinit_client_free(
    ctx: *mut c_void,
) {
    if !ctx.is_null() {
        drop(unsafe { Box::from_raw(ctx as *mut PkinitClientCtx) });
    }
}
