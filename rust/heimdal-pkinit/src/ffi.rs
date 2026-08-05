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
use crate::kdc::{self, PkClientParams};

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
    unsafe { kdc::initialize(context, config) }
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

    let max_skew = unsafe { bindings::krb5_get_max_time_skew(context) as i64 };
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    match unsafe { kdc::verify_padata(context, config, pa_data, pa_data_len, max_skew, current_time) } {
        Ok(cp) => {
            unsafe { *out_params = Box::into_raw(cp) as *mut c_void };
            0
        }
        Err(code) => code,
    }
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

    match unsafe { kdc::build_reply(context, config, cp, nonce, enctype, as_req_der, client_str, server_str) } {
        Ok((pa_rep_der, derived)) => {
            // Allocate the PA-DATA buffer via libc::malloc so Heimdal can free it
            let buf = unsafe { libc::malloc(pa_rep_der.len()) as *mut u8 };
            if buf.is_null() {
                return libc::ENOMEM as _;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(pa_rep_der.as_ptr(), buf, pa_rep_der.len());
                *out_pa_data = buf;
                *out_pa_len = pa_rep_der.len();
            }

            // Fill in the reply key
            let key_bytes = derived.key_data.as_ref();
            let key_buf = unsafe { libc::malloc(key_bytes.len()) as *mut u8 };
            if key_buf.is_null() {
                unsafe { libc::free(buf as *mut _) };
                return libc::ENOMEM as _;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(key_bytes.as_ptr(), key_buf, key_bytes.len());
                (*reply_key).keytype = derived.enctype as _;
                (*reply_key).keyvalue.data = key_buf as *mut _;
                (*reply_key).keyvalue.length = key_bytes.len();
            }

            0
        }
        Err(code) => code,
    }
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
    allow_upn: i32,
    out_subject: *mut *mut c_char,
) -> bindings::krb5_error_code {
    if params.is_null() || client_principal.is_null() || out_subject.is_null() {
        return libc::EINVAL as _;
    }

    let cp = unsafe { &*(params as *const PkClientParams) };
    let princ_str = unsafe { std::ffi::CStr::from_ptr(client_principal) }
        .to_str()
        .unwrap_or("");

    match kdc::check_client(cp, princ_str, allow_upn != 0) {
        Ok(subject) => {
            let c_subject = match std::ffi::CString::new(subject) {
                Ok(s) => s,
                Err(_) => return libc::EINVAL as _,
            };
            let len = c_subject.as_bytes_with_nul().len();
            let buf = unsafe { libc::malloc(len) as *mut c_char };
            if buf.is_null() {
                return libc::ENOMEM as _;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(c_subject.as_ptr(), buf, len);
                *out_subject = buf;
            }
            0
        }
        Err(code) => code,
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
