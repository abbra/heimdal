//! Bridge between Heimdal's `hx509` certificate objects and raw DER bytes
//! used by `pkinit-core`.

use crate::bindings;

/// Extract the DER-encoded certificate from an `hx509_cert`.
///
/// # Safety
///
/// `hx509ctx` and `cert` must be valid, non-null pointers.
pub(crate) unsafe fn cert_to_der(
    hx509ctx: bindings::hx509_context,
    cert: bindings::hx509_cert,
) -> Option<Vec<u8>> {
    let mut data = bindings::heim_octet_string {
        length: 0,
        data: std::ptr::null_mut(),
    };

    let ret = unsafe { bindings::hx509_cert_binary(hx509ctx, cert, &mut data) };
    if ret != 0 || data.data.is_null() || data.length == 0 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(data.data as *const u8, data.length) };
    let result = slice.to_vec();
    unsafe { bindings::der_free_octet_string(&mut data) };
    Some(result)
}

/// Create an `hx509_cert` from DER-encoded certificate bytes.
///
/// Returns `None` if the DER is invalid or `hx509_cert_init_data` fails.
///
/// # Safety
///
/// `hx509ctx` must be a valid, non-null hx509 context.
pub(crate) unsafe fn der_to_cert(
    hx509ctx: bindings::hx509_context,
    der: &[u8],
) -> Option<bindings::hx509_cert> {
    let cert = unsafe {
        bindings::hx509_cert_init_data(
            hx509ctx,
            der.as_ptr() as *const _,
            der.len(),
            std::ptr::null_mut(),
        )
    };
    if cert.is_null() {
        None
    } else {
        Some(cert)
    }
}

/// Get the subject DN as a string from an `hx509_cert`.
///
/// # Safety
///
/// `hx509ctx` and `cert` must be valid, non-null pointers.
pub(crate) unsafe fn cert_subject_name(
    _hx509ctx: bindings::hx509_context,
    cert: bindings::hx509_cert,
) -> Option<String> {
    let mut name: bindings::hx509_name = std::ptr::null_mut();
    let ret = unsafe { bindings::hx509_cert_get_subject(cert, &mut name) };
    if ret != 0 || name.is_null() {
        return None;
    }

    let mut cstr: *mut std::ffi::c_char = std::ptr::null_mut();
    let ret = unsafe { bindings::hx509_name_to_string(name, &mut cstr) };
    unsafe { bindings::hx509_name_free(&mut name) };

    if ret != 0 || cstr.is_null() {
        return None;
    }

    let result = unsafe { std::ffi::CStr::from_ptr(cstr) }
        .to_str()
        .ok()
        .map(|s| s.to_string());
    unsafe { libc::free(cstr as *mut _) };
    result
}
