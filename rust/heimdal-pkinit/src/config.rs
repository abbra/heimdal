//! Map Heimdal's `krb5_kdc_configuration` to `pkinit-core`'s config types.

use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{DhGroup, KemAlgorithm};

use crate::bindings;

/// Read KDC PKINIT configuration from Heimdal's `krb5_kdc_configuration`.
///
/// # Safety
///
/// `config` must be a valid, non-null pointer to a fully initialized
/// `krb5_kdc_configuration` struct.
pub(crate) unsafe fn read_kdc_config(
    context: bindings::krb5_context,
    config: *const bindings::krb5_kdc_configuration,
) -> PkinitKdcConfig {
    let config = unsafe { &*config };
    let mut kdc_config = PkinitKdcConfig::default();

    // pkinit_kdc_identity → identity
    if !config.pkinit_kdc_identity.is_null() {
        let cstr = unsafe { std::ffi::CStr::from_ptr(config.pkinit_kdc_identity) };
        if let Ok(s) = cstr.to_str() {
            kdc_config.identity = Some(s.to_string());
        }
    }

    // pkinit_kdc_anchors → anchors
    if !config.pkinit_kdc_anchors.is_null() {
        let cstr = unsafe { std::ffi::CStr::from_ptr(config.pkinit_kdc_anchors) };
        if let Ok(s) = cstr.to_str() {
            kdc_config.anchors.push(s.to_string());
        }
    }

    // pkinit_kdc_cert_pool → intermediates
    if !config.pkinit_kdc_cert_pool.is_null() {
        let mut i = 0;
        loop {
            let ptr = unsafe { *config.pkinit_kdc_cert_pool.add(i) };
            if ptr.is_null() {
                break;
            }
            let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
            if let Ok(s) = cstr.to_str() {
                kdc_config.intermediates.push(s.to_string());
            }
            i += 1;
        }
    }

    // pkinit_kdc_revoke → crls
    if !config.pkinit_kdc_revoke.is_null() {
        let mut i = 0;
        loop {
            let ptr = unsafe { *config.pkinit_kdc_revoke.add(i) };
            if ptr.is_null() {
                break;
            }
            let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
            if let Ok(s) = cstr.to_str() {
                kdc_config.crls.push(s.to_string());
            }
            i += 1;
        }
    }

    // pkinit_dh_min_bits
    kdc_config.dh_min_bits = config.pkinit_dh_min_bits as u32;

    // Read PQC config from krb5.conf via krb5_config_get_string
    let pqc_min = unsafe { read_config_string(context, &["kdc", "pkinit_pqc_min_algorithm"]) };
    if let Some(ref name) = pqc_min {
        if let Some(alg) = KemAlgorithm::from_name(name) {
            kdc_config.supported_kem_algorithms = alg.algorithms_at_or_above();
        }
    }

    kdc_config
}

/// Read client PKINIT configuration from `krb5.conf`.
///
/// # Safety
///
/// `context` must be a valid, non-null Heimdal krb5 context.
pub(crate) unsafe fn read_client_config(
    context: bindings::krb5_context,
) -> PkinitClientConfig {
    let mut config = PkinitClientConfig::default();

    // Read from [libdefaults]
    if let Some(v) = unsafe { read_config_string(context, &["libdefaults", "pkinit_identities"]) } {
        config.identity = Some(v);
    }

    if let Some(v) = unsafe { read_config_string(context, &["libdefaults", "pkinit_pqc_min_algorithm"]) } {
        config.kem_algorithm = KemAlgorithm::from_name(&v);
    }

    let dh_min = unsafe { read_config_int(context, &["libdefaults", "pkinit_dh_min_bits"], 2048) };
    config.dh_min_bits = dh_min as u32;
    config.dh_group = dh_group_from_min_bits(config.dh_min_bits);

    config
}

/// Read a string value from Heimdal's config.
///
/// # Safety
///
/// `context` must be valid.
unsafe fn read_config_string(
    context: bindings::krb5_context,
    path: &[&str],
) -> Option<String> {
    // Build the C strings for the config path
    let c_strings: Vec<std::ffi::CString> = path
        .iter()
        .filter_map(|s| std::ffi::CString::new(*s).ok())
        .collect();

    if c_strings.len() != path.len() {
        return None;
    }

    // For 2-element paths: krb5_config_get_string(ctx, NULL, p0, p1, NULL)
    match c_strings.len() {
        2 => {
            let val = unsafe {
                bindings::krb5_config_get_string(
                    context,
                    std::ptr::null(),
                    c_strings[0].as_ptr(),
                    c_strings[1].as_ptr(),
                    std::ptr::null::<std::ffi::c_char>(),
                )
            };
            if val.is_null() {
                None
            } else {
                unsafe { std::ffi::CStr::from_ptr(val) }
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            }
        }
        3 => {
            let val = unsafe {
                bindings::krb5_config_get_string(
                    context,
                    std::ptr::null(),
                    c_strings[0].as_ptr(),
                    c_strings[1].as_ptr(),
                    c_strings[2].as_ptr(),
                    std::ptr::null::<std::ffi::c_char>(),
                )
            };
            if val.is_null() {
                None
            } else {
                unsafe { std::ffi::CStr::from_ptr(val) }
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            }
        }
        _ => None,
    }
}

/// Read an integer value from Heimdal's config with a default.
///
/// # Safety
///
/// `context` must be valid.
unsafe fn read_config_int(
    context: bindings::krb5_context,
    path: &[&str],
    default: i32,
) -> i32 {
    let c_strings: Vec<std::ffi::CString> = path
        .iter()
        .filter_map(|s| std::ffi::CString::new(*s).ok())
        .collect();

    if c_strings.len() != path.len() {
        return default;
    }

    match c_strings.len() {
        2 => unsafe {
            bindings::krb5_config_get_int_default(
                context,
                std::ptr::null(),
                default,
                c_strings[0].as_ptr(),
                c_strings[1].as_ptr(),
                std::ptr::null::<std::ffi::c_char>(),
            )
        },
        _ => default,
    }
}

fn dh_group_from_min_bits(min_bits: u32) -> DhGroup {
    if min_bits <= 256 {
        DhGroup::EcP256
    } else if min_bits <= 2048 {
        DhGroup::Oakley2048
    } else {
        DhGroup::Oakley4096
    }
}
