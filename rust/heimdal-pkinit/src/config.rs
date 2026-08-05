//! Map Heimdal's `krb5_kdc_configuration` to `pkinit-core`'s config types.

use pkinit_core::config::{PkinitClientConfig, PkinitKdcConfig};
use pkinit_core::constants::{DhGroup, KemAlgorithm};

use crate::bindings;

/// Read KDC PKINIT configuration from `krb5.conf`.
///
/// We intentionally do NOT access `krb5_kdc_configuration` struct fields
/// because the struct is defined in an internal header (`kdc_locl.h`)
/// whose layout differs from the installed `kdc.h` that bindgen uses.
/// Reading directly from `krb5.conf` avoids struct layout mismatches.
///
/// # Safety
///
/// `context` must be a valid Heimdal krb5 context.
pub(crate) unsafe fn read_kdc_config(
    context: bindings::krb5_context,
    _config: *const bindings::krb5_kdc_configuration,
) -> PkinitKdcConfig {
    let mut kdc_config = PkinitKdcConfig::default();

    // pkinit_identity
    if let Some(v) = unsafe { read_config_string(context, &["kdc", "pkinit_identity"]) } {
        kdc_config.identity = Some(v);
    }

    // pkinit_anchors
    if let Some(v) = unsafe { read_config_string(context, &["kdc", "pkinit_anchors"]) } {
        kdc_config.anchors.push(v);
    }

    // pkinit_dh_min_bits
    let dh_min = unsafe { read_config_int(context, &["kdc", "pkinit_dh_min_bits"], 2048) };
    kdc_config.dh_min_bits = dh_min as u32;

    // pkinit_pqc_min_algorithm
    let pqc_min = unsafe { read_config_string(context, &["kdc", "pkinit_pqc_min_algorithm"]) };
    if let Some(ref name) = pqc_min {
        if let Some(alg) = KemAlgorithm::from_name(name) {
            kdc_config.supported_kem_algorithms = alg.algorithms_at_or_above();
        }
    }

    // pkinit_require_freshness
    let freshness = unsafe { read_config_string(context, &["kdc", "pkinit_require_freshness"]) };
    if let Some(ref v) = freshness {
        kdc_config.require_freshness = matches!(v.as_str(), "yes" | "true" | "1");
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
