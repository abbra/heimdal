// Copyright (c) 2025 Red Hat, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// accompanying LICENSE file are met.

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

    // pkinit_anchors (admin may repeat the key to list multiple sources)
    for v in unsafe { read_config_strings(context, &["kdc", "pkinit_anchors"]) } {
        kdc_config.anchors.push(v);
    }

    // pkinit_pool (intermediate certificates, admin may repeat the key)
    for v in unsafe { read_config_strings(context, &["kdc", "pkinit_pool"]) } {
        kdc_config.intermediates.push(v);
    }

    // pkinit_revoke (CRL / revocation bundle sources, admin may repeat)
    let revoke_sources = unsafe { read_config_strings(context, &["kdc", "pkinit_revoke"]) };
    if !revoke_sources.is_empty() {
        kdc_config.crls = revoke_sources;
        kdc_config.require_crl_checking = true;
    }

    // pkinit_dh_min_bits
    let dh_min = unsafe { read_config_int(context, &["kdc", "pkinit_dh_min_bits"], 2048) };
    kdc_config.dh_min_bits = dh_min as u32;

    // pkinit_pqc_min_algorithm
    let pqc_min = unsafe { read_config_string(context, &["kdc", "pkinit_pqc_min_algorithm"]) };
    if let Some(ref name) = pqc_min
        && let Some(alg) = KemAlgorithm::from_name(name)
    {
        kdc_config.supported_kem_algorithms = alg.algorithms_at_or_above();
    }

    // pkinit_require_freshness
    kdc_config.require_freshness =
        unsafe { read_config_bool(context, &["kdc", "pkinit_require_freshness"], false) };

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
pub(crate) unsafe fn read_config_string(
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

/// Read a multi-valued string relation (e.g. `pkinit_pool`, `pkinit_revoke`,
/// which admins may repeat) from Heimdal's config. Only 2-element paths
/// (`["kdc", "pkinit_pool"]`) are supported, matching the existing
/// `read_config_string` helper's scope.
///
/// # Safety
///
/// `context` must be valid.
pub(crate) unsafe fn read_config_strings(
    context: bindings::krb5_context,
    path: &[&str; 2],
) -> Vec<String> {
    let Ok(c0) = std::ffi::CString::new(path[0]) else {
        return Vec::new();
    };
    let Ok(c1) = std::ffi::CString::new(path[1]) else {
        return Vec::new();
    };

    let values = unsafe {
        bindings::krb5_config_get_strings(
            context,
            std::ptr::null(),
            c0.as_ptr(),
            c1.as_ptr(),
            std::ptr::null::<std::ffi::c_char>(),
        )
    };
    if values.is_null() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut i = 0isize;
    loop {
        // SAFETY: krb5_config_get_strings returns a NULL-terminated array
        // of NUL-terminated C strings; we stop at the first NULL entry
        // before ever reading past the allocation.
        let entry = unsafe { *values.offset(i) };
        if entry.is_null() {
            break;
        }
        if let Ok(s) = unsafe { std::ffi::CStr::from_ptr(entry) }.to_str() {
            result.push(s.to_string());
        }
        i += 1;
    }
    unsafe { bindings::krb5_config_free_strings(values) };
    result
}

/// Read a boolean value from Heimdal's config using the same semantics as
/// every other boolean option in this codebase (case-insensitive
/// yes/true, or any nonzero value via atoi — see
/// `krb5_config_get_bool_default` / `heim_config_vget_bool_default` in
/// `lib/base/config_file.c`), instead of hand-rolled string matching that
/// can silently disagree with the rest of Heimdal's config parsing.
///
/// # Safety
///
/// `context` must be valid.
pub(crate) unsafe fn read_config_bool(
    context: bindings::krb5_context,
    path: &[&str; 2],
    default: bool,
) -> bool {
    let Ok(c0) = std::ffi::CString::new(path[0]) else {
        return default;
    };
    let Ok(c1) = std::ffi::CString::new(path[1]) else {
        return default;
    };
    unsafe {
        bindings::krb5_config_get_bool_default(
            context,
            std::ptr::null(),
            default as std::ffi::c_int,
            c0.as_ptr(),
            c1.as_ptr(),
            std::ptr::null::<std::ffi::c_char>(),
        )
        != 0
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
