// Copyright (c) 2025 Red Hat, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// accompanying LICENSE file are met.

//! Tracing/logging bridge.
//!
//! `kdc_log` is only available in the KDC process, not in `libkrb5`.
//! Since this static library links into both, we use a C callback
//! function pointer that the KDC side sets at init time.  When
//! running client-side, the cell stays unset and tracing is a no-op.

use crate::bindings;

/// Signature of the trace callback (matches a simplified kdc_log).
type TraceFn = unsafe extern "C" fn(
    bindings::krb5_context,
    *mut bindings::krb5_kdc_configuration,
    std::ffi::c_int,
    *const std::ffi::c_char,
);

/// C-callable trace function pointer. Set once by
/// `heimdal_pkinit_initialize` on the KDC side. Unset on the client side
/// (tracing disabled). Function pointers are `Copy + Send + Sync`, so
/// `OnceLock` stores this with zero `unsafe` (unlike the previous
/// `AtomicPtr<()>` + `mem::transmute` approach, which relied on data
/// pointers and function pointers sharing representation — true on every
/// platform this crate targets, but not guaranteed by the language).
static TRACE_FN: std::sync::OnceLock<TraceFn> = std::sync::OnceLock::new();

/// Register the trace callback. Called once from `kdc::initialize`.
pub(crate) fn set_trace_fn(f: TraceFn) {
    // Matches the previous AtomicPtr::store's overwrite-once-per-process
    // semantics closely enough for this crate's single-KDC-init use case;
    // a second call is a no-op rather than an error.
    let _ = TRACE_FN.set(f);
}

/// Log a PKINIT message. No-op when the trace callback is unset.
///
/// # Safety
///
/// `context` and `config` must be valid, non-null pointers.
pub(crate) unsafe fn kdc_trace(
    context: bindings::krb5_context,
    config: *mut bindings::krb5_kdc_configuration,
    level: i32,
    msg: &str,
) {
    let Some(&f) = TRACE_FN.get() else {
        return;
    };

    let Ok(cmsg) = std::ffi::CString::new(msg) else {
        return;
    };
    // SAFETY: `f` was registered via set_trace_fn by the KDC's
    // pkinit-rust.c shim with the exact signature declared above;
    // context/config are the caller's responsibility per this function's
    // own `# Safety` contract.
    unsafe { f(context, config, level as _, cmsg.as_ptr()) };
}

macro_rules! pkinit_trace {
    ($ctx:expr, $config:expr, $($arg:tt)*) => {
        unsafe {
            $crate::trace::kdc_trace($ctx, $config, 0, &format!($($arg)*))
        }
    };
}
pub(crate) use pkinit_trace;
