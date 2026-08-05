//! Tracing/logging bridge.
//!
//! `kdc_log` is only available in the KDC process, not in `libkrb5`.
//! Since this static library links into both, we use a C callback
//! function pointer that the KDC side sets at init time.  When
//! running client-side, the pointer stays NULL and tracing is a no-op.

use crate::bindings;

/// C-callable trace function pointer.  Set by `heimdal_pkinit_initialize`
/// on the KDC side.  NULL on the client side (tracing disabled).
static TRACE_FN: std::sync::atomic::AtomicPtr<()> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Signature of the trace callback (matches a simplified kdc_log).
type TraceFn = unsafe extern "C" fn(
    bindings::krb5_context,
    *mut bindings::krb5_kdc_configuration,
    std::ffi::c_int,
    *const std::ffi::c_char,
);

/// Register the trace callback.  Called once from `kdc::initialize`.
pub(crate) fn set_trace_fn(f: TraceFn) {
    TRACE_FN.store(f as *mut (), std::sync::atomic::Ordering::Release);
}

/// Log a PKINIT message.  No-op when the trace callback is unset.
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
    let ptr = TRACE_FN.load(std::sync::atomic::Ordering::Acquire);
    if ptr.is_null() {
        return;
    }

    let Ok(cmsg) = std::ffi::CString::new(msg) else {
        return;
    };
    let f: TraceFn = unsafe { std::mem::transmute(ptr) };
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
