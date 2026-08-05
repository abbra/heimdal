//! Tracing/logging bridge to Heimdal's `kdc_log`.

use crate::bindings;

/// Log a PKINIT message through Heimdal's KDC logging facility.
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
    let Ok(cmsg) = std::ffi::CString::new(msg) else {
        return;
    };
    unsafe {
        bindings::kdc_log(context, config, level as _, c"%s".as_ptr(), cmsg.as_ptr());
    }
}

macro_rules! pkinit_trace {
    ($ctx:expr, $config:expr, $($arg:tt)*) => {
        unsafe {
            $crate::trace::kdc_trace($ctx, $config, 0, &format!($($arg)*))
        }
    };
}
pub(crate) use pkinit_trace;
