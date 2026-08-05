//! `OctetString2Key` implementation using Heimdal's `krb5_random_to_key`
//! and `krb5_c_keylengths`.

use pkinit_core::crypto::kdf::OctetString2Key;
use pkinit_core::error::PkinitError;

use crate::bindings;

/// Adapter that satisfies `pkinit-core`'s `OctetString2Key` trait by
/// calling into Heimdal's libkrb5 key-derivation primitives.
pub(crate) struct HeimdalOctetString2Key {
    ctx: bindings::krb5_context,
}

impl HeimdalOctetString2Key {
    /// # Safety
    ///
    /// `ctx` must be a valid, non-null Heimdal krb5 context pointer that
    /// outlives this struct.
    pub(crate) unsafe fn new(ctx: bindings::krb5_context) -> Self {
        Self { ctx }
    }
}

impl OctetString2Key for HeimdalOctetString2Key {
    fn random_to_key(
        &self,
        enctype: i32,
        random_data: &[u8],
    ) -> Result<native_ossl::util::SecretBuf, PkinitError> {
        // Validates the enctype is recognized before calling
        // krb5_random_to_key(); the resulting key length no longer needs
        // to be used directly now that the empty-keyvalue fallback below
        // fails closed instead of using it to pad/truncate.
        let _key_len = self.key_length(enctype)?;

        let mut keyblock = bindings::krb5_keyblock {
            keytype: enctype as _,
            keyvalue: bindings::heim_octet_string {
                length: 0,
                data: std::ptr::null_mut(),
            },
        };

        let ret = unsafe {
            bindings::krb5_random_to_key(
                self.ctx,
                enctype as bindings::krb5_enctype,
                random_data.as_ptr() as *const _,
                random_data.len(),
                &mut keyblock,
            )
        };

        if ret != 0 {
            return Err(PkinitError::KdfFailed(format!(
                "krb5_random_to_key failed: {ret}"
            )));
        }

        // Copy key material out. krb5_random_to_key() returning success
        // (ret == 0) with an empty keyvalue should not happen for a
        // correctly-behaving enctype; if it ever does, fail rather than
        // silently substitute a naive truncate/zero-pad of the raw KDF
        // seed, which bypasses the enctype-specific random-to-key
        // transform (e.g. DES parity bits) and produces key material the
        // peer will not independently derive — a KDF path must fail
        // closed, not synthesize plausible-looking key material.
        if keyblock.keyvalue.data.is_null() || keyblock.keyvalue.length == 0 {
            return Err(PkinitError::KdfFailed(
                "krb5_random_to_key returned success with empty keyvalue".into(),
            ));
        }
        let slice = unsafe {
            std::slice::from_raw_parts(
                keyblock.keyvalue.data as *const u8,
                keyblock.keyvalue.length,
            )
        };
        let key_data = slice.to_vec();
        unsafe { bindings::krb5_free_keyblock_contents(self.ctx, &mut keyblock) };

        Ok(native_ossl::util::SecretBuf::new(key_data))
    }

    fn random_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        let mut keybytes: usize = 0;
        let mut _keylength: usize = 0;
        let ret = unsafe {
            bindings::krb5_c_keylengths(
                self.ctx,
                enctype as bindings::krb5_enctype,
                &mut keybytes,
                &mut _keylength,
            )
        };
        if ret != 0 {
            return Err(PkinitError::KdfFailed(format!(
                "krb5_c_keylengths failed: {ret}"
            )));
        }
        Ok(keybytes)
    }

    fn key_length(&self, enctype: i32) -> Result<usize, PkinitError> {
        let mut _keybytes: usize = 0;
        let mut keylength: usize = 0;
        let ret = unsafe {
            bindings::krb5_c_keylengths(
                self.ctx,
                enctype as bindings::krb5_enctype,
                &mut _keybytes,
                &mut keylength,
            )
        };
        if ret != 0 {
            return Err(PkinitError::KdfFailed(format!(
                "krb5_c_keylengths failed: {ret}"
            )));
        }
        Ok(keylength)
    }
}
