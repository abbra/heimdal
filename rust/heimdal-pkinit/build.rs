use std::env;
use std::path::PathBuf;

fn main() {
    // Heimdal headers are typically in /usr/include/heimdal on Fedora/RHEL
    let heimdal_include = env::var("HEIMDAL_INCLUDE_DIR")
        .unwrap_or_else(|_| "/usr/include/heimdal".to_string());

    println!("cargo:rerun-if-env-changed=HEIMDAL_INCLUDE_DIR");
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{heimdal_include}"))
        // Heimdal krb5 types
        .allowlist_type("krb5_context_data")
        .allowlist_type("krb5_kdc_configuration")
        .allowlist_type("krb5_keyblock")
        .allowlist_type("krb5_data")
        .allowlist_type("krb5_enctype")
        .allowlist_type("krb5_error_code")
        .allowlist_type("krb5_timestamp")
        .allowlist_type("PA_DATA")
        .allowlist_type("METHOD_DATA")
        .allowlist_type("KDC_REQ")
        .allowlist_type("KDC_REQ_BODY")
        .allowlist_type("EncTicketPart")
        .allowlist_type("hdb_entry_ex")
        .allowlist_type("HDB")
        // PKINIT ASN.1 types
        .allowlist_type("PA_PK_AS_REQ")
        .allowlist_type("PA_PK_AS_REP")
        .allowlist_type("AuthPack")
        .allowlist_type("PKAuthenticator")
        .allowlist_type("DHRepInfo")
        .allowlist_type("KDCDHKeyInfo")
        .allowlist_type("TD_DH_PARAMETERS")
        .allowlist_type("SubjectPublicKeyInfo")
        .allowlist_type("AlgorithmIdentifier")
        .allowlist_type("ContentInfo")
        // krb5 functions we need
        .allowlist_function("krb5_random_to_key")
        .allowlist_function("krb5_c_keylengths")
        .allowlist_function("krb5_enctype_keysize")
        .allowlist_function("krb5_enctype_keybits")
        .allowlist_function("krb5_copy_keyblock_contents")
        .allowlist_function("krb5_free_keyblock_contents")
        .allowlist_function("krb5_generate_random_keyblock")
        .allowlist_function("krb5_timeofday")
        .allowlist_function("krb5_unparse_name")
        .allowlist_function("krb5_free_unparsed_name")
        .allowlist_function("krb5_config_get_string")
        .allowlist_function("krb5_config_get_strings")
        .allowlist_function("krb5_config_free_strings")
        .allowlist_function("krb5_config_get_bool_default")
        .allowlist_function("krb5_config_get_int_default")
        .allowlist_function("krb5_set_error_message")
        .allowlist_function("krb5_clear_error_message")
        .allowlist_function("krb5_get_max_time_skew")
        .allowlist_function("krb5_set_max_time_skew")
        .allowlist_function("krb5_crypto_init")
        .allowlist_function("krb5_crypto_destroy")
        .allowlist_function("krb5_crypto_fx_cf2")
        .allowlist_function("krb5_encrypt_EncryptedData")
        .allowlist_function("krb5_padata_add")
        // hx509 functions
        .allowlist_function("hx509_cert_init_data")
        .allowlist_function("hx509_cert_free")
        .allowlist_function("hx509_cert_get_subject")
        .allowlist_function("hx509_cert_binary")
        .allowlist_function("hx509_certs_init")
        .allowlist_function("hx509_certs_free")
        .allowlist_function("hx509_certs_add")
        .allowlist_function("hx509_certs_merge")
        .allowlist_function("hx509_certs_find")
        .allowlist_function("hx509_verify_init_ctx")
        .allowlist_function("hx509_verify_destroy_ctx")
        .allowlist_function("hx509_verify_set_time")
        .allowlist_function("hx509_verify_attach_anchors")
        .allowlist_function("hx509_name_to_string")
        .allowlist_function("hx509_name_free")
        .allowlist_function("hx509_cms_verify_signed")
        .allowlist_function("hx509_cms_create_signed_1")
        .allowlist_function("hx509_cms_unwrap_ContentInfo")
        // KDC functions — kdc_log is NOT listed here because it's only
        // available in the KDC binary, not libkrb5.  The trace module
        // uses a callback pointer instead.
        // ASN.1 encode/decode functions for PKINIT types
        .allowlist_function("encode_.*")
        .allowlist_function("decode_.*")
        .allowlist_function("length_.*")
        .allowlist_function("free_.*")
        // der functions
        .allowlist_function("der_heim_oid_cmp")
        .allowlist_function("der_free_heim_integer")
        .allowlist_function("der_free_octet_string")
        // Block recursive type aliases that bindgen can't handle
        .blocklist_type("hx509_peer_info")
        // OID constants
        .allowlist_var("asn1_oid_id_pk.*")
        .allowlist_var("asn1_oid_id_dhpublicnumber")
        .allowlist_var("asn1_oid_id_ecPublicKey")
        .allowlist_var("asn1_oid_id_pkcs7_.*")
        // Kerberos PA-DATA type constants
        .allowlist_var("KRB5_PADATA_.*")
        // Error codes
        .allowlist_var("KRB5KDC_ERR_.*")
        .allowlist_var("KRB5KRB_.*")
        .allowlist_var("KRB5_BADMSGTYPE")
        .allowlist_var("KRB5_KDC_ERR_.*")
        // Generate for Heimdal types
        .derive_debug(true)
        .derive_default(true)
        .use_core()
        .raw_line("pub type hx509_peer_info = *mut std::ffi::c_void;")
        // Heimdal's GENERATION struct has a field named `gen` which is
        // a reserved keyword in Rust 2024 edition.  Blocklist and
        // provide a manual definition.
        .blocklist_type("GENERATION")
        // Types with opaque internals that confuse bindgen size assertions
        .blocklist_type("krb5_log_facility")
        .opaque_type("ContentInfo")
        .opaque_type("heim_digest_data")
        .raw_line(r#"
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct GENERATION {
    pub time: time_t,
    pub usec: ::core::ffi::c_int,
    pub gen_: ::core::ffi::c_uint,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct krb5_log_facility {
    _opaque: [u8; 0],
}
"#)
        .generate()
        .expect("Unable to generate Heimdal bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}
