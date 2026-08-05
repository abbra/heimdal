/*
 * Copyright (c) 2025 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the conditions in the
 * accompanying LICENSE file are met.
 *
 * PKINIT client shim for the Rust pkinit-core adapter.
 *
 * When compiled with PKINIT_RUST, this file provides wrappers that
 * bridge Heimdal's client-side PKINIT API to the Rust FFI functions
 * in libheimdal_pkinit.a.
 */

#include "krb5_locl.h"

#ifdef PKINIT
#ifdef PKINIT_RUST

#include "heimdal_pkinit.h"
#include <pkinit_asn1.h>

/*
 * _krb5_pk_mk_padata — build PA-PK-AS-REQ
 *
 * This is the Rust-backed replacement.  The original C version in
 * pkinit.c does DH key generation, AuthPack construction, and CMS
 * signing.  All of that is now handled by pkinit-core.
 */
krb5_error_code
_krb5_pk_mk_padata_rust(krb5_context context,
			void *c,
			int ic_flags,
			int win2k,
			const KDC_REQ_BODY *req_body,
			unsigned nonce,
			krb5_error_code error_code,
			TYPED_DATA *td,
			METHOD_DATA *md)
{
    unsigned char *req_body_der = NULL;
    size_t req_body_len = 0, size;
    unsigned char *pa_data = NULL;
    size_t pa_len = 0;
    krb5_error_code ret;
    krb5_timestamp now;

    if (c == NULL)
	return EINVAL;

    /* Encode the request body to DER for pkinit-core's checksum */
    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, req_body_der, req_body_len,
		       req_body, &size, ret);
    if (ret)
	return ret;
    if (req_body_len != size) {
	free(req_body_der);
	return EINVAL;
    }

    krb5_timeofday(context, &now);

    ret = heimdal_pkinit_client_mk_padata(c,
					  (int)nonce,
					  (long long)now,
					  0, /* cusec */
					  req_body_der,
					  req_body_len,
					  &pa_data, &pa_len);
    free(req_body_der);
    if (ret)
	return ret;

    ret = krb5_padata_add(context, md, KRB5_PADATA_PK_AS_REQ,
			  pa_data, pa_len);
    if (ret) {
	free(pa_data);
	return ret;
    }

    return 0;
}

/*
 * _krb5_pk_rd_pa_reply — process PA-PK-AS-REP
 *
 * Rust-backed replacement.  Verifies the KDC's CMS signature,
 * performs Dagreement, and derives the reply key.
 */
krb5_error_code
_krb5_pk_rd_pa_reply_rust(krb5_context context,
			  void *c,
			  const AS_REQ *a,
			  const AS_REP *kdc_rep,
			  unsigned nonce,
			  const krb5_data *req_buffer,
			  PA_DATA *pa,
			  krb5_keyblock **key)
{
    krb5_error_code ret;
    krb5_keyblock *k = NULL;
    char *client_name = NULL;
    char *server_name = NULL;
    krb5_enctype enctype;

    if (c == NULL)
	return EINVAL;

    k = calloc(1, sizeof(*k));
    if (k == NULL)
	return krb5_enomem(context);

    /*
     * The enctype for key derivation comes from the KDC's reply
     * enc-part — that's what the original C code uses too.
     */
    enctype = kdc_rep->enc_part.etype;

    /*
     * Unparse client and server principals for KDF input.
     * The C pkinit.c uses krb5_pk_init_ctx->client/server for this,
     * but we need to derive them from the request/reply.
     */
    {
	krb5_principal cprinc = NULL;

	/* Client: use the cname from the reply (canonicalized) */
	if (kdc_rep->cname.name_string.len > 0) {
	    ret = _krb5_principalname2krb5_principal(context, &cprinc,
						     kdc_rep->cname,
						     kdc_rep->crealm);
	    if (ret == 0) {
		krb5_unparse_name(context, cprinc, &client_name);
		krb5_free_principal(context, cprinc);
	    }
	}

	/* Server: from the request sname */
	if (a->req_body.sname) {
	    krb5_principal sprinc = NULL;

	    ret = _krb5_principalname2krb5_principal(context, &sprinc,
						     *a->req_body.sname,
						     a->req_body.realm);
	    if (ret == 0) {
		krb5_unparse_name(context, sprinc, &server_name);
		krb5_free_principal(context, sprinc);
	    }
	}
    }

    ret = heimdal_pkinit_client_rd_pa_reply(context,
					    c,
					    pa->padata_value.data,
					    pa->padata_value.length,
					    (int)nonce,
					    (int)enctype,
					    req_buffer ? (const unsigned char *)req_buffer->data : NULL,
					    req_buffer ? req_buffer->length : 0,
					    client_name ? client_name : "",
					    server_name ? server_name : "",
					    k);
    free(client_name);
    free(server_name);

    if (ret) {
	free(k);
	return ret;
    }

    *key = k;
    return 0;
}

/*
 * Initialize a Rust PKINIT client context.
 *
 * Called from krb5_get_init_creds_opt_set_pkinit() when PKINIT_RUST
 * is defined.  Creates the Rust opaque handle and stores it so that
 * the pkinit_step() code path can pass it to the _rust() variants.
 *
 * Returns the opaque handle, or NULL on failure.
 */
void *
_krb5_pk_init_rust_ctx(krb5_context context,
		       krb5_principal principal,
		       const char *user_id,
		       const char *x509_anchors,
		       int anonymous)
{
    void *rust_ctx = NULL;
    krb5_error_code ret;
    const char *anchors_arr[2];
    size_t n_anchors = 0;
    char *server_name = NULL;

    if (x509_anchors) {
	/* Strip "FILE:" prefix if present */
	if (strncmp(x509_anchors, "FILE:", 5) == 0)
	    anchors_arr[0] = x509_anchors + 5;
	else
	    anchors_arr[0] = x509_anchors;
	n_anchors = 1;
    }
    anchors_arr[n_anchors] = NULL;

    if (principal) {
	krb5_principal krbtgt = NULL;
	const char *realm = krb5_principal_get_realm(context, principal);

	ret = krb5_make_principal(context, &krbtgt, realm,
				 KRB5_TGS_NAME, realm, NULL);
	if (ret == 0) {
	    krb5_unparse_name(context, krbtgt, &server_name);
	    krb5_free_principal(context, krbtgt);
	}
    }

    ret = heimdal_pkinit_client_init(context,
				     user_id ? user_id : "",
				     anchors_arr,
				     n_anchors,
				     anonymous,
				     server_name,
				     &rust_ctx);
    free(server_name);
    if (ret) {
	krb5_set_error_message(context, ret,
			       "PKINIT(rust): failed to initialize client context");
	return NULL;
    }

    return rust_ctx;
}

/*
 * Free a Rust PKINIT client context.
 */
void
_krb5_pk_free_rust_ctx(void *rust_ctx)
{
    heimdal_pkinit_client_free(rust_ctx);
}

#endif /* PKINIT_RUST */
#endif /* PKINIT */
