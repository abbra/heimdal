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
 * Client context: wraps the Rust opaque pointer alongside the fields
 * that Heimdal's init_creds_pw.c expects on the krb5_pk_init_ctx.
 *
 * The Rust side owns all crypto state; this struct just holds the
 * opaque handle and Heimdal-specific metadata.
 */
struct krb5_pk_init_ctx_rust {
    void *rust_ctx;		    /* heimdal_pkinit_client_init() handle */
    enum krb5_pk_type type;	    /* PKINIT_27 for IETF, PKINIT_WIN2K */
    enum keyex_enum keyex;	    /* USE_DH, USE_ECDH, or USE_RSA */
    unsigned int anonymous:1;
    krb5_data as_req;		    /* cached DER of last AS-REQ */
};

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
    struct krb5_pk_init_ctx_rust *ctx = c;
    unsigned char *req_body_der = NULL;
    size_t req_body_len = 0, size;
    unsigned char *pa_data = NULL;
    size_t pa_len = 0;
    krb5_error_code ret;
    krb5_timestamp now;

    if (ctx == NULL || ctx->rust_ctx == NULL)
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

    ret = heimdal_pkinit_client_mk_padata(ctx->rust_ctx,
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
 * performs DH/KEM key agreement, and derives the reply key.
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
    struct krb5_pk_init_ctx_rust *ctx = c;
    krb5_error_code ret;
    krb5_keyblock *k = NULL;
    char *client_name = NULL;
    char *server_name = NULL;

    if (ctx == NULL || ctx->rust_ctx == NULL)
	return EINVAL;

    k = calloc(1, sizeof(*k));
    if (k == NULL)
	return krb5_enomem(context);

    if (a->req_body.cname)
	krb5_unparse_name(context,
			  kdc_rep->cname ? (krb5_const_principal)kdc_rep->cname : NULL,
			  &client_name);
    if (a->req_body.sname)
	krb5_unparse_name(context,
			  kdc_rep->crealm ? (krb5_const_principal)NULL : NULL,
			  &server_name);

    /* Use cname/sname from the request if we couldn't get them above */
    ret = heimdal_pkinit_client_rd_pa_reply(context,
					    ctx->rust_ctx,
					    pa->padata_value.data,
					    pa->padata_value.length,
					    (int)nonce,
					    0, /* enctype — derived internally */
					    req_buffer ? req_buffer->data : NULL,
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

#endif /* PKINIT_RUST */
#endif /* PKINIT */
