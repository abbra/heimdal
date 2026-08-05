/*
 * Copyright (c) 2025 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the conditions in the
 * accompanying LICENSE file are met.
 *
 * C API for the Rust PKINIT adapter (heimdal-pkinit crate).
 *
 * This header declares the functions exported by libheimdal_pkinit.a.
 * Heimdal's KDC and client code call these instead of the original C
 * PKINIT implementation when built with PKINIT_RUST=1.
 *
 * Contract for all out_* parameters below: they are set to NULL/0 as soon
 * as argument validation passes, and only overwritten on success. Callers
 * do not need to pre-initialize them, but must not assume they are
 * touched at all before the null-argument check runs (i.e. do not read
 * them if this function returned early due to a NULL required argument).
 */

#ifndef HEIMDAL_PKINIT_H
#define HEIMDAL_PKINIT_H

#include <krb5.h>
#include <stddef.h>

/*
 * Forward-declare krb5_kdc_configuration so this header can be
 * included from both KDC code (which has kdc.h / kdc_locl.h) and
 * client code (which does not).  The KDC functions only take
 * pointers, so a forward declaration suffices.
 */
#ifndef __KDC_H__
struct krb5_kdc_configuration;
typedef struct krb5_kdc_configuration krb5_kdc_configuration;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── KDC side ──────────────────────────────────────────────────────── */

/*
 * Register the trace/logging callback.  Must be called before
 * heimdal_pkinit_initialize() so that init-time log messages
 * reach the KDC log.
 */
void
heimdal_pkinit_set_trace(void (*fn)(krb5_context,
                                    krb5_kdc_configuration *,
                                    int, const char *));

/*
 * Initialize the PKINIT subsystem (called once at KDC startup).
 * Replaces krb5_kdc_pk_initialize().
 */
krb5_error_code
heimdal_pkinit_initialize(krb5_context context,
                          krb5_kdc_configuration *config);

/*
 * Verify an incoming PA-PK-AS-REQ.
 * Replaces _kdc_pk_rd_padata().
 *
 * On success *out_params is an opaque handle passed to
 * heimdal_pkinit_mk_pa_reply() and freed by
 * heimdal_pkinit_free_client_param().
 */
krb5_error_code
heimdal_pkinit_rd_padata(krb5_context context,
                         krb5_kdc_configuration *config,
                         const unsigned char *pa_data,
                         size_t pa_data_len,
                         void **out_params);

/*
 * Build the PA-PK-AS-REP and derive the reply key.
 * Replaces _kdc_pk_mk_pa_reply().
 *
 * On success *out_pa_data / *out_pa_len are set to a malloc'd buffer
 * (caller frees) and reply_key is filled in.
 */
krb5_error_code
heimdal_pkinit_mk_pa_reply(krb5_context context,
                           krb5_kdc_configuration *config,
                           const void *params,
                           int nonce,
                           int enctype,
                           const unsigned char *as_req_data,
                           size_t as_req_len,
                           const char *client_name,
                           const char *server_name,
                           unsigned char **out_pa_data,
                           size_t *out_pa_len,
                           krb5_keyblock *reply_key);

/*
 * Authorize the client certificate for the requested principal.
 * Replaces _kdc_pk_check_client().
 *
 * princ_in_cert mirrors config->pkinit_princ_in_cert.
 *
 * is_client_anonymous_principal must be 1 only when the caller has
 * independently verified (via _kdc_is_anonymous(), not a string compare)
 * that the *requested* principal is the well-known anonymous principal or
 * that historical_anon_realm compatibility applies. This function has no
 * other way to enforce that a certless request is actually authorized for
 * anonymous PKINIT, so passing 1 unconditionally reintroduces a full
 * pre-authentication bypass.
 *
 * On success *out_subject is a malloc'd string (caller frees). *out_subject
 * is set to NULL on entry and only overwritten on success.
 *
 * On failure, if *out_reject_reason is non-NULL, it is a malloc'd
 * human-readable string describing why (caller frees); it may remain NULL
 * even on failure (e.g. allocation failure formatting the reason itself).
 */
krb5_error_code
heimdal_pkinit_check_client(const void *params,
                            const char *client_principal,
                            int princ_in_cert,
                            int is_client_anonymous_principal,
                            char **out_subject,
                            char **out_reject_reason);

/*
 * Free the opaque params allocated by heimdal_pkinit_rd_padata().
 * Replaces _kdc_pk_free_client_param().
 */
void
heimdal_pkinit_free_client_param(void *params);

/*
 * Return a static string naming the key-exchange algorithm negotiated
 * for this request (e.g. "ECDH-P256", "ML-KEM-768").
 * The returned pointer is valid until heimdal_pkinit_free_client_param().
 */
void
heimdal_pkinit_keyex_name(const void *params,
                          const char **out_name);

/*
 * Check whether the verified request is anonymous PKINIT.
 * Returns 1 if anonymous, 0 otherwise.
 */
int
heimdal_pkinit_is_anonymous(const void *params);

/*
 * Return the KEM algorithm hint for proactive advertisement.
 * The hint is a DER-encoded PA-PK-AS-REQ-Hint containing the KDC's
 * supported KEM algorithms.
 *
 * On success *out_data / *out_len are set to a malloc'd buffer
 * (caller frees).  If no KEM algorithms are configured, both are
 * set to NULL/0.
 */
void
heimdal_pkinit_get_hint(krb5_context context,
                        krb5_kdc_configuration *config,
                        unsigned char **out_data,
                        size_t *out_len);


/* ── Client side ───────────────────────────────────────────────────── */

/*
 * Create a new client PKINIT context.
 * Replaces the init path in _krb5_pk_set_user_id / _krb5_pk_load_id.
 *
 * identity    - e.g. "FILE:/path/to/cert.pem,/path/to/key.pem"
 * anchors     - NULL-terminated array of trust-anchor paths
 * anchors_len - number of entries in anchors[]
 * anonymous   - non-zero for anonymous PKINIT
 * server_principal - KDC principal for SAN checking, or NULL
 *
 * On success *out_ctx is an opaque handle for the other client calls.
 */
krb5_error_code
heimdal_pkinit_client_init(krb5_context context,
                           const char *identity,
                           const char * const *anchors,
                           size_t anchors_len,
                           int anonymous,
                           const char *server_principal,
                           void **out_ctx);

/*
 * Set the freshness token received from the KDC (PA-AS-FRESHNESS).
 */
void
heimdal_pkinit_client_set_freshness(void *ctx,
                                    const unsigned char *token,
                                    size_t token_len);

/*
 * Process a PA-PK-AS-REQ-Hint from the KDC (KEM algorithm advertisement).
 */
void
heimdal_pkinit_client_process_hint(void *ctx,
                                   const unsigned char *hint_data,
                                   size_t hint_len);

/*
 * Build the PA-PK-AS-REQ PA-DATA value.
 * Replaces _krb5_pk_mk_padata().
 *
 * On success *out_data / *out_len are set to a malloc'd buffer
 * (caller frees).
 */
krb5_error_code
heimdal_pkinit_client_mk_padata(void *ctx,
                                int nonce,
                                long long ctime,
                                int cusec,
                                const unsigned char *req_body_data,
                                size_t req_body_len,
                                unsigned char **out_data,
                                size_t *out_len);

/*
 * Process the KDC's PA-PK-AS-REP and derive the reply key.
 * Replaces _krb5_pk_rd_pa_reply().
 *
 * On success reply_key is filled in with the derived key.
 */
krb5_error_code
heimdal_pkinit_client_rd_pa_reply(krb5_context context,
                                  void *ctx,
                                  const unsigned char *pa_data,
                                  size_t pa_len,
                                  int nonce,
                                  int enctype,
                                  const unsigned char *as_req_data,
                                  size_t as_req_len,
                                  const char *client_name,
                                  const char *server_name,
                                  krb5_keyblock *reply_key);

/*
 * Handle a KDC error with retry hints (TD-DH-PARAMETERS, etc.).
 * Returns 0 if a retry is possible (context updated), error otherwise.
 */
krb5_error_code
heimdal_pkinit_client_tryagain(void *ctx,
                               const unsigned char *error_padata,
                               size_t error_padata_len);

/*
 * Free a client PKINIT context.
 */
void
heimdal_pkinit_client_free(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HEIMDAL_PKINIT_H */
