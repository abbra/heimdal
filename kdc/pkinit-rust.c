/*
 * Copyright (c) 2025 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the conditions in the
 * accompanying LICENSE file are met.
 *
 * PKINIT KDC shim for the Rust pkinit-core adapter.
 *
 * When compiled with PKINIT_RUST, this file provides thin wrappers
 * that bridge Heimdal's internal _kdc_pk_* API to the Rust FFI
 * functions in libheimdal_pkinit.a.  The original C pkinit.c is
 * still compiled (for Win2k paths and fallback), but the main
 * entry points are redirected here.
 */

#include "kdc_locl.h"

#ifdef PKINIT
#ifdef PKINIT_RUST

#include "heimdal_pkinit.h"

/*
 * This translation unit only needs to exist when PKINIT_RUST is
 * enabled.  It provides the glue between Heimdal's astgs_request_t
 * and the Rust FFI's opaque-pointer model.
 *
 * Currently the pa_pkinit_validate() function in kerberos5.c calls
 * the heimdal_pkinit_* functions directly (guarded by #ifdef
 * PKINIT_RUST).  This file is reserved for any additional KDC-side
 * helpers that may be needed, such as:
 *
 * - Encoding the KDC_REQ_BODY for req_body_der
 * - Building METHOD_DATA entries from the Rust PA-DATA output
 * - OCSP stapling integration
 */

#endif /* PKINIT_RUST */
#endif /* PKINIT */
