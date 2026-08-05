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
 * Tracing bridge: the Rust library calls this function pointer to
 * log messages.  kdc_log() is a variadic function in libkdc, so
 * we provide a simplified wrapper that takes a pre-formatted string.
 */
void
pkinit_rust_trace(krb5_context ctx,
		  krb5_kdc_configuration *config,
		  int level,
		  const char *msg)
{
    kdc_log(ctx, config, level, "%s", msg);
}

/*
 * Called from heimdal_pkinit_initialize() FFI to register the trace
 * callback.  The Rust side stores this as a function pointer.
 */
extern void heimdal_pkinit_set_trace(void (*fn)(krb5_context,
					     krb5_kdc_configuration *,
					     int, const char *));

#endif /* PKINIT_RUST */
#endif /* PKINIT */
