// Copyright (c) 2025 Red Hat, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// accompanying LICENSE file are met.

//! Heimdal PKINIT adapter — bridges `pkinit-core` to the Heimdal KDC and
//! client libraries.
//!
//! This crate is built as a `staticlib` and linked into Heimdal's `libkdc`
//! and `libkrb5`.  It exposes C-callable functions that replace the
//! existing C PKINIT implementation with the Rust `pkinit-core` library,
//! adding support for post-quantum key exchange via ML-KEM
//! (draft-bokovoy-kitten-pkinit-pqc).

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    unsafe_op_in_unsafe_fn,
    clippy::all
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod client;
mod config;
mod ffi;
mod kdc;
mod o2k;
mod trace;
