//! Reusable TCP and generator implementations built on the generic Wabrix API.
//!
//! Plugins that only need packet, mailbox, or shared-state APIs can depend on
//! `wabrix_api` directly.

#![no_std]

extern crate alloc;

pub mod connections;
pub mod engine_common;
pub mod tcp_common;
