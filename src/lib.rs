//! SEC-01 integration prototype. External security review is pending.
pub const SUITE: &str = "SPORA_LIBSIGNAL_0_108_V1";
mod client;
mod model;
mod provider;
mod signal;
mod vault;
pub use client::{Client, Prepared, Status};
pub mod transport;
pub use model::{Device, Invitation, InvitationBody, LocalMessage, Outgoing, SecureRoute};
#[cfg(test)]
mod crypto_tests;

mod retention;
mod storage;
