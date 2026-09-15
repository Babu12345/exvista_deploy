//! Device-side client for ExVista model deployments.
//!
//! ExVista scans a model for backdoors, fingerprints it, gates it, and serves it to
//! the devices a deployment targets. This crate is the device's half of that
//! contract (see `DEPLOY_FRAMEWORK.md` in the ExVista repo):
//!
//! 1. **pull** — ask what this device is cleared to run (`POST` the pull URL with
//!    the device key); `404` means *nothing*, and the gate is why.
//! 2. **compare** — if the staged fingerprint is the served one, stop.
//! 3. **download + verify** — stream each artifact, SHA-256 it as it arrives,
//!    unzip it on the fly into storage.
//! 4. **commit** — only after the hash matched; otherwise abort and keep what you had.
//! 5. **report** — tell ExVista what you loaded, so provenance shows it serving.
//!
//! # On a std host: batteries included
//!
//! With the default `std` feature the crate brings its own HTTP transport
//! ([`host::UreqTransport`]) and a directory storage with an atomic swap
//! ([`host::DirStorage`]), and reads the device's configuration from the
//! environment or an env file. A Linux appliance is a few lines:
//!
//! ```no_run
//! # #[cfg(not(feature = "std"))] fn main() {}
//! # #[cfg(feature = "std")] fn main() {
//! use exvista_deploy::{host::{DirStorage, UreqTransport}, Config, Device, Report, Sync};
//!
//! let config = Config::discover("/etc/exvista/device.env").expect("not enrolled");
//! let mut device = Device::new(config, UreqTransport::default(), DirStorage::new("/opt/model"));
//! let current = match device.sync() {
//!     Ok(Sync::Current(c)) | Ok(Sync::Staged(c)) => c,   // verified checkpoint at /opt/model
//!     Ok(Sync::Nothing) => std::process::exit(3),        // the gate served nothing
//!     Ok(Sync::NoArtifact(_)) => std::process::exit(3),
//!     Err(e) => std::process::exit(if e.is_transient() { 4 } else { 5 }),
//! };
//! // … load the model from /opt/model …
//! device.report(&Report::Loaded, Some(&current)).ok();
//! # }
//! ```
//!
//! # Everywhere else: `no_std`, bring your own
//!
//! With `default-features = false` the crate is `no_std + alloc` and contains no
//! networking or filesystem code. You implement two small traits — [`Transport`]
//! (one request/response, one streamed GET) and [`Storage`] (a staging area with
//! begin / write / commit / abort semantics) — on whatever your platform has:
//! `reqwless` + littlefs on a microcontroller, a vendor SDK, anything. See
//! `examples/embedded_traits.rs` for the shape. Everything the crate decides —
//! what a response means, whether the bytes are intact, when it is safe to
//! commit, what to retry — is identical on every target.
//!
//! # Policy is yours
//!
//! [`Device::sync`] never starts anything and never waits. Fail closed or open,
//! how long to retry a transient error after a cold boot ([`Error::is_transient`]),
//! what `NoArtifact` means — that is a few dozen lines on top, and it belongs to
//! the integrator. Two things every integrator must get right: **TLS needs a
//! correct clock** (a device that boots at 1970 must sync time before its first
//! pull), and **the device key is the only secret** — keep it out of logs.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod contract;
mod device;
mod error;
#[cfg(feature = "std")]
pub mod host;
mod traits;
mod verify;
mod zipstream;

pub use contract::{
    parse_pull_response, Artifact, Config, Current, GateStatus, Method, Report, Request, Response,
    Served, Verdict,
};
pub use device::{Device, Sync};
pub use error::Error;
pub use traits::{DownloadError, Storage, Transport};
pub use verify::Sha256Verifier;
pub use zipstream::{ZipError, ZipStream};

/// Where a device records the fingerprint of the checkpoint it has staged — the
/// name every ExVista client uses, so a directory staged by one client reads as
/// current to another.
pub const FINGERPRINT_MARKER: &str = ".exvista-fingerprint";
/// Where a device records which deployment the staged checkpoint came from.
pub const DEPLOYMENT_MARKER: &str = ".exvista-deployment";
