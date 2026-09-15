//! Device-side client for ExVista model deployments — the bare contract, `no_std`.
//!
//! ExVista scans a model for backdoors, fingerprints it, gates it, and serves it to
//! the devices a deployment targets. This crate is the device's half of that
//! contract (see `DEPLOY_FRAMEWORK.md` in the ExVista repo), and nothing more:
//!
//! 1. **pull** — ask what this device is cleared to run (`POST` the pull URL with
//!    the device key); `404` means *nothing*, and the gate is why.
//! 2. **compare** — if the staged fingerprint is the served one, stop.
//! 3. **download + verify** — stream each artifact, SHA-256 it as it arrives,
//!    unzip it on the fly into your storage.
//! 4. **commit** — only after the hash matched; otherwise abort and keep what you had.
//! 5. **report** — tell ExVista what you loaded, so provenance shows it serving.
//!
//! What this crate does **not** do is talk to a network or a filesystem. You
//! implement two small traits — [`Transport`] (an HTTPS request/response and a
//! streamed GET) and [`Storage`] (a staging area with begin / write / commit /
//! abort semantics) — on whatever your platform has: `ureq` + `std::fs` on a
//! Linux box, `reqwless` + littlefs on a microcontroller, a vendor SDK on
//! anything else. Everything the crate decides — what a response means, whether
//! the bytes are intact, when it is safe to commit, what to retry — is the same
//! on every target. Your **policy** (fail closed? how long to wait for the
//! network? what to do on refusal?) goes on top of [`Device`].
//!
//! ```ignore
//! let mut device = Device::new(config, my_transport, my_storage);
//! match device.sync()? {
//!     Sync::Nothing            => refuse_to_start(),          // gate served nothing
//!     Sync::Current(c)         => start(&c),                  // same bytes already staged
//!     Sync::Staged(c)          => start(&c),                  // downloaded + verified + committed
//!     Sync::NoArtifact(served) => resolve_yourself(&served),  // deployment carries no files
//! }
//! device.report("loaded", Some(&current))?;
//! ```
//!
//! Two things every integrator must get right and this crate cannot do for them:
//! **TLS needs a correct clock** (certificate validity — a device that boots at
//! 1970 must sync time before its first pull), and **the device key is the only
//! secret** — keep it out of logs.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod contract;
mod device;
mod error;
mod traits;
mod verify;
mod zipstream;

pub use contract::{
    parse_pull_response, Artifact, Config, Current, Method, Request, Response, Served,
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
