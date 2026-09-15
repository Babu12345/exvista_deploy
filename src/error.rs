use alloc::string::String;
use core::fmt;

/// Everything that can go wrong, classified so a policy can act on it without
/// parsing strings. `T` and `S` are your transport's and storage's own error types.
#[derive(Debug)]
pub enum Error<T, S> {
    /// The [`Config`](crate::Config) is missing something (a report URL, say).
    Config(&'static str),
    /// ExVista rejected the device key (401/403): revoked, rotated, or wrong.
    /// Not transient — retrying will not help.
    Unauthorized {
        /// HTTP status.
        status: u16,
        /// Response body, for the log.
        body: String,
    },
    /// The device exists but is not attached to a project yet (409).
    NotProvisioned(String),
    /// Any other 4xx: the request was understood and refused.
    Rejected {
        /// HTTP status.
        status: u16,
        /// Response body, for the log.
        body: String,
    },
    /// A 5xx from ExVista. Transient.
    Server {
        /// HTTP status.
        status: u16,
        /// Response body, for the log.
        body: String,
    },
    /// Your transport could not complete the request (no network, DNS, TLS, a
    /// clock that has not synced). Treated as transient.
    Transport(T),
    /// Your storage failed. Not retried by this crate.
    Storage(S),
    /// The response was not the JSON the contract promises.
    Malformed(String),
    /// A downloaded artifact's SHA-256 did not match the manifest. Storage was
    /// aborted; whatever was current before is still current.
    Integrity {
        /// The artifact's `relPath`.
        path: String,
        /// The SHA-256 the manifest promised.
        want: String,
        /// The SHA-256 the bytes had.
        got: String,
    },
    /// The artifact zip is not something a streaming extractor can take apart —
    /// or an entry tried to escape its directory.
    Archive(String),
    /// The served deployment carries no files (ExVista could not package it);
    /// the device would have to resolve the model itself and verify it against
    /// the fingerprint. This crate refuses to guess.
    NoArtifact {
        /// The deployment in question.
        deployment_id: String,
    },
}

impl<T, S> Error<T, S> {
    /// Worth another try shortly: the network/TLS layer failed, or ExVista
    /// answered 5xx. Everything else is a decision, not a hiccup.
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Transport(_) | Error::Server { .. })
    }
}

impl<T: fmt::Display, S: fmt::Display> fmt::Display for Error<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(what) => write!(f, "configuration: {what}"),
            Error::Unauthorized { status, body } => {
                write!(f, "device key rejected (HTTP {status}): {body}")
            }
            Error::NotProvisioned(body) => write!(f, "device not provisioned (HTTP 409): {body}"),
            Error::Rejected { status, body } => write!(f, "refused (HTTP {status}): {body}"),
            Error::Server { status, body } => write!(f, "server error (HTTP {status}): {body}"),
            Error::Transport(e) => write!(f, "transport: {e}"),
            Error::Storage(e) => write!(f, "storage: {e}"),
            Error::Malformed(what) => write!(f, "malformed response: {what}"),
            Error::Integrity { path, want, got } => {
                write!(f, "integrity: {path} sha256 want {want} got {got}")
            }
            Error::Archive(what) => write!(f, "archive: {what}"),
            Error::NoArtifact { deployment_id } => {
                write!(f, "deployment {deployment_id} carries no artifact to stage")
            }
        }
    }
}

impl<T: fmt::Debug + fmt::Display, S: fmt::Debug + fmt::Display> core::error::Error
    for Error<T, S>
{
}
