use crate::contract::{Request, Response};

/// Why a streamed download stopped early.
#[derive(Debug)]
pub enum DownloadError<E> {
    /// Your transport failed (connection dropped, TLS, timeout, …).
    Transport(E),
    /// The sink returned `Err(())`: the crate found a problem in the bytes
    /// (bad archive, storage failure) and asked you to stop. Return this and the
    /// crate will surface the real cause.
    Aborted,
}

/// Your HTTP(S) client. Two operations, both blocking:
///
/// - [`exchange`](Transport::exchange): a small request with a small response
///   (the pull and the report — a few KB of JSON). Return **every** HTTP status
///   as `Ok(Response)`; the crate decides what 401 / 404 / 409 / 5xx mean. Only
///   return `Err` when no HTTP response was obtained at all.
/// - [`download`](Transport::download): a plain `GET` of a presigned URL (no
///   auth header — the signature is in the URL), streamed to `sink` in chunks
///   of whatever size is natural for you. Artifacts can be gigabytes; never
///   buffer the whole body.
///
/// A device that boots before its clock is set will fail TLS with "certificate
/// not yet valid"; that is a transport error and the crate treats it as
/// transient, so your policy can wait for time sync and retry.
pub trait Transport {
    /// Your error type (shown in logs via `Display`).
    type Error;

    /// Perform `req` and return the status + body, whatever the status.
    fn exchange(&mut self, req: &Request) -> Result<Response, Self::Error>;

    /// `GET url` and feed the body to `sink` as it arrives. Stop and return
    /// [`DownloadError::Aborted`] as soon as the sink returns `Err(())`.
    fn download(
        &mut self,
        url: &str,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    ) -> Result<(), DownloadError<Self::Error>>;
}

/// Where the checkpoint lives on your device, with the one property that makes
/// the gate honest: **nothing becomes current until [`commit`](Storage::commit)**.
///
/// The crate drives it like a transaction:
///
/// ```text
/// current()  → what is staged now (from your markers), if anything
/// begin()    → open a fresh staging area (discard any half-finished one)
///   begin_entry("config.json") · write(..) · write(..) · end_entry()
///   begin_entry("model.safetensors") · write(..) … · end_entry()
/// commit(&current) → the staged tree becomes THE checkpoint; record the markers
///      — or —
/// abort()    → drop the staging area; whatever was current stays current
/// ```
///
/// On a Linux host that is a sibling directory renamed into place plus two marker
/// files ([`FINGERPRINT_MARKER`](crate::FINGERPRINT_MARKER) /
/// [`DEPLOYMENT_MARKER`](crate::DEPLOYMENT_MARKER) — use those names and a
/// directory staged by ExVista's Python client reads as current to yours). On a
/// microcontroller it might be two flash slots and a boot record.
///
/// Entry paths are relative, forward-slash separated, already checked by the
/// crate for `..` and absolute prefixes. A zip that wraps the checkpoint in one
/// top-level directory is common (uploads); promote it at commit time if your
/// loader wants `config.json` at the root.
pub trait Storage {
    /// Your error type (shown in logs via `Display`).
    type Error;

    /// The staged checkpoint's fingerprint + deployment id, or `None` when
    /// nothing (or nothing intact) is staged. "Intact" is yours to define — at
    /// least "the files the marker vouches for are really there".
    fn current(&mut self) -> Result<Option<crate::Current>, Self::Error>;

    /// Open a fresh staging area.
    fn begin(&mut self) -> Result<(), Self::Error>;
    /// Start writing the entry at `rel_path` (create parent directories as needed).
    fn begin_entry(&mut self, rel_path: &str) -> Result<(), Self::Error>;
    /// Append bytes to the open entry.
    fn write(&mut self, chunk: &[u8]) -> Result<(), Self::Error>;
    /// The open entry is complete.
    fn end_entry(&mut self) -> Result<(), Self::Error>;
    /// Every artifact verified: make the staging area current and record `current`.
    fn commit(&mut self, current: &crate::Current) -> Result<(), Self::Error>;
    /// Discard the staging area. Must be safe to call at any point after `begin`.
    fn abort(&mut self) -> Result<(), Self::Error>;
    /// Update the markers WITHOUT touching the checkpoint: the same bytes were
    /// redeployed under a new deployment id, and the id you report on load
    /// should be the one ExVista is serving now.
    fn record(&mut self, current: &crate::Current) -> Result<(), Self::Error>;
}
