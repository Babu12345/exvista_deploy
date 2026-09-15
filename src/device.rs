//! The device algorithm over your [`Transport`] and [`Storage`].

use alloc::format;
use alloc::string::String;

use crate::contract::{
    parse_pull_response, pull_request, report_request, Artifact, Config, Current, Served,
};
use crate::error::Error;
use crate::traits::{DownloadError, Storage, Transport};
use crate::verify::{same_digest, Sha256Verifier};
use crate::zipstream::{check_rel_path, ZipError, ZipStream};

/// What a [`Device::sync`] found.
#[derive(Debug)]
pub enum Sync {
    /// ExVista serves this device nothing: no READY deployment matches it, or
    /// the candidates are BLOCKED. The gate said no.
    Nothing,
    /// The staged checkpoint already is the served one (same fingerprint). No
    /// download happened; the deployment marker was refreshed if the same bytes
    /// were redeployed under a new id.
    Current(Current),
    /// A new deployment was downloaded, verified, and committed.
    Staged(Current),
    /// The served deployment carries no files. Nothing was staged; the
    /// integrator decides whether to resolve the model itself.
    NoArtifact(Served),
}

/// A device: configuration + your transport + your storage.
pub struct Device<T: Transport, S: Storage> {
    config: Config,
    transport: T,
    storage: S,
}

type DevResult<T, S, V> = Result<V, Error<<T as Transport>::Error, <S as Storage>::Error>>;

impl<T: Transport, S: Storage> Device<T, S> {
    /// Assemble a device.
    pub fn new(config: Config, transport: T, storage: S) -> Self {
        Self {
            config,
            transport,
            storage,
        }
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Your transport, for whatever else you need it for.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Your storage.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    /// Take the parts back.
    pub fn into_parts(self) -> (Config, T, S) {
        (self.config, self.transport, self.storage)
    }

    /// Step 1: ask ExVista what this device is cleared to run.
    ///
    /// `Ok(None)` is a `404`: nothing is assigned, or the only candidates are
    /// blocked — ExVista does not say which, on purpose.
    pub fn pull(&mut self) -> DevResult<T, S, Option<Served>> {
        let req = pull_request(&self.config);
        let resp = self.transport.exchange(&req).map_err(Error::Transport)?;
        match resp.status {
            200 => parse_pull_response(&resp.body)
                .map(Some)
                .map_err(Error::Malformed),
            404 => Ok(None),
            401 | 403 => Err(Error::Unauthorized {
                status: resp.status,
                body: resp.body_text(),
            }),
            409 => Err(Error::NotProvisioned(resp.body_text())),
            500..=599 => Err(Error::Server {
                status: resp.status,
                body: resp.body_text(),
            }),
            other => Err(Error::Rejected {
                status: other,
                body: resp.body_text(),
            }),
        }
    }

    /// Steps 1–4: pull, compare with what is staged, download + verify +
    /// commit if it differs. Never starts anything; it only leaves your storage
    /// holding a verified checkpoint (or untouched) and tells you which.
    pub fn sync(&mut self) -> DevResult<T, S, Sync> {
        let served = match self.pull()? {
            None => return Ok(Sync::Nothing),
            Some(s) => s,
        };
        if !served.fingerprint.is_empty() {
            if let Some(have) = self.storage.current().map_err(Error::Storage)? {
                if same_digest(&have.fingerprint, &served.fingerprint) {
                    let current = Current {
                        fingerprint: served.fingerprint.clone(),
                        deployment_id: served.deployment_id.clone(),
                    };
                    if have.deployment_id != current.deployment_id {
                        self.storage.record(&current).map_err(Error::Storage)?;
                    }
                    return Ok(Sync::Current(current));
                }
            }
        }
        if served.files.is_empty() {
            return Ok(Sync::NoArtifact(served));
        }
        self.stage(&served).map(Sync::Staged)
    }

    /// Steps 3–4 for a deployment you already pulled: download every artifact
    /// into a fresh staging area, verifying each one's SHA-256 as it streams
    /// and unzipping `.zip` artifacts on the fly, then commit. Any failure
    /// aborts the staging area and leaves what was current in place.
    pub fn stage(&mut self, served: &Served) -> DevResult<T, S, Current> {
        if served.files.is_empty() {
            return Err(Error::NoArtifact {
                deployment_id: served.deployment_id.clone(),
            });
        }
        self.storage.begin().map_err(Error::Storage)?;
        for artifact in &served.files {
            if let Err(e) = self.stage_artifact(artifact) {
                // Best effort: the original error is the one worth reporting.
                let _ = self.storage.abort();
                return Err(e);
            }
        }
        let current = Current {
            fingerprint: served.fingerprint.clone(),
            deployment_id: served.deployment_id.clone(),
        };
        self.storage.commit(&current).map_err(Error::Storage)?;
        Ok(current)
    }

    fn stage_artifact(&mut self, artifact: &Artifact) -> DevResult<T, S, ()> {
        check_rel_path(&artifact.rel_path)
            .map_err(|p| Error::Archive(format!("unsafe artifact path {p:?}")))?;
        let is_zip = artifact.rel_path.len() >= 4
            && artifact.rel_path[artifact.rel_path.len() - 4..].eq_ignore_ascii_case(".zip");

        let mut hasher = Sha256Verifier::new();
        let mut failure: Option<Error<T::Error, S::Error>> = None;

        if is_zip {
            let mut zip = ZipStream::new(&mut self.storage);
            let outcome = self.transport.download(&artifact.url, &mut |chunk| {
                hasher.update(chunk);
                zip.push(chunk).map_err(|e| {
                    failure = Some(map_zip(e));
                })
            });
            match outcome {
                Ok(()) => {}
                Err(DownloadError::Aborted) => {
                    return Err(failure.take().unwrap_or_else(|| {
                        Error::Malformed(String::from("download aborted without a cause"))
                    }))
                }
                Err(DownloadError::Transport(e)) => return Err(Error::Transport(e)),
            }
            let entries = zip.finish().map_err(map_zip)?;
            if entries == 0 {
                // The 22-byte empty zip: a "checkpoint" with no files in it.
                return Err(Error::Archive(format!(
                    "{} contains no files",
                    artifact.rel_path
                )));
            }
        } else {
            self.storage
                .begin_entry(&artifact.rel_path)
                .map_err(Error::Storage)?;
            let storage = &mut self.storage;
            let outcome = self.transport.download(&artifact.url, &mut |chunk| {
                hasher.update(chunk);
                storage.write(chunk).map_err(|e| {
                    failure = Some(Error::Storage(e));
                })
            });
            match outcome {
                Ok(()) => {}
                Err(DownloadError::Aborted) => {
                    return Err(failure.take().unwrap_or_else(|| {
                        Error::Malformed(String::from("download aborted without a cause"))
                    }))
                }
                Err(DownloadError::Transport(e)) => return Err(Error::Transport(e)),
            }
            self.storage.end_entry().map_err(Error::Storage)?;
        }

        if let Some(want) = &artifact.sha256 {
            let got = hasher.finish();
            if !same_digest(want, &got) {
                return Err(Error::Integrity {
                    path: artifact.rel_path.clone(),
                    want: want.clone(),
                    got,
                });
            }
        }
        Ok(())
    }

    /// Step 5: tell ExVista what this device did. `status` is free text that
    /// ExVista classifies (`"loaded"` → LOADED, anything with `error`/`fail` →
    /// ERROR, else a heartbeat). Pass the [`Current`] you are running so the
    /// provenance row names the model.
    pub fn report(&mut self, status: &str, current: Option<&Current>) -> DevResult<T, S, ()> {
        let url = self
            .config
            .report_url
            .clone()
            .ok_or(Error::Config("report_url is not set"))?;
        let req = report_request(&self.config, &url, status, current);
        let resp = self.transport.exchange(&req).map_err(Error::Transport)?;
        match resp.status {
            200..=299 => Ok(()),
            401 | 403 => Err(Error::Unauthorized {
                status: resp.status,
                body: resp.body_text(),
            }),
            500..=599 => Err(Error::Server {
                status: resp.status,
                body: resp.body_text(),
            }),
            other => Err(Error::Rejected {
                status: other,
                body: resp.body_text(),
            }),
        }
    }
}

fn map_zip<T, S>(e: ZipError<S>) -> Error<T, S> {
    match e {
        ZipError::Storage(s) => Error::Storage(s),
        ZipError::Archive(m) => Error::Archive(m),
        ZipError::UnsafeEntry(n) => Error::Archive(format!("unsafe entry {n:?}")),
    }
}
