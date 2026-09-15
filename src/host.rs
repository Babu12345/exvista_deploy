//! Batteries for a std host (feature `std`, on by default): an HTTP transport on
//! `ureq`, a directory storage with an atomic swap, and configuration from the
//! environment or an env file. Use them as they are, or as the reference for
//! your own [`Transport`] / [`Storage`].

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::contract::{Config, Current, Method, Request, Response};
use crate::traits::{DownloadError, Storage, Transport};
use crate::{DEPLOYMENT_MARKER, FINGERPRINT_MARKER};

// ── configuration ───────────────────────────────────────────────────────────

impl Config {
    /// From `EXVISTA_DEPLOY_URL`, `EXVISTA_DEPLOY_KEY` and (optionally)
    /// `EXVISTA_DEPLOY_REPORT_URL`. `None` unless both required variables are set.
    pub fn from_env() -> Option<Self> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let mut c = Self::new(env("EXVISTA_DEPLOY_URL")?, env("EXVISTA_DEPLOY_KEY")?);
        if let Some(r) = env("EXVISTA_DEPLOY_REPORT_URL") {
            c = c.with_report_url(r);
        }
        Some(c)
    }

    /// From a `KEY=VALUE` file holding the same three variables (`export`
    /// prefixes, quotes and `#` comments tolerated). `Ok(None)` when the file
    /// does not contain both required keys; `Err` only when it cannot be read.
    pub fn from_env_file(path: impl AsRef<Path>) -> std::io::Result<Option<Self>> {
        let text = fs::read_to_string(path)?;
        Ok(Self::parse_env_text(&text))
    }

    /// The usual order for an appliance: the environment wins, else the env
    /// file; `None` means this device is not enrolled.
    pub fn discover(env_file: impl AsRef<Path>) -> Option<Self> {
        Self::from_env().or_else(|| Self::from_env_file(env_file).ok().flatten())
    }
}

// ── transport: ureq ─────────────────────────────────────────────────────────

/// [`Transport`] on a `ureq` agent. Every HTTP status comes back as a
/// [`Response`]; only a failure to get any response at all is an error.
pub struct UreqTransport {
    agent: ureq::Agent,
    download_timeout: Duration,
    chunk: usize,
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new(
            ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(15))
                .timeout_read(Duration::from_secs(60))
                .build(),
        )
    }
}

impl UreqTransport {
    /// Use your own agent (proxies, TLS settings, timeouts).
    pub fn new(agent: ureq::Agent) -> Self {
        Self {
            agent,
            download_timeout: Duration::from_secs(3600),
            chunk: 256 * 1024,
        }
    }

    /// Overall timeout for one artifact download (default one hour — artifacts
    /// can be gigabytes on a slow link).
    pub fn with_download_timeout(mut self, timeout: Duration) -> Self {
        self.download_timeout = timeout;
        self
    }
}

impl Transport for UreqTransport {
    type Error = String;

    fn exchange(&mut self, req: &Request) -> Result<Response, String> {
        let mut r = match req.method {
            Method::Get => self.agent.get(&req.url),
            Method::Post => self.agent.post(&req.url),
        };
        for (k, v) in &req.headers {
            r = r.set(k, v);
        }
        match r.send_bytes(&req.body) {
            Ok(resp) | Err(ureq::Error::Status(_, resp)) => {
                let status = resp.status();
                let mut body = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut body)
                    .map_err(|e| e.to_string())?;
                Ok(Response { status, body })
            }
            Err(ureq::Error::Transport(t)) => Err(t.to_string()),
        }
    }

    fn download(
        &mut self,
        url: &str,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    ) -> Result<(), DownloadError<String>> {
        let resp = self
            .agent
            .get(url)
            .timeout(self.download_timeout)
            .call()
            .map_err(|e| DownloadError::Transport(e.to_string()))?;
        let mut reader = resp.into_reader();
        let mut buf = vec![0u8; self.chunk];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| DownloadError::Transport(e.to_string()))?;
            if n == 0 {
                return Ok(());
            }
            if sink(&buf[..n]).is_err() {
                return Err(DownloadError::Aborted);
            }
        }
    }
}

// ── storage: a directory, swapped in atomically ─────────────────────────────

/// Weight-file extensions a Hugging-Face-style checkpoint can carry.
pub const WEIGHT_EXTENSIONS: &[&str] = &["safetensors", "bin", "pt", "pth", "gguf", "ckpt"];

/// The default "is there really a checkpoint here" rule: `config.json` plus at
/// least one weights file at the top level. A fingerprint marker with nothing
/// behind it must never read as current.
pub fn checkpoint_present(dir: &Path) -> bool {
    dir.join("config.json").is_file()
        && fs::read_dir(dir).is_ok_and(|rd| {
            rd.flatten().any(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| WEIGHT_EXTENSIONS.contains(&x))
            })
        })
}

/// [`Storage`] as a directory. Entries are written to a `<dest>.staging`
/// sibling; `commit` renames it into place, keeping the previous checkpoint as
/// `<dest>.previous` until the rename succeeded, then writes the marker files.
/// A zip that wraps everything in one top-level directory is promoted so
/// `config.json` lands at the root.
pub struct DirStorage {
    dest: PathBuf,
    staging: PathBuf,
    file: Option<File>,
    intact: fn(&Path) -> bool,
}

fn sibling(dest: &Path, suffix: &str) -> PathBuf {
    dest.with_file_name(format!(
        "{}.{suffix}",
        dest.file_name().and_then(|s| s.to_str()).unwrap_or("model")
    ))
}

fn io<T>(r: std::io::Result<T>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}

fn single_subdir_or(path: &Path) -> PathBuf {
    let entries: Vec<_> = fs::read_dir(path).into_iter().flatten().flatten().collect();
    match entries.as_slice() {
        [only] if only.path().is_dir() => only.path(),
        _ => path.to_path_buf(),
    }
}

impl DirStorage {
    /// Stage into `dest` (created on first commit).
    pub fn new(dest: impl Into<PathBuf>) -> Self {
        let dest: PathBuf = dest.into();
        let staging = sibling(&dest, "staging");
        Self {
            dest,
            staging,
            file: None,
            intact: checkpoint_present,
        }
    }

    /// Replace the "is there really something here" rule (default:
    /// [`checkpoint_present`]) for artifacts that are not HF-style checkpoints.
    pub fn with_intact_check(mut self, check: fn(&Path) -> bool) -> Self {
        self.intact = check;
        self
    }

    /// The checkpoint directory.
    pub fn dest(&self) -> &Path {
        &self.dest
    }

    fn write_markers(&self, current: &Current) -> std::io::Result<()> {
        fs::write(self.dest.join(FINGERPRINT_MARKER), &current.fingerprint)?;
        fs::write(self.dest.join(DEPLOYMENT_MARKER), &current.deployment_id)
    }
}

impl Storage for DirStorage {
    type Error = String;

    fn current(&mut self) -> Result<Option<Current>, String> {
        if !(self.intact)(&self.dest) {
            return Ok(None);
        }
        let fingerprint =
            fs::read_to_string(self.dest.join(FINGERPRINT_MARKER)).unwrap_or_default();
        if fingerprint.trim().is_empty() {
            return Ok(None);
        }
        let deployment_id =
            fs::read_to_string(self.dest.join(DEPLOYMENT_MARKER)).unwrap_or_default();
        Ok(Some(Current {
            fingerprint: fingerprint.trim().into(),
            deployment_id: deployment_id.trim().into(),
        }))
    }

    fn begin(&mut self) -> Result<(), String> {
        let _ = fs::remove_dir_all(&self.staging);
        io(fs::create_dir_all(&self.staging))
    }

    fn begin_entry(&mut self, rel_path: &str) -> Result<(), String> {
        let path = self.staging.join(rel_path);
        if let Some(parent) = path.parent() {
            io(fs::create_dir_all(parent))?;
        }
        self.file = Some(io(File::create(path))?);
        Ok(())
    }

    fn write(&mut self, chunk: &[u8]) -> Result<(), String> {
        io(self.file.as_mut().ok_or("no open entry")?.write_all(chunk))
    }

    fn end_entry(&mut self) -> Result<(), String> {
        if let Some(f) = self.file.take() {
            io(f.sync_all())?;
        }
        Ok(())
    }

    fn commit(&mut self, current: &Current) -> Result<(), String> {
        let payload = single_subdir_or(&self.staging);
        let previous = sibling(&self.dest, "previous");
        let _ = fs::remove_dir_all(&previous);
        if let Some(parent) = self.dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let had_previous = self.dest.exists();
        if had_previous {
            io(fs::rename(&self.dest, &previous))?;
        }
        if let Err(e) = fs::rename(&payload, &self.dest) {
            if had_previous {
                let _ = fs::rename(&previous, &self.dest); // put the old one back
            }
            return Err(e.to_string());
        }
        let _ = fs::remove_dir_all(&previous);
        let _ = fs::remove_dir_all(&self.staging);
        io(self.write_markers(current))
    }

    fn abort(&mut self) -> Result<(), String> {
        self.file = None;
        let _ = fs::remove_dir_all(&self.staging);
        Ok(())
    }

    fn record(&mut self, current: &Current) -> Result<(), String> {
        io(self.write_markers(current))
    }
}
