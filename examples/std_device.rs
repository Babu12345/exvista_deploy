//! A complete device on a std host: `ureq` for the transport, a directory for
//! the storage. This is the shape onlooker-rs and any Linux appliance would use;
//! it is an EXAMPLE, not part of the library, so that the library stays `no_std`
//! and every integrator chooses their own HTTP client and storage.
//!
//!     EXVISTA_DEPLOY_URL=… EXVISTA_DEPLOY_KEY=exd_… EXVISTA_DEPLOY_REPORT_URL=… \
//!         cargo run --example std_device -- ~/models/current
//!
//! Policy lives here, not in the crate: this example fails closed (any outcome
//! but a staged/current checkpoint exits non-zero), and it does not wait for
//! the network — a real appliance would retry transient errors for a while
//! before giving up (see `Error::is_transient`).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use exvista_deploy::Report;

use exvista_deploy::{
    Config, Current, Device, DownloadError, Error, Method, Request, Response, Storage, Sync,
    Transport, DEPLOYMENT_MARKER, FINGERPRINT_MARKER,
};

// ── transport: ureq ─────────────────────────────────────────────────────────

struct Ureq(ureq::Agent);

impl Transport for Ureq {
    type Error = String;

    fn exchange(&mut self, req: &Request) -> Result<Response, String> {
        let mut r = match req.method {
            Method::Get => self.0.get(&req.url),
            Method::Post => self.0.post(&req.url),
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
            .0
            .get(url)
            .timeout(Duration::from_secs(3600))
            .call()
            .map_err(|e| DownloadError::Transport(e.to_string()))?;
        let mut reader = resp.into_reader();
        let mut buf = vec![0u8; 256 * 1024];
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

struct Dir {
    dest: PathBuf,
    staging: PathBuf,
    file: Option<File>,
}

impl Dir {
    fn new(dest: impl Into<PathBuf>) -> Self {
        let dest: PathBuf = dest.into();
        let staging = dest.with_file_name(format!(
            "{}.staging",
            dest.file_name().and_then(|s| s.to_str()).unwrap_or("model")
        ));
        Self {
            dest,
            staging,
            file: None,
        }
    }

    fn intact(&self) -> bool {
        const WEIGHTS: &[&str] = &["safetensors", "bin", "pt", "pth", "gguf", "ckpt"];
        self.dest.join("config.json").is_file()
            && fs::read_dir(&self.dest).is_ok_and(|rd| {
                rd.flatten().any(|e| {
                    e.path()
                        .extension()
                        .and_then(|x| x.to_str())
                        .is_some_and(|x| WEIGHTS.contains(&x))
                })
            })
    }

    fn write_markers(&self, current: &Current) -> std::io::Result<()> {
        fs::write(self.dest.join(FINGERPRINT_MARKER), &current.fingerprint)?;
        fs::write(self.dest.join(DEPLOYMENT_MARKER), &current.deployment_id)
    }
}

fn io<T>(r: std::io::Result<T>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}

/// A zip that wraps the checkpoint in one top-level directory (common for
/// uploads) should still land with `config.json` at the root.
fn single_subdir_or(path: &Path) -> PathBuf {
    let entries: Vec<_> = fs::read_dir(path).into_iter().flatten().flatten().collect();
    match entries.as_slice() {
        [only] if only.path().is_dir() => only.path(),
        _ => path.to_path_buf(),
    }
}

impl Storage for Dir {
    type Error = String;

    fn current(&mut self) -> Result<Option<Current>, String> {
        if !self.intact() {
            return Ok(None);
        }
        let fingerprint =
            fs::read_to_string(self.dest.join(FINGERPRINT_MARKER)).unwrap_or_default();
        let deployment_id =
            fs::read_to_string(self.dest.join(DEPLOYMENT_MARKER)).unwrap_or_default();
        if fingerprint.trim().is_empty() {
            return Ok(None);
        }
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
        let previous = self.dest.with_file_name(format!(
            "{}.previous",
            self.dest
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("model")
        ));
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

// ── policy: fail closed ─────────────────────────────────────────────────────

fn main() {
    let dest = std::env::args().nth(1).unwrap_or_else(|| "./model".into());
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let (Some(url), Some(key)) = (env("EXVISTA_DEPLOY_URL"), env("EXVISTA_DEPLOY_KEY")) else {
        eprintln!("set EXVISTA_DEPLOY_URL and EXVISTA_DEPLOY_KEY");
        std::process::exit(2);
    };
    let mut config = Config::new(url, key);
    if let Some(r) = env("EXVISTA_DEPLOY_REPORT_URL") {
        config = config.with_report_url(r);
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(60))
        .build();
    let mut device = Device::new(config, Ureq(agent), Dir::new(&dest));

    let current = match device.sync() {
        Ok(Sync::Current(c)) => {
            println!(
                "current: {} (deployment {}) at {dest}",
                c.fingerprint, c.deployment_id
            );
            c
        }
        Ok(Sync::Staged(c)) => {
            println!(
                "staged:  {} (deployment {}) at {dest}",
                c.fingerprint, c.deployment_id
            );
            c
        }
        Ok(Sync::Nothing) => {
            eprintln!("refused: ExVista serves this device nothing");
            std::process::exit(3);
        }
        Ok(Sync::NoArtifact(served)) => {
            eprintln!("deployment {} carries no artifact", served.deployment_id);
            std::process::exit(3);
        }
        Err(e) => {
            let transient = e.is_transient();
            eprintln!(
                "{e}{}",
                if transient {
                    " (transient — a real appliance would retry)"
                } else {
                    ""
                }
            );
            std::process::exit(if transient { 4 } else { 5 });
        }
    };

    // Here is where you would load the model. Then:
    if device.config().report_url.is_some() {
        match device.report(&Report::Loaded, Some(&current)) {
            Ok(()) => println!("reported loaded"),
            Err(e) => eprintln!("report failed: {e}"),
        }
    }
    let _: Result<(), Error<String, String>> = Ok(()); // keeps the Error type in scope for readers
}
