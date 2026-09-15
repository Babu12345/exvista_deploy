//! The shape of a `no_std` integration: implement `Transport` and `Storage` on
//! your platform's primitives. The crate core never touches a network or a
//! filesystem, so on a microcontroller these two impls are the whole port.
//!
//! This file builds and runs on a host (`cargo run --example embedded_traits`)
//! so the shape can be read and stepped through, but the two impls use only
//! `core` + `alloc` types — every `// PLATFORM:` line marks where your HAL /
//! TLS stack / flash driver goes. Here they are backed by in-memory fakes that
//! script a pull answer and a small artifact, which is exactly how the crate's
//! own tests drive it.
//!
//! Build the real thing with `default-features = false`:
//!
//!     exvista_deploy = { version = "0.2", default-features = false }

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

extern crate alloc;

use exvista_deploy::{
    Config, Current, Device, DownloadError, Report, Request, Response, Storage, Sync, Transport,
};

// ── Transport: one small exchange, one streamed GET ─────────────────────────

struct MyTransport {
    // PLATFORM: your TLS-capable HTTP client handle (reqwless, esp-idf, …).
    scripted_pull: Option<(u16, Vec<u8>)>,
    artifacts: BTreeMap<String, Vec<u8>>,
}

impl Transport for MyTransport {
    type Error = String; // PLATFORM: your stack's error type

    fn exchange(&mut self, req: &Request) -> Result<Response, String> {
        // PLATFORM: send req.method / req.url / req.headers / req.body over TLS and
        // return the status + whole body. Return EVERY status as Ok; the crate
        // decides what 401 / 404 / 409 / 5xx mean. Err only if no response came.
        let _sent = (&req.method, &req.url, &req.headers, &req.body);
        let (status, body) = self.scripted_pull.take().unwrap_or((404, Vec::new()));
        Ok(Response { status, body })
    }

    fn download(
        &mut self,
        url: &str,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    ) -> Result<(), DownloadError<String>> {
        // PLATFORM: plain GET of the presigned URL (no auth header), streamed.
        // Feed chunks of whatever size your stack yields; never buffer the body.
        let bytes = self
            .artifacts
            .get(url)
            .ok_or_else(|| DownloadError::Transport("no route".to_string()))?;
        for chunk in bytes.chunks(512) {
            if sink(chunk).is_err() {
                return Err(DownloadError::Aborted); // the crate found a problem; stop
            }
        }
        Ok(())
    }
}

// ── Storage: a staging area with commit / abort semantics ───────────────────

struct MyStorage {
    // PLATFORM: two flash slots (A/B) and a boot record, or a littlefs directory.
    current: Option<Current>,
    live: BTreeMap<String, Vec<u8>>,
    staging: Option<BTreeMap<String, Vec<u8>>>,
    open: Option<String>,
}

impl Storage for MyStorage {
    type Error = String;

    fn current(&mut self) -> Result<Option<Current>, String> {
        // PLATFORM: read the boot record. Report a checkpoint as current only if
        // the files it vouches for are really there.
        Ok(self.current.clone().filter(|_| !self.live.is_empty()))
    }
    fn begin(&mut self) -> Result<(), String> {
        self.staging = Some(BTreeMap::new()); // PLATFORM: erase the inactive slot
        Ok(())
    }
    fn begin_entry(&mut self, rel_path: &str) -> Result<(), String> {
        self.staging
            .as_mut()
            .ok_or("begin first")?
            .insert(rel_path.into(), Vec::new());
        self.open = Some(rel_path.into());
        Ok(())
    }
    fn write(&mut self, chunk: &[u8]) -> Result<(), String> {
        let open = self.open.clone().ok_or("no open entry")?;
        self.staging
            .as_mut()
            .unwrap()
            .get_mut(&open)
            .unwrap()
            .extend_from_slice(chunk);
        Ok(()) // PLATFORM: program the next flash page
    }
    fn end_entry(&mut self) -> Result<(), String> {
        self.open = None;
        Ok(())
    }
    fn commit(&mut self, current: &Current) -> Result<(), String> {
        // PLATFORM: flip the boot record to the inactive slot — the one atomic step.
        self.live = self.staging.take().ok_or("nothing staged")?;
        self.current = Some(current.clone());
        Ok(())
    }
    fn abort(&mut self) -> Result<(), String> {
        self.staging = None; // PLATFORM: leave the active slot untouched
        self.open = None;
        Ok(())
    }
    fn record(&mut self, current: &Current) -> Result<(), String> {
        self.current = Some(current.clone()); // same bytes, new deployment id
        Ok(())
    }
}

// ── a scripted run ──────────────────────────────────────────────────────────

fn main() {
    // A tiny STORED zip holding config.json + a "weights" file, as ExVista
    // would serve it, and the pull answer that points at it.
    let artifact = tiny_stored_zip(&[("config.json", b"{}"), ("model.safetensors", &[1, 2, 3, 4])]);
    let mut hasher = exvista_deploy::Sha256Verifier::new();
    hasher.update(&artifact);
    let sha = hasher.finish();
    let pull = alloc::format!(
        r#"{{"deploymentId":"dep-1","modelName":"tiny","verdict":"CLEAN",
            "fingerprint":{{"crypto":"{fp}"}},
            "attestation":{{"deploymentId":"dep-1","fingerprintCrypto":"{fp}","gateStatus":"PASSED"}},
            "files":[{{"relPath":"dep-1.zip","sha256":"{sha}","url":"flash://artifact"}}]}}"#,
        fp = "a".repeat(64)
    );

    let transport = MyTransport {
        scripted_pull: Some((200, pull.into_bytes())),
        artifacts: BTreeMap::from([("flash://artifact".to_string(), artifact)]),
    };
    let storage = MyStorage {
        current: None,
        live: BTreeMap::new(),
        staging: None,
        open: None,
    };
    // PLATFORM: the device key comes from secure storage, never from source.
    let config = Config::parse_env_text(
        "EXVISTA_DEPLOY_URL=https://pull.example/\nEXVISTA_DEPLOY_KEY=exd_dev.secret\n",
    )
    .expect("config");
    let mut device = Device::new(config, transport, storage);

    match device.sync() {
        Ok(Sync::Staged(c)) => {
            let entries: Vec<&String> = device.storage_mut().live.keys().collect();
            std::println!(
                "staged deployment {} → entries {:?}",
                c.deployment_id,
                entries
            );
            // PLATFORM: report after your runtime has actually loaded the model.
            let _ = device.report(&Report::Loaded, Some(&c));
        }
        other => std::println!("{other:?}"),
    }
}

/// Enough of a zip writer for the demo: local headers + a central directory,
/// STORED, no zip64. (The crate's tests use the `zip` crate for this.)
fn tiny_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        {
            let buf = &mut out;
            buf.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
            buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&0u16.to_le_bytes()); // STORED
            buf.extend_from_slice(&[0, 0, 0, 0]); // time/date
            buf.extend_from_slice(&crc.to_le_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(data);
        }
        central.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        central.extend_from_slice(&20u16.to_le_bytes()); // made by
        central.extend_from_slice(&20u16.to_le_bytes()); // needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // STORED
        central.extend_from_slice(&[0, 0, 0, 0]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // extra, comment, disk
        central.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // int/ext attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&[0, 0, 0, 0]); // disks
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
