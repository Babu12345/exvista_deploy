//! The device algorithm against in-memory doubles of the two traits. These
//! doubles are also the smallest correct implementations of `Transport` and
//! `Storage` — a good starting point for a port.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;

use exvista_deploy::{
    Config, Current, Device, DownloadError, Error, Method, Request, Response, Sha256Verifier,
    Storage, Sync, Transport, DEPLOYMENT_MARKER, FINGERPRINT_MARKER,
};

use exvista_deploy::{GateStatus, Report, Verdict};

const KEY: &str = "exd_dev1.secret";
const FP: &str = "aeb82e9d659c311de12fc23ed2d9d15cf1688354f6ed8f8d28a483a630765054";

// ── doubles ────────────────────────────────────────────────────────────────

#[derive(Default)]
struct MemTransport {
    replies: VecDeque<(u16, Vec<u8>)>,
    files: BTreeMap<String, Vec<u8>>,
    chunk: usize,
    requests: Vec<Request>,
    downloads: Vec<String>,
    fail_exchange: Option<String>,
    fail_download_after: Option<usize>,
}

impl Transport for MemTransport {
    type Error = String;

    fn exchange(&mut self, req: &Request) -> Result<Response, String> {
        self.requests.push(req.clone());
        if let Some(e) = &self.fail_exchange {
            return Err(e.clone());
        }
        let (status, body) = self.replies.pop_front().expect("a scripted reply");
        Ok(Response { status, body })
    }

    fn download(
        &mut self,
        url: &str,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), ()>,
    ) -> Result<(), DownloadError<String>> {
        self.downloads.push(url.to_string());
        let bytes = match self.files.get(url) {
            Some(b) => b.clone(),
            None => return Err(DownloadError::Transport(format!("404 {url}"))),
        };
        for (i, c) in bytes.chunks(self.chunk.max(1)).enumerate() {
            if self.fail_download_after == Some(i) {
                return Err(DownloadError::Transport("connection reset".into()));
            }
            if sink(c).is_err() {
                return Err(DownloadError::Aborted);
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct MemStorage {
    current: Option<Current>,
    committed: BTreeMap<String, Vec<u8>>,
    staging: Option<BTreeMap<String, Vec<u8>>>,
    open: Option<String>,
    log: Vec<String>,
}

impl Storage for MemStorage {
    type Error = String;

    fn current(&mut self) -> Result<Option<Current>, String> {
        // "Intact" here: something is actually committed behind the marker.
        Ok(self.current.clone().filter(|_| !self.committed.is_empty()))
    }
    fn begin(&mut self) -> Result<(), String> {
        self.staging = Some(BTreeMap::new());
        self.log.push("begin".into());
        Ok(())
    }
    fn begin_entry(&mut self, rel_path: &str) -> Result<(), String> {
        self.staging
            .as_mut()
            .ok_or("begin first")?
            .insert(rel_path.into(), Vec::new());
        self.open = Some(rel_path.into());
        self.log.push(format!("entry {rel_path}"));
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
        Ok(())
    }
    fn end_entry(&mut self) -> Result<(), String> {
        self.open = None;
        Ok(())
    }
    fn commit(&mut self, current: &Current) -> Result<(), String> {
        self.committed = self.staging.take().ok_or("nothing staged")?;
        self.current = Some(current.clone());
        self.log.push("commit".into());
        Ok(())
    }
    fn abort(&mut self) -> Result<(), String> {
        self.staging = None;
        self.open = None;
        self.log.push("abort".into());
        Ok(())
    }
    fn record(&mut self, current: &Current) -> Result<(), String> {
        self.current = Some(current.clone());
        self.log.push("record".into());
        Ok(())
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

fn zip_of(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default().compression_method(method);
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn sha256(bytes: &[u8]) -> String {
    let mut v = Sha256Verifier::new();
    v.update(bytes);
    v.finish()
}

fn pull_body(deployment_id: &str, fp: &str, files: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "deploymentId": deployment_id,
        "modelName": "Qwen/Qwen3-VL-2B-Instruct",
        "source": "Qwen/Qwen3-VL-2B-Instruct",
        "verdict": "CLEAN",
        "fingerprint": { "crypto": fp },
        "attestation": {
            "deploymentId": deployment_id, "modelName": "Qwen/Qwen3-VL-2B-Instruct",
            "verdict": "CLEAN", "gateStatus": "PASSED", "scanJobId": "job-1",
            "fingerprintCrypto": fp, "issuedAt": "2026-09-15T12:00:00Z"
        },
        "presignTtlSeconds": 3600,
        "files": files
    }))
    .unwrap()
}

fn artifact_json(url: &str, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!([{ "relPath": "job-1.zip", "sha256": sha256(bytes), "size": bytes.len(), "url": url }])
}

const CHECKPOINT: &[(&str, &[u8])] = &[
    ("config.json", br#"{"model_type":"qwen3_vl"}"#),
    ("model.safetensors", &[7u8; 5000]),
    ("tokenizer/tokenizer.json", b"{}"),
];

fn device(t: MemTransport, s: MemStorage) -> Device<MemTransport, MemStorage> {
    let config =
        Config::new("https://pull.example/", KEY).with_report_url("https://report.example/");
    Device::new(config, t, s)
}

// ── pull ───────────────────────────────────────────────────────────────────

#[test]
fn pull_sends_the_device_key_as_bearer_with_an_empty_json_body() {
    let mut t = MemTransport::default();
    t.replies.push_back((
        404,
        b"{\"error\":\"no deployment assigned to this device\"}".to_vec(),
    ));
    let mut d = device(t, MemStorage::default());
    assert!(matches!(d.pull(), Ok(None)));
    let req = &d.transport_mut().requests[0];
    assert_eq!(req.method, Method::Post);
    assert_eq!(req.url, "https://pull.example/");
    assert!(req
        .headers
        .contains(&("Authorization", format!("Bearer {KEY}"))));
    assert_eq!(req.body, b"{}");
}

#[test]
fn pull_classifies_every_status() {
    for (status, check) in [
        (401u16, "unauthorized"),
        (403, "unauthorized"),
        (409, "not-provisioned"),
        (503, "server"),
        (418, "rejected"),
    ] {
        let mut t = MemTransport::default();
        t.replies.push_back((status, b"body".to_vec()));
        let err = device(t, MemStorage::default()).pull().unwrap_err();
        match (check, &err) {
            ("unauthorized", Error::Unauthorized { .. }) => assert!(!err.is_transient()),
            ("not-provisioned", Error::NotProvisioned(_)) => assert!(!err.is_transient()),
            ("server", Error::Server { .. }) => assert!(err.is_transient()),
            ("rejected", Error::Rejected { .. }) => assert!(!err.is_transient()),
            _ => panic!("{status} → {err:?}"),
        }
    }
}

#[test]
fn a_transport_failure_is_transient() {
    let t = MemTransport {
        fail_exchange: Some("Temporary failure in name resolution".into()),
        ..Default::default()
    };
    let err = device(t, MemStorage::default()).pull().unwrap_err();
    assert!(matches!(err, Error::Transport(_)) && err.is_transient());
}

#[test]
fn pull_parses_the_served_deployment_and_falls_back_to_the_attestation() {
    let mut t = MemTransport::default();
    // No top-level fingerprint/deploymentId: the attestation carries them.
    let body = serde_json::to_vec(&serde_json::json!({
        "attestation": { "deploymentId": "dep-9", "fingerprintCrypto": FP, "modelName": "m",
                         "verdict": "clean", "gateStatus": "OVERRIDDEN" },
        "files": []
    }))
    .unwrap();
    t.replies.push_back((200, body));
    let served = device(t, MemStorage::default()).pull().unwrap().unwrap();
    assert_eq!(served.deployment_id, "dep-9");
    assert_eq!(served.fingerprint, FP);
    assert_eq!(served.model_name, "m");
    assert_eq!(served.verdict, Some(Verdict::Clean), "case-insensitive");
    assert_eq!(served.gate_status, Some(GateStatus::Overridden));
    assert!(served.files.is_empty());
    // A value this crate has never heard of must not break parsing.
    assert_eq!(
        Verdict::parse("QUARANTINED"),
        Verdict::Other("QUARANTINED".into())
    );
    assert_eq!(Verdict::Other("QUARANTINED".into()).as_str(), "QUARANTINED");
}

// ── sync / stage ───────────────────────────────────────────────────────────

fn staged_sync(method: zip::CompressionMethod, chunk: usize) -> (Sync, MemStorage, MemTransport) {
    let zip = zip_of(CHECKPOINT, method);
    let url = "https://s3.example/job-1.zip";
    let mut t = MemTransport {
        chunk,
        ..Default::default()
    };
    t.replies
        .push_back((200, pull_body("dep-1", FP, artifact_json(url, &zip))));
    t.files.insert(url.into(), zip);
    let mut d = device(t, MemStorage::default());
    let sync = d.sync().unwrap();
    let (_, t, s) = d.into_parts();
    (sync, s, t)
}

#[test]
fn a_stored_zip_streams_into_storage_and_commits() {
    let (sync, s, t) = staged_sync(zip::CompressionMethod::Stored, 7); // tiny chunks: headers straddle
    match sync {
        Sync::Staged(c) => assert_eq!(
            c,
            Current {
                fingerprint: FP.into(),
                deployment_id: "dep-1".into()
            }
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(t.downloads, vec!["https://s3.example/job-1.zip"]);
    let names: Vec<&String> = s.committed.keys().collect();
    assert_eq!(
        names,
        [
            "config.json",
            "model.safetensors",
            "tokenizer/tokenizer.json"
        ]
    );
    assert_eq!(s.committed["model.safetensors"], vec![7u8; 5000]);
    assert_eq!(s.log.first().map(String::as_str), Some("begin"));
    assert_eq!(s.log.last().map(String::as_str), Some("commit"));
    assert!(s.staging.is_none());
}

#[test]
fn a_deflated_zip_inflates_on_the_fly() {
    let (sync, s, _) = staged_sync(zip::CompressionMethod::Deflated, 1024);
    assert!(matches!(sync, Sync::Staged(_)));
    assert_eq!(s.committed["config.json"], CHECKPOINT[0].1);
    assert_eq!(s.committed["model.safetensors"], vec![7u8; 5000]);
}

#[test]
fn a_sha256_mismatch_aborts_and_keeps_the_old_checkpoint() {
    let zip = zip_of(CHECKPOINT, zip::CompressionMethod::Stored);
    let url = "https://s3.example/job-2.zip";
    let mut files = artifact_json(url, &zip);
    files[0]["sha256"] = serde_json::Value::String("0".repeat(64));
    let mut t = MemTransport {
        chunk: 4096,
        ..Default::default()
    };
    t.replies
        .push_back((200, pull_body("dep-2", "b".repeat(64).as_str(), files)));
    t.files.insert(url.into(), zip);
    let mut s = MemStorage::default();
    s.committed.insert("config.json".into(), b"old".to_vec());
    s.current = Some(Current {
        fingerprint: "a".repeat(64),
        deployment_id: "dep-1".into(),
    });
    let mut d = device(t, s);
    let err = d.sync().unwrap_err();
    assert!(matches!(err, Error::Integrity { .. }), "{err:?}");
    let (_, _, s) = d.into_parts();
    assert_eq!(s.committed["config.json"], b"old");
    assert_eq!(s.current.as_ref().unwrap().deployment_id, "dep-1");
    assert_eq!(s.log.last().map(String::as_str), Some("abort"));
}

#[test]
fn an_empty_zip_is_refused_not_staged() {
    // The 22-byte empty archive ExVista once shipped: a "checkpoint" with no files.
    let zip = zip_of(&[], zip::CompressionMethod::Stored);
    assert_eq!(zip.len(), 22);
    let url = "https://s3.example/empty.zip";
    let mut t = MemTransport {
        chunk: 4096,
        ..Default::default()
    };
    t.replies
        .push_back((200, pull_body("dep-3", FP, artifact_json(url, &zip))));
    t.files.insert(url.into(), zip);
    let mut d = device(t, MemStorage::default());
    let err = d.sync().unwrap_err();
    assert!(
        matches!(err, Error::Archive(ref m) if m.contains("no files")),
        "{err:?}"
    );
    let (_, _, s) = d.into_parts();
    assert!(s.committed.is_empty() && s.current.is_none());
    assert_eq!(s.log.last().map(String::as_str), Some("abort"));
}

#[test]
fn an_entry_that_escapes_the_directory_is_refused() {
    let zip = zip_of(
        &[("../evil.sh", b"rm -rf /")],
        zip::CompressionMethod::Stored,
    );
    let url = "https://s3.example/evil.zip";
    let mut t = MemTransport {
        chunk: 4096,
        ..Default::default()
    };
    t.replies
        .push_back((200, pull_body("dep-4", FP, artifact_json(url, &zip))));
    t.files.insert(url.into(), zip);
    let mut d = device(t, MemStorage::default());
    let err = d.sync().unwrap_err();
    assert!(
        matches!(err, Error::Archive(ref m) if m.contains("unsafe")),
        "{err:?}"
    );
}

#[test]
fn a_dropped_download_aborts_with_a_transient_error() {
    let zip = zip_of(CHECKPOINT, zip::CompressionMethod::Stored);
    let url = "https://s3.example/job-5.zip";
    let mut t = MemTransport {
        chunk: 100,
        fail_download_after: Some(3),
        ..Default::default()
    };
    t.replies
        .push_back((200, pull_body("dep-5", FP, artifact_json(url, &zip))));
    t.files.insert(url.into(), zip);
    let mut d = device(t, MemStorage::default());
    let err = d.sync().unwrap_err();
    assert!(matches!(err, Error::Transport(_)) && err.is_transient());
    let (_, _, s) = d.into_parts();
    assert_eq!(s.log.last().map(String::as_str), Some("abort"));
}

#[test]
fn same_fingerprint_already_staged_means_no_download() {
    let mut t = MemTransport::default();
    t.replies.push_back((
        200,
        pull_body("dep-1", FP, artifact_json("https://s3.example/x.zip", b"")),
    ));
    let mut s = MemStorage::default();
    s.committed.insert("config.json".into(), b"{}".to_vec());
    s.current = Some(Current {
        fingerprint: FP.to_uppercase(),
        deployment_id: "dep-1".into(),
    });
    let mut d = device(t, s);
    match d.sync().unwrap() {
        Sync::Current(c) => assert_eq!(c.deployment_id, "dep-1"),
        other => panic!("{other:?}"),
    }
    let (_, t, s) = d.into_parts();
    assert!(t.downloads.is_empty());
    assert!(
        !s.log.iter().any(|l| l == "record"),
        "same deployment: nothing to re-record"
    );
}

#[test]
fn same_bytes_under_a_new_deployment_refreshes_the_marker_only() {
    let mut t = MemTransport::default();
    t.replies.push_back((
        200,
        pull_body("dep-2", FP, artifact_json("https://s3.example/x.zip", b"")),
    ));
    let mut s = MemStorage::default();
    s.committed.insert("config.json".into(), b"{}".to_vec());
    s.current = Some(Current {
        fingerprint: FP.into(),
        deployment_id: "dep-1".into(),
    });
    let mut d = device(t, s);
    assert!(matches!(d.sync().unwrap(), Sync::Current(ref c) if c.deployment_id == "dep-2"));
    let (_, t, s) = d.into_parts();
    assert!(t.downloads.is_empty());
    assert_eq!(s.log, vec!["record"]);
    assert_eq!(s.current.unwrap().deployment_id, "dep-2");
}

#[test]
fn a_marker_with_nothing_behind_it_is_not_current() {
    // Storage decides "intact"; here nothing is committed, so the marker is ignored
    // and the artifact is downloaded again.
    let zip = zip_of(CHECKPOINT, zip::CompressionMethod::Stored);
    let url = "https://s3.example/job-6.zip";
    let mut t = MemTransport {
        chunk: 4096,
        ..Default::default()
    };
    t.replies
        .push_back((200, pull_body("dep-6", FP, artifact_json(url, &zip))));
    t.files.insert(url.into(), zip);
    let s = MemStorage {
        current: Some(Current {
            fingerprint: FP.into(),
            deployment_id: "dep-6".into(),
        }),
        ..Default::default()
    };
    let mut d = device(t, s);
    assert!(matches!(d.sync().unwrap(), Sync::Staged(_)));
    assert_eq!(d.transport_mut().downloads.len(), 1);
}

#[test]
fn a_deployment_without_files_is_reported_not_staged() {
    let mut t = MemTransport::default();
    t.replies
        .push_back((200, pull_body("dep-7", FP, serde_json::json!([]))));
    let mut d = device(t, MemStorage::default());
    match d.sync().unwrap() {
        Sync::NoArtifact(served) => assert_eq!(served.deployment_id, "dep-7"),
        other => panic!("{other:?}"),
    }
    let (_, _, s) = d.into_parts();
    assert!(s.log.is_empty(), "storage must not even be opened");
}

#[test]
fn nothing_assigned_is_not_an_error() {
    let mut t = MemTransport::default();
    t.replies.push_back((404, Vec::new()));
    assert!(matches!(
        device(t, MemStorage::default()).sync().unwrap(),
        Sync::Nothing
    ));
}

// ── report ─────────────────────────────────────────────────────────────────

#[test]
fn report_posts_status_fingerprint_and_deployment_with_the_key() {
    let mut t = MemTransport::default();
    t.replies.push_back((200, b"{\"ok\":true}".to_vec()));
    let mut d = device(t, MemStorage::default());
    let current = Current {
        fingerprint: FP.into(),
        deployment_id: "dep-1".into(),
    };
    d.report(&Report::Loaded, Some(&current)).unwrap();
    let req = &d.transport_mut().requests[0];
    assert_eq!(req.url, "https://report.example/");
    assert!(req
        .headers
        .contains(&("Authorization", format!("Bearer {KEY}"))));
    let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(body["status"], "loaded");
    // The wire strings ExVista classifies: "loaded" → LOADED, "error: …" → ERROR.
    assert_eq!(
        Report::Error("cuda init failed".into()).status(),
        "error: cuda init failed"
    );
    assert_eq!(Report::Heartbeat.status(), "heartbeat");
    assert_eq!(body["fingerprint"], FP);
    assert_eq!(body["deploymentId"], "dep-1");
}

#[test]
fn report_without_a_report_url_is_a_config_error() {
    let mut d = Device::new(
        Config::new("https://pull.example/", KEY),
        MemTransport::default(),
        MemStorage::default(),
    );
    assert!(matches!(
        d.report(&Report::Loaded, None),
        Err(Error::Config(_))
    ));
}

#[test]
fn report_rejections_are_classified_like_pulls() {
    let mut t = MemTransport::default();
    t.replies.push_back((401, b"invalid device key".to_vec()));
    let err = device(t, MemStorage::default())
        .report(&Report::Error("cuda init failed".into()), None)
        .unwrap_err();
    assert!(matches!(err, Error::Unauthorized { status: 401, .. }));
}

#[test]
fn marker_names_match_the_python_client() {
    assert_eq!(FINGERPRINT_MARKER, ".exvista-fingerprint");
    assert_eq!(DEPLOYMENT_MARKER, ".exvista-deployment");
}
