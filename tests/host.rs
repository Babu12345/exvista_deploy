//! The std batteries: `host::UreqTransport` against a local HTTP server,
//! `host::DirStorage` against a real temp directory, config discovery.

#![cfg(feature = "std")]

use std::fs;
use std::io::Write as _;

use exvista_deploy::host::{checkpoint_present, DirStorage, UreqTransport};
use exvista_deploy::{
    Config, Current, Device, Report, Storage, Sync, DEPLOYMENT_MARKER, FINGERPRINT_MARKER,
};

const FP: &str = "aeb82e9d659c311de12fc23ed2d9d15cf1688354f6ed8f8d28a483a630765054";

fn current() -> Current {
    Current {
        fingerprint: FP.into(),
        deployment_id: "dep-1".into(),
    }
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn sha256(bytes: &[u8]) -> String {
    let mut v = exvista_deploy::Sha256Verifier::new();
    v.update(bytes);
    v.finish()
}

// ── the whole thing, end to end, over real HTTP into a real directory ───────

#[test]
fn ureq_transport_and_dir_storage_stage_a_served_checkpoint_end_to_end() {
    let mut server = mockito::Server::new();
    let artifact = zip_of(&[
        ("m/config.json", br#"{"model_type":"qwen3_vl"}"#),
        ("m/model.safetensors", &[9u8; 3000]),
    ]);
    let pull_body = serde_json::json!({
        "deploymentId": "dep-1", "modelName": "m", "verdict": "CLEAN",
        "fingerprint": { "crypto": FP },
        "attestation": { "deploymentId": "dep-1", "fingerprintCrypto": FP, "gateStatus": "PASSED" },
        "files": [{ "relPath": "dep-1.zip", "sha256": sha256(&artifact), "size": artifact.len(),
                    "url": format!("{}/artifact.zip", server.url()) }]
    });
    let pull = server
        .mock("POST", "/pull")
        .match_header("authorization", "Bearer exd_dev.secret")
        .match_header("content-type", "application/json")
        .match_body("{}")
        .with_status(200)
        .with_body(pull_body.to_string())
        .create();
    let get = server
        .mock("GET", "/artifact.zip")
        .with_status(200)
        .with_body(artifact)
        .create();
    let report = server
        .mock("POST", "/report")
        .match_header("authorization", "Bearer exd_dev.secret")
        .match_body(mockito::Matcher::PartialJsonString(format!(
            r#"{{"status":"loaded","fingerprint":"{FP}","deploymentId":"dep-1"}}"#
        )))
        .with_status(200)
        .with_body(r#"{"ok":true}"#)
        .create();

    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("captioner");
    let config = Config::new(format!("{}/pull", server.url()), "exd_dev.secret")
        .with_report_url(format!("{}/report", server.url()));
    let mut device = Device::new(config, UreqTransport::default(), DirStorage::new(&dest));

    match device.sync().unwrap() {
        Sync::Staged(c) => assert_eq!(c, current()),
        other => panic!("{other:?}"),
    }
    pull.assert();
    get.assert();
    // The wrapping `m/` directory was promoted: config.json is at the root.
    assert_eq!(
        fs::read(dest.join("config.json")).unwrap(),
        br#"{"model_type":"qwen3_vl"}"#
    );
    assert_eq!(
        fs::read(dest.join("model.safetensors")).unwrap(),
        vec![9u8; 3000]
    );
    assert_eq!(
        fs::read_to_string(dest.join(FINGERPRINT_MARKER)).unwrap(),
        FP
    );
    assert_eq!(
        fs::read_to_string(dest.join(DEPLOYMENT_MARKER)).unwrap(),
        "dep-1"
    );
    assert!(checkpoint_present(&dest));
    assert!(!dest.with_file_name("captioner.staging").exists());

    device.report(&Report::Loaded, Some(&current())).unwrap();
    report.assert();
}

#[test]
fn ureq_transport_returns_every_status_as_a_response() {
    let mut server = mockito::Server::new();
    for status in [404usize, 401, 409, 503] {
        let _m = server
            .mock("POST", "/pull")
            .with_status(status)
            .with_body("why")
            .create();
        let mut device = Device::new(
            Config::new(format!("{}/pull", server.url()), "exd_k"),
            UreqTransport::default(),
            DirStorage::new(tempfile::tempdir().unwrap().path().join("m")),
        );
        let outcome = device.pull();
        match status {
            404 => assert!(matches!(outcome, Ok(None))),
            401 => assert!(matches!(
                outcome,
                Err(exvista_deploy::Error::Unauthorized { .. })
            )),
            409 => assert!(matches!(
                outcome,
                Err(exvista_deploy::Error::NotProvisioned(_))
            )),
            _ => assert!(matches!(
                outcome,
                Err(exvista_deploy::Error::Server { status: 503, .. })
            )),
        }
    }
}

#[test]
fn a_dead_host_is_a_transport_error() {
    let mut device = Device::new(
        Config::new("http://127.0.0.1:9/pull", "exd_k"),
        UreqTransport::default(),
        DirStorage::new(tempfile::tempdir().unwrap().path().join("m")),
    );
    let err = device.pull().unwrap_err();
    assert!(matches!(err, exvista_deploy::Error::Transport(_)) && err.is_transient());
}

// ── DirStorage on its own ───────────────────────────────────────────────────

fn stage(s: &mut DirStorage, entries: &[(&str, &[u8])]) {
    s.begin().unwrap();
    for (name, data) in entries {
        s.begin_entry(name).unwrap();
        s.write(data).unwrap();
        s.end_entry().unwrap();
    }
}

#[test]
fn a_marker_with_nothing_behind_it_is_not_current() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("m");
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join(FINGERPRINT_MARKER), FP).unwrap();
    assert_eq!(DirStorage::new(&dest).current().unwrap(), None);
}

#[test]
fn abort_keeps_the_previous_checkpoint_and_commit_replaces_it() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("m");
    let mut s = DirStorage::new(&dest);
    stage(
        &mut s,
        &[("config.json", b"old"), ("model.safetensors", b"old")],
    );
    s.commit(&current()).unwrap();
    assert_eq!(s.current().unwrap(), Some(current()));

    stage(&mut s, &[("config.json", b"half")]);
    s.abort().unwrap();
    assert_eq!(fs::read(dest.join("config.json")).unwrap(), b"old");

    stage(
        &mut s,
        &[("config.json", b"new"), ("model.safetensors", b"new")],
    );
    let newer = Current {
        fingerprint: "b".repeat(64),
        deployment_id: "dep-2".into(),
    };
    s.commit(&newer).unwrap();
    assert_eq!(fs::read(dest.join("config.json")).unwrap(), b"new");
    assert_eq!(s.current().unwrap(), Some(newer));
    assert!(!dest.with_file_name("m.previous").exists());
}

#[test]
fn record_updates_only_the_markers() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("m");
    let mut s = DirStorage::new(&dest);
    stage(&mut s, &[("config.json", b"{}"), ("model.gguf", b"w")]);
    s.commit(&current()).unwrap();
    let redeployed = Current {
        fingerprint: FP.into(),
        deployment_id: "dep-2".into(),
    };
    s.record(&redeployed).unwrap();
    assert_eq!(s.current().unwrap(), Some(redeployed));
    assert_eq!(fs::read(dest.join("config.json")).unwrap(), b"{}");
}

#[test]
fn a_custom_intact_rule_replaces_the_checkpoint_one() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("m");
    let mut s = DirStorage::new(&dest).with_intact_check(|d| d.join("model.onnx").is_file());
    stage(&mut s, &[("model.onnx", b"onnx")]);
    s.commit(&current()).unwrap();
    assert_eq!(s.current().unwrap(), Some(current()));
    assert!(
        !checkpoint_present(&dest),
        "no config.json — the default rule would say no"
    );
}

// ── configuration ───────────────────────────────────────────────────────────

#[test]
fn config_from_env_file_and_discover() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("device.env");
    fs::write(
        &file,
        "# identity\nEXVISTA_DEPLOY_URL=https://pull/\nexport EXVISTA_DEPLOY_KEY=\"exd_a.b\"\nEXVISTA_DEPLOY_REPORT_URL='https://report/'\n",
    )
    .unwrap();
    let c = Config::from_env_file(&file).unwrap().unwrap();
    assert_eq!(
        (c.pull_url.as_str(), c.key.as_str()),
        ("https://pull/", "exd_a.b")
    );
    assert_eq!(c.report_url.as_deref(), Some("https://report/"));

    fs::write(&file, "EXVISTA_DEPLOY_URL=https://pull/\n").unwrap();
    assert!(
        Config::from_env_file(&file).unwrap().is_none(),
        "no key → not enrolled"
    );
    assert!(Config::from_env_file(tmp.path().join("missing.env")).is_err());

    // discover(): env vars win; with none set and no usable file, None.
    std::env::remove_var("EXVISTA_DEPLOY_URL");
    std::env::remove_var("EXVISTA_DEPLOY_KEY");
    assert!(Config::discover(&file).is_none());
    assert!(Config::discover(tmp.path().join("missing.env")).is_none());
}
