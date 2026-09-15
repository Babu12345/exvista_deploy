//! The wire contract: what the device sends, what ExVista answers.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::Value;

/// Where to pull from, where to report to, and who this device is.
#[derive(Clone, Debug)]
pub struct Config {
    /// The `deployPull` URL from the dashboard's "Connect a device" card.
    pub pull_url: String,
    /// The `deployReport` URL. Optional: without it [`Device::report`](crate::Device::report)
    /// returns [`Error::Config`](crate::Error::Config).
    pub report_url: Option<String>,
    /// The device key minted at enrollment (`exd_<deviceId>.<secret>`). The only
    /// secret the device holds — keep it out of logs.
    pub key: String,
}

impl Config {
    /// Pull URL + device key.
    pub fn new(pull_url: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            pull_url: pull_url.into(),
            report_url: None,
            key: key.into(),
        }
    }

    /// Add the report URL.
    pub fn with_report_url(mut self, url: impl Into<String>) -> Self {
        self.report_url = Some(url.into());
        self
    }

    pub(crate) fn bearer(&self) -> String {
        let mut s = String::with_capacity(7 + self.key.len());
        s.push_str("Bearer ");
        s.push_str(&self.key);
        s
    }
}

/// HTTP method of a [`Request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
}

/// A small request the crate asks your [`Transport`](crate::Transport) to perform.
#[derive(Clone, Debug)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Absolute URL.
    pub url: String,
    /// Headers to send, in order.
    pub headers: Vec<(&'static str, String)>,
    /// Body bytes (may be empty).
    pub body: Vec<u8>,
}

/// What your transport got back: the status and the whole body.
#[derive(Clone, Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// The body as text, lossily, for logs.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// What is staged on the device: the checkpoint's fingerprint (ExVista's
/// SHA-256 over its weights, config and tokenizer) and the deployment it came
/// from. Stored by your [`Storage`](crate::Storage), reported back on load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    /// `fingerprint.crypto` of the served deployment.
    pub fingerprint: String,
    /// The deployment id.
    pub deployment_id: String,
}

/// One downloadable file of a deployment. ExVista serves a single `.zip` of the
/// checkpoint directory; the schema allows more.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    /// Path relative to the staged checkpoint. A `.zip` is extracted in place.
    pub rel_path: String,
    /// Lowercase hex SHA-256 of the file, when the manifest carries one.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Size in bytes, when known.
    #[serde(default)]
    pub size: Option<u64>,
    /// Presigned `GET` URL. No auth header — the signature is in the URL, and it
    /// expires (`presign_ttl_seconds`).
    pub url: String,
}

/// A successful pull: the deployment this device is cleared to run.
#[derive(Clone, Debug)]
pub struct Served {
    /// Deployment id.
    pub deployment_id: String,
    /// Model name as deployed.
    pub model_name: String,
    /// Scan verdict (`CLEAN` for anything the gate serves).
    pub verdict: Option<String>,
    /// Gate status (`PASSED`, or an explicit override).
    pub gate_status: Option<String>,
    /// The scan job that produced the verdict.
    pub scan_job_id: Option<String>,
    /// `fingerprint.crypto`. Empty only if ExVista sent none.
    pub fingerprint: String,
    /// Where the model came from (an upload key, an HF repo id, an `s3://` URI).
    pub source: Option<String>,
    /// How long the presigned URLs stay valid.
    pub presign_ttl_seconds: Option<u64>,
    /// Files to download. Empty means ExVista could not package an artifact.
    pub files: Vec<Artifact>,
    /// The attestation object verbatim, for logging or your own checks.
    pub attestation: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullBody {
    deployment_id: Option<String>,
    model_name: Option<String>,
    source: Option<String>,
    verdict: Option<String>,
    fingerprint: Option<FingerprintBody>,
    attestation: Option<Value>,
    presign_ttl_seconds: Option<u64>,
    #[serde(default)]
    files: Vec<Artifact>,
}

#[derive(Deserialize)]
struct FingerprintBody {
    crypto: Option<String>,
}

fn attest_str(attestation: &Value, key: &str) -> Option<String> {
    attestation
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

/// Parse the body of a `200` pull response. Exposed so a transport-less test or
/// a non-[`Device`](crate::Device) integration can reuse the contract.
pub fn parse_pull_response(body: &[u8]) -> Result<Served, String> {
    let raw: PullBody =
        serde_json::from_slice(body).map_err(|e| alloc::format!("pull body: {e}"))?;
    let attestation = raw.attestation.unwrap_or(Value::Null);
    let deployment_id = raw
        .deployment_id
        .or_else(|| attest_str(&attestation, "deploymentId"))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| String::from("pull body has no deploymentId"))?;
    let fingerprint = raw
        .fingerprint
        .and_then(|f| f.crypto)
        .or_else(|| attest_str(&attestation, "fingerprintCrypto"))
        .unwrap_or_default();
    Ok(Served {
        deployment_id,
        model_name: raw
            .model_name
            .or_else(|| attest_str(&attestation, "modelName"))
            .unwrap_or_default(),
        verdict: raw.verdict.or_else(|| attest_str(&attestation, "verdict")),
        gate_status: attest_str(&attestation, "gateStatus"),
        scan_job_id: attest_str(&attestation, "scanJobId"),
        fingerprint,
        source: raw.source,
        presign_ttl_seconds: raw.presign_ttl_seconds,
        files: raw.files,
        attestation,
    })
}

pub(crate) fn pull_request(config: &Config) -> Request {
    Request {
        method: Method::Post,
        url: config.pull_url.clone(),
        headers: alloc::vec![
            ("Authorization", config.bearer()),
            ("Content-Type", String::from("application/json")),
        ],
        body: b"{}".to_vec(),
    }
}

pub(crate) fn report_request(
    config: &Config,
    url: &str,
    status: &str,
    current: Option<&Current>,
) -> Request {
    let mut body = serde_json::Map::new();
    body.insert("status".into(), Value::String(status.into()));
    if let Some(c) = current {
        if !c.fingerprint.is_empty() {
            body.insert("fingerprint".into(), Value::String(c.fingerprint.clone()));
        }
        if !c.deployment_id.is_empty() {
            body.insert(
                "deploymentId".into(),
                Value::String(c.deployment_id.clone()),
            );
        }
    }
    Request {
        method: Method::Post,
        url: url.into(),
        headers: alloc::vec![
            ("Authorization", config.bearer()),
            ("Content-Type", String::from("application/json")),
        ],
        body: serde_json::to_vec(&Value::Object(body)).unwrap_or_else(|_| b"{}".to_vec()),
    }
}
