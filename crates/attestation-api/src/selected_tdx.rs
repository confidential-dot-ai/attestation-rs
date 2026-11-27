//! A measured local helper authenticates the site's selected snapshot and time.
//! The verifier still checks Intel's signatures, dates and quote selectors.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use attestation::collateral::{Collateral, Fmspc, PckCa, PckCrl, QeIdentity, RootCrl, TcbInfo};
use attestation::{AttachedCollateral, AttestationError, HeldResponse};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTdx {
    pub helper: PathBuf,
    pub profile: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Selection {
    generation: u64,
    sha256: String,
    time: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    objects: [AttachedCollateral; 4],
}

pub(crate) struct Snapshot {
    pub time: DateTime<Utc>,
    generation: u64,
    sha256: String,
    fmspc: Fmspc,
    ca: PckCa,
    pub responses: Vec<HeldResponse>,
}

fn invalid(reason: &str) -> AttestationError {
    AttestationError::CertChainError(format!("selected TDX snapshot: {reason}"))
}

fn unavailable(reason: &str) -> AttestationError {
    AttestationError::CollateralUnavailable {
        collateral: "selected TDX snapshot".into(),
        retry_after: Some(1),
        detail: reason.into(),
    }
}

/// Require a fresh selection before opening the listener.
pub async fn check_startup(config: &crate::config::VerifyConfig) -> attestation::Result<()> {
    if let Some(source) = &config.selected_tdx {
        source
            .recheck("startup", Duration::from_millis(config.fetch_deadline_ms))
            .await?;
    }
    Ok(())
}

impl SelectedTdx {
    async fn recheck(&self, trigger: &str, deadline: Duration) -> attestation::Result<()> {
        let end = tokio::time::Instant::now() + deadline;
        let mut record = json!({
            "event":"selected_tdx_recheck", "trigger":trigger, "scope":"intel_collateral",
            "generation":null, "sha256":null, "siteTime":null
        });
        let mut late_worker = None;
        let result = async {
            let snapshot = self.open(deadline).await?;
            record["generation"] = snapshot.generation.into();
            record["sha256"] = snapshot.sha256.into();
            record["siteTime"] = json!(snapshot.time);
            let runtime = tokio::runtime::Handle::current();
            let mut validation = tokio::task::spawn_blocking(move || {
                runtime.block_on(attestation::check_selected_tdx_collateral(
                    snapshot.fmspc,
                    snapshot.ca,
                    snapshot.responses,
                    snapshot.time.timestamp(),
                ))
            });
            match tokio::time::timeout_at(end, &mut validation).await {
                Ok(joined) => joined.map_err(|_| unavailable("vendor validation worker failed"))?,
                Err(_) => {
                    late_worker = Some(validation);
                    Err(unavailable("vendor validation exceeded deadline"))
                }
            }
        }
        .await;
        match &result {
            Ok(()) => {
                record["outcome"] = "valid".into();
                tracing::info!(target: "selected_tdx", "{}", record);
            }
            Err(error) => {
                record["outcome"] = if error.is_retryable() {
                    "unavailable"
                } else {
                    "invalid"
                }
                .into();
                record["error"] = error.to_string().into();
                tracing::warn!(target: "selected_tdx", "{}", record);
            }
        }
        if let Some(worker) = late_worker {
            // Report the deadline immediately, then drain this check before accepting another signal.
            let _ = worker.await;
        }
        result
    }

    /// Recheck the active source once per SIGHUP, serially, for the life of the service.
    #[cfg(unix)]
    pub async fn on_hangup(
        &self,
        mut signals: tokio::signal::unix::Signal,
        deadline: Duration,
    ) -> anyhow::Result<()> {
        while signals.recv().await.is_some() {
            let _ = self.recheck("sighup", deadline).await;
        }
        anyhow::bail!("selected TDX refresh signal stream closed")
    }

    pub(crate) async fn open(&self, deadline: Duration) -> attestation::Result<Snapshot> {
        Snapshot::parse(&self.read(deadline).await?)
    }

    pub(crate) async fn read(&self, deadline: Duration) -> attestation::Result<Vec<u8>> {
        const MAX: u64 = 48 << 20;
        let run = async {
            let mut child = Command::new(&self.helper)
                .args(["collateral", "selected-tdx"])
                .arg(&self.profile)
                .current_dir("/")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| unavailable("could not start configured helper"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| unavailable("helper stdout unavailable"))?;
            let mut bytes = Vec::new();
            stdout
                .take(MAX + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| unavailable("could not read helper stdout"))?;
            if bytes.len() as u64 > MAX {
                return Err(invalid("helper output is too large"));
            }
            let status = child
                .wait()
                .await
                .map_err(|_| unavailable("could not wait for helper"))?;
            match status.code() {
                Some(0) => Ok(bytes),
                Some(3) => Err(unavailable("selection or authenticated time unavailable")),
                _ => Err(invalid("helper rejected the snapshot")),
            }
        };
        tokio::time::timeout(deadline, run)
            .await
            .map_err(|_| unavailable("helper exceeded deadline"))?
    }
}

impl Snapshot {
    pub(crate) fn parse(bytes: &[u8]) -> attestation::Result<Self> {
        let selection: Selection =
            serde_json::from_slice(bytes).map_err(|_| invalid("malformed helper output"))?;
        if selection.generation == 0
            || selection.sha256.len() != 64
            || !selection
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("missing or invalid active selection identity"));
        }
        if selection.time >= selection.expires_at {
            return Err(invalid("expired at authenticated site time"));
        }
        let mut fmspc = None;
        let mut ca = None;
        let mut kinds = std::collections::HashSet::new();
        let mut responses = Vec::with_capacity(4);
        for object in selection.objects {
            let (kind, url) =
                intel_url(&object.url).ok_or_else(|| invalid("unexpected Intel URL"))?;
            if !kinds.insert(std::mem::discriminant(&kind)) {
                return Err(invalid("duplicate Intel collateral type"));
            }
            match kind {
                IntelObject::TcbInfo(id) => fmspc = Some(id),
                IntelObject::PckCrl(issuer) => ca = Some(issuer),
                _ => {}
            }
            let valid_chain = match kind {
                IntelObject::RootCrl => object.issuer_chain.is_none(),
                _ => object
                    .issuer_chain
                    .as_deref()
                    .is_some_and(|chain| !chain.is_empty()),
            };
            if object.body.is_empty() || !valid_chain {
                return Err(invalid("missing body or unexpected issuer chain"));
            }
            responses.push((url, object.body, object.issuer_chain));
        }
        Ok(Self {
            time: selection.time,
            generation: selection.generation,
            sha256: selection.sha256,
            fmspc: fmspc.ok_or_else(|| invalid("missing TCB Info"))?,
            ca: ca.ok_or_else(|| invalid("missing PCK CRL"))?,
            responses,
        })
    }
}

#[derive(Clone, Copy)]
enum IntelObject {
    TcbInfo(Fmspc),
    QeIdentity,
    PckCrl(PckCa),
    RootCrl,
}

/// The helper names the DER PCK CRL representation explicitly. The store's
/// URL for that same Intel-signed CRL omits the encoding parameter.
fn intel_url(url: &str) -> Option<(IntelObject, String)> {
    if let Some((_, id)) = url.rsplit_once("?fmspc=") {
        let id = hex::decode(id).ok()?.try_into().ok()?;
        let expected = TcbInfo::url(&id);
        return (url == expected).then_some((IntelObject::TcbInfo(id), expected));
    }
    if url == QeIdentity::url(&()) {
        return Some((IntelObject::QeIdentity, url.to_string()));
    }
    for ca in [PckCa::Platform, PckCa::Processor] {
        let expected = PckCrl::url(&ca);
        if url.strip_suffix("&encoding=der") == Some(&expected) {
            return Some((IntelObject::PckCrl(ca), expected));
        }
    }
    (url == RootCrl::url(&())).then(|| (IntelObject::RootCrl, url.to_string()))
}
