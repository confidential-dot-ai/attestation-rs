//! A measured local helper authenticates the site's selected snapshot and time.
//! The verifier still checks Intel's signatures, dates and quote selectors.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use attestation::collateral::{Collateral, PckCa, PckCrl, QeIdentity, RootCrl, TcbInfo};
use attestation::{AttachedCollateral, AttestationError, HeldResponse};
use chrono::{DateTime, Utc};
use serde::Deserialize;
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
    time: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    objects: [AttachedCollateral; 4],
}

pub(crate) struct Snapshot {
    pub time: i64,
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
            .open(Duration::from_millis(config.fetch_deadline_ms))
            .await?;
    }
    Ok(())
}

impl SelectedTdx {
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
        if selection.time >= selection.expires_at {
            return Err(invalid("expired at authenticated site time"));
        }
        let mut kinds = std::collections::HashSet::new();
        let mut responses = Vec::with_capacity(4);
        for object in selection.objects {
            let (kind, url) =
                intel_url(&object.url).ok_or_else(|| invalid("unexpected Intel URL"))?;
            if !kinds.insert(kind) {
                return Err(invalid("duplicate Intel collateral type"));
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
            time: selection.time.timestamp(),
            responses,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum IntelObject {
    TcbInfo,
    QeIdentity,
    PckCrl,
    RootCrl,
}

/// The helper names the DER PCK CRL representation explicitly. The store's
/// URL for that same Intel-signed CRL omits the encoding parameter.
fn intel_url(url: &str) -> Option<(IntelObject, String)> {
    if let Some((_, id)) = url.rsplit_once("?fmspc=") {
        let id = hex::decode(id).ok()?.try_into().ok()?;
        let expected = TcbInfo::url(&id);
        return (url == expected).then_some((IntelObject::TcbInfo, expected));
    }
    if url == QeIdentity::url(&()) {
        return Some((IntelObject::QeIdentity, url.to_string()));
    }
    for ca in [PckCa::Platform, PckCa::Processor] {
        let expected = PckCrl::url(&ca);
        if url.strip_suffix("&encoding=der") == Some(&expected) {
            return Some((IntelObject::PckCrl, expected));
        }
    }
    (url == RootCrl::url(&())).then(|| (IntelObject::RootCrl, url.to_string()))
}
