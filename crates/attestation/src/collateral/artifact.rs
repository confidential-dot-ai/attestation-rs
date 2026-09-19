//! One artifact type with three origins (fetched, stored, inline) and the
//! validity window read from the artifact itself.

use super::key::{CollateralKey, CollateralKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Where a copy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Fetched,
    Stored,
    Inline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collateral {
    pub key: CollateralKey,
    /// Canonical bytes: DER for certificates and CRLs, the PEM bundle for an
    /// AMD chain, JSON for PCS bodies and JWKS.
    #[serde(with = "serde_bytes_b64")]
    pub bytes: Vec<u8>,
    /// The Intel signing chain (PEM) that arrived with a TCB Info or QE
    /// Identity body; always present for those kinds, never for others.
    #[serde(default, with = "serde_opt_bytes_b64")]
    pub signing_chain: Option<Vec<u8>>,
    pub fetched_at: DateTime<Utc>,
    /// The artifact's own `notAfter` or `nextUpdate`; `None` when it carries none.
    pub valid_until: Option<DateTime<Utc>>,
    pub origin: Origin,
}

mod serde_bytes_b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

mod serde_opt_bytes_b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        s.map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

impl Collateral {
    pub fn kind(&self) -> CollateralKind {
        self.key.kind()
    }

    /// Whether the artifact may be served at `now`: inside its own window, and
    /// no older than `max_age` since it was fetched.
    pub fn is_fresh(&self, now: DateTime<Utc>, max_age: chrono::Duration) -> bool {
        if let Some(until) = self.valid_until {
            if now >= until {
                return false;
            }
        }
        now < self.fetched_at + max_age
    }

    /// The instant the copy stops being served: the earlier of its own window
    /// and the max-age cap.
    pub fn expires_at(&self, max_age: chrono::Duration) -> DateTime<Utc> {
        let cap = self.fetched_at + max_age;
        match self.valid_until {
            Some(until) if until < cap => until,
            _ => cap,
        }
    }

    /// (ARK DER, ASK DER) of an AMD chain, in the order the verifier expects.
    /// AMD KDS serves the PEM as ASK then ARK.
    pub fn snp_chain_parts(&self) -> super::error::CollateralResult<(Vec<u8>, Vec<u8>)> {
        use super::error::CollateralError;
        let certs = pem::parse_many(&self.bytes).map_err(|e| CollateralError::Parse {
            key: self.key.clone(),
            reason: format!("chain PEM: {e}"),
        })?;
        if certs.len() < 2 {
            return Err(CollateralError::Parse {
                key: self.key.clone(),
                reason: format!("chain has {} certificates, needs ASK and ARK", certs.len()),
            });
        }
        if certs.len() > 2 {
            log::warn!(
                "{}: chain carries {} certificates; only ASK and ARK are used",
                self.key,
                certs.len()
            );
        }
        Ok((certs[1].contents().to_vec(), certs[0].contents().to_vec()))
    }
}

pub type SharedCollateral = Arc<Collateral>;

/// Validity windows read from the artifacts themselves.
pub mod validity {
    use super::super::error::{CollateralError, CollateralResult};
    use super::super::key::{CollateralKey, CollateralKind};
    use chrono::{DateTime, Utc};

    fn parse_err(key: &CollateralKey, what: &str, e: impl std::fmt::Display) -> CollateralError {
        CollateralError::Parse {
            key: key.clone(),
            reason: format!("{what}: {e}"),
        }
    }

    fn asn1_to_utc(t: x509_parser::time::ASN1Time) -> Option<DateTime<Utc>> {
        DateTime::<Utc>::from_timestamp(t.timestamp(), 0)
    }

    fn cert_not_after(key: &CollateralKey, der: &[u8]) -> CollateralResult<DateTime<Utc>> {
        let (_, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| parse_err(key, "certificate", e))?;
        asn1_to_utc(cert.validity().not_after)
            .ok_or_else(|| parse_err(key, "certificate", "notAfter out of range"))
    }

    fn crl_next_update(key: &CollateralKey, der: &[u8]) -> CollateralResult<Option<DateTime<Utc>>> {
        let (_, crl) = x509_parser::parse_x509_crl(der).map_err(|e| parse_err(key, "CRL", e))?;
        Ok(crl.next_update().and_then(asn1_to_utc))
    }

    fn json_next_update(
        key: &CollateralKey,
        body: &[u8],
        object: &str,
    ) -> CollateralResult<DateTime<Utc>> {
        let v: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| parse_err(key, object, e))?;
        let s = v
            .get(object)
            .and_then(|o| o.get("nextUpdate"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| parse_err(key, object, "no nextUpdate"))?;
        DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| parse_err(key, object, format!("nextUpdate {s:?}: {e}")))
    }

    /// The artifact's own end of validity. Parsing also proves the bytes are
    /// the kind of artifact the key names, so a wrong body never enters the
    /// cache. `Ok(None)` only for kinds without a window.
    pub fn valid_until(
        key: &CollateralKey,
        bytes: &[u8],
    ) -> CollateralResult<Option<DateTime<Utc>>> {
        match key.kind() {
            CollateralKind::SnpVcek => cert_not_after(key, bytes).map(Some),
            CollateralKind::SnpCertChain => {
                let certs = pem::parse_many(bytes).map_err(|e| parse_err(key, "chain PEM", e))?;
                if certs.len() < 2 {
                    return Err(parse_err(
                        key,
                        "chain PEM",
                        format!("{} certificates", certs.len()),
                    ));
                }
                let mut earliest: Option<DateTime<Utc>> = None;
                for c in &certs[..2] {
                    let t = cert_not_after(key, c.contents())?;
                    earliest = Some(earliest.map_or(t, |e| e.min(t)));
                }
                Ok(earliest)
            }
            CollateralKind::SnpCrl | CollateralKind::TdxPckCrl | CollateralKind::TdxRootCrl => {
                crl_next_update(key, bytes)
            }
            CollateralKind::TdxTcbInfo => json_next_update(key, bytes, "tcbInfo").map(Some),
            CollateralKind::TdxQeIdentity => {
                json_next_update(key, bytes, "enclaveIdentity").map(Some)
            }
            CollateralKind::NrasJwks => {
                serde_json::from_slice::<serde_json::Value>(bytes)
                    .map_err(|e| parse_err(key, "JWKS", e))?
                    .get("keys")
                    .and_then(|k| k.as_array())
                    .ok_or_else(|| parse_err(key, "JWKS", "no keys array"))?;
                Ok(None)
            }
        }
    }
}
