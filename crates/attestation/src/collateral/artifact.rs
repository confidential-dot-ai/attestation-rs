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
        now < self.age_cap(max_age)
    }

    /// `fetched_at + max_age`, saturating at the end of time instead of panicking.
    pub fn age_cap(&self, max_age: chrono::Duration) -> DateTime<Utc> {
        self.fetched_at
            .checked_add_signed(max_age)
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }

    /// The instant the copy stops being served: the earlier of its own window
    /// and the max-age cap.
    pub fn expires_at(&self, max_age: chrono::Duration) -> DateTime<Utc> {
        let cap = self.age_cap(max_age);
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

/// Validity windows read from the artifacts themselves, and the binding of
/// the bytes to the key that names them.
pub mod validity {
    use super::super::error::{CollateralError, CollateralResult};
    use super::super::key::{CollateralKey, PckCa};
    use chrono::{DateTime, Utc};
    use x509_parser::prelude::*;

    fn parse_err(key: &CollateralKey, what: &str, e: impl std::fmt::Display) -> CollateralError {
        CollateralError::Parse {
            key: key.clone(),
            reason: format!("{what}: {e}"),
        }
    }

    fn asn1_to_utc(t: x509_parser::time::ASN1Time) -> Option<DateTime<Utc>> {
        DateTime::<Utc>::from_timestamp(t.timestamp(), 0)
    }

    fn common_name(name: &X509Name<'_>) -> Option<String> {
        name.iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .map(str::to_string)
    }

    fn expect_cn(
        key: &CollateralKey,
        what: &str,
        name: &X509Name<'_>,
        expected: &str,
    ) -> CollateralResult<()> {
        let cn = common_name(name).unwrap_or_default();
        if cn != expected {
            return Err(parse_err(
                key,
                what,
                format!("CN is {cn:?}, expected {expected:?}"),
            ));
        }
        Ok(())
    }

    fn parse_cert<'a>(
        key: &CollateralKey,
        what: &str,
        der: &'a [u8],
    ) -> CollateralResult<X509Certificate<'a>> {
        let (rest, cert) = parse_x509_certificate(der).map_err(|e| parse_err(key, what, e))?;
        if !rest.is_empty() {
            return Err(parse_err(key, what, "trailing bytes after the certificate"));
        }
        Ok(cert)
    }

    fn cert_not_after(
        key: &CollateralKey,
        what: &str,
        cert: &X509Certificate<'_>,
    ) -> CollateralResult<DateTime<Utc>> {
        asn1_to_utc(cert.validity().not_after)
            .ok_or_else(|| parse_err(key, what, "notAfter out of range"))
    }

    /// A CRL's `nextUpdate`, required: the three vendors always set it, and
    /// without it the copy would fall back to a cache timer.
    fn crl_next_update(
        key: &CollateralKey,
        der: &[u8],
        issuer_cn: &str,
    ) -> CollateralResult<DateTime<Utc>> {
        let (rest, crl) = parse_x509_crl(der).map_err(|e| parse_err(key, "CRL", e))?;
        if !rest.is_empty() {
            return Err(parse_err(key, "CRL", "trailing bytes after the CRL"));
        }
        expect_cn(key, "CRL issuer", crl.issuer(), issuer_cn)?;
        crl.next_update()
            .and_then(asn1_to_utc)
            .ok_or_else(|| parse_err(key, "CRL", "no nextUpdate"))
    }

    fn pcs_body(
        key: &CollateralKey,
        body: &[u8],
        object: &str,
    ) -> CollateralResult<serde_json::Value> {
        let v: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| parse_err(key, object, e))?;
        v.get(object)
            .cloned()
            .ok_or_else(|| parse_err(key, object, "missing object"))
    }

    fn pcs_str<'a>(
        key: &CollateralKey,
        object: &str,
        o: &'a serde_json::Value,
        field: &str,
    ) -> CollateralResult<&'a str> {
        o.get(field)
            .and_then(|n| n.as_str())
            .ok_or_else(|| parse_err(key, object, format!("no {field}")))
    }

    fn pcs_next_update(
        key: &CollateralKey,
        object: &str,
        o: &serde_json::Value,
    ) -> CollateralResult<DateTime<Utc>> {
        let s = pcs_str(key, object, o, "nextUpdate")?;
        DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| parse_err(key, object, format!("nextUpdate {s:?}: {e}")))
    }

    /// Parse the bytes as the artifact the key names, check that they are
    /// bound to the key's parameters (generation, FMSPC, CA, identity), and
    /// return the artifact's own end of validity. `Ok(None)` only for kinds
    /// without a window. A body under the wrong key never enters the cache.
    pub fn inspect(key: &CollateralKey, bytes: &[u8]) -> CollateralResult<Option<DateTime<Utc>>> {
        match key {
            CollateralKey::SnpVcek { generation, .. } => {
                let cert = parse_cert(key, "VCEK", bytes)?;
                expect_cn(key, "VCEK subject", cert.subject(), "SEV-VCEK")?;
                expect_cn(
                    key,
                    "VCEK issuer",
                    cert.issuer(),
                    &format!("SEV-{}", generation.product_name()),
                )?;
                cert_not_after(key, "VCEK", &cert).map(Some)
            }
            CollateralKey::SnpCertChain { generation } => {
                let certs = ::pem::parse_many(bytes).map_err(|e| parse_err(key, "chain PEM", e))?;
                if certs.len() < 2 {
                    return Err(parse_err(
                        key,
                        "chain PEM",
                        format!("{} certificates", certs.len()),
                    ));
                }
                let ask = parse_cert(key, "ASK", certs[0].contents())?;
                let ark = parse_cert(key, "ARK", certs[1].contents())?;
                let product = generation.product_name();
                expect_cn(key, "ASK subject", ask.subject(), &format!("SEV-{product}"))?;
                expect_cn(key, "ARK subject", ark.subject(), &format!("ARK-{product}"))?;
                let a = cert_not_after(key, "ASK", &ask)?;
                let b = cert_not_after(key, "ARK", &ark)?;
                Ok(Some(a.min(b)))
            }
            CollateralKey::SnpCrl { generation } => {
                crl_next_update(key, bytes, &format!("ARK-{}", generation.product_name())).map(Some)
            }
            CollateralKey::TdxPckCrl { ca } => {
                let issuer = match ca {
                    PckCa::Platform => "Intel SGX PCK Platform CA",
                    PckCa::Processor => "Intel SGX PCK Processor CA",
                };
                crl_next_update(key, bytes, issuer).map(Some)
            }
            CollateralKey::TdxRootCrl => crl_next_update(key, bytes, "Intel SGX Root CA").map(Some),
            CollateralKey::TdxTcbInfo { fmspc } => {
                let o = pcs_body(key, bytes, "tcbInfo")?;
                let id = pcs_str(key, "tcbInfo", &o, "id")?;
                if id != "TDX" {
                    return Err(parse_err(
                        key,
                        "tcbInfo",
                        format!("id is {id:?}, expected TDX"),
                    ));
                }
                let body_fmspc = pcs_str(key, "tcbInfo", &o, "fmspc")?.to_ascii_lowercase();
                if body_fmspc != fmspc.as_str() {
                    return Err(parse_err(
                        key,
                        "tcbInfo",
                        format!("fmspc is {body_fmspc:?}, key names {fmspc}"),
                    ));
                }
                pcs_next_update(key, "tcbInfo", &o).map(Some)
            }
            CollateralKey::TdxQeIdentity { td } => {
                let o = pcs_body(key, bytes, "enclaveIdentity")?;
                let id = pcs_str(key, "enclaveIdentity", &o, "id")?;
                let expected = if *td { "TD_QE" } else { "QE" };
                if id != expected {
                    return Err(parse_err(
                        key,
                        "enclaveIdentity",
                        format!("id is {id:?}, expected {expected}"),
                    ));
                }
                pcs_next_update(key, "enclaveIdentity", &o).map(Some)
            }
            CollateralKey::NrasJwks { .. } => {
                let keys = serde_json::from_slice::<serde_json::Value>(bytes)
                    .map_err(|e| parse_err(key, "JWKS", e))?
                    .get("keys")
                    .and_then(|k| k.as_array())
                    .map(Vec::len)
                    .ok_or_else(|| parse_err(key, "JWKS", "no keys array"))?;
                if keys == 0 {
                    return Err(parse_err(key, "JWKS", "empty key set"));
                }
                Ok(None)
            }
        }
    }

    /// Kept for callers that only need the window; identical to [`inspect`].
    pub fn valid_until(
        key: &CollateralKey,
        bytes: &[u8],
    ) -> CollateralResult<Option<DateTime<Utc>>> {
        inspect(key, bytes)
    }
}
