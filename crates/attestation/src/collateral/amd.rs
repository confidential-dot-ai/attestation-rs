//! AMD KDS documents: VCEKs and the per-generation CRLs.

use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

use super::document::{crl_number, AmdCrl, AmdSigner, AmdVcek, Document, Info, Raw};
use crate::platforms::snp::certs;
use crate::platforms::snp::verify::{check_vek_binding, verify_cert_chain, verify_crl_signature};

impl AmdVcek {
    fn chip_id_bytes(&self) -> Result<[u8; 64], String> {
        hex::decode(&self.chip_id)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or_else(|| "CHIP_ID is not 64 hex bytes".to_string())
    }
}

impl Document for AmdVcek {
    /// The certificate, DER.
    type Value = Vec<u8>;

    /// Issued by the bundled ASK of the generation, for this chip and TCB.
    fn check(&self, raw: &Raw) -> Result<(Vec<u8>, Info), String> {
        let der = &raw.body;
        let gen = self.generation;
        verify_cert_chain(certs::get_ark(gen), certs::get_ask(gen), der)
            .map_err(|e| e.to_string())?;
        check_vek_binding(der, &self.chip_id_bytes()?, &self.tcb, gen)
            .map_err(|e| e.to_string())?;
        let (rest, cert) = X509Certificate::from_der(der).map_err(|e| format!("VCEK: {e}"))?;
        if !rest.is_empty() {
            return Err("VCEK has trailing bytes".into());
        }
        let validity = cert.validity();
        Ok((
            der.clone(),
            Info {
                this_update: Some(validity.not_before.timestamp()),
                next_update: Some(validity.not_after.timestamp()),
                version: None,
            },
        ))
    }
}

impl Document for AmdCrl {
    /// The CRL, DER.
    type Value = Vec<u8>;

    /// Signed by the bundled ARK of the generation; AMD lists the
    /// ARK-issued ASKs and ASVKs in it.
    fn check(&self, raw: &Raw) -> Result<(Vec<u8>, Info), String> {
        let der = &raw.body;
        let (rest, crl) =
            CertificateRevocationList::from_der(der).map_err(|e| format!("AMD CRL: {e}"))?;
        if !rest.is_empty() {
            return Err("AMD CRL has trailing bytes".into());
        }
        let (_, ark) = X509Certificate::from_der(certs::get_ark(self.generation))
            .map_err(|e| format!("bundled ARK: {e}"))?;
        if crl.issuer() != ark.subject() {
            return Err(format!(
                "AMD CRL is issued by {}, not the {:?} ARK",
                crl.issuer(),
                self.generation
            ));
        }
        verify_crl_signature(&crl, der, &ark).map_err(|e| e.to_string())?;
        let next_update = crl.next_update().ok_or("AMD CRL has no nextUpdate")?;
        Ok((
            der.clone(),
            Info {
                this_update: Some(crl.last_update().timestamp()),
                next_update: Some(next_update.timestamp()),
                version: crl_number(&crl),
            },
        ))
    }
}

impl AmdCrl {
    /// The CRL that can revoke `vek_der`'s issuer: the ASVK's for a VLEK,
    /// the ASK's for a VCEK.
    pub fn for_vek(
        generation: crate::types::ProcessorGeneration,
        vek_der: &[u8],
    ) -> crate::error::Result<Self> {
        let signer = if crate::platforms::snp::verify::is_vlek_cert(vek_der)? {
            AmdSigner::Asvk
        } else {
            AmdSigner::Ask
        };
        Ok(Self { generation, signer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::document::Freshness;
    use crate::types::{ProcessorGeneration, SnpTcb};

    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_data/collateral/2026-10-14/"
    );

    fn raw(file: &str) -> Raw {
        Raw {
            body: std::fs::read(format!("{DIR}{file}")).unwrap(),
            issuer_chain: None,
        }
    }

    fn vcek() -> AmdVcek {
        AmdVcek {
            generation: ProcessorGeneration::Genoa,
            chip_id: "b5f9a4c8280e63c97d288db6648577dc2b848884aa682d7a227ba40e50deb2b0\
                      d112b599d87aaccda78d06f4254b1e81c4d953ef3c699db39d4e06013e9fa4ce"
                .into(),
            tcb: SnpTcb {
                bootloader: 10,
                tee: 0,
                snp: 27,
                microcode: 28,
                fmc: None,
            },
        }
    }

    fn crl(generation: ProcessorGeneration) -> AmdCrl {
        AmdCrl {
            generation,
            signer: AmdSigner::Ask,
        }
    }

    /// 2026-10-15T00:00:00Z.
    const NOW: i64 = 1_792_022_400;

    fn flip_last(mut r: Raw) -> Raw {
        let last = r.body.len() - 1;
        r.body[last] ^= 1;
        r
    }

    #[test]
    fn a_kds_vcek_checks_for_its_chip_and_tcb() {
        let (der, info) = vcek().check(&raw("amd_vcek_genoa.der")).unwrap();
        assert_eq!(der, raw("amd_vcek_genoa.der").body);
        assert_eq!(info.freshness(NOW), Freshness::Current);
        assert_eq!(info.version, None);
    }

    #[test]
    fn a_vcek_with_a_bad_signature_is_refused() {
        assert!(vcek().check(&flip_last(raw("amd_vcek_genoa.der"))).is_err());
    }

    #[test]
    fn a_vcek_for_another_chip_tcb_or_generation_is_refused() {
        let mut other_chip = vcek();
        other_chip.chip_id = "00".repeat(64);
        let mut other_tcb = vcek();
        other_tcb.tcb.snp = 26;
        let mut other_gen = vcek();
        other_gen.generation = ProcessorGeneration::Milan;
        for key in [other_chip, other_tcb, other_gen] {
            assert!(key.check(&raw("amd_vcek_genoa.der")).is_err(), "{key:?}");
        }
    }

    #[test]
    fn a_vcek_past_not_after_is_expired() {
        let (_, info) = vcek().check(&raw("amd_vcek_genoa.der")).unwrap();
        assert_eq!(
            info.freshness(info.next_update.unwrap() + 1),
            Freshness::Expired
        );
    }

    #[test]
    fn each_generations_crl_checks_against_its_ark() {
        for (gen, file, number) in [
            (ProcessorGeneration::Milan, "amd_crl_milan.der", 12),
            (ProcessorGeneration::Genoa, "amd_crl_genoa.der", 11),
            (ProcessorGeneration::Turin, "amd_crl_turin.der", 8),
        ] {
            let (_, info) = crl(gen).check(&raw(file)).unwrap();
            assert_eq!(info.version, Some(number), "{gen:?}");
            assert_eq!(info.freshness(NOW), Freshness::Current);
            // 2026-11-09T01:00Z, the shared nextUpdate.
            assert_eq!(info.freshness(1_794_186_001), Freshness::Expired);
        }
        let asvk = AmdCrl {
            generation: ProcessorGeneration::Genoa,
            signer: AmdSigner::Asvk,
        };
        assert!(asvk.check(&raw("amd_vlek_crl_genoa.der")).is_ok());
    }

    #[test]
    fn a_crl_from_another_generations_ark_is_refused() {
        assert!(crl(ProcessorGeneration::Milan)
            .check(&raw("amd_crl_genoa.der"))
            .is_err());
        assert!(crl(ProcessorGeneration::Genoa)
            .check(&raw("amd_crl_turin.der"))
            .is_err());
    }

    #[test]
    fn a_crl_with_a_bad_signature_is_refused() {
        for (gen, file) in [
            (ProcessorGeneration::Milan, "amd_crl_milan.der"),
            (ProcessorGeneration::Genoa, "amd_crl_genoa.der"),
        ] {
            assert!(crl(gen).check(&flip_last(raw(file))).is_err());
        }
    }

    #[test]
    fn an_unsigned_algorithm_field_that_differs_from_the_signed_one_is_refused() {
        // Found by fuzzing: the outer RSA-PSS MGF1 hash OID of the Milan CRL
        // is not covered by the signature.
        let mut r = raw("amd_crl_milan.der");
        r.body[335] ^= 0xf3;
        assert!(crl(ProcessorGeneration::Milan).check(&r).is_err());
    }

    #[test]
    fn malformed_bytes_are_refused() {
        for body in [
            vec![],
            b"<html>503</html>".to_vec(),
            raw("amd_crl_genoa.der").body[..400].to_vec(),
        ] {
            let r = Raw {
                body,
                issuer_chain: None,
            };
            assert!(crl(ProcessorGeneration::Genoa).check(&r).is_err());
            assert!(vcek().check(&r).is_err());
        }
    }

    #[test]
    fn a_vek_names_its_crl() {
        let der = raw("amd_vcek_genoa.der").body;
        assert_eq!(
            AmdCrl::for_vek(ProcessorGeneration::Genoa, &der).unwrap(),
            crl(ProcessorGeneration::Genoa)
        );
        let vlek = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/snp/test-vlek.der"
        ))
        .unwrap();
        assert_eq!(
            AmdCrl::for_vek(ProcessorGeneration::Genoa, &vlek)
                .unwrap()
                .signer,
            AmdSigner::Asvk
        );
    }
}
