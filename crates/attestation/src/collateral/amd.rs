//! AMD KDS collateral: VCEKs and the per-generation CRLs.

use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

use super::{crl_number, AmdSigner, Refused};
use crate::platforms::snp::certs;
use crate::platforms::snp::verify::{check_vek_binding, verify_cert_chain, verify_crl_signature};
use crate::types::{ProcessorGeneration, SnpTcb};

const AMD_KDS: &str = "https://kdsintf.amd.com";

/// An AMD VCEK: the per-chip key a SEV-SNP report is signed with, for one
/// TCB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vcek {
    /// The certificate, DER.
    pub der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

impl Vcek {
    /// Where AMD KDS publishes the VCEK. Turin keys the lookup on the first
    /// 8 bytes of CHIP_ID.
    pub fn url(generation: ProcessorGeneration, chip_id: &[u8; 64], tcb: &SnpTcb) -> String {
        let chip_id = match generation {
            ProcessorGeneration::Turin => hex::encode(&chip_id[..8]),
            _ => hex::encode(chip_id),
        };
        let mut url = format!(
            "{AMD_KDS}/vcek/v1/{}/{chip_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            generation.product_name(),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        );
        if let Some(fmc) = tcb.fmc {
            url.push_str(&format!("&fmcSPL={fmc:02}"));
        }
        url
    }

    /// Issued by the bundled ASK of the generation, for this chip and TCB.
    pub fn verify(
        der: &[u8],
        generation: ProcessorGeneration,
        chip_id: &[u8; 64],
        tcb: &SnpTcb,
    ) -> Result<Self, Refused> {
        verify_cert_chain(certs::get_ark(generation), certs::get_ask(generation), der)?;
        check_vek_binding(der, chip_id, tcb, generation)?;
        let (rest, cert) = X509Certificate::from_der(der).map_err(|e| format!("VCEK: {e}"))?;
        if !rest.is_empty() {
            return Err("VCEK has trailing bytes".into());
        }
        Ok(Self {
            der: der.to_vec(),
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
        })
    }
}

/// The AMD CRL for one generation and signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdCrl {
    /// The CRL, DER.
    pub der: Vec<u8>,
    pub generation: ProcessorGeneration,
    pub signer: AmdSigner,
    pub this_update: i64,
    pub next_update: i64,
    pub number: Option<u64>,
}

impl AmdCrl {
    pub fn url(generation: ProcessorGeneration, signer: AmdSigner) -> String {
        let path = match signer {
            AmdSigner::Ask => "vcek",
            AmdSigner::Asvk => "vlek",
        };
        format!("{AMD_KDS}/{path}/v1/{}/crl", generation.product_name())
    }

    /// Signed by the bundled ARK of the generation; AMD lists the
    /// ARK-issued ASKs and ASVKs in it.
    pub fn verify(
        der: &[u8],
        generation: ProcessorGeneration,
        signer: AmdSigner,
    ) -> Result<Self, Refused> {
        let (rest, crl) =
            CertificateRevocationList::from_der(der).map_err(|e| format!("AMD CRL: {e}"))?;
        if !rest.is_empty() {
            return Err("AMD CRL has trailing bytes".into());
        }
        let (_, ark) = X509Certificate::from_der(certs::get_ark(generation))
            .map_err(|e| format!("bundled ARK: {e}"))?;
        if crl.issuer() != ark.subject() {
            return Err(Refused(format!(
                "AMD CRL is issued by {}, not the {generation:?} ARK",
                crl.issuer()
            )));
        }
        verify_crl_signature(&crl, der, &ark)?;
        let next_update = crl.next_update().ok_or("AMD CRL has no nextUpdate")?;
        Ok(Self {
            der: der.to_vec(),
            generation,
            signer,
            this_update: crl.last_update().timestamp(),
            next_update: next_update.timestamp(),
            number: crl_number(&crl),
        })
    }
}

impl AmdSigner {
    /// The signer whose CRL can revoke `vek_der`'s issuer: the ASVK for a
    /// VLEK, the ASK for a VCEK.
    pub fn of_vek(vek_der: &[u8]) -> crate::error::Result<Self> {
        Ok(if crate::platforms::snp::verify::is_vlek_cert(vek_der)? {
            AmdSigner::Asvk
        } else {
            AmdSigner::Ask
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_data/collateral/2026-10-14/"
    );

    fn file(name: &str) -> Vec<u8> {
        std::fs::read(format!("{DIR}{name}")).unwrap()
    }

    fn chip_id() -> [u8; 64] {
        hex::decode(
            "b5f9a4c8280e63c97d288db6648577dc2b848884aa682d7a227ba40e50deb2b0\
             d112b599d87aaccda78d06f4254b1e81c4d953ef3c699db39d4e06013e9fa4ce",
        )
        .unwrap()
        .try_into()
        .unwrap()
    }
    const TCB: SnpTcb = SnpTcb {
        bootloader: 10,
        tee: 0,
        snp: 27,
        microcode: 28,
        fmc: None,
    };

    fn vcek(der: &[u8]) -> Result<Vcek, Refused> {
        Vcek::verify(der, ProcessorGeneration::Genoa, &chip_id(), &TCB)
    }

    fn crl(der: &[u8], generation: ProcessorGeneration) -> Result<AmdCrl, Refused> {
        AmdCrl::verify(der, generation, AmdSigner::Ask)
    }

    /// 2026-10-15T00:00:00Z.
    const NOW: i64 = 1_792_022_400;

    fn flip_last(mut b: Vec<u8>) -> Vec<u8> {
        *b.last_mut().unwrap() ^= 1;
        b
    }

    #[test]
    fn a_kds_vcek_verifies_for_its_chip_and_tcb() {
        let v = vcek(&file("amd_vcek_genoa.der")).unwrap();
        assert_eq!(v.der, file("amd_vcek_genoa.der"));
        assert!(v.not_before <= NOW && NOW <= v.not_after);
    }

    #[test]
    fn a_vcek_with_a_bad_signature_is_refused() {
        assert!(vcek(&flip_last(file("amd_vcek_genoa.der"))).is_err());
    }

    #[test]
    fn a_vcek_for_another_chip_tcb_or_generation_is_refused() {
        let der = file("amd_vcek_genoa.der");
        let gen = ProcessorGeneration::Genoa;
        let other_tcb = SnpTcb { snp: 26, ..TCB };
        assert!(Vcek::verify(&der, gen, &[0; 64], &TCB).is_err());
        assert!(Vcek::verify(&der, gen, &chip_id(), &other_tcb).is_err());
        assert!(Vcek::verify(&der, ProcessorGeneration::Milan, &chip_id(), &TCB).is_err());
    }

    #[test]
    fn each_generations_crl_verifies_against_its_ark() {
        for (gen, name, number) in [
            (ProcessorGeneration::Milan, "amd_crl_milan.der", 12),
            (ProcessorGeneration::Genoa, "amd_crl_genoa.der", 11),
            (ProcessorGeneration::Turin, "amd_crl_turin.der", 8),
        ] {
            let c = crl(&file(name), gen).unwrap();
            assert_eq!(c.number, Some(number), "{gen:?}");
            assert!(c.this_update <= NOW && NOW <= c.next_update);
            // 2026-11-09T01:00Z, the shared nextUpdate.
            assert_eq!(c.next_update, 1_794_186_000);
        }
        let asvk = AmdCrl::verify(
            &file("amd_vlek_crl_genoa.der"),
            ProcessorGeneration::Genoa,
            AmdSigner::Asvk,
        );
        assert!(asvk.is_ok());
    }

    #[test]
    fn a_crl_from_another_generations_ark_is_refused() {
        assert!(crl(&file("amd_crl_genoa.der"), ProcessorGeneration::Milan).is_err());
        assert!(crl(&file("amd_crl_turin.der"), ProcessorGeneration::Genoa).is_err());
    }

    #[test]
    fn a_crl_with_a_bad_signature_is_refused() {
        for (gen, name) in [
            (ProcessorGeneration::Milan, "amd_crl_milan.der"),
            (ProcessorGeneration::Genoa, "amd_crl_genoa.der"),
        ] {
            assert!(crl(&flip_last(file(name)), gen).is_err());
        }
    }

    #[test]
    fn an_unsigned_algorithm_field_that_differs_from_the_signed_one_is_refused() {
        // Found by fuzzing: the outer RSA-PSS MGF1 hash OID of the Milan CRL
        // is not covered by the signature.
        let mut der = file("amd_crl_milan.der");
        der[335] ^= 0xf3;
        assert!(crl(&der, ProcessorGeneration::Milan).is_err());
    }

    #[test]
    fn malformed_bytes_are_refused() {
        for body in [
            vec![],
            b"<html>503</html>".to_vec(),
            file("amd_crl_genoa.der")[..400].to_vec(),
        ] {
            assert!(crl(&body, ProcessorGeneration::Genoa).is_err());
            assert!(vcek(&body).is_err());
        }
    }

    #[test]
    fn a_vek_names_its_crl_signer() {
        assert_eq!(
            AmdSigner::of_vek(&file("amd_vcek_genoa.der")).unwrap(),
            AmdSigner::Ask
        );
        let vlek = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/snp/test-vlek.der"
        ))
        .unwrap();
        assert_eq!(AmdSigner::of_vek(&vlek).unwrap(), AmdSigner::Asvk);
    }

    #[test]
    fn urls_name_the_kds_paths() {
        assert_eq!(
            Vcek::url(ProcessorGeneration::Genoa, &[0xab; 64], &TCB),
            format!(
                "https://kdsintf.amd.com/vcek/v1/Genoa/{}?blSPL=10&teeSPL=00&snpSPL=27&ucodeSPL=28",
                "ab".repeat(64)
            )
        );
        let turin = SnpTcb {
            fmc: Some(3),
            ..TCB
        };
        assert_eq!(
            Vcek::url(ProcessorGeneration::Turin, &[0xcd; 64], &turin),
            format!(
                "https://kdsintf.amd.com/vcek/v1/Turin/{}?blSPL=10&teeSPL=00&snpSPL=27&ucodeSPL=28&fmcSPL=03",
                "cd".repeat(8)
            )
        );
        assert_eq!(
            AmdCrl::url(ProcessorGeneration::Milan, AmdSigner::Asvk),
            "https://kdsintf.amd.com/vlek/v1/Milan/crl"
        );
    }
}
