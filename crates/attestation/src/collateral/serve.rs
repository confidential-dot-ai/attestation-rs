//! Serving collateral by vendor URL, for an attestation-cache: the URL
//! names the piece, the store gets and verifies it, and the vendor's bytes
//! are handed on.

use super::store::Failure;
use super::{Collateral, Store};
use crate::context::HeldResponse;

/// What the store has for a vendor URL.
#[derive(Debug)]
pub enum Served {
    /// The vendor's response, verified as the piece the URL names.
    Piece(HeldResponse),
    /// The vendor does not publish it (404).
    NotPublished(String),
    /// The only copies found do not verify.
    Refused(String),
    /// No copy, and the upstream did not answer.
    Unavailable {
        retry_after: Option<u64>,
        detail: String,
    },
    /// The URL names no piece this build knows.
    Unknown,
}

impl Store {
    /// The vendor's response for `url` (`https://{host}/{path}?{query}`),
    /// from wherever the store gets it, verified at `now`.
    pub async fn serve(&self, url: &str, now: i64) -> Served {
        #[cfg(feature = "snp")]
        {
            use super::{AmdCrl, AmdKey, Vcek};
            use crate::types::ProcessorGeneration::{Genoa, Milan, Turin};
            for generation in [Milan, Genoa, Turin] {
                for key in [AmdKey::Vcek, AmdKey::Vlek] {
                    if AmdCrl::url(&(generation, key)) == url {
                        return self.raw::<AmdCrl>(&(generation, key), now).await;
                    }
                }
            }
            if let Some(id) = vcek_id(url) {
                if Vcek::url(&id) == url {
                    return self.raw::<Vcek>(&id, now).await;
                }
            }
        }
        #[cfg(feature = "tdx")]
        {
            use super::{PckCa, PckCrl, QeIdentity, RootCrl, TcbInfo};
            if QeIdentity::url(&()) == url {
                return self.raw::<QeIdentity>(&(), now).await;
            }
            if RootCrl::url(&()) == url {
                return self.raw::<RootCrl>(&(), now).await;
            }
            for ca in [PckCa::Platform, PckCa::Processor] {
                if PckCrl::url(&ca) == url {
                    return self.raw::<PckCrl>(&ca, now).await;
                }
            }
            let fmspc = url
                .rsplit_once("fmspc=")
                .and_then(|(_, f)| hex::decode(f).ok())
                .and_then(|f| <[u8; 6]>::try_from(f).ok());
            if let Some(fmspc) = fmspc.filter(|f| TcbInfo::url(f) == url) {
                return self.raw::<TcbInfo>(&fmspc, now).await;
            }
        }
        #[cfg(any(feature = "gcp-tdx", feature = "gcp-snp"))]
        {
            use super::GceEndorsement;
            use crate::types::PlatformType;
            let measurement = url
                .rsplit_once('/')
                .and_then(|(_, file)| file.strip_suffix(".binarypb"))
                .and_then(|m| hex::decode(m).ok());
            for platform in [PlatformType::GcpTdx, PlatformType::GcpSnp] {
                if let Some(m) = &measurement {
                    let id = (platform, m.clone());
                    if GceEndorsement::url(&id) == url {
                        return self.raw::<GceEndorsement>(&id, now).await;
                    }
                }
            }
        }
        #[cfg(feature = "nvidia-gpu")]
        if url.starts_with("https://nras.attestation.nvidia.com/") && url.ends_with("/jwks.json") {
            return self.raw::<super::NrasJwks>(&url.to_string(), now).await;
        }
        let _ = (url, now);
        Served::Unknown
    }

    async fn raw<C: Collateral>(&self, id: &C::Id, now: i64) -> Served {
        let view = self.view(Vec::new(), &Default::default(), true);
        match view.lookup::<C>(id, now).await {
            Ok(_) => match view.used().pop() {
                Some(piece) => Served::Piece(piece),
                None => Served::Unknown,
            },
            Err(Failure::NotPublished(why)) => Served::NotPublished(why),
            Err(Failure::Unavailable(e)) if e.not_found() => Served::NotPublished(e.detail),
            Err(Failure::Unavailable(e)) => Served::Unavailable {
                retry_after: e.retry_after,
                detail: e.detail,
            },
            Err(Failure::Refused(why)) => Served::Refused(why),
        }
    }
}

/// The VCEK a KDS URL names: generation, CHIP_ID (Turin: the first 8 bytes,
/// zero-padded) and TCB.
#[cfg(feature = "snp")]
fn vcek_id(url: &str) -> Option<<super::Vcek as Collateral>::Id> {
    use crate::types::{ProcessorGeneration, SnpTcb};
    let rest = url.strip_prefix("https://kdsintf.amd.com/vcek/v1/")?;
    let (generation, rest) = rest.split_once('/')?;
    let (chip, query) = rest.split_once('?')?;
    let generation = [
        ProcessorGeneration::Milan,
        ProcessorGeneration::Genoa,
        ProcessorGeneration::Turin,
    ]
    .into_iter()
    .find(|g| g.product_name() == generation)?;
    let chip = hex::decode(chip).ok()?;
    let mut chip_id = [0u8; 64];
    chip_id.get_mut(..chip.len())?.copy_from_slice(&chip);
    let spl = |name: &str| {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
            .and_then(|v| v.parse::<u8>().ok())
    };
    let tcb = SnpTcb {
        bootloader: spl("blSPL")?,
        tee: spl("teeSPL")?,
        snp: spl("snpSPL")?,
        microcode: spl("ucodeSPL")?,
        fmc: spl("fmcSPL"),
    };
    Some((generation, chip_id, tcb))
}

#[cfg(all(test, feature = "snp", feature = "tdx", feature = "gcp-tdx"))]
mod tests {
    use super::*;
    use crate::testing;
    use crate::types::{PlatformType, ProcessorGeneration, SnpTcb};

    #[tokio::test]
    async fn every_kind_of_piece_is_served_by_its_vendor_url() {
        let chip_id: [u8; 64] = hex::decode(
            "b5f9a4c8280e63c97d288db6648577dc2b848884aa682d7a227ba40e50deb2b0\
             d112b599d87aaccda78d06f4254b1e81c4d953ef3c699db39d4e06013e9fa4ce",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let tcb = SnpTcb {
            bootloader: 10,
            tee: 0,
            snp: 27,
            microcode: 28,
            fmc: None,
        };
        let vcek = super::super::Vcek::url(&(ProcessorGeneration::Genoa, chip_id, tcb));
        let mrtd = hex::decode("c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5").unwrap();
        let gce = super::super::GceEndorsement::url(&(PlatformType::GcpTdx, mrtd));
        let mut held = testing::intel();
        held.push(testing::amd_crl(ProcessorGeneration::Genoa));
        held.push((
            vcek,
            testing::raw("2026-10-14/amd_vcek_genoa.der", None).0,
            None,
        ));
        held.push((
            gce,
            include_bytes!("../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb").to_vec(),
            None,
        ));
        let store = testing::context(held.clone());
        for (url, body, chain) in held {
            match store.store().serve(&url, testing::NOW).await {
                Served::Piece(piece) => assert_eq!(piece, (url, body, chain)),
                other => panic!("{url}: {other:?}"),
            }
        }
        let unknown = "https://kdsintf.amd.com/vcek/v1/Genoa/00?blSPL=1";
        assert!(matches!(
            store.store().serve(unknown, testing::NOW).await,
            Served::Unknown
        ));
    }
}
