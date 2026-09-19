//! The unified collateral cache against loopback vendors: single flight,
//! backoff, signing-chain capture, validity-driven serving, the disk store,
//! and the real verifier end to end with Intel's own collateral.

use attestation::collateral::{
    CachePolicy, CollateralCache, CollateralError, CollateralKey, CollateralKind, DiskStore,
    Endpoints, Fetcher, PckCa,
};
use attestation::{ProcessorGeneration, SnpTcb, TdxCollateralProvider};
use chrono::{DateTime, TimeZone, Utc};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const INTEL_TCB_INFO: &[u8] = include_bytes!("../test_data/collateral/tcb_info_50806f000000.json");
const INTEL_TD_QE_IDENTITY: &[u8] = include_bytes!("../test_data/collateral/td_qe_identity.json");
const INTEL_TCB_SIGNING_CHAIN: &[u8] =
    include_bytes!("../test_data/collateral/tcb_signing_chain.pem");
const INTEL_PCK_CRL: &[u8] = include_bytes!("../test_data/collateral/pck_crl_platform.der");
const INTEL_ROOT_CA_CRL: &[u8] = include_bytes!("../test_data/collateral/root_ca_crl.der");
const GENOA_VCEK: &[u8] = include_bytes!("../test_data/snp/live-vcek-genoa.der");
#[cfg(feature = "tdx")]
const V4_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");

/// The Intel fixtures were captured on 2026-03-16 and expire on 2026-04-15.
fn fixture_clock() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 17, 0, 0, 0).unwrap()
}

/// What the loopback vendor serves per path. `chain` is the PEM sent in the
/// Intel issuer-chain headers; `None` sends no header. `delay` holds every
/// response so concurrent requests overlap. `fail_after` turns the endpoint
/// into a 500 after that many requests.
#[derive(Clone)]
struct Vendor {
    tcb_info: Vec<u8>,
    td_qe_identity: Vec<u8>,
    pck_crl: Vec<u8>,
    root_ca_crl: Vec<u8>,
    chain: Option<String>,
    vcek: Vec<u8>,
    delay: Duration,
    fail_after: Option<usize>,
}

impl Vendor {
    fn intel() -> Self {
        Vendor {
            tcb_info: INTEL_TCB_INFO.to_vec(),
            td_qe_identity: INTEL_TD_QE_IDENTITY.to_vec(),
            pck_crl: INTEL_PCK_CRL.to_vec(),
            root_ca_crl: INTEL_ROOT_CA_CRL.to_vec(),
            chain: Some(String::from_utf8(INTEL_TCB_SIGNING_CHAIN.to_vec()).unwrap()),
            vcek: GENOA_VCEK.to_vec(),
            delay: Duration::ZERO,
            fail_after: None,
        }
    }
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Loopback vendor: one origin for AMD KDS, Intel PCS and the Intel CRL host.
async fn vendor(routes: Vendor) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let routes = routes.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = sock.into_split();
                let mut lines = BufReader::new(rd).lines();
                let request_line = lines.next_line().await.ok().flatten().unwrap_or_default();
                while let Ok(Some(l)) = lines.next_line().await {
                    if l.is_empty() {
                        break;
                    }
                }
                tokio::time::sleep(routes.delay).await;
                let path = request_line.split(' ').nth(1).unwrap_or("");
                let failing = routes.fail_after.is_some_and(|k| n > k);
                let (status, header, body): (&str, Option<&str>, &[u8]) = if failing {
                    ("500 Internal Server Error", None, &[])
                } else if path.starts_with("/tdx/certification/v4/tcb") {
                    ("200 OK", Some("TCB-Info-Issuer-Chain"), &routes.tcb_info)
                } else if path.starts_with("/tdx/certification/v4/qe/identity") {
                    (
                        "200 OK",
                        Some("SGX-Enclave-Identity-Issuer-Chain"),
                        &routes.td_qe_identity,
                    )
                } else if path.starts_with("/sgx/certification/v4/pckcrl") {
                    ("200 OK", None, &routes.pck_crl)
                } else if path.starts_with("/IntelSGXRootCA.der") {
                    ("200 OK", None, &routes.root_ca_crl)
                } else if path.contains("/Genoa/") && path.contains("blSPL=") {
                    ("200 OK", None, &routes.vcek)
                } else {
                    ("404 Not Found", None, &[])
                };
                let mut head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if let (Some(h), Some(chain)) = (header, &routes.chain) {
                    head.push_str(&format!("{h}: {}\r\n", percent_encode(chain)));
                }
                head.push_str("\r\n");
                let _ = wr.write_all(head.as_bytes()).await;
                let _ = wr.write_all(body).await;
            });
        }
    });
    (format!("http://{addr}"), hits)
}

fn cache_with_clock(
    origin: &str,
    policy: CachePolicy,
    store: Option<DiskStore>,
    clock: attestation::collateral::Clock,
) -> Arc<CollateralCache> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let fetcher = Fetcher::with_client(client, Endpoints::default().with_upstream_override(origin));
    Arc::new(CollateralCache::with_fetcher(policy, fetcher, store).with_clock(clock))
}

/// A cache whose clock sits at the fixtures' capture time.
fn cache_at(origin: &str, policy: CachePolicy, store: Option<DiskStore>) -> Arc<CollateralCache> {
    cache_with_clock(origin, policy, store, Arc::new(fixture_clock))
}

fn dials(c: &Arc<AtomicUsize>) -> usize {
    c.load(Ordering::SeqCst)
}

#[tokio::test]
async fn concurrent_gets_share_one_upstream_request() {
    let (origin, hits) = vendor(Vendor {
        delay: Duration::from_millis(300),
        ..Vendor::intel()
    })
    .await;
    let cache = cache_at(&origin, CachePolicy::default(), None);
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let cache = cache.clone();
        tasks.push(tokio::spawn(async move {
            cache
                .get(&CollateralKey::TdxRootCrl)
                .await
                .map(|c| c.bytes.len())
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap().unwrap(), INTEL_ROOT_CA_CRL.len());
    }
    assert_eq!(
        dials(&hits),
        1,
        "sixteen concurrent gets must cost one fetch"
    );
    assert_eq!(cache.count(CollateralKind::TdxRootCrl), 1);
}

#[tokio::test]
async fn a_failed_fetch_backs_off_instead_of_dialling_per_request() {
    let (origin, hits) = vendor(Vendor {
        fail_after: Some(0),
        ..Vendor::intel()
    })
    .await;
    let cache = cache_at(
        &origin,
        CachePolicy {
            backoff_base: Duration::from_secs(300),
            ..CachePolicy::default()
        },
        None,
    );
    let first = cache.get(&CollateralKey::TdxRootCrl).await.unwrap_err();
    assert!(matches!(first, CollateralError::Fetch { .. }), "{first}");
    let second = cache.get(&CollateralKey::TdxRootCrl).await.unwrap_err();
    assert!(
        matches!(second, CollateralError::Backoff { consecutive: 1, .. }),
        "{second}"
    );
    assert_eq!(dials(&hits), 1);

    let (origin, hits) = vendor(Vendor {
        fail_after: Some(0),
        ..Vendor::intel()
    })
    .await;
    let always = cache_at(
        &origin,
        CachePolicy {
            backoff_base: Duration::ZERO,
            ..CachePolicy::default()
        },
        None,
    );
    for _ in 0..3 {
        assert!(always.get(&CollateralKey::TdxRootCrl).await.is_err());
    }
    assert_eq!(dials(&hits), 3, "a zero base dials every time");
}

#[tokio::test]
async fn signed_bodies_carry_their_chain_and_unsigned_ones_are_refused() {
    let (origin, _) = vendor(Vendor::intel()).await;
    let cache = cache_at(&origin, CachePolicy::default(), None);
    let key = CollateralKey::tdx_tcb_info("50806F000000").unwrap();
    let tcb = cache.get(&key).await.unwrap();
    assert_eq!(tcb.signing_chain.as_deref(), Some(INTEL_TCB_SIGNING_CHAIN));
    assert_eq!(
        tcb.valid_until,
        Some(Utc.with_ymd_and_hms(2026, 4, 15, 22, 21, 30).unwrap())
    );
    assert_eq!(
        cache.get_tcb_signing_chain().await.unwrap().as_deref(),
        Some(INTEL_TCB_SIGNING_CHAIN)
    );
    let qe = cache
        .get(&CollateralKey::TdxQeIdentity { td: true })
        .await
        .unwrap();
    assert!(qe.signing_chain.is_some());
    assert_eq!(
        cache
            .get_td_qe_identity_signing_chain()
            .await
            .unwrap()
            .as_deref(),
        Some(INTEL_TCB_SIGNING_CHAIN)
    );

    let (origin, _) = vendor(Vendor {
        chain: None,
        ..Vendor::intel()
    })
    .await;
    let cache = cache_at(&origin, CachePolicy::default(), None);
    let err = cache.get(&key).await.unwrap_err();
    assert!(matches!(err, CollateralError::Unsigned { .. }), "{err}");
    assert!(err.to_string().contains("refusing unsigned collateral"));
    assert_eq!(
        cache.count(CollateralKind::TdxTcbInfo),
        0,
        "nothing unsigned enters the cache"
    );
    assert!(
        cache.get_tcb_signing_chain().await.is_err(),
        "no chain without a body"
    );
}

#[tokio::test]
async fn a_copy_inside_its_window_outlives_a_vendor_outage() {
    let (origin, hits) = vendor(Vendor {
        fail_after: Some(1),
        ..Vendor::intel()
    })
    .await;
    // Real clock: the max age must actually elapse, and the root CRL fixture
    // is inside its window until 2027.
    let cache = cache_with_clock(
        &origin,
        CachePolicy {
            max_age_crl: Duration::from_millis(50),
            backoff_base: Duration::ZERO,
            ..CachePolicy::default()
        },
        None,
        Arc::new(Utc::now),
    );
    let first = cache.get(&CollateralKey::TdxRootCrl).await.unwrap();
    assert_eq!(dials(&hits), 1);
    // Past its max age: a refetch is attempted, fails, and the copy inside
    // its window (valid until 2027) is served.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(cache.status().entries[0].stale);
    let again = cache.get(&CollateralKey::TdxRootCrl).await.unwrap();
    assert_eq!(
        dials(&hits),
        2,
        "the stale copy triggers one refetch attempt"
    );
    assert_eq!(again.bytes, first.bytes);
    assert_eq!(
        again.fetched_at, first.fetched_at,
        "the old copy, not a new one"
    );
}

#[tokio::test]
async fn an_artifact_past_its_own_window_is_refused() {
    let (origin, _) = vendor(Vendor::intel()).await;
    let client = reqwest::Client::new();
    let fetcher =
        Fetcher::with_client(client, Endpoints::default().with_upstream_override(&origin));
    let late = Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap();
    let cache = Arc::new(
        CollateralCache::with_fetcher(CachePolicy::default(), fetcher, None)
            .with_clock(Arc::new(move || late)),
    );
    let err = cache
        .get(&CollateralKey::TdxPckCrl {
            ca: PckCa::Platform,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, CollateralError::Expired { .. }), "{err}");
    // The root CRL runs to 2027 and is fine at that clock.
    cache.get(&CollateralKey::TdxRootCrl).await.unwrap();
}

#[tokio::test]
async fn the_disk_store_survives_a_restart_and_reads_the_legacy_chain_layout() {
    let dir = tempfile::tempdir().unwrap();
    let (origin, hits) = vendor(Vendor::intel()).await;
    let key = CollateralKey::SnpVcek {
        generation: ProcessorGeneration::Genoa,
        chip_id: [0xab; 64],
        tcb: SnpTcb {
            bootloader: 3,
            tee: 0,
            snp: 10,
            microcode: 27,
            fmc: None,
        },
    };
    let cache = cache_at(
        &origin,
        CachePolicy::default(),
        Some(DiskStore::new(dir.path())),
    );
    let vcek = cache.get(&key).await.unwrap();
    assert_eq!(vcek.bytes, GENOA_VCEK);
    assert_eq!(dials(&hits), 1);
    assert!(
        dir.path().join("vcek/Genoa").exists(),
        "legacy VCEK layout is kept"
    );

    // A cold process with no network serves the stored copy.
    let cold = cache_at(
        "http://127.0.0.1:1",
        CachePolicy::default(),
        Some(DiskStore::new(dir.path())),
    );
    let stored = cold.get(&key).await.unwrap();
    assert_eq!(stored.bytes, GENOA_VCEK);
    assert_eq!(stored.origin, attestation::collateral::Origin::Stored);

    // A TCB Info body is stored with its chain; a copy without a chain is not served.
    let tcb_key = CollateralKey::tdx_tcb_info("50806f000000").unwrap();
    cache.get(&tcb_key).await.unwrap();
    let again = cold.get(&tcb_key).await.unwrap();
    assert_eq!(
        again.signing_chain.as_deref(),
        Some(INTEL_TCB_SIGNING_CHAIN)
    );
    std::fs::remove_file(dir.path().join("tdx_tcb_info/50806f000000.meta.json")).unwrap();
    let cold2 = cache_at(
        "http://127.0.0.1:1",
        CachePolicy::default(),
        Some(DiskStore::new(dir.path())),
    );
    assert!(
        cold2.get(&tcb_key).await.is_err(),
        "a stored body without its chain is not served"
    );
}

#[cfg(feature = "snp")]
#[tokio::test]
async fn a_legacy_chain_on_disk_is_read_as_one_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let (ark, ask) =
        attestation::platforms::snp::certs::get_bundled_certs(ProcessorGeneration::Genoa);
    let gen_dir = dir.path().join("chain/Genoa");
    std::fs::create_dir_all(&gen_dir).unwrap();
    std::fs::write(gen_dir.join("ark.der"), ark).unwrap();
    std::fs::write(gen_dir.join("ask.der"), ask).unwrap();
    let store = DiskStore::new(dir.path());
    let chain = store
        .get(
            &CollateralKey::SnpCertChain {
                generation: ProcessorGeneration::Genoa,
            },
            fixture_clock(),
        )
        .expect("legacy layout is readable");
    let (ark2, ask2) = chain.snp_chain_parts().unwrap();
    assert_eq!((ark2.as_slice(), ask2.as_slice()), (ark, ask));
    std::fs::remove_file(gen_dir.join("ask.der")).unwrap();
    assert!(
        store
            .get(
                &CollateralKey::SnpCertChain {
                    generation: ProcessorGeneration::Genoa
                },
                fixture_clock()
            )
            .is_none(),
        "a half-written chain must not be served"
    );
}

#[cfg(feature = "tdx")]
mod end_to_end {
    use super::*;
    use base64::Engine;

    fn v4_envelope() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "platform": "tdx",
            "evidence": { "quote": base64::engine::general_purpose::STANDARD.encode(V4_QUOTE) },
        }))
        .unwrap()
    }

    async fn verify_through(v: Vendor) -> attestation::Result<attestation::VerificationResult> {
        let (origin, _) = vendor(v).await;
        let cache = cache_at(&origin, CachePolicy::default(), None);
        let verifier = attestation::Verifier::new().with_collateral(cache);
        // The v4 fixture was minted with the TD debug attribute set.
        let params = attestation::VerifyParams {
            allow_debug: true,
            ..Default::default()
        };
        verifier.verify(&v4_envelope(), &params).await
    }

    #[tokio::test]
    async fn intel_signed_collateral_verifies_through_the_shared_cache() {
        let result = verify_through(Vendor::intel())
            .await
            .expect("the v4 quote with Intel's own collateral must verify");
        assert!(result.collateral_verified);
        assert!(result.tcb_status.is_some());
    }

    #[tokio::test]
    async fn a_tcb_info_intel_did_not_sign_is_rejected() {
        let mut v = Vendor::intel();
        v.tcb_info = String::from_utf8(v.tcb_info)
            .unwrap()
            .replacen("\"pceId\":\"0000\"", "\"pceId\":\"0001\"", 1)
            .into_bytes();
        assert_ne!(v.tcb_info, INTEL_TCB_INFO);
        let err = verify_through(v)
            .await
            .expect_err("tampered TCB Info must fail");
        assert!(
            err.to_string()
                .contains("TCB Info signature verification failed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn collateral_served_without_its_chain_fails_the_verification() {
        let err = verify_through(Vendor {
            chain: None,
            ..Vendor::intel()
        })
        .await
        .expect_err("unsigned collateral must fail closed");
        assert!(
            err.to_string().contains("refusing unsigned collateral"),
            "{err}"
        );
    }
}
