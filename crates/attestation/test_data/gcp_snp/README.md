# GCP SEV-SNP and GCE launch endorsement fixtures

- `evidence-boot1.json`: SEV-SNP evidence from a GCE n2d-standard-2 Confidential
  VM (`SEV_SNP`, AMD Milan, 2 vCPUs, us-central1-a), collected 2026-10-11 with
  `POST /attest {"platform":"snp"}` on attestation-api. The `cert_chain` (VCEK,
  ASK, ARK) is the host-supplied one, so it verifies offline. The envelope says
  `snp`; tests use its `evidence` as gcp-snp evidence (the tag is an attester
  claim). MEASUREMENT `0e017d2f...a2de00f`, guest policy 0x30000, REPORT_DATA a
  random nonce.
- `endorsement-0e017d2f.binarypb`: Google's launch endorsement for that
  MEASUREMENT, `gcloud storage cp
  gs://gce_tcb_integrity/ovmf_x64_csm/sevsnp/0e017d2fba7c4964575fdd8c770061abf07f0753148d030f94e969a2d1fa5a5747ba0ced9174f2d44b5f6663fa2de00f.binarypb`
  (2026-10-12). It lists the measurement for 2 VMSAs.
- `../gcp_tdx/endorsement-c1ee9c16.binarypb`: the endorsement for the MRTD of
  `../gcp_tdx/boot-quote.dat`, from
  `gs://gce_tcb_integrity/ovmf_x64_csm/tdx/c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5.binarypb`
  (2026-10-12).

Both endorsements verify with `gcetcbendorsement verify` from
github.com/google/gce-tcb-verifier @4092757. They are for two different OVMF
builds, so each is a real "wrong build" endorsement for the other platform's
evidence. Their signing certificate (CN GCE-uefi-signer, serial 30) is valid
2026-05-05 to 2031-05-05.
