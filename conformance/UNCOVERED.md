# Statements without a case

Normative statements of the standard (`docs/standard/cvm-attestation-v1.md`,
sections 4 to 13 and 15.9) that no case in `cases/` exercises yet, with what closes
each. The list shrinks; an entry is removed in the commit that adds its case.
Most rows need evidence the hardware signs, since changing a signed report
exercises its signature and not the rule.

| Section | Statement | What closes it |
| --- | --- | --- |
| 5.1, 5.2, 5.3 | an appraisal bound through a key (`spki-sha256`, `x509-tbs-sha256`, `raw`), and the certificate pattern's `not_before` and `not_after` | a recording made with a key binding; every refusal these rules make has a case |
| 9.1.2, 9.1.3 | report versions 2 and 6; a Turin part of any model | recordings of a version 2 report, of a version 6 report and of a Turin part; the corpus holds version 3 and version 5 reports of family 0x19 only, and the reference implementation's unit tests cover the version 2 generation rule, the version 6 layout and the Turin models |
| 9.1.2, 9.1.4 | `SIGNATURE_ALGO` other than 1; `KEY_INFO` reserved bits, `MASK_CHIP_KEY` and `SIGNING_KEY` values other than 0 and 1; a non-zero byte in a reserved range; the two encodings of the VCEK hardware ID | a genuine report with those values, which AMD firmware does not sign; changing a signed report exercises the signature, and the reference implementation's unit tests cover each |
| 9.1.4 | the ASK or ASVK serial against the CRL; the ARK and ASK or ASVK windows | a CRL that revokes a current intermediate, and an evaluation time inside the VEK's window but outside its chain's, neither of which exists; the unit tests use AMD's Genoa CRL, which revokes the original Genoa ASK (serial 020001), and the pinned roots' windows |
| 9.1.4 | step 4: a VEK cross-check failure is `chain-invalid`, and a Turin VEK without the FMC extension is refused | no genuine input isolates either rule: AMD derives a VEK from the TCB it certifies, so a VCEK for the report's chip at another TCB (one fetched from KDS was tried) fails the report signature first, and AMD issues no Turin VCEK without the extension; the reference implementation's unit tests cover both against minted certificates |
| 10.1, 10.2 | inline `snp.crl` and `nras.jwks`; an appraisal from inline TDX collateral; an inline artifact outside its window ignored in favor of the verifier's copy; the verifier's own valid copy preferred to a valid inline one (item 4) | cases that carry each artifact inline, and two vendor-signed artifacts of different ages whose windows overlap |
| 11 | step 6: `revoked` | a CRL that revokes a certificate we hold, which no vendor has issued |
| 4.1, 11 | step 1: an `eat_nonce` that differs from the relying party's nonce is refused with `binding-mismatch` | a relying-party nonce in the case format; the reference implementation enforces the rule in its service, CLI and WebAssembly entry points |
| 8.5, 9.1.5 | a report whose `VMPL` is above 3 (host-requested) is refused whatever the policy says | a recording of a host-requested report |
