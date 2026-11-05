# Statements without a case

Normative statements of the standard (`docs/standard/cvm-attestation-v1.md`,
sections 4 to 13 and 15.9) that no case in `cases/` exercises yet, with what closes
each. The list shrinks; an entry is removed in the commit that adds its case.
Most rows need evidence the hardware signs, since changing a signed report
exercises its signature and not the rule.

| Section | Statement | What closes it |
| --- | --- | --- |
| 5.1, 5.2, 5.3 | an appraisal bound through a key (`spki-sha256`, `x509-tbs-sha256`, `raw`), and the certificate pattern's `not_before` and `not_after` | a recording made with a key binding; every refusal these rules make has a case |
| 11 | step 6: `revoked` | a CRL that revokes a certificate we hold, which no vendor has issued |
| 4.1, 11 | step 1: an `eat_nonce` that differs from the relying party's nonce is refused with `binding-mismatch` | a relying-party nonce in the case format; the reference implementation enforces the rule in its service, CLI and WebAssembly entry points |
