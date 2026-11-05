# Layer 16: certificate pattern and CBOR (experimental)

Section 5.5 and Appendix A, and the CBOR rules that Sections 4.1, 4.7 and 4.8 carry from layer 4: evidence carried in an X.509 certificate, and the CBOR encoding of evidence. The reference implementation accepts the certificate pattern when the relying party supplies the certificate's digest; it has no parser for the certificate extension and no CBOR entry point. One entry is open.

### CRT-1. Evidence in a certificate rides in `id-pe-cmw`

A certificate carries the envelope in the `id-pe-cmw` extension of RFC 9999, in its `json` choice, as the CMW record `[type, value, 4]` typed `application/eat-ucs+json` with the profile parameter. A certificate with more than one such extension is refused.

- Why: `id-pe-cmw` is the extension RFC 9999 defines for carrying RATS messages in a certificate, so a TLS stack that knows it finds the evidence without a private OID.
- Rejected: the private OID arcs in use (dstack's `1.3.6.1.4.1.62397.1`), which are outside the profile.
- Where: Section 5.5.

### CRT-2. The certificate's binding value excludes the extension that carries the evidence

`x509-tbs-sha256` is the SHA-256 of the DER `TBSCertificate` with the `id-pe-cmw` extension removed: the remaining extensions keep their order and encoding, and the enclosing lengths are re-encoded.

- Why: the evidence binds the certificate's digest, so the extension that holds the evidence cannot be inside that digest.
- Where: Sections 5.3, 5.5. No vector exists for the re-encoding yet (`UNCOVERED.md`).

### CRT-3. The relying party supplies the certificate's digest

The relying party computes the digest from the certificate it was presented and gives it to the verifier, which never takes it from the evidence and refuses the `certificate` pattern without it. A version 1 verifier emits no `not_before` or `not_after`, since it never sees the certificate.

- Why: the digest in the evidence is the attester's claim. Only the party that holds the presented certificate can say which certificate the evidence must match.
- Where: Sections 3.2, 5.1, 5.5. Case: `snp-certificate-pattern-without-presented-certificate`. BND-8 (layer 5) is open on how the digest reaches the verifier.

### CBR-1. CBOR is a second encoding of the same claims

In CBOR the envelope is a UCCS under tag 601. EAT's own claims use their registered keys, the profile's claims use integer keys below -65536 (Appendix A), and names inside profile objects stay text. An attester writes deterministic encoding with definite lengths.

- Why: constrained and CBOR-native stacks (COSE, CoRIM, the Arm CCA token) should not need a JSON parser. JSON stays primary because every current attester and relying party of this profile speaks it.
- Where: Sections 4.1, 4.7, 4.8, Appendix A. CON-6 (layer 17) is open on registering the keys.

### CBR-2. A CBOR verifier refuses anything but one encoding (open)

Today Section 4.7 requires a verifier to refuse a CBOR envelope that lacks tag 601, uses an indefinite length, repeats a map key or is not in deterministic encoding. RFC 8949 asks this of an encoder and leaves a decoder free to accept more.

- Options: (a) refuse, as today; (b) accept any well-formed CBOR and compare decoded values.
- Recommendation: (a). It is the JSON rule of ENV-7 applied to CBOR, and it keeps two verifiers from reading different claims out of the same bytes. The cost is that an attester using a generic CBOR library must enable its deterministic mode.
- If accepted: no change. The rule has no implementation and no case until a CBOR entry point exists.
