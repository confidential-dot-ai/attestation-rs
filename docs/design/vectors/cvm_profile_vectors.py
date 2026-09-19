#!/usr/bin/env python3
"""Regenerates the test vectors in docs/design/cvm-attestation-profile-v1.md, Appendix B.

Every formula is written out with the exact byte strings the profile specifies,
so a reader can diff this file against the document and an implementation in
another language can check itself against the printed values.
"""
import hashlib


def sha384(b: bytes) -> bytes:
    return hashlib.sha384(b).digest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def pad64(x: bytes) -> bytes:
    assert len(x) <= 64
    return x + bytes(64 - len(x))


def anchor(nonce: bytes, key=None) -> bytes:
    """Section 4.5."""
    if key is None:
        return nonce
    kind, value = key
    kind = kind.encode("ascii")
    assert 16 <= len(nonce) <= 64 and len(kind) <= 255 and len(value) <= 65535
    return sha384(
        b"ats-anchor-v1"
        + bytes([len(nonce)]) + nonce
        + bytes([len(kind)]) + kind
        + len(value).to_bytes(2, "big") + value
    )


SEED = sha384(b"ats-mr-v1/seed")            # the constant genesis seed, section 4.9
REG_COUNT = 16
HEADER16 = b"ATS-MR-1" + bytes([1, 1, REG_COUNT, 0]) + bytes(4)   # section 4.9


def genesis(i: int, seed: bytes = SEED) -> bytes:
    return sha384(bytes(48) + b"ats-mr-v1/genesis" + seed + bytes([i]))


def extend(r: bytes, d: bytes) -> bytes:
    return sha384(r + d)


def commit(regs, chain_len: int, caller_data: bytes) -> bytes:
    assert len(regs) == REG_COUNT and all(len(r) == 48 for r in regs) and len(caller_data) == 64
    return sha384(b"ats-mr-v1/commit" + b"".join(regs) + chain_len.to_bytes(8, "little") + caller_data)


def cbor_head(major: int, n: int) -> bytes:
    """Shortest-form head, RFC 8949 section 4.2.1."""
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    raise ValueError("no vector needs a longer length")


def cbor_uint(n: int) -> bytes:
    return cbor_head(0, n)


def cbor_tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return cbor_head(3, len(b)) + b


def cbor_bstr(b: bytes) -> bytes:
    return cbor_head(2, len(b)) + b


def cbor_map(pairs) -> bytes:
    """Map with unsigned integer keys; deterministic order is by encoded key, length first."""
    enc = [(cbor_uint(k), v) for k, v in pairs]
    assert [k for k, _ in enc] == sorted((k for k, _ in enc), key=lambda k: (len(k), k))
    return cbor_head(5, len(enc)) + b"".join(k + v for k, v in enc)


def c8s_event(domain: str, operation: str, content_digest: bytes, content: bytes | None = None) -> bytes:
    """Section 4.8: the content bytes of one runtime event record."""
    pairs = [(0, cbor_tstr(domain)), (1, cbor_tstr(operation)), (2, cbor_bstr(content_digest))]
    if content is not None:
        pairs.append((3, cbor_bstr(content)))
    return cbor_map(pairs)


CVM_CONTENT_TYPE = 200      # CEL content type `cvm`, section 4.8 (decision 3)
TPM_ALG_SHA384 = 0x000C


def cel_record(recnum: int, slot: int, d: bytes, content: bytes) -> bytes:
    """Section 4.8: one CEL-CBOR record {0: recnum, 1: pcr, 3: digests, 200: content}."""
    digests = cbor_head(4, 1) + cbor_map([(0, cbor_uint(TPM_ALG_SHA384)), (1, cbor_bstr(d))])
    return cbor_map([(0, cbor_uint(recnum)), (1, cbor_uint(slot)), (3, digests), (CVM_CONTENT_TYPE, cbor_bstr(content))])


def main() -> None:
    hx = bytes.hex
    nonce = bytes(range(16))
    key = ("spki-sha256", bytes([0x11]) * 32)
    a = anchor(nonce, key)
    print("anchor (key)   ", hx(a))
    print("anchor (x509)  ", hx(anchor(nonce, ("x509-tbs-sha256", bytes([0x22]) * 32))))
    print("pad64(anchor)  ", hx(pad64(a)))
    print("gpu spdm nonce ", hx(sha256(nonce + b"NVIDIA-GPU-EAT-v1")))
    print("switch nonce   ", hx(sha256(nonce + b"NVIDIA-SWITCH-EAT-v1")))
    print("seed           ", hx(SEED))
    regs = [genesis(i) for i in range(REG_COUNT)]
    for i in (0, 3, 15):
        print(f"R[{i}] genesis  ", hx(regs[i]))
    print("header16       ", hx(HEADER16))
    c0 = commit(regs, 0, pad64(nonce))
    print("commit chain0  ", hx(c0))
    print("report_data 0  ", hx(HEADER16 + c0))
    content = bytes.fromhex("a3006373386301706d73746172742d636f6e7461696e65720258300102")
    d = sha384(content)
    regs[3] = extend(regs[3], d)
    print("record digest d", hx(d))
    print("R[3] after ext ", hx(regs[3]))
    c1 = commit(regs, 1, pad64(a))
    print("commit chain1  ", hx(c1))
    print("report_data 1  ", hx(HEADER16 + c1))
    # Section 4.9: the boot record, record 0 of the log, slot 3, bootseed 0x33 repeated 32 times.
    bootseed = bytes([0x33]) * 32
    boot = c8s_event("ats", "boot", sha384(bootseed))
    db = sha384(boot)
    print("boot content   ", hx(boot))
    print("boot digest d  ", hx(db))
    print("R[3] boot only ", hx(extend(genesis(3), db)))
    print("boot CEL record", hx(cel_record(0, 3, db, boot)))
    # Section 4.9: the claim record, record 1 of the log, first record of workload slot 4.
    claim_body = cbor_map([(0, cbor_tstr("c8s")), (1, cbor_tstr("workload"))])
    claim = c8s_event("ats", "claim", sha384(claim_body), claim_body)
    dc = sha384(claim)
    print("claim body     ", hx(claim_body))
    print("claim content  ", hx(claim))
    print("claim digest d ", hx(dc))
    print("R[4] claim only", hx(extend(genesis(4), dc)))
    print("claim CEL rec  ", hx(cel_record(1, 4, dc, claim)))


if __name__ == "__main__":
    main()
