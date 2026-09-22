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


def record_digest(recnum: int, index: int, content: bytes) -> bytes:
    return sha384(b"ats-mr-v1/record" + recnum.to_bytes(8, "little") + index.to_bytes(2, "little") + content)


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
    import json
    import sys

    out = {}
    as_json = "--json" in sys.argv[1:]

    def hx(b: bytes) -> str:
        return b.hex()

    def emit(key: str, label: str, value: bytes) -> None:
        out[key] = hx(value)
        if not as_json:
            print(label, hx(value))
    nonce = bytes(range(16))
    key = ("spki-sha256", bytes([0x11]) * 32)
    a = anchor(nonce, key)
    emit("anchor_key", "anchor (key)   ", a)
    emit("anchor_x509", "anchor (x509)  ", anchor(nonce, ("x509-tbs-sha256", bytes([0x22]) * 32)))
    emit("pad64_anchor_key", "pad64(anchor)  ", pad64(a))
    emit("nras_gpu_nonce", "gpu spdm nonce ", sha256(nonce + b"NVIDIA-GPU-EAT-v1"))
    emit("nras_switch_nonce", "switch nonce   ", sha256(nonce + b"NVIDIA-SWITCH-EAT-v1"))
    emit("seed", "seed           ", SEED)
    regs = [genesis(i) for i in range(REG_COUNT)]
    for i in (0, 3, 15):
        emit(f"genesis_{i}", f"R[{i}] genesis  ", regs[i])
    emit("header16", "header16       ", HEADER16)
    c0 = commit(regs, 0, pad64(nonce))
    emit("commit_chain0", "commit chain0  ", c0)
    emit("report_data_chain0", "report_data 0  ", HEADER16 + c0)
    content = bytes.fromhex("a3006373386301706d73746172742d636f6e7461696e65720258300102")
    d = record_digest(0, 3, content)
    regs[3] = extend(regs[3], d)
    emit("extend_content", "extend content ", content)
    emit("extend_digest", "record digest d", d)
    emit("extend_r3", "R[3] after ext ", regs[3])
    c1 = commit(regs, 1, pad64(a))
    emit("commit_chain1", "commit chain1  ", c1)
    emit("report_data_chain1", "report_data 1  ", HEADER16 + c1)
    # Section 4.9: the boot record, record 0 of the log, slot 3, bootseed 0x33 repeated 32 times.
    bootseed = bytes([0x33]) * 32
    boot = c8s_event("ats", "boot", sha384(bootseed))
    db = record_digest(0, 3, boot)
    emit("boot_content", "boot content   ", boot)
    emit("boot_digest", "boot digest d  ", db)
    emit("boot_r3", "R[3] boot only ", extend(genesis(3), db))
    emit("boot_cel_record", "boot CEL record", cel_record(0, 3, db, boot))
    # Section 4.9: the claim record, record 1 of the log, first record of workload slot 4.
    claim_body = cbor_map([(0, cbor_tstr("c8s")), (1, cbor_tstr("workload"))])
    claim = c8s_event("ats", "claim", sha384(claim_body), claim_body)
    dc = record_digest(1, 4, claim)
    emit("claim_body", "claim body     ", claim_body)
    emit("claim_content", "claim content  ", claim)
    emit("claim_digest", "claim digest d ", dc)
    emit("claim_r4", "R[4] claim only", extend(genesis(4), dc))
    emit("claim_cel_record", "claim CEL rec  ", cel_record(1, 4, dc, claim))
    if as_json:
        out["nonce"] = hx(nonce)
        out["key_spki_value"] = hx(key[1])
        out["key_x509_value"] = hx(bytes([0x22]) * 32)
        out["bootseed"] = hx(bootseed)
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
