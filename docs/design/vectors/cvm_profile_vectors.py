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


SEED = sha384(b"ats-mr-v1/seed")            # recommended constant seed, decision 1
REG_COUNT = 16
HEADER16 = b"ATS-MR-1" + bytes([1, 1, REG_COUNT, 0]) + bytes(4)   # section 4.9


def genesis(i: int, seed: bytes = SEED) -> bytes:
    return sha384(bytes(48) + b"ats-mr-v1/genesis" + seed + bytes([i]))


def extend(r: bytes, d: bytes) -> bytes:
    return sha384(r + d)


def commit(regs, chain_len: int, caller_data: bytes) -> bytes:
    assert len(regs) == REG_COUNT and all(len(r) == 48 for r in regs) and len(caller_data) == 64
    return sha384(b"ats-mr-v1/commit" + b"".join(regs) + chain_len.to_bytes(8, "little") + caller_data)


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


if __name__ == "__main__":
    main()
