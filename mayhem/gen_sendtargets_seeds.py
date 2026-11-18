#!/usr/bin/env python3
"""Regenerates mayhem/fuzz_sendtargets/testsuite/ (target-side byte streams for fuzz_sendtargets.c).

Seed layout: 1 selector byte (bits 0-1 auth: 0 none, 1 CHAP, 2 mutual CHAP), then the Login
Response PDUs a target would send, then the Text Response PDUs carrying its SendTargets answer.
"""
import os
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_login_seeds import CHAP, CHAP_MUTUAL, FFP, OPN, OPS, SEC, kv, login_rsp  # noqa: E402

FINAL = 0x80
NO_TTT = 0xFFFFFFFF
T1 = "iqn.2001-04.com.example:storage.disk1"
T2 = "iqn.2001-04.com.example:storage.disk2"


def text_rsp(data, final=True, ttt=NO_TTT, statsn=2):
    hdr = struct.pack(">BBHB3s8sIIIII12s", 0x24, FINAL if final else 0, 0, 0,
                      len(data).to_bytes(3, "big"), b"", 0, ttt, statsn, 2, 2, b"")
    assert len(hdr) == 48, len(hdr)
    return hdr + data + b"\0" * (-len(data) % 4)


def tgt(name, *addrs):
    return kv(("TargetName", name), *[("TargetAddress", a) for a in addrs])


LOGIN = login_rsp(OPN, FFP, True, OPS)
TWO = tgt(T1, "10.1.2.3:3261,2") + tgt(T2, "[::1]:3262,5", "192.0.2.9,7")

SEEDS = {
    "two_targets": bytes([0x00]) + LOGIN + text_rsp(TWO),
    "default_portal": bytes([0x00]) + LOGIN + text_rsp(kv(("TargetName", T1))),
    "split_record": bytes([0x00]) + LOGIN + text_rsp(TWO[:50], final=False, ttt=0x1234) +
                    text_rsp(TWO[50:90], final=False, ttt=0x1234) + text_rsp(TWO[90:]),
    "split_per_target": bytes([0x00]) + LOGIN + text_rsp(tgt(T1, "10.1.2.3"), final=False, ttt=7) +
                        text_rsp(tgt(T2, "10.4.5.6:3260,1")),
    "bad_records": bytes([0x00]) + LOGIN + text_rsp(kv(("TargetName", "not-an-iqn"), ("TargetAddress", "1.2.3.4")) +
                                                    kv(("Stray", "value")) + tgt(T2, "no.such.host:99999,x")),
    "chap_then_targets": bytes([0x01]) + login_rsp(SEC, SEC, False, kv(("AuthMethod", "CHAP"))) +
                         login_rsp(SEC, SEC, False, CHAP) + login_rsp(SEC, OPN, True, b"") +
                         login_rsp(OPN, FFP, True, OPS) + text_rsp(tgt(T1, "10.1.2.3")),
    "mutual_chap": bytes([0x02]) + login_rsp(SEC, SEC, False, kv(("AuthMethod", "CHAP"))) +
                   login_rsp(SEC, SEC, False, CHAP) + login_rsp(SEC, SEC, True, CHAP_MUTUAL),
    "redirect": bytes([0x00]) + login_rsp(OPN, OPN, True, kv(("TargetAddress", "127.0.0.1:3261,1")),
                                          status=(1, 1)),
}


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "mayhem/fuzz_sendtargets/testsuite")
