#!/usr/bin/env python3
"""Regenerates mayhem/fuzz_iscsi_login/testsuite/ (target-side byte streams for fuzz_iscsi_login.c).

Seed layout: 1 selector byte (bits 0-1 auth: 0 none, 1 CHAP, 2 mutual CHAP; bit 2 digests
preferred; bit 3 rdma transport; bit 4 normal session instead of discovery), then the
concatenated Login Response PDUs a target would send.
"""
import os
import struct
import sys

SEC, OPN, FFP = 0, 1, 3


def kv(*pairs):
    return b"".join(k.encode() + b"=" + (v if isinstance(v, bytes) else v.encode()) + b"\0" for k, v in pairs)


def login_rsp(csg, nsg, transit, data, status=(0, 0), tsih=0, statsn=0, version=0):
    flags = (0x80 if transit else 0) | (csg << 2) | nsg
    hdr = struct.pack(">BBBBB3s6sHIIIIIBB10s", 0x23, flags, 0, version, 0,
                      len(data).to_bytes(3, "big"), bytes([0, 2, 0x3D, 0, 0, 0]), tsih,
                      0, 0, statsn, 1, 1, status[0], status[1], b"")
    assert len(hdr) == 48, len(hdr)
    return hdr + data + b"\0" * (-len(data) % 4)


OPS = kv(("HeaderDigest", "None"), ("DataDigest", "None"), ("MaxRecvDataSegmentLength", "8192"),
         ("MaxBurstLength", "262144"), ("FirstBurstLength", "65536"), ("DefaultTime2Wait", "2"),
         ("DefaultTime2Retain", "0"), ("MaxOutstandingR2T", "1"), ("InitialR2T", "Yes"),
         ("ImmediateData", "Yes"), ("DataPDUInOrder", "Yes"), ("DataSequenceInOrder", "Yes"),
         ("ErrorRecoveryLevel", "0"), ("MaxConnections", "1"), ("TargetPortalGroupTag", "1"))
CHAP = kv(("CHAP_A", "5"), ("CHAP_I", "77"), ("CHAP_C", "0x" + "ab" * 16))
CHAP_MUTUAL = kv(("CHAP_N", "target-user"), ("CHAP_R", "0x" + "cd" * 16))

SEEDS = {
    "discovery_none": bytes([0x00]) + login_rsp(OPN, FFP, True, OPS[:60]) + b"",
    "normal_ops_full": bytes([0x10]) + login_rsp(OPN, FFP, True, OPS, tsih=1),
    "chap_challenge": bytes([0x11]) + login_rsp(SEC, SEC, False, kv(("AuthMethod", "CHAP"))) +
                      login_rsp(SEC, SEC, False, CHAP) + login_rsp(SEC, OPN, True, b""),
    "chap_mutual": bytes([0x12]) + login_rsp(SEC, SEC, False, kv(("AuthMethod", "CHAP"))) +
                   login_rsp(SEC, SEC, False, CHAP) + login_rsp(SEC, SEC, True, CHAP_MUTUAL),
    "redirect": bytes([0x10]) + login_rsp(SEC, SEC, True, kv(("TargetAddress", "127.0.0.1:3261,1")),
                                          status=(1, 1)),
    "digests": bytes([0x14]) + login_rsp(OPN, FFP, True, kv(("HeaderDigest", "CRC32C"), ("DataDigest", "CRC32C"))),
}


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "mayhem/fuzz_iscsi_login/testsuite")
