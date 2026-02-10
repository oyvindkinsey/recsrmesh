"""MCP-layer AES-OFB crypto for CSRMesh mesh commands.

Based on https://github.com/nkaminski/csrmesh/blob/master/csrmesh/crypto.py
Licensed under LGPL-3.0-or-later.
"""

import hashlib
import hmac
import random
import struct

from Cryptodome.Cipher import AES


def generate_key(binary):
    """SHA-256 key derivation: hash, reverse, truncate to 16 bytes."""
    h = hashlib.sha256()
    h.update(binary)
    dig = bytearray(h.digest())
    dig.reverse()
    return bytes(dig)[:16]


def make_packet(key, seq, data):
    """Build encrypted MCP packet with HMAC."""
    source = 32768
    eof = b"\xff"
    dlen = len(data)
    seq_arr = int.to_bytes(seq, 3, byteorder="little")
    iv = struct.pack("<3sxH10x", seq_arr, source)
    enc = AES.new(key, AES.MODE_OFB, iv)
    payload = bytearray(enc.encrypt(data))
    prehmac = struct.pack("<8x3sH" + str(dlen) + "s", seq_arr, source, bytes(payload))
    hm = bytearray(hmac.new(key, msg=prehmac, digestmod=hashlib.sha256).digest())
    hm.reverse()
    hm = bytes(hm)[:8]
    final = struct.pack("<3sH" + str(dlen) + "s8sc", seq_arr, source, bytes(payload), hm, eof)
    return final


def decrypt_packet(key, data):
    """Decrypt MCP packet and verify HMAC."""
    if len(data) < 14:
        return None
    od = {}
    dlen = len(data) - 14
    (seq_arr, source, epayload, hmac_packet, eof) = struct.unpack(
        "<3sH" + str(dlen) + "s8sc", data
    )
    prehmac = struct.pack("<8x3sH" + str(len(epayload)) + "s", seq_arr, source, epayload)
    hm = bytearray(hmac.new(key, msg=prehmac, digestmod=hashlib.sha256).digest())
    hm.reverse()
    hmac_computed = bytes(hm)[:8]
    iv = struct.pack("<3sxH10x", seq_arr, source)
    enc = AES.new(key, AES.MODE_OFB, iv)
    decpayload = enc.decrypt(bytes(epayload))
    seq = int.from_bytes(seq_arr, byteorder="little")
    od["seq"] = seq
    od["source"] = source
    od["encpayload"] = epayload
    od["decpayload"] = decpayload
    od["hmac_computed"] = hmac_computed
    od["hmac_packet"] = hmac_packet
    od["eof"] = eof
    return od


def random_seq():
    """Generate random 24-bit sequence number."""
    return random.randint(1, 16777215)
