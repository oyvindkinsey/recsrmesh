"""MCP-layer AES-OFB crypto for CSRMesh mesh commands.

Based on https://github.com/nkaminski/csrmesh/blob/master/csrmesh/crypto.py
Licensed under LGPL-3.0-or-later.
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .crypto import hmac_sha256_truncated


def generate_key(binary: bytes) -> bytes:
    """SHA-256 key derivation: hash, reverse, truncate to 16 bytes."""
    h = hashlib.sha256()
    h.update(binary)
    dig = bytearray(h.digest())
    dig.reverse()
    return bytes(dig)[:16]


def make_packet(key: bytes, seq: int, data: bytes) -> bytes:
    """Build encrypted MCP packet with HMAC."""
    source = 32768
    eof = b"\xff"
    dlen = len(data)
    seq_arr = int.to_bytes(seq, 3, byteorder="little")
    iv = struct.pack("<3sxH10x", seq_arr, source)

    # AES-OFB encryption using cryptography library
    cipher = Cipher(
        algorithms.AES(key),
        modes.OFB(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    payload = bytearray(encryptor.update(data) + encryptor.finalize())

    prehmac = struct.pack("<8x3sH" + str(dlen) + "s", seq_arr, source, bytes(payload))
    hm = hmac_sha256_truncated(prehmac, key, 8)
    final = struct.pack("<3sH" + str(dlen) + "s8sc", seq_arr, source, bytes(payload), hm, eof)
    return final


def decrypt_packet(key: bytes, data: bytes) -> dict | None:
    """Decrypt MCP packet and verify HMAC.

    Returns None if packet is too short or HMAC verification fails.
    """
    if len(data) < 14:
        return None

    dlen = len(data) - 14
    (seq_arr, source, epayload, hmac_packet, eof) = struct.unpack(
        "<3sH" + str(dlen) + "s8sc", data
    )
    prehmac = struct.pack("<8x3sH" + str(len(epayload)) + "s", seq_arr, source, epayload)
    hmac_computed = hmac_sha256_truncated(prehmac, key, 8)

    # CRITICAL: Verify HMAC before processing packet
    if not hmac.compare_digest(hmac_computed, hmac_packet):
        return None

    iv = struct.pack("<3sxH10x", seq_arr, source)
    cipher = Cipher(
        algorithms.AES(key),
        modes.OFB(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decpayload = decryptor.update(bytes(epayload)) + decryptor.finalize()
    seq = int.from_bytes(seq_arr, byteorder="little")

    return {
        "seq": seq,
        "source": source,
        "encpayload": epayload,
        "decpayload": decpayload,
        "hmac_computed": hmac_computed,
        "hmac_packet": hmac_packet,
        "eof": eof,
    }


def random_seq() -> int:
    """Generate cryptographically random 24-bit sequence number."""
    return int.from_bytes(os.urandom(3), 'little') | 1
