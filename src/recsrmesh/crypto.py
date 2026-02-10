"""Shared cryptographic primitives for CSRMesh MASP protocol."""

import hashlib
import hmac

# XOR mask for MASP packets (25 bytes)
MASP_XOR_MASK = bytes([
    0x52, 0x20, 0x2A, 0x39, 0x40, 0x18, 0xc4, 0x41,
    0xaa, 0xd1, 0x7d, 0x26, 0x05, 0xd5, 0x7f, 0xae,
    0x2c, 0xb3, 0x0e, 0xf5, 0xc5, 0x2d, 0x06, 0x24, 0x15,
])

# Default sequence ID (reversed for LE transmission)
DEFAULT_SEQ_ID = bytes([1, 0, 0, 0, 0, 0, 0, 0])

# Version counter (global)
_version_counter = 0


def get_version_counter() -> int:
    """Get next version counter value (masked to 24 bits like Java)."""
    global _version_counter
    _version_counter = (_version_counter + 1) & 0xFFFFFF
    return _version_counter


def set_version_counter(value: int):
    """Set version counter to specific value (for replay testing)."""
    global _version_counter
    _version_counter = value & 0xFFFFFF


def reverse_bytes(data: bytes) -> bytes:
    """Reverse byte order."""
    return bytes(reversed(data))


def derive_key(passphrase: str, salt: str) -> bytes:
    """
    Derive 16-byte key from passphrase using SHA-256.
    SHA256(passphrase + salt) -> reverse all 32 bytes -> take first 16
    """
    data = (passphrase + salt).encode('utf-8')
    digest = bytearray(hashlib.sha256(data).digest())
    digest.reverse()
    return bytes(digest)[:16]


def hmac_sha256(data: bytes, key: bytes) -> bytes:
    """Full HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_sha256_truncated(data: bytes, key: bytes, length: int) -> bytes:
    """
    HMAC-SHA256 truncated to specified length.
    Returns LAST n bytes of HMAC, reversed.
    """
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return bytes(reversed(mac[-length:]))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte arrays."""
    return bytes(x ^ y for x, y in zip(a, b))


def xor_encrypt(data: bytes, shared_secret: bytes, label: str) -> bytes:
    """XOR encryption using HMAC-derived keystream."""
    keystream = hmac_sha256_truncated(label.encode('utf-8'), shared_secret, len(data))
    return xor_bytes(data, keystream)


def uuid_to_hash31(uuid_bytes: bytes) -> int:
    """
    Calculate 31-bit UUID hash.

    CRITICAL: Does NOT reverse UUID before hashing!
    The reversal happens during UUID construction from packets,
    not during hash calculation.
    """
    digest = hashlib.sha256(uuid_bytes).digest()
    last_4 = bytearray(digest[-4:])
    last_4[0] = last_4[0] & 0x7F  # Mask MSB to get 31 bits
    return int.from_bytes(last_4, 'big')


def uuid_to_hash64(uuid_bytes: bytes) -> int:
    """Calculate 64-bit UUID hash."""
    uuid_reversed = reverse_bytes(uuid_bytes)
    digest = hashlib.sha256(uuid_reversed).digest()
    return int.from_bytes(digest[-8:], 'little')


def xor_masp_packet(data: bytes) -> bytes:
    """
    XOR MASP packet with mask.

    Uses Math.min(i, length-1) NOT modulo — this is a BUG in the original
    code but we must replicate it exactly! After byte 24, all bytes XOR with last mask byte (0x15).
    """
    result = bytearray(len(data))
    mask_len = len(MASP_XOR_MASK)
    for i, b in enumerate(data):
        result[i] = b ^ MASP_XOR_MASK[min(i, mask_len - 1)]
    return bytes(result)


def add_packet_mac(payload: bytes, key: bytes, ttl: int = 255) -> bytes:
    """
    Add 8-byte HMAC and TTL to packet.
    Final MTL packet format: [payload][8-byte MAC][TTL]
    HMAC is calculated over: 8 zero bytes + payload
    """
    mac_input = b'\x00' * 8 + payload
    mac = hmac_sha256_truncated(mac_input, key, 8)
    return payload + mac + bytes([ttl & 0xFF])


def verify_packet_mac(packet: bytes, key: bytes) -> tuple[bytes, bool]:
    """
    Verify and strip MAC from received packet.
    Returns (payload, is_valid).
    HMAC is calculated over: 8 zero bytes + payload
    """
    if len(packet) < 9:
        return packet, False

    payload = packet[:-9]
    received_mac = packet[-9:-1]

    mac_input = b'\x00' * 8 + payload
    expected_mac = hmac_sha256_truncated(mac_input, key, 8)
    return payload, hmac.compare_digest(received_mac, expected_mac)


def int_to_bytes_le(value: int, length: int) -> bytes:
    """Convert integer to little-endian bytes."""
    return value.to_bytes(length, 'little')


def bytes_to_int_le(data: bytes) -> int:
    """Convert little-endian bytes to integer."""
    return int.from_bytes(data, 'little')
