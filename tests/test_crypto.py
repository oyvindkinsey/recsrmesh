"""Unit tests for crypto primitives using known values."""

from recsrmesh.crypto import (
    add_packet_mac,
    derive_key,
    uuid_to_hash31,
    verify_packet_mac,
    xor_masp_packet,
)


def test_derive_masp_key():
    """MASP key derivation: derive_key("", "\\x00MASP") -> known value."""
    key = derive_key("", "\x00MASP")
    assert key.hex() == "e9d804f88624ac0c7b1e06d884785994"


def test_uuid_to_hash31():
    """UUID hash for device C7:B0 -> 0x771ff53e."""
    uuid_bytes = b"\xb0\xc7\x9f\xbd\xd6\x1c\x14\x00\x00\x12\x00\x00\x00\x00\x00\x00"
    assert uuid_to_hash31(uuid_bytes) == 0x771FF53E


def test_xor_roundtrip():
    """XOR is self-inverse: xor(xor(data)) == data."""
    data = bytes(range(30))
    assert xor_masp_packet(xor_masp_packet(data)) == data


def test_mac_roundtrip():
    """add_packet_mac -> verify_packet_mac succeeds."""
    key = derive_key("", "\x00MASP")
    payload = bytes(range(15))
    packet = add_packet_mac(payload, key)
    recovered, valid = verify_packet_mac(packet, key)
    assert valid
    assert recovered == payload


def test_mac_wrong_key():
    """verify_packet_mac fails with wrong key."""
    key = derive_key("", "\x00MASP")
    wrong_key = derive_key("wrong", "\x00MASP")
    payload = bytes(range(15))
    packet = add_packet_mac(payload, key)
    _, valid = verify_packet_mac(packet, wrong_key)
    assert not valid


def test_mac_tampered():
    """verify_packet_mac fails on tampered data."""
    key = derive_key("", "\x00MASP")
    payload = bytes(range(15))
    packet = bytearray(add_packet_mac(payload, key))
    packet[0] ^= 0xFF  # Tamper
    _, valid = verify_packet_mac(bytes(packet), key)
    assert not valid
