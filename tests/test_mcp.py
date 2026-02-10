"""Unit tests for MCP packet building and parsing."""

from recsrmesh.mcp import (
    DISASSOCIATE_OPCODE,
    build_disassociate,
    build_packet,
    parse_packet,
)


def test_build_parse_roundtrip():
    """build_packet -> parse_packet returns same fields."""
    dest_id = 33896
    opcode = 0x73
    payload = bytes([0, 10, 0, 0, 0, 128, 0, 0, 0, 0])

    raw = build_packet(dest_id, opcode, payload)
    parsed = parse_packet(raw)

    assert parsed is not None
    assert parsed["source"] == dest_id
    assert parsed["opcode"] == opcode
    assert parsed["payload"] == payload


def test_build_packet_broadcast():
    """dest_id=0 produces zero dest bytes."""
    raw = build_packet(0, 0x73, b"\x01\x0a")
    assert raw[0] == 0
    assert raw[1] == 0
    assert raw[2] == 0x73


def test_build_packet_minimal():
    """Packet with no payload is just 3 bytes."""
    raw = build_packet(1, 0x04)
    assert len(raw) == 3
    assert raw[2] == 0x04


def test_build_disassociate():
    """Verify disassociate packet format matches known-good."""
    raw = build_disassociate(33896)
    assert len(raw) == 13
    assert raw[0] == 0x68  # 33896 & 0xFF
    assert raw[1] == 0x84  # 33896 >> 8
    assert raw[2] == DISASSOCIATE_OPCODE
    assert raw[3:] == bytes(10)


def test_build_disassociate_matches_legacy():
    """build_disassociate matches the old _build_unclaim_payload logic."""
    device_id = 33897
    target = device_id.to_bytes(2, byteorder="big")
    legacy = bytes([target[1], target[0], DISASSOCIATE_OPCODE]) + bytes(10)
    assert build_disassociate(device_id) == legacy


def test_build_disassociate_uses_build_packet():
    """build_disassociate is equivalent to build_packet + DISASSOCIATE_OPCODE."""
    device_id = 33896
    assert build_disassociate(device_id) == build_packet(device_id, DISASSOCIATE_OPCODE, bytes(10))


def test_parse_too_short():
    """Payload shorter than 3 bytes returns None."""
    assert parse_packet(bytes(2)) is None
    assert parse_packet(b"") is None


def test_parse_returns_opcode():
    """parse_packet returns the raw opcode byte."""
    raw = build_packet(100, 0x04, b"\x00" * 10)
    parsed = parse_packet(raw)
    assert parsed["opcode"] == 0x04
    assert parsed["source"] == 100
