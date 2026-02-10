"""MCP (Mesh Control Protocol) packet building and parsing.

CSR MCP packet format (before encryption):
    [dest_lo, dest_hi, opcode, payload...]

The dest/opcode header is CSR-defined. Everything after the opcode
is application-specific (verb/noun/group schemes are OEM conventions).
"""

DISASSOCIATE_OPCODE = 0x04
MODEL_OPCODE = 0x73


def build_packet(dest_id: int, opcode: int, payload: bytes = b"") -> bytes:
    """Build MCP packet: [dest_lo, dest_hi, opcode, *payload]."""
    dest = dest_id.to_bytes(2, byteorder="big")
    return bytes([dest[1], dest[0], opcode]) + payload


def parse_packet(data: bytes) -> dict | None:
    """Parse decrypted MCP packet.

    Returns {'source': int, 'opcode': int, 'payload': bytes}
    or None if too short (< 3 bytes).
    """
    if len(data) < 3:
        return None
    source = int.from_bytes(bytes([data[1], data[0]]), byteorder="big")
    return {
        "source": source,
        "opcode": data[2],
        "payload": data[3:],
    }


def build_disassociate(device_id: int) -> bytes:
    """Build disassociate packet (opcode 0x04, 10 zero bytes payload)."""
    return build_packet(device_id, DISASSOCIATE_OPCODE, bytes(10))
