"""CSRMesh Association Protocol (MASP) state and handshake logic."""

import hmac
import os
from dataclasses import dataclass
from enum import IntEnum

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP192R1,
    EllipticCurvePublicNumbers,
)

from .crypto import (
    DEFAULT_SEQ_ID,
    bytes_to_int_le,
    derive_key,
    get_version_counter,
    hmac_sha256_truncated,
    int_to_bytes_le,
    reverse_bytes,
    xor_encrypt,
    xor_masp_packet,
)


class MaspOpcode(IntEnum):
    """MASP protocol opcodes (logical values before XOR)."""
    DEVICE_ID_ANNOUNCE = 0x00
    UUID_ANNOUNCE = 0x01
    ASSOC_REQUEST = 0x02
    ASSOC_RESPONSE = 0x03
    PUBKEY_REQUEST = 0x04
    PUBKEY_RESPONSE = 0x05
    CONFIRM_REQUEST = 0x06
    CONFIRM_RESPONSE = 0x07
    RANDOM_REQUEST = 0x08
    RANDOM_RESPONSE = 0x09
    DEVICE_ID_DIST = 0x0A
    DEVICE_ID_ACK = 0x0B
    NETKEY_DIST = 0x0C
    NETKEY_ACK = 0x0D


class AssocState(IntEnum):
    """Association state machine states."""
    IDLE = 2
    ASSOC_REQUEST_SENT = 3
    PUBKEY_REQUEST_SENT = 4
    CONFIRM_REQUEST_SENT = 5
    RANDOM_REQUEST_SENT = 6
    WAIT_ID_DIST_ACK = 7
    NETKEY_DISTRIBUTE_SENT = 8


@dataclass
class AssociationResult:
    """Result of a successful association."""
    device_id: int
    uuid_hash31: int
    success: bool
    error: str | None = None


class CSRMeshAssociation:
    """Handles the CSR Mesh device association (key exchange) protocol."""

    def __init__(self, network_passphrase: str):
        self.network_key = derive_key(network_passphrase, "\x00MCP")
        self.masp_key = derive_key("", "\x00MASP")

        # Generate ECDH keypair (prime192v1 = secp192r1)
        self.private_key = ec.generate_private_key(ec.SECP192R1(), default_backend())
        self.public_key = self.private_key.public_key()

        pub_numbers = self.public_key.public_numbers()
        self.pub_x = pub_numbers.x.to_bytes(24, 'big')
        self.pub_y = pub_numbers.y.to_bytes(24, 'big')

        # Reverse for little-endian transmission
        self.pub_x_le = reverse_bytes(self.pub_x)
        self.pub_y_le = reverse_bytes(self.pub_y)

        # Device's public key (filled during exchange)
        self.device_pub_x = bytearray(24)
        self.device_pub_y = bytearray(24)

        # Shared secret (computed after key exchange)
        self.shared_secret: bytes | None = None

        # Association state
        self.state = AssocState.IDLE
        self.uuid_hash31: int = 0
        self.uuid_hash31_bytes: bytes = b"\x00\x00\x00\x00"
        self.device_id: int | None = None
        self.short_code: int | None = None
        self.use_short_code = False

        # Random nonces for confirmation
        self.local_random = os.urandom(8)
        self.device_random: bytes | None = None
        self.local_confirm: bytes | None = None
        self.device_confirm: bytes | None = None

        # Public key exchange tracking
        self.pubkey_chunk_index = 0
        self.pubkey_rx_index = 0

        # Network key distribution tracking
        self.netkey_chunk_index = 0

        # Response type tracking
        self.confirm_type: int = 0

    def set_target(self, uuid_hash31: int, short_code: int | None = None):
        """Set the target device for association."""
        self.uuid_hash31 = uuid_hash31
        self.uuid_hash31_bytes = int_to_bytes_le(uuid_hash31, 4)
        self.short_code = short_code
        self.use_short_code = short_code is not None

    def build_device_id_announce(self) -> bytes:
        """Build MASP device ID announce packet (opcode 0x00)."""
        packet = bytearray(18)
        packet[0] = MaspOpcode.DEVICE_ID_ANNOUNCE
        packet[1:5] = self.uuid_hash31_bytes
        packet[5] = 0x00
        packet[6:14] = DEFAULT_SEQ_ID
        packet[14:18] = b'\x00\x00\x00\x00'
        return xor_masp_packet(bytes(packet))

    def build_association_request(self) -> bytes:
        """Build MASP association request packet (opcode 0x02)."""
        packet = bytearray(15)
        packet[0] = MaspOpcode.ASSOC_REQUEST
        packet[1:5] = self.uuid_hash31_bytes
        packet[5] = 0x01 if self.use_short_code else 0x00
        packet[6:14] = DEFAULT_SEQ_ID
        packet[14] = get_version_counter() & 0xFF
        return xor_masp_packet(bytes(packet))

    def parse_association_response(self, data: bytes) -> tuple[bool, int]:
        """
        Parse association response (opcode 0x03).
        Returns (success, confirm_type).
        """
        decrypted = xor_masp_packet(data)

        if decrypted[0] != MaspOpcode.ASSOC_RESPONSE:
            return False, -1

        resp_uuid_hash = bytes_to_int_le(decrypted[1:5])
        if resp_uuid_hash != self.uuid_hash31:
            return False, -1

        confirm_type = decrypted[5]

        if confirm_type == 3:
            return False, 3

        if confirm_type not in (0, 1):
            return False, -1

        self.confirm_type = confirm_type
        return True, confirm_type

    def build_pubkey_packet(self) -> bytes:
        """Build public key exchange packet (opcode 0x04)."""
        packet = bytearray(15)
        packet[0] = MaspOpcode.PUBKEY_REQUEST
        packet[1:5] = self.uuid_hash31_bytes
        packet[5] = self.pubkey_chunk_index

        # Combined pubkey: Y first, then X (both little-endian)
        combined = self.pub_y_le + self.pub_x_le
        start = self.pubkey_chunk_index * 8
        packet[6:14] = combined[start:start + 8]
        packet[14] = 0x00

        return xor_masp_packet(bytes(packet))

    def parse_pubkey_response(self, data: bytes) -> bool:
        """Parse public key response (opcode 0x05)."""
        decrypted = xor_masp_packet(data)

        if decrypted[0] != MaspOpcode.PUBKEY_RESPONSE:
            return False

        chunk_index = decrypted[5]
        if chunk_index != self.pubkey_rx_index:
            return False

        chunk_data = decrypted[6:14]

        # First 3 chunks (0-2) are Y, next 3 (3-5) are X
        offset = chunk_index * 8
        if offset < 24:
            self.device_pub_y[offset:offset + 8] = chunk_data
        else:
            self.device_pub_x[offset - 24:offset - 24 + 8] = chunk_data

        self.pubkey_rx_index += 1
        return True

    def compute_shared_secret(self) -> bool:
        """Compute ECDH shared secret after receiving device's public key."""
        try:
            x = int.from_bytes(reverse_bytes(bytes(self.device_pub_x)), 'big')
            y = int.from_bytes(reverse_bytes(bytes(self.device_pub_y)), 'big')

            peer_numbers = EllipticCurvePublicNumbers(x, y, SECP192R1())
            peer_public = peer_numbers.public_key(default_backend())

            shared = self.private_key.exchange(ECDH(), peer_public)
            # Reverse the shared secret (Java code reverses it)
            self.shared_secret = reverse_bytes(shared)
            return True
        except Exception as e:
            print(f"ECDH computation failed: {e}")
            return False

    def _build_confirm_data(self, is_local: bool) -> bytes:
        """Build data for confirmation HMAC calculation."""
        if self.use_short_code and self.confirm_type == 1:
            if is_local:
                data = self.pub_y_le + self.pub_x_le
            else:
                data = bytes(self.device_pub_y) + bytes(self.device_pub_x)
            short_code_bytes = int_to_bytes_le(self.short_code or 0, 8)
            return data + short_code_bytes
        else:
            short_code_flag = 0x01 if self.short_code and self.short_code != 0 else 0x00
            short_code_bytes = int_to_bytes_le(self.short_code or 0, 8)
            header = DEFAULT_SEQ_ID + bytes([self.confirm_type, short_code_flag])
            if is_local:
                pubkey = self.pub_y_le + self.pub_x_le
            else:
                pubkey = bytes(self.device_pub_y) + bytes(self.device_pub_x)
            return header + pubkey + short_code_bytes

    def build_confirm_request(self) -> bytes:
        """Build confirmation request packet (opcode 0x06)."""
        confirm_data = self._build_confirm_data(is_local=True)
        self.local_confirm = hmac_sha256_truncated(confirm_data, self.local_random, 8)

        packet = bytearray(14)
        packet[0] = MaspOpcode.CONFIRM_REQUEST
        packet[1:5] = self.uuid_hash31_bytes
        packet[5:13] = self.local_confirm
        packet[13] = 0x00

        return xor_masp_packet(bytes(packet))

    def parse_confirm_response(self, data: bytes) -> bool:
        """Parse confirmation response (opcode 0x07)."""
        decrypted = xor_masp_packet(data)

        if decrypted[0] != MaspOpcode.CONFIRM_RESPONSE:
            return False

        self.device_confirm = decrypted[5:13]
        return True

    def build_random_request(self) -> bytes:
        """Build random exchange packet (opcode 0x08)."""
        packet = bytearray(14)
        packet[0] = MaspOpcode.RANDOM_REQUEST
        packet[1:5] = self.uuid_hash31_bytes
        packet[5:13] = self.local_random
        packet[13] = 0x00

        return xor_masp_packet(bytes(packet))

    def parse_random_response(self, data: bytes) -> bool:
        """Parse random response (opcode 0x09)."""
        decrypted = xor_masp_packet(data)

        if decrypted[0] != MaspOpcode.RANDOM_RESPONSE:
            return False

        self.device_random = decrypted[5:13]

        verify_data = self._build_confirm_data(is_local=False)
        expected_confirm = hmac_sha256_truncated(verify_data, self.device_random, 8)

        assert self.device_confirm is not None
        if not hmac.compare_digest(self.device_confirm, expected_confirm):
            print("Device confirmation verification failed!")
            return False

        return True

    def build_device_id_packet(self, device_id: int) -> bytes:
        """Build device ID distribution packet (opcode 0x0A)."""
        self.device_id = device_id

        assert self.shared_secret is not None
        id_bytes = int_to_bytes_le(device_id, 2)
        encrypted_id = xor_encrypt(id_bytes, self.shared_secret, "DeviceID")

        print(f"  [DEVID]       id={device_id} (0x{device_id:04x}), id_bytes={id_bytes.hex()}, encrypted={encrypted_id.hex()}")

        packet = bytearray(8)
        packet[0] = MaspOpcode.DEVICE_ID_DIST
        packet[1:5] = self.uuid_hash31_bytes
        packet[5:7] = encrypted_id
        packet[7] = 0x00

        plain = bytes(packet)
        xored = xor_masp_packet(plain)
        print(f"  [DEVID]       plain={plain.hex()}, xored={xored.hex()}")
        return xored

    def parse_device_id_ack(self, data: bytes) -> bool:
        """Parse device ID acknowledgment (opcode 0x0B)."""
        decrypted = xor_masp_packet(data)
        return decrypted[0] == MaspOpcode.DEVICE_ID_ACK

    def build_netkey_packet(self) -> bytes:
        """Build network key distribution packet (opcode 0x0C)."""
        assert self.shared_secret is not None
        encrypted_key = xor_encrypt(self.network_key, self.shared_secret, "NetworkKey")

        packet = bytearray(15)
        packet[0] = MaspOpcode.NETKEY_DIST
        packet[1:5] = self.uuid_hash31_bytes
        packet[5] = self.netkey_chunk_index

        start = self.netkey_chunk_index * 8
        packet[6:14] = encrypted_key[start:start + 8]
        packet[14] = 0x00

        return xor_masp_packet(bytes(packet))

    def parse_netkey_ack(self, data: bytes) -> bool:
        """Parse network key acknowledgment (opcode 0x0D)."""
        decrypted = xor_masp_packet(data)

        if decrypted[0] != MaspOpcode.NETKEY_ACK:
            return False

        ack_index = decrypted[5]
        return ack_index == self.netkey_chunk_index - 1
