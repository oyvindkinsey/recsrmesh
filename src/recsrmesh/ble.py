"""BLE state machine for CSRMesh association."""

import asyncio
import logging
import time
from enum import IntEnum, auto

from .crypto import (
    MASP_XOR_MASK,
    add_packet_mac,
    derive_key,
    uuid_to_hash31,
    verify_packet_mac,
    xor_masp_packet,
)
from .masp import MaspOpcode
from .protocol import ProtocolState, ProtocolStateMachine

logger = logging.getLogger(__name__)

# CSRMesh GATT Service
SERVICE_UUID = "c4edc000-9daf-11e3-8000-00025b000b00"

# MTL Characteristics (legacy)
CHARACTERISTIC_LOW = "c4edc000-9daf-11e3-8003-00025b000b00"
CHARACTERISTIC_HIGH = "c4edc000-9daf-11e3-8004-00025b000b00"

# CCCD Descriptor
CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"


class AssociationState(IntEnum):
    """Association session states."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    ASSOCIATING = auto()
    COMPLETE = auto()
    FAILED = auto()


class AssociationStateMachine:
    """
    MASP association protocol runner.

    MTL reassembly and notification management are handled by CSRMesh.
    Raw reassembled bytes arrive via feed_raw().
    """

    def __init__(
        self,
        client,
        uuid_hash: int,
        passphrase: str,
        device_id: int | None = None,
    ):
        self.client = client
        self.uuid_hash = uuid_hash
        self.passphrase = passphrase

        if device_id is None:
            device_id = 33896

        self.protocol = ProtocolStateMachine(uuid_hash, device_id, passphrase)

        self.masp_key = derive_key("", "\x00MASP")

        # State
        self.state = AssociationState.DISCONNECTED
        self.error: str | None = None
        self.pending_response: bytes | None = None

    def feed_raw(self, raw: bytes):
        """Accept raw reassembled bytes from CSRMesh notification layer."""
        payload, valid = verify_packet_mac(raw, self.masp_key)
        if valid:
            raw = payload
            logger.debug(f"[MAC valid]   payload {len(raw)}B")
        else:
            logger.debug(f"[MAC invalid] passing raw {len(raw)}B")
        message = xor_masp_packet(raw)

        opcode = message[0]
        opname = MaspOpcode(opcode).name if opcode in MaspOpcode._value2member_map_ else f"0x{opcode:02x}"
        logger.debug(f"[message]     opcode={opname} ({len(message)}B)")
        self.pending_response = message

    async def run(self) -> bool:
        """Execute full association sequence."""
        try:
            self.state = AssociationState.ASSOCIATING
            await self._run_protocol()
            return self.state == AssociationState.COMPLETE
        except Exception as e:
            self.error = str(e)
            self.state = AssociationState.FAILED
            return False

    async def _run_protocol(self, retries: int = 3, timeout: float = 10.0):
        """Execute MASP protocol state machine with per-message retries."""
        request = self.protocol.get_initial_request()

        while request is not None:
            advanced = False
            for attempt in range(retries + 1):
                if attempt > 0:
                    logger.debug(f"[retry]       attempt {attempt + 1}/{retries + 1}"
                               f" (state={self.protocol.state.name})")
                assert request is not None
                await self._send_masp_message(request)

                deadline = time.time() + timeout
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break

                    response = await self._wait_for_response(timeout=remaining)
                    if response is None:
                        break

                    next_request = self.protocol.process(response)
                    if self.protocol.error:
                        raise RuntimeError(self.protocol.error)
                    if next_request is not None or self.protocol.state == ProtocolState.COMPLETE:
                        request = next_request
                        advanced = True
                        break

                if advanced:
                    break
            else:
                raise TimeoutError(
                    f"No response from device after {retries + 1} attempts "
                    f"(state={self.protocol.state.name})")

        if self.protocol.state == ProtocolState.COMPLETE:
            self.state = AssociationState.COMPLETE
        else:
            raise RuntimeError(f"Protocol ended in state {self.protocol.state}")

    async def _send_masp_message(self, message_after_xor: bytes):
        """Send MASP message, fragmenting across characteristics if needed."""
        # TTL=55 (0x37) matches Android app behavior
        packet_with_mac = add_packet_mac(message_after_xor, self.masp_key, ttl=55)

        xor_opcode = message_after_xor[0]
        decoded_opcode = xor_opcode ^ MASP_XOR_MASK[0]
        opname = MaspOpcode(decoded_opcode).name if decoded_opcode in MaspOpcode._value2member_map_ else f"0x{decoded_opcode:02x}"
        logger.debug(f"[send]        {opname} ({len(packet_with_mac)}B) wire={packet_with_mac.hex()}")

        # Short packets (<=20B): write to 8004 only
        # Long packets (>20B): first 20 to 8003, overflow to 8004
        if len(packet_with_mac) <= 20:
            await self.client.write_gatt_char(
                CHARACTERISTIC_HIGH, packet_with_mac, response=False)
        else:
            chunk1 = packet_with_mac[:20]
            chunk2 = packet_with_mac[20:]

            await self.client.write_gatt_char(
                CHARACTERISTIC_LOW, chunk1, response=False)

            if chunk2:
                await self.client.write_gatt_char(
                    CHARACTERISTIC_HIGH, chunk2, response=False)

    async def _wait_for_response(self, timeout: float) -> bytes | None:
        """Wait for complete response to arrive."""
        start = time.time()
        while self.pending_response is None:
            if time.time() - start > timeout:
                return None
            await asyncio.sleep(0.01)

        response = self.pending_response
        self.pending_response = None
        return response


def _process_discovery_packet(raw: bytes, masp_key: bytes, results: list):
    """Process a received packet during discovery."""
    payload, valid = verify_packet_mac(raw, masp_key)
    if not valid:
        return

    message = xor_masp_packet(payload)
    if len(message) < 17 or message[0] != MaspOpcode.UUID_ANNOUNCE:
        return

    uuid_bytes = message[1:17]
    uuid_hash = uuid_to_hash31(uuid_bytes)
    if not any(r['uuid_hash'] == uuid_hash for r in results):
        results.append({'uuid': uuid_bytes, 'uuid_hash': uuid_hash})
        logger.debug(f"[discovered]  uuid_hash=0x{uuid_hash:08X} uuid={uuid_bytes.hex()}")
