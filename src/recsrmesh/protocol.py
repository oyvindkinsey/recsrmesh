"""MASP protocol state machine for CSRMesh association."""

import logging
from enum import IntEnum, auto

from .crypto import xor_masp_packet
from .masp import CSRMeshAssociation, MaspOpcode

logger = logging.getLogger(__name__)


class ProtocolState(IntEnum):
    """Protocol state machine states matching Android implementation."""
    INIT = auto()
    WAIT_ASSOC_RESPONSE = auto()
    PUBKEY_EXCHANGE = auto()
    WAIT_CONFIRM_RESPONSE = auto()
    WAIT_RANDOM_RESPONSE = auto()
    WAIT_DEVICE_ID_ACK = auto()
    NETKEY_EXCHANGE = auto()
    COMPLETE = auto()
    ERROR = auto()


class ProtocolStateMachine:
    """
    CSRMesh Association state machine.

    Pattern: out = process(in); if out: send(out)

    - get_initial_request() returns first ASSOC_REQUEST
    - process(response) returns next request or None
    - None means unexpected message (keep waiting)
    """

    def __init__(self, uuid_hash: int, device_id: int, passphrase: str):
        self.assoc = CSRMeshAssociation(passphrase)
        self.assoc.set_target(uuid_hash)
        self.device_id = device_id

        self.state = ProtocolState.INIT
        self.pubkey_chunk = 0
        self.netkey_chunk = 0
        self.error: str | None = None

        # For replay testing: skip ECDH computation and verification
        self.replay_mode: bool = False

    def get_initial_request(self) -> bytes | None:
        """Get the first request packet (ASSOC_REQUEST)."""
        if self.state != ProtocolState.INIT:
            return None

        self.state = ProtocolState.WAIT_ASSOC_RESPONSE
        return self.assoc.build_association_request()

    def _build_next_request(self) -> bytes | None:
        """Build the next request packet based on current state."""
        if self.state == ProtocolState.PUBKEY_EXCHANGE:
            self.assoc.pubkey_chunk_index = self.pubkey_chunk
            return self.assoc.build_pubkey_packet()

        elif self.state == ProtocolState.WAIT_CONFIRM_RESPONSE:
            return self.assoc.build_confirm_request()

        elif self.state == ProtocolState.WAIT_RANDOM_RESPONSE:
            return self.assoc.build_random_request()

        elif self.state == ProtocolState.WAIT_DEVICE_ID_ACK:
            return self.assoc.build_device_id_packet(self.device_id)

        elif self.state == ProtocolState.NETKEY_EXCHANGE:
            self.assoc.netkey_chunk_index = self.netkey_chunk
            return self.assoc.build_netkey_packet()

        return None

    def process(self, response_before_xor: bytes) -> bytes | None:
        """
        Process a response and return the next request.

        Args:
            response_before_xor: Response packet BEFORE XOR

        Returns:
            Next request packet if response was expected, None otherwise.
        """
        if self.state == ProtocolState.ERROR:
            return None

        if not response_before_xor:
            return None

        wire = xor_masp_packet(response_before_xor)
        opcode = response_before_xor[0]

        if self.state == ProtocolState.WAIT_ASSOC_RESPONSE:
            if opcode != MaspOpcode.ASSOC_RESPONSE:
                return None

            success, confirm_type = self.assoc.parse_association_response(wire)
            if not success:
                self.error = f"ASSOC rejected (confirm_type={confirm_type})"
                self.state = ProtocolState.ERROR
                return None

            self.state = ProtocolState.PUBKEY_EXCHANGE
            return self._build_next_request()

        elif self.state == ProtocolState.PUBKEY_EXCHANGE:
            if opcode != MaspOpcode.PUBKEY_RESPONSE:
                return None

            if not self.assoc.parse_pubkey_response(wire):
                self.error = f"PUBKEY_RESPONSE[{self.pubkey_chunk}] parse failed"
                self.state = ProtocolState.ERROR
                return None

            self.pubkey_chunk += 1
            if self.pubkey_chunk >= 6:
                if not self.replay_mode:
                    if not self.assoc.compute_shared_secret():
                        self.error = "ECDH computation failed"
                        self.state = ProtocolState.ERROR
                        return None
                    if self.assoc.shared_secret is None:
                        self.error = "ECDH shared_secret is None after computation"
                        self.state = ProtocolState.ERROR
                        return None
                    logger.debug(f"  [ECDH] shared_secret={self.assoc.shared_secret.hex()}")
                self.state = ProtocolState.WAIT_CONFIRM_RESPONSE
            return self._build_next_request()

        elif self.state == ProtocolState.WAIT_CONFIRM_RESPONSE:
            if opcode != MaspOpcode.CONFIRM_RESPONSE:
                return None

            if not self.assoc.parse_confirm_response(wire):
                self.error = "CONFIRM_RESPONSE parse failed"
                self.state = ProtocolState.ERROR
                return None

            self.state = ProtocolState.WAIT_RANDOM_RESPONSE
            return self._build_next_request()

        elif self.state == ProtocolState.WAIT_RANDOM_RESPONSE:
            if opcode != MaspOpcode.RANDOM_RESPONSE:
                return None

            if self.replay_mode:
                self.assoc.device_random = response_before_xor[5:13]
            elif not self.assoc.parse_random_response(wire):
                self.error = "RANDOM_RESPONSE verification failed"
                self.state = ProtocolState.ERROR
                return None

            self.state = ProtocolState.WAIT_DEVICE_ID_ACK
            return self._build_next_request()

        elif self.state == ProtocolState.WAIT_DEVICE_ID_ACK:
            if opcode != MaspOpcode.DEVICE_ID_ACK:
                return None

            self.state = ProtocolState.NETKEY_EXCHANGE
            return self._build_next_request()

        elif self.state == ProtocolState.NETKEY_EXCHANGE:
            if opcode != MaspOpcode.NETKEY_ACK:
                return None

            self.netkey_chunk += 1
            if self.netkey_chunk >= 2:
                self.state = ProtocolState.COMPLETE
                return None
            return self._build_next_request()

        return None

    def is_complete(self) -> bool:
        return self.state == ProtocolState.COMPLETE

    def is_error(self) -> bool:
        return self.state == ProtocolState.ERROR

    def get_state_name(self) -> str:
        return self.state.name
