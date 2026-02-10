"""High-level CSRMesh mesh interface."""

import asyncio
import logging
from collections.abc import Callable

from .ble import (
    CHARACTERISTIC_HIGH,
    CHARACTERISTIC_LOW,
    AssociationStateMachine,
    BleClient,
    _process_discovery_packet,
)
from .crypto import (
    DEFAULT_SEQ_ID,
    add_packet_mac,
    derive_key,
    set_version_counter,
    xor_masp_packet,
)
from .masp import MaspOpcode
from .mcp import build_disassociate, build_packet, parse_packet
from .mcp_crypto import decrypt_packet, generate_key, make_packet, random_seq

logger = logging.getLogger(__name__)


class CSRMesh:
    """High-level CSRMesh mesh interface.

    Usage:
        async with BleakClient(bridge_mac) as client:
            async with CSRMesh(client, passphrase) as mesh:
                devices = await mesh.discover_unassociated(timeout=5.0)
                result = await mesh.associate(target['uuid_hash'])
                await mesh.disassociate(device_id, repeats=3)
                await mesh.send(dest_id, opcode, payload)
                responses = await mesh.receive(timeout=3.0)
    """

    def __init__(self, client: BleClient, passphrase: str):
        self.client = client
        self.passphrase = passphrase
        self._masp_key = derive_key("", "\x00MASP")
        self._mcp_key = generate_key(passphrase.encode("ascii") + b"\x00MCP")
        self._responses: asyncio.Queue | None = None
        self._low_buf: bytes | None = None
        self._low_timer: asyncio.TimerHandle | None = None
        self._notifying = False
        self._raw_handler: Callable[[bytes], None] = self._mcp_handler

    async def __aenter__(self) -> "CSRMesh":
        await self._start_notifications()
        return self

    async def __aexit__(self, *exc):
        await self._stop_notifications()

    async def _start_notifications(self):
        if self._notifying:
            return
        self._responses = asyncio.Queue()
        self._low_buf = None
        await self.client.start_notify(CHARACTERISTIC_LOW, self._on_low)
        await self.client.start_notify(CHARACTERISTIC_HIGH, self._on_high)
        self._notifying = True

    async def _stop_notifications(self):
        if not self._notifying:
            return
        try:
            await self.client.stop_notify(CHARACTERISTIC_LOW)
            await self.client.stop_notify(CHARACTERISTIC_HIGH)
        except (OSError, EOFError):
            # BLE connection may already be closed
            logger.debug("BLE connection closed during stop_notify")
        self._notifying = False

    def _on_low(self, sender, data: bytearray):
        """8003 = first fragment of long packet (or lone short packet)."""
        logger.debug(f"[8003 notify] {len(data)}B: {bytes(data).hex()}")
        self._low_buf = bytes(data)
        if self._low_timer is not None:
            self._low_timer.cancel()
        loop = asyncio.get_running_loop()
        self._low_timer = loop.call_later(0.2, self._flush_low_buf)

    def _flush_low_buf(self):
        """Timeout: no 8004 followed — treat 8003 data as complete packet."""
        self._low_timer = None
        if self._low_buf is not None:
            raw = self._low_buf
            self._low_buf = None
            self._raw_handler(raw)

    def _on_high(self, sender, data: bytearray):
        """8004 = complete short packet OR second fragment of long packet."""
        logger.debug(f"[8004 notify] {len(data)}B: {bytes(data).hex()}")
        if self._low_timer is not None:
            self._low_timer.cancel()
            self._low_timer = None
        if self._low_buf is not None:
            raw = self._low_buf + bytes(data)
            self._low_buf = None
        else:
            raw = bytes(data)
        self._raw_handler(raw)

    def _mcp_handler(self, raw: bytes):
        """Default handler: MCP decrypt + parse + queue."""
        result = decrypt_packet(self._mcp_key, raw)
        if result is None:
            return
        parsed = parse_packet(result["decpayload"])
        if parsed is not None and self._responses is not None:
            parsed["crypto_source"] = result["source"]
            self._responses.put_nowait(parsed)

    async def _write_encrypted(self, encrypted: bytes):
        """Write encrypted MCP packet, splitting across LOW/HIGH characteristics."""
        low = encrypted[:20]
        high = encrypted[20:]
        await self.client.write_gatt_char(CHARACTERISTIC_LOW, low)
        await self.client.write_gatt_char(CHARACTERISTIC_HIGH, high)

    async def discover_unassociated(self, timeout: float = 5.0) -> list[dict]:
        """Find unprovisioned devices via bridge.

        Returns list of dicts with 'uuid' (bytes) and 'uuid_hash' (int).
        """
        results: list[dict] = []
        masp_key = self._masp_key

        def discovery_handler(raw: bytes):
            _process_discovery_packet(raw, masp_key, results)

        prev_handler = self._raw_handler
        self._raw_handler = discovery_handler
        try:
            # Build DEVICE_ID_ANNOUNCE with hash=0 (broadcast)
            announce = bytearray(18)
            announce[0] = MaspOpcode.DEVICE_ID_ANNOUNCE
            announce[1:5] = (0).to_bytes(4, 'little')
            announce[5] = 0x00
            announce[6:14] = DEFAULT_SEQ_ID
            announce[14:18] = b'\x00\x00\x00\x00'
            xored = xor_masp_packet(bytes(announce))
            packet = add_packet_mac(xored, masp_key, ttl=55)

            if len(packet) <= 20:
                await self.client.write_gatt_char(
                    CHARACTERISTIC_HIGH, packet, response=False)
            else:
                await self.client.write_gatt_char(
                    CHARACTERISTIC_LOW, packet[:20], response=False)
                await self.client.write_gatt_char(
                    CHARACTERISTIC_HIGH, packet[20:], response=False)

            await asyncio.sleep(timeout)
        finally:
            self._raw_handler = prev_handler

        return results

    async def associate(
        self, uuid_hash: int, device_id: int, *,
        _replay_crypto: dict | None = None,
    ) -> int:
        """Associate a device into the mesh. Returns assigned device_id.

        Caller must provide device_id — valid ranges are OEM-specific.
        Raises RuntimeError on failure.
        """

        sm = AssociationStateMachine(
            client=self.client,
            uuid_hash=uuid_hash,
            passphrase=self.passphrase,
            device_id=device_id,
        )

        if _replay_crypto is not None:
            sm.protocol.replay_mode = True
            crypto = _replay_crypto
            if "ecdh_public_key_y" in crypto and "ecdh_public_key_x" in crypto:
                sm.protocol.assoc.pub_y_le = bytes.fromhex(
                    crypto["ecdh_public_key_y"].replace(" ", "").replace("\n", ""))
                sm.protocol.assoc.pub_x_le = bytes.fromhex(
                    crypto["ecdh_public_key_x"].replace(" ", "").replace("\n", ""))
            sm.protocol.assoc.shared_secret = bytes.fromhex(
                crypto["ecdh_shared_secret"].replace(" ", "").replace("\n", ""))
            sm.protocol.assoc.local_random = bytes.fromhex(
                crypto["random_nonces"][0].replace(" ", "").replace("\n", ""))
            if "version_counter" in crypto:
                set_version_counter(crypto["version_counter"])

        prev_handler = self._raw_handler
        self._raw_handler = sm.feed_raw
        try:
            success = await sm.run()
            if not success:
                error = sm.protocol.error or sm.error or "unknown error"
                raise RuntimeError(f"Association failed: {error}")
            return sm.protocol.device_id
        finally:
            self._raw_handler = prev_handler

    async def disassociate(self, device_id: int, repeats: int = 3):
        """Remove a device from the mesh (disassociate opcode 0x04)."""
        payload = build_disassociate(device_id)
        for i in range(repeats):
            encrypted = make_packet(self._mcp_key, random_seq(), payload)
            await self._write_encrypted(encrypted)
            if i < repeats - 1:
                await asyncio.sleep(0.5)

    async def send(
        self, dest_id: int, opcode: int, payload: bytes = b"",
        repeats: int = 1,
    ):
        """Send an MCP packet. Fire-and-forget.

        Args:
            dest_id: Destination device ID (0 = broadcast).
            opcode: MCP opcode byte.
            payload: Opcode-specific payload bytes.
            repeats: Number of times to send (mesh is unreliable).
        """
        raw = build_packet(dest_id, opcode, payload)
        for i in range(repeats):
            encrypted = make_packet(self._mcp_key, random_seq(), raw)
            await self._write_encrypted(encrypted)
            if i < repeats - 1:
                await asyncio.sleep(0.5)

    async def receive(self, timeout: float = 3.0,
                      match: Callable[[dict], bool] | None = None) -> list[dict]:
        """Collect MCP responses until timeout.

        Args:
            timeout: Seconds to wait for responses.
            match: Optional predicate. When provided, only matching responses
                   are returned and collection stops after the first match
                   (unicast pattern). Without match, all responses are
                   collected for the full timeout (broadcast pattern).

        Returns list of {'source': int, 'opcode': int, 'payload': bytes}.
        Requires notification lifecycle (async with CSRMesh(...)).
        """
        if self._responses is None:
            raise RuntimeError("Must use 'async with CSRMesh(...)' to enable notifications")

        # Drain stale responses
        while not self._responses.empty():
            try:
                self._responses.get_nowait()
            except asyncio.QueueEmpty:
                break

        results = []
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                resp = await asyncio.wait_for(self._responses.get(), timeout=remaining)
                if match is None:
                    results.append(resp)
                elif match(resp):
                    results.append(resp)
                    break
            except TimeoutError:
                break
        return results

    async def recv(self, timeout: float = 1.0) -> dict | None:
        """Get next MCP response, or None on timeout."""
        if self._responses is None:
            raise RuntimeError("Must use 'async with CSRMesh(...)' to enable notifications")
        try:
            return await asyncio.wait_for(self._responses.get(), timeout=timeout)
        except TimeoutError:
            return None
