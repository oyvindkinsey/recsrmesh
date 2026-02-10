"""Fake BleakClient for replay testing."""

import asyncio
from collections.abc import Callable
from typing import Any


class FakeBleakClient:
    """
    Device simulator for replay testing.

    Acts like a real BleakClient: accepts writes, verifies against transcript,
    delivers notifications to handlers.
    """

    def __init__(self, transcript: dict[str, Any]):
        self.transcript = transcript
        self.event_ptr = 0
        self.notification_handlers: dict[str, Callable[[Any, bytearray], None]] = {}
        self.connected = True

    async def start_notify(
        self, char_uuid: str, callback: Callable[[Any, bytearray], None]
    ) -> None:
        """Register notification handler, skip CCCD events."""
        self.notification_handlers[char_uuid] = callback

        while self.event_ptr < len(self.transcript["events"]):
            event = self.transcript["events"][self.event_ptr]
            if event["type"] == "descriptor_write" and \
               event["details"]["characteristic"] == char_uuid:
                self.event_ptr += 1
            else:
                break

        await self._replay_notifications()

    async def write_gatt_char(
        self,
        char_uuid: str,
        data: bytes,
        response: bool = True
    ) -> None:
        """Verify write matches transcript, then replay device response."""
        if self.event_ptr >= len(self.transcript["events"]):
            raise RuntimeError(
                f"State machine wrote beyond transcript end\n"
                f"  Characteristic: {char_uuid}\n"
                f"  Data: {data.hex()}"
            )

        event = self.transcript["events"][self.event_ptr]

        if event["type"] != "gatt_write":
            raise RuntimeError(
                f"Protocol violation at event {self.event_ptr}:\n"
                f"  Expected: {event['type']} (state machine should be waiting)\n"
                f"  Got: gatt_write to {char_uuid}"
            )

        expected_char = event["details"]["characteristic"]
        expected_data = bytes.fromhex(event["details"]["value"].replace(" ", "").replace("\n", ""))
        expected_type = event["details"]["write_type"]
        actual_type = "write_without_response" if not response else "write_with_response"

        if char_uuid != expected_char:
            raise AssertionError(
                f"Write to wrong characteristic at event {self.event_ptr}:\n"
                f"  Expected: {expected_char}\n"
                f"  Got:      {char_uuid}"
            )

        if data != expected_data:
            raise AssertionError(
                f"Write data mismatch at event {self.event_ptr}:\n"
                f"  Expected: {expected_data.hex()}\n"
                f"  Got:      {data.hex()}"
            )

        if actual_type != expected_type:
            raise AssertionError(
                f"Write type mismatch at event {self.event_ptr}:\n"
                f"  Expected: {expected_type}\n"
                f"  Got:      {actual_type}"
            )

        self.event_ptr += 1
        await self._replay_notifications()

    async def _replay_notifications(self):
        """Deliver consecutive notification events to handlers."""
        while self.event_ptr < len(self.transcript["events"]):
            event = self.transcript["events"][self.event_ptr]
            if event["type"] != "notification":
                break

            char_uuid = event["details"]["characteristic"]
            data = bytes.fromhex(event["details"]["value"].replace(" ", "").replace("\n", ""))

            handler = self.notification_handlers.get(char_uuid)
            if not handler:
                raise RuntimeError(
                    f"No handler registered for {char_uuid} at event {self.event_ptr}"
                )

            handler(None, bytearray(data))
            self.event_ptr += 1
            await asyncio.sleep(0.001)

    async def disconnect(self):
        self.connected = False

    async def stop_notify(self, char_uuid: str) -> None:
        pass

    def verify_complete(self):
        """Verify all transcript events were consumed."""
        if self.event_ptr != len(self.transcript["events"]):
            remaining = len(self.transcript["events"]) - self.event_ptr
            next_event = self.transcript["events"][self.event_ptr]
            raise AssertionError(
                f"Transcript not fully replayed:\n"
                f"  Consumed: {self.event_ptr}/{len(self.transcript['events'])}\n"
                f"  Remaining: {remaining} events\n"
                f"  Next event: {next_event['type']}"
            )
