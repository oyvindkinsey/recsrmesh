"""Replay tests: verify byte-for-byte match against captured Android transcripts."""

import json
from pathlib import Path

import pytest

from recsrmesh._fake_client import FakeBleakClient
from recsrmesh.crypto import xor_masp_packet
from recsrmesh.mesh import CSRMesh

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def get_transcripts():
    """Discover all capture transcript fixtures."""
    return sorted(FIXTURES_DIR.glob("capture_*.json"))


async def _run_replay(transcript_path: Path) -> None:
    """Run a single transcript replay, asserting byte-for-byte match."""
    with open(transcript_path) as f:
        transcript = json.load(f)

    device_id = transcript["metadata"]["assigned_device_id"]

    # Extract UUID hash and version counter from first packet
    first_write = transcript["events"][0]["details"]["value"]
    first_write_bytes = bytes.fromhex(first_write.replace(" ", "").replace("\n", ""))
    decoded = xor_masp_packet(first_write_bytes)
    device_uuid_hash = int.from_bytes(decoded[1:5], "little")
    version_counter = decoded[14]

    passphrase = "dfj4nNQJwZ3jw5ZlahvSWk5GeDLU71NyQrHY5vCDr+VTDNBnsTIuIssNWvTxuWQ+pTtEAs43NsBc2ovV0rLJ5A=="

    crypto = transcript["crypto_material"]
    crypto["version_counter"] = version_counter - 1

    fake_client = FakeBleakClient(transcript)
    async with CSRMesh(fake_client, passphrase) as mesh:
        result = await mesh.associate(
            device_uuid_hash,
            device_id=device_id,
            _replay_crypto=crypto,
        )
        assert result == device_id
    fake_client.verify_complete()


@pytest.mark.parametrize("transcript_path", get_transcripts(), ids=lambda p: p.name)
async def test_transcript_replay(transcript_path):
    """Each captured transcript replays with exact byte-for-byte match."""
    await _run_replay(transcript_path)
