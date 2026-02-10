# recsrmesh

A Python library for the CSRMesh Bluetooth mesh protocol. Provides MASP
association, MCP mesh commands, and BLE transport over GATT.

## Features

- **Device discovery** -- find unprovisioned CSRMesh devices via a bridge
- **Association** -- full MASP handshake (ECDH key exchange, device ID and
  network key distribution)
- **Mesh commands** -- send and receive MCP packets (AES-OFB encrypted)
- **Disassociate** -- remove devices from the mesh
- **Async API** -- built on [bleak](https://github.com/hbldh/bleak) for
  cross-platform BLE

## Usage

```python
from bleak import BleakClient
from recsrmesh import CSRMesh

async with BleakClient(bridge_mac) as client:
    async with CSRMesh(client, passphrase) as mesh:
        # Discover unprovisioned devices
        devices = await mesh.discover_unassociated(timeout=5.0)

        # Associate a device into the mesh
        device_id = await mesh.associate(devices[0]["uuid_hash"], device_id=100)

        # Send a mesh command
        await mesh.send(dest_id=100, opcode=0x73, payload=b"\x01\x80")

        # Receive responses
        responses = await mesh.receive(timeout=3.0)

        # Remove a device from the mesh
        await mesh.disassociate(device_id=100)
```

## Installation

```
pip install recsrmesh
```

Requires Python 3.11+.

## License

LGPL-3.0-or-later
