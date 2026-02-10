# CSRMesh Association Protocol Specification

**Version:** 3.1
**Status:** Verified byte-for-byte via replay tests AND real device association
**Last Updated:** 2026-02-08

This is the formal specification of the CSRMesh device association protocol.

---

## Table of Contents

1. [Overview](#overview)
2. [BLE Transport Layer](#ble-transport-layer)
3. [Cryptography](#cryptography)
4. [Protocol Messages](#protocol-messages)
5. [Message Flow](#message-flow)
6. [Constants Reference](#constants-reference)

---

## Overview

CSRMesh uses a multi-step handshake protocol to associate new devices with a mesh network.

**Protocol Stack:**
```
Application Layer:  Device association logic
Message Layer:      MASP (Mesh Association Protocol) - Opcodes 0x00-0x0D
Security Layer:     XOR obfuscation + HMAC-SHA256 authentication
Transport Layer:    MTL (Mesh Transport Layer) - BLE GATT packet fragmentation
Physical Layer:     BLE GATT characteristics
```

**Security Features:**
- XOR obfuscation with 25-byte mask (all MASP packets)
- HMAC-SHA256 message authentication (8-byte MAC)
- ECDH key exchange (SECP192R1 curve) for secure provisioning
- 31-bit UUID hash for device identification

---

## BLE Transport Layer

### Service and Characteristics

**CSRMesh Service:**
- UUID: `0000fef1-0000-1000-8000-00805f9b34fb`

**Legacy MTL Characteristics:**

| Characteristic | UUID | Properties | Usage |
|----------------|------|------------|-------|
| Write (Low) | `c4edc000-9daf-11e3-8003-00025b000b00` | write-without-response, write, notify | First 20 bytes of packet |
| Write/Notify (High) | `c4edc000-9daf-11e3-8004-00025b000b00` | write-without-response, write, notify | Overflow bytes, bi-directional |

**Modern MTL Characteristics:**
- Write: `0000d011-d102-11e1-9b23-00025b00a5a5`
- Notify: `0000d012-d102-11e1-9b23-00025b00a5a5`

### Packet Fragmentation

**Complete Packet Structure:**
```
[Payload (N bytes)][MAC (8 bytes)][TTL (1 byte)]
```

**Transmission (TX to device):**
```
Short packets (≤20 bytes): Write to 8004 only
Long packets (>20 bytes):  Write first 20 bytes to 8003, overflow to 8004
```
**Reception (RX from device):**
```
Via bridge:  Notifications arrive reassembled on 8003 or 8004 (short packets on 8004).
             The bridge's MTL layer handles reassembly.
Direct BLE: Short packets arrive on 8004, long packets as 8003 + 8004 fragments.
```

### Bridge Requirement

**Association MUST be routed through a bridge device on an existing mesh.**

The Android app uses "GATT Bridge Mode".
It connects to a bridge device on the mesh and routes all MASP packets through it.

**Why:** After processing DEVICE_ID_DIST, the target device switches to mesh radio
for responses. DEVICE_ID_ACK, NETKEY_ACK etc. are sent via mesh, not back on GATT.
A bridge is needed to relay between GATT (our BLE connection) and mesh (the device).

**Direct BLE works partially:** ASSOC_REQUEST through RANDOM_RESPONSE all succeed
over a direct GATT connection. The failure point is DEVICE_ID_DIST → DEVICE_ID_ACK.

**Bridge selection:** Any CSRMesh device in BLE range can relay MASP — not just
devices on the same mesh. MASP uses a hardcoded key shared by all CSRMesh firmware,
so any device can decrypt and forward MASP packets. This was verified when a
neighbor's device (F2:31, different mesh) successfully relayed association.

The reference Android app scans for CSRMesh devices (service UUID `0000fef1`) and
picks the strongest-signal device — with **no exclusion of the target device**.
Since standard procedure during claiming is to be close to the target, the target
itself is likely selected as the bridge. Self-bridging fails (see below), so the
app relies on retry/fallback: after 2 failed attempts, the device is marked
unavailable and the selector falls through to the next strongest-RSSI device.

**Self-bridge fails:** A device cannot bridge its own association. Direct BLE
works through RANDOM_RESPONSE, but fails at DEVICE_ID_ACK — the device switches
to mesh radio responses and has no mesh peer to relay back to GATT.

**Bootstrap / first device:** The Android app always uses MASP, even for the first
device on a new mesh. There is no separate bootstrap protocol. This implies
the app expects at least one other CSRMesh device in BLE range (even on a different
mesh) to serve as relay. In dense installations (e.g. building fixtures),
neighboring devices are practically always present.

**Partial association timeout:** If MASP fails between DEVICE_ID_DIST and NETKEY
completion, the device rejects new ASSOC_REQUEST until it times out (~2 minutes)
or is factory reset. Sending UNCLAIM (see below) can help unstick faster.

**Example - 27 byte packet:**
- TX to 8003: bytes 0-19 (20 bytes)
- TX to 8004: bytes 20-26 (7 bytes)

---

## Cryptography

### Key Derivation

**Algorithm:**
```python
def derive_key(passphrase: str, salt: str) -> bytes:
    """
    Derive 16-byte key from passphrase and salt.

    Steps:
    1. Concatenate passphrase + salt (UTF-8 encoding)
    2. SHA256 hash → 32 bytes
    3. Reverse all 32 bytes
    4. Take first 16 bytes

    """
    data = passphrase.encode('utf-8') + salt.encode('utf-8')
    digest = bytearray(hashlib.sha256(data).digest())
    digest.reverse()
    return bytes(digest)[:16]
```

**Standard Keys:**

| Key Type | Derivation | Value (hex) |
|----------|------------|-------------|
| MASP Key | `derive_key("", "\x00MASP")` | `e9d804f88624ac0c7b1e06d884785994` |
| Network Key | `derive_key(network_passphrase, "\x00MCP")` | Device/network specific |

**Example Network Key:**
- Passphrase: `dfj4nNQJwZ3jw5ZlahvSWk5GeDLU71NyQrHY5vCDr+VTDNBnsTIuIssNWvTxuWQ+pTtEAs43NsBc2ovV0rLJ5A==`
- Key: `1da7b566dae6a009a3b70b2e1bb5003a`

### XOR Obfuscation

**CRITICAL:** Must replicate the implementation bug exactly!

**Algorithm:**
```python
def xor_masp_packet(data: bytes) -> bytes:
    """
    XOR packet with MASP obfuscation mask.

    BUG: Uses Math.min(i, mask_length-1) instead of i % mask_length
    After index 24, all bytes XOR with last mask byte (0x15)
    This bug MUST be replicated for compatibility!
    """
    mask = bytes([
        0x52, 0x20, 0xac, 0x39, 0x40, 0x18, 0xc4, 0x41,
        0xaa, 0xd1, 0x7d, 0x26, 0x05, 0xd5, 0x7f, 0xae,
        0x2c, 0xb3, 0x0e, 0xf5, 0xc5, 0x2d, 0x06, 0x24, 0x15
    ])
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ mask[min(i, len(mask) - 1)]  # Replicates firmware bug
    return bytes(result)
```

**XOR Mask (25 bytes):**
```
52 20 ac 39 40 18 c4 41 aa d1 7d 26 05 d5 7f ae 2c b3 0e f5 c5 2d 06 24 15
```

**Properties:**
- Symmetric: XOR twice returns original
- Applied to entire packet (before adding MAC)
- Bug causes bytes 25+ to XOR with 0x15

### HMAC Authentication

**Algorithm:**
```python
def hmac_sha256_truncated(data: bytes, key: bytes, length: int) -> bytes:
    """
    Calculate HMAC-SHA256 and return last N bytes reversed.

    Steps:
    1. HMAC-SHA256(data, key) → 32 bytes
    2. Take last 'length' bytes
    3. Reverse byte order

    """
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return bytes(reversed(mac[-length:]))
```

**Adding MAC to Packet:**
```python
def add_packet_mac(payload: bytes, key: bytes, ttl: int = 255) -> bytes:
    """
    Add 8-byte MAC and 1-byte TTL to packet.

    Structure: [payload][8-byte MAC][1-byte TTL]

    MAC is calculated over: 8 zero bytes + payload

    """
    mac_input = b'\x00' * 8 + payload
    mac = hmac_sha256_truncated(mac_input, key, 8)
    return payload + mac + bytes([ttl & 0xFF])
```

**Verifying MAC:**
```python
def verify_packet_mac(packet: bytes, key: bytes) -> tuple[bytes, bool]:
    """
    Verify and strip MAC from received packet.

    Returns: (payload, is_valid)

    Try MASP key first, then Network key if verification fails.
    """
    if len(packet) < 9:
        return packet, False

    payload = packet[:-9]
    received_mac = packet[-9:-1]

    mac_input = b'\x00' * 8 + payload
    expected_mac = hmac_sha256_truncated(mac_input, key, 8)

    return payload, hmac.compare_digest(received_mac, expected_mac)
```

### UUID Hash Calculation

**Algorithm:**
```python
def uuid_to_hash31(uuid_bytes: bytes) -> int:
    """
    Calculate 31-bit hash from 16-byte UUID.

    Steps:
    1. SHA256(uuid_bytes) → 32 bytes
    2. Take last 4 bytes
    3. Mask MSB to create 31-bit value
    4. Read as little-endian integer

    CRITICAL: Do NOT reverse UUID before hashing!
    """
    digest = hashlib.sha256(uuid_bytes).digest()
    last_4 = bytearray(digest[-4:])
    last_4[0] = last_4[0] & 0x7F  # Mask MSB (31-bit)
    return int.from_bytes(last_4, 'little')
```

**Example:**
- UUID: `00000000-0000-1200-0014-1cd6bd9fc7b0` (bytes: `b0c79fbdd61c14000012000000000000`)
- Hash: `0x771ff53e` (decimal: 1998181694)

**Usage:**
- App receives UUID_ANNOUNCE containing device UUID
- App calculates hash from extracted UUID
- App uses calculated hash (NOT advertised hash) in ASSOC_REQUEST

---

## Protocol Messages

### Opcodes

All opcodes are **logical values before XOR obfuscation**.

| Opcode | Name | XORs to | Direction | Description |
|--------|------|---------|-----------|-------------|
| 0x00 | DEVICE_ID_ANNOUNCE | 0x52 | App → Device | Initiate handshake |
| 0x01 | UUID_ANNOUNCE | 0x53 | Device → App | Device response with UUID |
| 0x02 | ASSOC_REQUEST | 0x50 | App → Device | Association request |
| 0x03 | ASSOC_RESPONSE | 0x51 | Device → App | Association response |
| 0x04 | PUBKEY_REQUEST | 0x56 | App → Device | Public key exchange request |
| 0x05 | PUBKEY_RESPONSE | 0x57 | Device → App | Public key exchange response |
| 0x06 | CONFIRM_REQUEST | 0x54 | App → Device | Confirmation request |
| 0x07 | CONFIRM_RESPONSE | 0x55 | Device → App | Confirmation response |
| 0x08 | RANDOM_REQUEST | 0x5A | App → Device | Random request |
| 0x09 | RANDOM_RESPONSE | 0x5B | Device → App | Random response |
| 0x0A | DEVICE_ID_DIST | 0x58 | App → Device | Device ID distribution |
| 0x0B | DEVICE_ID_ACK | 0x59 | Device → App | Device ID acknowledge |
| 0x0C | NETKEY_DIST | 0x5E | App → Device | Network key distribution |
| 0x0D | NETKEY_ACK | 0x5F | Device → App | Network key acknowledge |

### Message Structures

#### DEVICE_ID_ANNOUNCE (0x00)

**Purpose:** Initiate handshake with device

**Structure (18 bytes before XOR):**
```
Offset  Size  Field           Example         Description
------  ----  -----           -------         -----------
0       1     Opcode          0x00            DEVICE_ID_ANNOUNCE
1       4     UUID Hash       3e f5 1f 77     31-bit hash (LE)
5       1     Reserved        0x00
6       8     Sequence ID     00 00 00 00     Default: [0,0,0,0,0,0,0,1]
                              00 00 00 01
14      4     Padding         00 00 00 00
```

**After processing:**
1. XOR with mask
2. Add 8-byte MAC (MASP key)
3. Add 1-byte TTL (0xFF)
4. Total: 27 bytes

#### UUID_ANNOUNCE (0x01)

**Purpose:** Device announces its UUID

**Structure (18 bytes decoded):**
```
Offset  Size  Field           Description
------  ----  -----           -----------
0       1     Opcode          0x01 (UUID_ANNOUNCE)
1       16    UUID            Device UUID (16 bytes)
17      1     Counter/TTL     Increments with each announcement
```

**UUID Format:**
- Contains MAC address in reversed byte order in last 6 bytes
- Example: MAC `1C:D6:BD:9F:C7:B0` → UUID ends with `b0 c7 9f bd d6 1c`

**Note:** The first byte of the UUID is NOT a state byte — it is simply the
first byte of the 16-byte device UUID. Early investigation incorrectly
interpreted this as a readiness indicator (0xC7 vs 0x41). The byte varies
because different devices have different UUIDs.

#### ASSOC_REQUEST (0x02)

**Purpose:** Request association with device

**Structure (15 bytes before XOR):**
```
Offset  Size  Field           Example         Description
------  ----  -----           -------         -----------
0       1     Opcode          0x02            ASSOC_REQUEST
1       4     UUID Hash       3e f5 1f 77     Calculated hash (LE)
5       1     Auth Code Flag  0x00            0x00 = no code, 0x01 = use code
6       8     Sequence ID     00 00 00 00     Default sequence
                              00 00 00 01
14      1     Version         0x01            Protocol version
```

**After processing:**
1. XOR with mask
2. Add 8-byte MAC (MASP key)
3. Add 1-byte TTL (0xFF)
4. Total: 24 bytes

#### ASSOC_RESPONSE (0x03)

**Purpose:** Device accepts or rejects association

**Structure:**
```
Offset  Size  Field           Description
------  ----  -----           -----------
0       1     Opcode          0x03 (ASSOC_RESPONSE)
1       4     UUID Hash       Confirmed hash (LE)
5       1     Response Code   0=success no auth, 1=success with auth, 3=rejected
```

**Response Codes:**
- `0`: Success, no authorization code required
- `1`: Success, authorization code accepted
- `3`: Rejected

---

## Message Flow

### Complete Association Sequence

The following sequence is confirmed byte-for-byte via replay tests
against 4 captured Android association sequences, and verified against
real devices (2026-02-07).

All traffic is routed through a bridge device on the existing mesh.
The bridge relays MASP packets between the app (GATT) and the target device (mesh radio).

```
App              Bridge (GATT↔Mesh)          Target Device
 |                    |                           |
 |  ASSOC_REQUEST     |                           |
 |  (0x02)            |                           |
 |-----------------→  |  ~~~~~~~~relay~~~~~~~~→   |
 |                    |                           |
 |                    |   ←~~~~~relay~~~~~~~~~    |
 |  ASSOC_RESPONSE    |                           |
 |  (0x03)            |                           |
 | ←------------------|                           |
 |                    |                           |
 |  PUBKEY x6         |                           |
 |-----------------→  |  ~~~~~~~~relay~~~~~~~~→   |
 | ←------------------|  ←~~~~~relay~~~~~~~~~     |
 |                    |                           |
 |  CONFIRM           |                           |
 |-----------------→  |  ~~~~~~~~relay~~~~~~~~→   |
 | ←------------------|  ←~~~~~relay~~~~~~~~~     |
 |                    |                           |
 |  RANDOM            |                           |
 |-----------------→  |  ~~~~~~~~relay~~~~~~~~→   |
 | ←------------------|  ←~~~~~relay~~~~~~~~~     |
 |                    |                           |
 |  DEVICE_ID_DIST    |                           |
 |  (0x0A)            |                           |
 |-----------------→  |  ~~~~~~~~relay~~~~~~~~→   |
 |                    |                           |
 |                    |   ←~~~~~relay~~~~~~~~~    |
 |  DEVICE_ID_ACK     |  (device now on mesh)     |
 |  (0x0B)            |                           |
 | ←------------------|                           |
 |                    |                           |
 |  NETKEY_DIST x2    |                           |
 |  (0x0C)            |                           |
 |-----------------→  |  ~~~~~~~~relay~~~~~~~~→   |
 |                    |                           |
 |                    |   ←~~~~~relay~~~~~~~~~    |
 |  NETKEY_ACK x2     |                           |
 |  (0x0D)            |                           |
 | ←------------------|                           |
 |                    |                           |
```

**Note:** DEVICE_ID_ANNOUNCE (0x00) → UUID_ANNOUNCE (0x01) exchange is
optional and happens during the scanning/discovery phase, not during
association itself.

### Key Selection

**MAC Verification Order:**
1. Try MASP key first
2. If verification fails, try Network key
3. Early messages (0x00-0x03) typically use MASP key
4. Later messages may use Network key

---

## Constants Reference

### Sequence ID
```python
DEFAULT_SEQ_ID = bytes([0, 0, 0, 0, 0, 0, 0, 1])
```
### XOR Mask
```python
MASP_MASK = bytes([
    0x52, 0x20, 0xac, 0x39, 0x40, 0x18, 0xc4, 0x41,
    0xaa, 0xd1, 0x7d, 0x26, 0x05, 0xd5, 0x7f, 0xae,
    0x2c, 0xb3, 0x0e, 0xf5, 0xc5, 0x2d, 0x06, 0x24, 0x15
])
```
### BLE UUIDs
```python
# Service
CSR_MESH_SERVICE = "0000fef1-0000-1000-8000-00805f9b34fb"

# Legacy MTL Characteristics
CHAR_8003 = "c4edc000-9daf-11e3-8003-00025b000b00"  # Primary write/notify
CHAR_8004 = "c4edc000-9daf-11e3-8004-00025b000b00"  # Overflow write/notify

# Modern MTL Characteristics
MTL_WRITE_MODERN = "0000d011-d102-11e1-9b23-00025b00a5a5"
MTL_NOTIFY_MODERN = "0000d012-d102-11e1-9b23-00025b00a5a5"
```

### ECDH Curve
```python
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP192R1()  # Also known as prime192v1
```

### TTL Values
```python
ASSOCIATION_TTL = 55   # 0x37 - Used during association
DEFAULT_TTL = 255      # 0xFF - Used in documentation/other contexts
```
Android app uses TTL=55 for all association messages. This is confirmed
by replay test byte-for-byte match.

## Implementation Notes

### Critical Bugs to Replicate

1. **XOR Algorithm Bug**
   - Uses `Math.min(i, 24)` instead of `i % 25`
   - Bytes after index 24 XOR with last mask byte (0x15)
   - **Must replicate exactly** for compatibility

2. **No UUID Reversal**
   - UUID is hashed as-is (bytes from UUID_ANNOUNCE packet)
   - Do NOT reverse before hashing
   - Previous implementations had this bug

### Verification

**Packet should match Android exactly:**
- XOR obfuscation: byte-for-byte identical
- HMAC calculation: last 8 bytes of SHA256, reversed
- Hash calculation: no UUID reversal, 31-bit mask, little-endian

---

## Post-Association Operations

### UNCLAIM (Device Removal from Mesh)

Removes a device from the CSRMesh network. This is distinct from "disassociate"
which manages controller-slot pairings (which switch controls which light).

**Opcode:** `0x04` (distinct from `0x73` used for regular mesh commands)

**Packet format (13 bytes plaintext):**
```
Offset  Size  Field           Description
------  ----  -----           -----------
0       1     Target (low)    Device ID low byte
1       1     Target (high)   Device ID high byte
2       1     Opcode          0x04 (UNCLAIM)
3-12    10    Padding         All zeros
```

**Target byte order:** Big-endian device ID, then bytes swapped to little-endian
in the packet. For device_id=33896 (0x8468): `target = [0x68, 0x84, 0x04, 0x00...]`

**Encryption:** Same as regular mesh commands — encrypted with the network key
via `csrmeshcrypto.make_packet()` (AES-OFB + HMAC). NOT XOR-obfuscated like MASP.

**Transmission:** Standard MTL fragmentation (first 20 bytes → 8003, overflow → 8004).
Fire-and-forget — no ACK. Send 3x with 500ms delay for reliability.

**After unclaim:** Device leaves mesh, reverts to unprovisioned state, and
re-advertises with service UUID `0000fef1`.

**Implementation:** `CSRMesh.unclaim_device()` in `recsrmesh.mesh`

### Active Mesh Probe (Device Discovery)

Passive BLE scanning cannot distinguish provisioned from unprovisioned CSRMesh
devices — all advertise with the same service UUID `0000fef1`.

The Android app uses an **active mesh probe**: broadcast `READ DIMMING` with
`device_id=0` (all devices), encrypted with the network key. Only devices
sharing the network key can decrypt the command and respond with their
brightness state. Each response identifies a provisioned device.

**This is the only reliable method to enumerate provisioned mesh members.**

### Active MASP Discovery

Connects to a bridge device and sends DEVICE_ID_ANNOUNCE (opcode 0x00) with
hash=0 (broadcast). Only unprovisioned devices in MASP IDLE state respond with
UUID_ANNOUNCE. This is the same mechanism the Android app uses internally.

**Implementation:** `CSRMesh.discover_unclaimed()` in `recsrmesh.mesh`

### Passive Scan Limitations

Passive BLE scanning cannot distinguish provisioned from unprovisioned CSRMesh devices:

- Service UUID `0000fef1` is present on ALL CSRMesh devices (provisioned and not)
- OEM-specific manufacturer data and device names are identical across states
- Neighbor devices on other meshes also match all these criteria

---

## Appendix: Example Packets

### DEVICE_ID_ANNOUNCE

**Before XOR:**
```
00 3e f5 1f 77 00 00 00 00 00 00 00 00 01 00 00 00 00
```

**After XOR:**
```
52 1e 59 26 37 18 c4 41 aa d1 7d 26 05 d4 7f ae 2c b3
```

**With MAC and TTL:**
```
52 1e 59 26 37 18 c4 41 aa d1 7d 26 05 d4 7f ae 2c b3
4d cb 47 9c 13 7b ff 6f ff
```

### ASSOC_REQUEST

**Before XOR:**
```
02 3e f5 1f 77 00 00 00 00 00 00 00 00 01 01
```

**After XOR:**
```
50 1e 59 26 37 18 c4 41 aa d1 7d 26 05 d4 7e
```

**With MAC and TTL:**
```
50 1e 59 26 37 18 c4 41 aa d1 7d 26 05 d4 7e
3b b5 36 a0 2a 8d f9 14 ff
```

---

**Document Version:** 3.1
**Protocol Version:** Verified byte-for-byte against captured Android CSRMesh traffic via replay tests
**Last Updated:** 2026-02-08
