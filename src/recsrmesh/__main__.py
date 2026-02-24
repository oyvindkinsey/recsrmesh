"""SG (CSRMesh) terminal UI — manage mesh devices from the command line."""

import asyncio
import json
import os

from bleak import BleakClient, BleakError, BleakScanner

from recsrmesh import CSRMesh

# CSR standard model opcodes (from FACTS.md)
POWER_OPCODE = 0x89   # PowerModelApi — model_id 19
LIGHT_OPCODE = 0x8A   # LightModelApi — model_id 20
GROUP_GET_NUM = 0x0D  # GET_NUM_GROUPS  payload: [model_id, TID]
GROUP_SET     = 0x0F  # SET_GROUP       payload: [model_id, slot, instance, gid_lo, gid_hi, TID]
GROUP_GET     = 0x10  # GET_GROUP       payload: [model_id, slot, TID]

POWER_MODEL_ID = 19
LIGHT_MODEL_ID = 20

DB_PATH = os.path.join(os.getcwd(), "sg_mesh_db.json")

# SG device ID range (distinct from Avi-on 32896-65407)
MIN_DEVICE_ID = 0x0020   # 32
MAX_DEVICE_ID = 0x7FFF   # 32767

MIN_GROUP_ID = 0x0100   # 256
MAX_GROUP_ID = 0x7EFF   # 32511

_tid = 0


def _next_tid() -> int:
    global _tid
    _tid = (_tid + 1) & 0xFF
    return _tid


# --- Async input ---


async def ainput(prompt: str = "") -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


# --- Database ---


def load_db() -> dict:
    if os.path.exists(DB_PATH):
        with open(DB_PATH) as f:
            db: dict = json.load(f)
        db.setdefault("groups", [])
        return db
    return {"passphrase": None, "devices": [], "groups": []}


def save_db(db: dict) -> None:
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f, indent=2)
        f.write("\n")
    os.replace(tmp, DB_PATH)


def find_device(db: dict, device_id: int) -> dict | None:
    for d in db["devices"]:
        if d["device_id"] == device_id:
            return d
    return None


def upsert_device(db: dict, device: dict) -> None:
    for i, d in enumerate(db["devices"]):
        if d["device_id"] == device["device_id"]:
            db["devices"][i] = device
            return
    db["devices"].append(device)


def remove_device(db: dict, device_id: int) -> None:
    db["devices"] = [d for d in db["devices"] if d["device_id"] != device_id]


def next_device_id(db: dict) -> int:
    existing = [
        d["device_id"] for d in db["devices"]
        if MIN_DEVICE_ID <= d["device_id"] <= MAX_DEVICE_ID
    ]
    return int(max(existing)) + 1 if existing else MIN_DEVICE_ID


def find_group(db: dict, group_id: int) -> dict | None:
    for g in db["groups"]:
        if g["group_id"] == group_id:
            return g
    return None


def upsert_group(db: dict, group: dict) -> None:
    for i, g in enumerate(db["groups"]):
        if g["group_id"] == group["group_id"]:
            db["groups"][i] = group
            return
    db["groups"].append(group)


def remove_group(db: dict, group_id: int) -> None:
    db["groups"] = [g for g in db["groups"] if g["group_id"] != group_id]


def next_group_id(db: dict) -> int:
    existing = [
        g["group_id"] for g in db["groups"]
        if MIN_GROUP_ID <= g["group_id"] <= MAX_GROUP_ID
    ]
    return int(max(existing)) + 1 if existing else MIN_GROUP_ID


# --- CSR model helpers ---


async def power_set(csr: CSRMesh, dest_id: int, on: bool) -> None:
    """SET_STATE no-ack."""
    await csr.send(dest_id, POWER_OPCODE, bytes([0x00, 0x01 if on else 0x00]))


async def light_set_level(csr: CSRMesh, dest_id: int, level: int) -> None:
    """SET_LEVEL no-ack. level: 0-255."""
    await csr.send(dest_id, LIGHT_OPCODE, bytes([0x00, level]))


async def light_set_color_temp(csr: CSRMesh, dest_id: int, kelvin: int) -> None:
    """SET_COLOR_TEMP acked. kelvin: 0-65535."""
    tid = _next_tid()
    ct_lo = kelvin & 0xFF
    ct_hi = (kelvin >> 8) & 0xFF
    await csr.send(dest_id, LIGHT_OPCODE, bytes([0x06, ct_lo, ct_hi, 0x00, 0x00, tid]))


async def light_get_state(csr: CSRMesh, dest_id: int) -> dict | None:
    """GET_STATE acked. Returns parsed state dict or None."""
    tid = _next_tid()
    await csr.send(dest_id, LIGHT_OPCODE, bytes([0x07, tid]))

    def _match(r: dict) -> bool:
        return r["opcode"] == LIGHT_OPCODE and len(r.get("payload", b"")) >= 9 and r["payload"][0] == 0x08

    responses = await csr.receive(timeout=2.0, match=_match)
    if not responses:
        return None
    p = responses[0]["payload"]
    return {
        "source": responses[0].get("crypto_source") or responses[0].get("source"),
        "power_state": p[1],
        "level": p[2],
        "r": p[3], "g": p[4], "b": p[5],
        "color_temp": int.from_bytes(p[6:8], "little"),
        "supports": p[8],
    }


async def power_get_state(csr: CSRMesh, dest_id: int) -> dict | None:
    """GET_STATE acked. Returns parsed power dict or None."""
    tid = _next_tid()
    await csr.send(dest_id, POWER_OPCODE, bytes([0x04, tid]))

    def _match(r: dict) -> bool:
        return r["opcode"] == POWER_OPCODE and len(r.get("payload", b"")) >= 2 and r["payload"][0] == 0x05

    responses = await csr.receive(timeout=2.0, match=_match)
    if not responses:
        return None
    p = responses[0]["payload"]
    return {
        "source": responses[0].get("crypto_source") or responses[0].get("source"),
        "power_state": p[1],   # 0=OFF 1=ON 2=STANDBY 3=ON_FROM_STANDBY
    }


# --- Group model ---

_POWER_STATES = {0: "OFF", 1: "ON", 2: "STANDBY", 3: "ON_FROM_STANDBY"}


async def group_get_capacity(csr: CSRMesh, device_id: int, model_id: int) -> int:
    """GET_NUM_GROUPS for model_id. Returns capacity (0 on no response)."""
    tid = _next_tid()
    await csr.send(device_id, GROUP_GET_NUM, bytes([model_id, tid]))

    def _match(r: dict) -> bool:
        return (r["opcode"] == 0x0E and len(r.get("payload", b"")) >= 2
                and r["payload"][0] == model_id)

    responses = await csr.receive(timeout=2.0, match=_match)
    if not responses:
        return 0
    return responses[0]["payload"][1]


async def group_read_slots(csr: CSRMesh, device_id: int, model_id: int) -> list[int]:
    """Read all non-zero group IDs from device for given model."""
    capacity = await group_get_capacity(csr, device_id, model_id)
    if not capacity:
        return []

    def _match_slot(r: dict) -> bool:
        return (r["opcode"] == 0x11 and len(r.get("payload", b"")) >= 5
                and r["payload"][0] == model_id)

    group_ids = []
    for slot in range(capacity):
        tid = _next_tid()
        await csr.send(device_id, GROUP_GET, bytes([model_id, slot, tid]))
        responses = await csr.receive(timeout=2.0, match=_match_slot)
        if not responses:
            continue
        p = responses[0]["payload"]
        # Response: [model_id, slot, instance, gid_lo, gid_hi] — little-endian gid
        gid = int.from_bytes(p[3:5], "little")
        if gid:
            group_ids.append(gid)
    return group_ids


async def group_assign(csr: CSRMesh, device_id: int, model_id: int, group_id: int) -> bool:
    """Assign group_id to the first free slot on device for model_id. Returns True on success."""
    capacity = await group_get_capacity(csr, device_id, model_id)
    if not capacity:
        return False

    def _match_slot(r: dict) -> bool:
        return (r["opcode"] == 0x11 and len(r.get("payload", b"")) >= 5
                and r["payload"][0] == model_id)

    # Find free slot (gid == 0)
    for slot in range(capacity):
        tid = _next_tid()
        await csr.send(device_id, GROUP_GET, bytes([model_id, slot, tid]))
        responses = await csr.receive(timeout=2.0, match=_match_slot)
        if not responses:
            continue
        p = responses[0]["payload"]
        gid = int.from_bytes(p[3:5], "little")
        if gid == 0:
            # Write here
            gid_lo = group_id & 0xFF
            gid_hi = (group_id >> 8) & 0xFF
            tid2 = _next_tid()
            await csr.send(device_id, GROUP_SET,
                           bytes([model_id, slot, 0, gid_lo, gid_hi, tid2]))
            await csr.receive(timeout=1.0)
            return True
    return False  # no free slot


async def group_remove(csr: CSRMesh, device_id: int, model_id: int, group_id: int) -> None:
    """Remove group_id from device for model_id by zeroing its slot."""
    capacity = await group_get_capacity(csr, device_id, model_id)
    if not capacity:
        return

    def _match_slot(r: dict) -> bool:
        return (r["opcode"] == 0x11 and len(r.get("payload", b"")) >= 5
                and r["payload"][0] == model_id)

    for slot in range(capacity):
        tid = _next_tid()
        await csr.send(device_id, GROUP_GET, bytes([model_id, slot, tid]))
        responses = await csr.receive(timeout=2.0, match=_match_slot)
        if not responses:
            continue
        p = responses[0]["payload"]
        gid = int.from_bytes(p[3:5], "little")
        if gid == group_id:
            tid2 = _next_tid()
            await csr.send(device_id, GROUP_SET,
                           bytes([model_id, slot, 0, 0x00, 0x00, tid2]))
            await csr.receive(timeout=1.0)
            return


# --- BLE ---


async def find_bridges(timeout: float = 5.0) -> list[str]:
    """Scan BLE devices, return all addresses sorted by RSSI (strongest first)."""
    devices_advs = await BleakScanner.discover(timeout=timeout, return_adv=True)
    candidates = [(dev, adv) for dev, adv in devices_advs.values()]
    candidates.sort(key=lambda x: x[1].rssi or -999, reverse=True)
    return [c[0].address for c in candidates]


class BLEConnection:
    def __init__(self):
        self._client: BleakClient | None = None
        self._csr: CSRMesh | None = None
        self._passphrase: str | None = None
        self._bridge: str | None = None
        self._bridge_candidates: list[str] = []

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def connect(self, passphrase: str, bridge: str | None = None) -> None:
        cached = bridge or self._bridge
        await self.disconnect()
        if cached:
            bridge_addr = cached
            print(f"Reconnecting to {bridge_addr}...")
        else:
            print("Scanning for BLE devices...")
            self._bridge_candidates = await find_bridges()
            if not self._bridge_candidates:
                raise RuntimeError("No BLE devices found")
            bridge_addr = self._bridge_candidates[0]
            print(f"Connecting to {bridge_addr}...")
        self._bridge = bridge_addr
        self._client = BleakClient(bridge_addr)
        try:
            await self._client.disconnect()
        except Exception:
            pass
        try:
            await self._client.__aenter__()
        except Exception:
            self._bridge = None
            raise
        self._csr = CSRMesh(self._client, passphrase)
        await self._csr.__aenter__()
        self._passphrase = passphrase
        print(f"Connected to {bridge_addr}")

    async def disconnect(self) -> None:
        if self._csr:
            try:
                await self._csr.__aexit__(None, None, None)
            except Exception:
                pass
            self._csr = None
        if self._client:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:
                pass
            self._client = None
        self._passphrase = None

    def alternative_bridges(self) -> list[str]:
        return [b for b in self._bridge_candidates if b != self._bridge]

    async def ensure_connected(self, passphrase: str) -> CSRMesh:
        if not (self.is_connected and self._passphrase == passphrase):
            await self.connect(passphrase)
        assert self._csr is not None
        return self._csr


# --- Actions ---


async def action_setup_passphrase(db: dict) -> dict:
    passphrase = (await ainput("Enter passphrase: ")).strip()
    if not passphrase:
        print("Cancelled.")
        return db
    db["passphrase"] = passphrase
    save_db(db)
    print("Passphrase saved.")
    return db


async def action_scan_claim(db: dict, conn: BLEConnection) -> dict:
    if not db["passphrase"]:
        print("Set passphrase first (option 1).")
        return db

    csr = await conn.ensure_connected(db["passphrase"])
    print("Scanning for unclaimed devices (5s)...")
    found = await csr.discover_unassociated(timeout=5.0)
    if not found:
        print("No unclaimed devices found.")
        return db

    print(f"\nFound {len(found)} unclaimed device(s):")
    for i, dev in enumerate(found):
        print(f"  {i + 1}. uuid_hash=0x{dev['uuid_hash']:08x}")

    choice = (await ainput("Pick device # (or Enter to cancel): ")).strip()
    if not choice:
        return db
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(found):
            raise ValueError
    except ValueError:
        print("Invalid choice.")
        return db

    picked = found[idx]
    uuid_hash = picked["uuid_hash"]
    candidate_id = next_device_id(db)

    print(f"Associating 0x{uuid_hash:08x} as device_id={candidate_id}...")
    try:
        device_id = await csr.associate(uuid_hash, candidate_id)
    except RuntimeError as e:
        if "WAIT_DEVICE_ID_ACK" not in str(e):
            raise
        alternatives = conn.alternative_bridges()
        if not alternatives:
            print("  DEVICE_ID_ACK timeout and no alternative bridge available.")
            raise
        device_id = None
        for alt in alternatives:
            print(f"  DEVICE_ID_ACK timeout — switching to bridge {alt}...")
            await conn.connect(db["passphrase"], bridge=alt)
            assert conn._csr is not None
            csr = conn._csr
            try:
                device_id = await csr.associate(uuid_hash, candidate_id)
                break
            except RuntimeError as e2:
                if "WAIT_DEVICE_ID_ACK" not in str(e2):
                    raise
        if device_id is None:
            print("  All bridges exhausted.")
            return db

    print(f"Assigned device_id={device_id}")

    name = (await ainput("Name for this device: ")).strip() or f"Device {device_id}"
    upsert_device(db, {"device_id": device_id, "name": name})
    save_db(db)
    print(f"Saved '{name}' (id={device_id}).")
    return db


async def action_discover_mesh(db: dict, conn: BLEConnection) -> dict:
    if not db["passphrase"]:
        print("Set passphrase first (option 1).")
        return db

    csr = await conn.ensure_connected(db["passphrase"])
    known_ids = {d["device_id"] for d in db["devices"]}

    print("Broadcasting Power GET_STATE to mesh (5s)...")
    tid = _next_tid()
    # Broadcast to dest_id=0
    await csr.send(0, POWER_OPCODE, bytes([0x04, tid]))
    responses = await csr.receive(timeout=5.0)

    seen: dict[int, int] = {}  # device_id → power_state
    for r in responses:
        if r["opcode"] != POWER_OPCODE:
            continue
        p = r.get("payload", b"")
        if len(p) < 2 or p[0] != 0x05:
            continue
        did = r.get("crypto_source") or r.get("source")
        if did and did not in seen:
            seen[did] = p[1]

    if not seen:
        print("No devices responded.")
        return db

    unknown = {did: ps for did, ps in seen.items() if did not in known_ids}
    known_found = {did: ps for did, ps in seen.items() if did in known_ids}

    if known_found:
        print(f"\nKnown devices ({len(known_found)}):")
        for did, ps in sorted(known_found.items()):
            dev = find_device(db, did)
            name = dev["name"] if dev else f"Device {did}"
            print(f"  {name} (id={did})  power={_POWER_STATES.get(ps, ps)}")

    if not unknown:
        print(f"\nAll {len(seen)} responding device(s) are already in the database.")
        return db

    print(f"\nUnknown devices ({len(unknown)}):")
    unknown_list = sorted(unknown.items())
    for i, (did, ps) in enumerate(unknown_list):
        print(f"  {i + 1}. id={did}  power={_POWER_STATES.get(ps, ps)}")

    choice = (await ainput("Pick device # to add (or Enter to cancel): ")).strip()
    if not choice:
        return db
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(unknown_list):
            raise ValueError
    except ValueError:
        print("Invalid choice.")
        return db

    did, _ = unknown_list[idx]
    name = (await ainput("Name for this device: ")).strip() or f"Device {did}"
    upsert_device(db, {"device_id": did, "name": name})
    save_db(db)
    print(f"Saved '{name}' (id={did}).")
    return db


async def action_examine_device(csr: CSRMesh, device: dict, db: dict) -> None:
    did = device["device_id"]
    print(f"\n=== {device['name']} (id={did}) ===\n")

    print("Light state:")
    state = await light_get_state(csr, did)
    if state:
        ps = _POWER_STATES.get(state["power_state"], state["power_state"])
        ct = state["color_temp"]
        print(f"  Power:      {ps}")
        print(f"  Level:      {state['level']}")
        print(f"  RGB:        ({state['r']}, {state['g']}, {state['b']})")
        print(f"  Color temp: {ct}K" if ct else "  Color temp: (not set)")
        print(f"  Supports:   0x{state['supports']:02x}")
    else:
        print("  (no response)")

    print("\nPower state:")
    pstate = await power_get_state(csr, did)
    if pstate:
        print(f"  {_POWER_STATES.get(pstate['power_state'], pstate['power_state'])}")
    else:
        print("  (no response)")

    print("\nGroups (Light model):")
    gids = await group_read_slots(csr, did, LIGHT_MODEL_ID)
    if gids:
        for gid in gids:
            g = find_group(db, gid)
            label = f' "{g["name"]}"' if g else ""
            print(f"  - {gid}{label}")
    else:
        print("  (none)")


async def _device_group_menu(db: dict, csr: CSRMesh, device: dict) -> None:
    did = device["device_id"]
    while True:
        print(f"\nReading groups on {device['name']}...")
        gids = await group_read_slots(csr, did, LIGHT_MODEL_ID)

        print(f"\nGroups on {device['name']}:")
        if gids:
            for gid in gids:
                g = find_group(db, gid)
                label = f' "{g["name"]}"' if g else ""
                print(f"  - {gid}{label}")
        else:
            print("  (none)")

        print("\n1. Add to group")
        print("2. Remove from group")
        print("3. Back")

        choice = (await ainput("> ")).strip()
        try:
            if choice == "1":
                if db["groups"]:
                    print("Known groups:")
                    for i, grp in enumerate(db["groups"]):
                        print(f'  {i + 1}. Group {grp["group_id"]} "{grp["name"]}"')
                    pick = (await ainput("Group # or raw group ID (or Enter to cancel): ")).strip()
                    if not pick:
                        continue
                    val = int(pick)
                    gid = db["groups"][val - 1]["group_id"] if 1 <= val <= len(db["groups"]) else val
                else:
                    pick = (await ainput("Group ID (or Enter to cancel): ")).strip()
                    if not pick:
                        continue
                    gid = int(pick)

                ok = await group_assign(csr, did, LIGHT_MODEL_ID, gid)
                if ok:
                    # Also assign to Power model so group commands work for both
                    await group_assign(csr, did, POWER_MODEL_ID, gid)
                    g = find_group(db, gid)
                    label = f' "{g["name"]}"' if g else ""
                    print(f"Added to group {gid}{label}.")
                else:
                    print("No free group slot available.")

            elif choice == "2":
                if not gids:
                    print("No groups to remove.")
                    continue
                print("Current groups:")
                for i, gid in enumerate(gids):
                    g = find_group(db, gid)
                    label = f' "{g["name"]}"' if g else ""
                    print(f"  {i + 1}. {gid}{label}")
                pick = (await ainput("Group # to remove (or Enter to cancel): ")).strip()
                if not pick:
                    continue
                idx = int(pick) - 1
                if idx < 0 or idx >= len(gids):
                    raise ValueError
                gid = gids[idx]
                await group_remove(csr, did, LIGHT_MODEL_ID, gid)
                await group_remove(csr, did, POWER_MODEL_ID, gid)
                print(f"Removed from group {gid}.")

            elif choice == "3":
                return

        except (BleakError, RuntimeError, TimeoutError) as e:
            print(f"Error: {e}")
        except (ValueError, IndexError):
            print("Invalid input.")
        except EOFError:
            return


async def device_control_menu(db: dict, conn: BLEConnection, device: dict) -> dict:
    did = device["device_id"]
    while True:
        print(f"\n=== {device['name']} (id={did}) ===")
        print("1. Set brightness (0-255)")
        print("2. Set color temp (2700-6500K)")
        print("3. Turn ON")
        print("4. Turn OFF")
        print("5. Manage groups")
        print("6. Examine device")
        print("7. Unclaim (disassociate)")
        print("8. Back")

        choice = (await ainput("> ")).strip()
        try:
            csr = await conn.ensure_connected(db["passphrase"])

            if choice == "1":
                val = int((await ainput("Brightness (0-255): ")).strip())
                if not 0 <= val <= 255:
                    raise ValueError
                await light_set_level(csr, did, val)
                print(f"Brightness -> {val}")

            elif choice == "2":
                val = int((await ainput("Color temp (2700-6500): ")).strip())
                if not 2700 <= val <= 6500:
                    raise ValueError
                await light_set_color_temp(csr, did, val)
                print(f"Color temp -> {val}K")

            elif choice == "3":
                await power_set(csr, did, True)
                print("ON")

            elif choice == "4":
                await power_set(csr, did, False)
                print("OFF")

            elif choice == "5":
                await _device_group_menu(db, csr, device)

            elif choice == "6":
                await action_examine_device(csr, device, db)

            elif choice == "7":
                confirm = (await ainput(f"Unclaim '{device['name']}'? (y/N): ")).strip().lower()
                if confirm == "y":
                    await csr.disassociate(did)
                    remove_device(db, did)
                    save_db(db)
                    print("Device unclaimed and removed.")
                    return db

            elif choice == "8":
                return db

        except (BleakError, RuntimeError, TimeoutError) as e:
            print(f"Error: {e}")
            await conn.disconnect()
        except (ValueError, IndexError):
            print("Invalid input.")
        except EOFError:
            return db


async def action_manage_groups(db: dict, conn: BLEConnection) -> dict:
    while True:
        print("\nGroups:")
        if db["groups"]:
            for i, g in enumerate(db["groups"]):
                print(f'  {i + 1}. Group {g["group_id"]} "{g["name"]}"')
        else:
            print("  (none)")

        print("\na. Create group")
        print("b. Rename group")
        print("c. Delete group")
        print("d. Back")

        choice = (await ainput("> ")).strip().lower()
        try:
            if choice == "a":
                gid = next_group_id(db)
                name = (await ainput(f"Group name (id={gid}): ")).strip()
                if not name:
                    print("Cancelled.")
                    continue
                upsert_group(db, {"group_id": gid, "name": name})
                save_db(db)
                print(f'Created group {gid} "{name}".')

            elif choice == "b":
                if not db["groups"]:
                    print("No groups to rename.")
                    continue
                pick = (await ainput("Group # to rename: ")).strip()
                idx = int(pick) - 1
                if idx < 0 or idx >= len(db["groups"]):
                    raise ValueError
                g = db["groups"][idx]
                name = (await ainput(f"New name for group {g['group_id']}: ")).strip()
                if not name:
                    print("Cancelled.")
                    continue
                g["name"] = name
                save_db(db)
                print(f'Renamed group {g["group_id"]} to "{name}".')

            elif choice == "c":
                if not db["groups"]:
                    print("No groups to delete.")
                    continue
                pick = (await ainput("Group # to delete: ")).strip()
                idx = int(pick) - 1
                if idx < 0 or idx >= len(db["groups"]):
                    raise ValueError
                g = db["groups"][idx]
                confirm = (
                    await ainput(
                        f'Delete group {g["group_id"]} "{g["name"]}"? '
                        f"Remove from all known devices? (y/N): "
                    )
                ).strip().lower()
                if confirm != "y":
                    print("Cancelled.")
                    continue
                if db["passphrase"] and db["devices"]:
                    try:
                        csr = await conn.ensure_connected(db["passphrase"])
                        for dev in db["devices"]:
                            await group_remove(csr, dev["device_id"], LIGHT_MODEL_ID, g["group_id"])
                            await group_remove(csr, dev["device_id"], POWER_MODEL_ID, g["group_id"])
                        print(f"  Removed from {len(db['devices'])} device(s).")
                    except (BleakError, RuntimeError, TimeoutError) as e:
                        print(f"  Warning: could not remove from devices: {e}")
                remove_group(db, g["group_id"])
                save_db(db)
                print(f"Group {g['group_id']} deleted.")

            elif choice == "d":
                return db

        except (ValueError, IndexError):
            print("Invalid input.")
        except EOFError:
            return db


async def group_control_menu(db: dict, conn: BLEConnection, group: dict) -> dict:
    gid = group["group_id"]

    while True:
        print(f'\n=== Group {gid} "{group["name"]}" ===')
        print("1. Set brightness (0-255)")
        print("2. Set color temp (2700-6500K)")
        print("3. Turn ON")
        print("4. Turn OFF")
        print("5. Back")

        choice = (await ainput("> ")).strip()
        try:
            csr = await conn.ensure_connected(db["passphrase"])

            if choice == "1":
                val = int((await ainput("Brightness (0-255): ")).strip())
                if not 0 <= val <= 255:
                    raise ValueError
                await light_set_level(csr, gid, val)
                print(f"Brightness -> {val}")

            elif choice == "2":
                val = int((await ainput("Color temp (2700-6500): ")).strip())
                if not 2700 <= val <= 6500:
                    raise ValueError
                await light_set_color_temp(csr, gid, val)
                print(f"Color temp -> {val}K")

            elif choice == "3":
                await power_set(csr, gid, True)
                print("ON")

            elif choice == "4":
                await power_set(csr, gid, False)
                print("OFF")

            elif choice == "5":
                return db

        except (BleakError, RuntimeError, TimeoutError) as e:
            print(f"Error: {e}")
            await conn.disconnect()
        except (ValueError, IndexError):
            print("Invalid input.")
        except EOFError:
            return db


async def action_view_control(db: dict, conn: BLEConnection) -> dict:
    if not db["devices"] and not db["groups"]:
        print("No devices or groups in database.")
        return db

    n_dev = len(db["devices"])
    print("\nDevices:")
    if db["devices"]:
        for i, dev in enumerate(db["devices"]):
            print(f"  {i + 1}. {dev['name']}  (id={dev['device_id']})")
    else:
        print("  (none)")

    print("Groups:")
    if db["groups"]:
        for i, grp in enumerate(db["groups"]):
            print(f"  {n_dev + i + 1}. {grp['name']}  (group_id={grp['group_id']})")
    else:
        print("  (none)")

    choice = (await ainput("Pick # (or Enter to cancel): ")).strip()
    if not choice:
        return db
    try:
        idx = int(choice) - 1
        total = n_dev + len(db["groups"])
        if idx < 0 or idx >= total:
            raise ValueError
    except ValueError:
        print("Invalid choice.")
        return db

    if idx < n_dev:
        return await device_control_menu(db, conn, db["devices"][idx])
    else:
        return await group_control_menu(db, conn, db["groups"][idx - n_dev])


async def action_scan_all_groups(db: dict, conn: BLEConnection) -> dict:
    """Read group memberships from all known devices and sync DB."""
    if not db["passphrase"]:
        print("Set passphrase first (option 1).")
        return db
    if not db["devices"]:
        print("No devices in database.")
        return db

    csr = await conn.ensure_connected(db["passphrase"])
    print("\nScanning group memberships (Light model) from all devices...\n")

    all_gids: set[int] = set()
    for dev in db["devices"]:
        did = dev["device_id"]
        print(f"  {dev['name']} (id={did})...", end=" ", flush=True)
        try:
            gids = await group_read_slots(csr, did, LIGHT_MODEL_ID)
        except (BleakError, RuntimeError, TimeoutError) as e:
            print(f"ERROR: {e}")
            continue
        dev["groups"] = sorted(gids)
        all_gids.update(gids)
        labels = []
        for gid in gids:
            g = find_group(db, gid)
            labels.append(str(gid) + (f' "{g["name"]}"' if g else " (unknown)"))
        print(", ".join(labels) if labels else "(none)")

    known_ids = {g["group_id"] for g in db["groups"]}
    missing = all_gids - known_ids
    if missing:
        print(f"\n{len(missing)} unknown group(s) found — adding with placeholder names.")
        for gid in sorted(missing):
            upsert_group(db, {"group_id": gid, "name": f"Group {gid}"})

    save_db(db)
    print("\nDatabase saved.")
    return db


# --- Main menu ---


async def main_menu() -> None:
    db = load_db()
    conn = BLEConnection()

    try:
        while True:
            pp = db["passphrase"] or "not set"
            print(f"""
========================================
  SG Mesh Manager
========================================
  Passphrase: {pp}
  Devices: {len(db["devices"])}  Groups: {len(db["groups"])}
  BLE connected: {"yes" if conn.is_connected else "no"}

1. Setup passphrase
2. Scan for unclaimed devices
3. View/control devices
4. Manage groups
5. Discover mesh devices
6. Scan group memberships
7. Quit""")

            choice = (await ainput("> ")).strip()
            try:
                if choice == "1":
                    db = await action_setup_passphrase(db)
                elif choice == "2":
                    db = await action_scan_claim(db, conn)
                elif choice == "3":
                    db = await action_view_control(db, conn)
                elif choice == "4":
                    db = await action_manage_groups(db, conn)
                elif choice == "5":
                    db = await action_discover_mesh(db, conn)
                elif choice == "6":
                    db = await action_scan_all_groups(db, conn)
                elif choice == "7":
                    break
            except (BleakError, RuntimeError, TimeoutError) as e:
                print(f"Error: {e}")
                await conn.disconnect()
            except EOFError:
                break

    finally:
        await conn.disconnect()

    print("Bye.")


def main():
    try:
        asyncio.run(main_menu())
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
