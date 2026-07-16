#!/usr/bin/env python3
"""
wifi_scanner.py
---------------
Passiver WiFi Probe-Request-Scanner.

- Sniff via Scapy auf Monitor-Interface
- Channel-Hopping 1 / 6 / 11 (2.4 GHz)
- Parsing der Information Elements (IEs) für Fingerprinting
- Persistierung in SQLite via db_insert.DBHandler

Aufruf:
    sudo python3 wifi_scanner.py
"""

import hashlib
import json
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from subprocess import run, DEVNULL

from scapy.all import sniff
from scapy.layers.dot11 import (
    Dot11,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
)
from config import DB_PATH
from init_db import init_db
from db_insert import DBHandler

# Wichtige Werte
INTERFACE       = "wlan1mon"       # Monitor-Interface
CHANNELS        = [1, 6, 11]       # 2.4 GHz nicht-überlappende Kanäle
DWELL_SECONDS   = 3                # Verweildaür pro Kanal
BATCH_SIZE      = 50               # DB-Batch-Grösse
FLUSH_INTERVAL  = 2.0              # DB-Flush-Intervall

# 802.11 Information Element Tag-IDs
TAG_SSID             = 0
TAG_SUPPORTED_RATES  = 1
TAG_EXT_RATES        = 50
TAG_HT_CAPABILITIES  = 45
TAG_VHT_CAPABILITIES = 191
TAG_HE_CAPABILITIES  = 255
TAG_EXT_CAPABILITIES = 127
TAG_VENDOR_SPECIFIC  = 221

# Von Element ID Extension Sub-IDs (Tag 255).
# 35 = HE Capabilities ist hardware stabil.
# Andere Sub-IDs (z.B. 36 = HE Operation) werden ignoriert, da sie dynamische Parameter enthalten können.
HE_EXT_ID_CAPABILITIES = 35

# Whitelist für ie_fingerprint: nur stabile Hardware-/Software-Capabilities.
# Alle anderen Tags fliessen zwar in tagged_params_hash ein (Reihenfolge zählt),
FINGERPRINT_TAG_WHITELIST = {
    TAG_SUPPORTED_RATES,    # 1
    TAG_EXT_RATES,          # 50
    TAG_HT_CAPABILITIES,    # 45
    TAG_EXT_CAPABILITIES,   # 127
    TAG_VHT_CAPABILITIES,   # 191
    TAG_HE_CAPABILITIES,    # 255 (nur ext_id=35, siehe Filter unten)
}

# SCANNER-ZUSTAND
class ScannerState:
    # Gemeinsamer Zustand von Sniff-Callback und Channel-Hopper-Thread.
    def __init__(self):
        self.lock = threading.Lock()
        self.current_channel = CHANNELS[0]
        self.current_hop_session_id = None
        self.stop_event = threading.Event()
        self.packet_counter = 0

state = ScannerState()
db = None

# CHANNEL-HOPPING
def set_channel(iface, channel):
    # Setzt den WiFi-Adapter auf einen bestimmten Kanal (mit iw).
    run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        stdout=DEVNULL,
        stderr=DEVNULL,
    )


def channel_hopper():
    # Wechselt zyklisch zwischen den Kanälen 1/6/11.
    # Für jeden Kanalwechsel wird eine neue Hop-Session in der DB (Runs) angelegt, damit jedes Paket seinem Empfangs-Kanal zugeordnet werden kann.
    cycle_id = 0
    dwell_ms = int(DWELL_SECONDS * 1000)

    while not state.stop_event.is_set():
        cycle_id += 1
        for hop_index, ch in enumerate(CHANNELS):
            if state.stop_event.is_set():
                break

            set_channel(INTERFACE, ch)

            # Alte Hop-Session abschliessen, neue starten
            with state.lock:
                old_id = state.current_hop_session_id
            if old_id is not None:
                db.end_hop_session(old_id)

            new_id = db.start_hop_session(cycle_id, hop_index, ch, dwell_ms)
            with state.lock:
                state.current_channel = ch
                state.current_hop_session_id = new_id

            state.stop_event.wait(DWELL_SECONDS)

    # Beim Beenden noch offene Hop-Session schliessen
    with state.lock:
        last_id = state.current_hop_session_id
    if last_id is not None:
        db.end_hop_session(last_id)


# IE-PARSING
def iter_ies(pkt):
    # Iterator über alle Information Elements eines Probe-Requests.
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        yield elt
        elt = elt.payload.getlayer(Dot11Elt)


def parse_information_elements(pkt):
    # Parst die IEs eines Probe-Requests und extrahiert, die unteren Parameter:
    out = {
        'ssid': None,
        'is_broadcast': 0,
        'ht_capabilities': None,
        'ext_capabilities': None,
        'vht_capabilities': None,
        'he_capabilities': None,
        'supported_rates': None,
        'vendor_ouis': None,
        'vendor_oui_set': None,
        'ie_fingerprint': None,
        'tagged_params_hash': None,
    }

    rates_parts = []
    vendor_ouis = []
    tag_sequence = []
    ie_full_sequence = []

    for elt in iter_ies(pkt):
        tag_id = elt.ID
        info = bytes(elt.info) if elt.info else b""
        length = len(info)

        # tag_sequence -> tagged_params_hash.
        # Bei SSID und Vendor-IEs wird die Länge auf 0 gesetzt, damit der Hash unabhängig von der SSID und Grösse der Vendor-IEs ist.
        if tag_id in (TAG_SSID, TAG_VENDOR_SPECIFIC):
            tag_sequence.append((tag_id, 0))
        else:
            tag_sequence.append((tag_id, length))

        # ie_full_sequence -> ie_fingerprint.
        # Nur Tags aus der Whitelist (stabile Capabilities).
        # Sonderfall Tag 255: nur ext_id=35 (HE Capabilities) zählt, andere Sub-Typen (HE Operation etc.) werden ignoriert.
        if tag_id in FINGERPRINT_TAG_WHITELIST:
            if tag_id == TAG_HE_CAPABILITIES:
                if length >= 1 and info[0] == HE_EXT_ID_CAPABILITIES:
                    ie_full_sequence.append((tag_id, length, info))
            else:
                ie_full_sequence.append((tag_id, length, info))

        # Feld-spezifische Extraktion
        if tag_id == TAG_SSID:
            # Leere SSID = Broadcast-Probe
            if length == 0:
                out['is_broadcast'] = 1
                out['ssid'] = None
            else:
                try:
                    out['ssid'] = info.decode('utf-8', errors='replace')
                except Exception:
                    out['ssid'] = info.hex()

        elif tag_id == TAG_SUPPORTED_RATES:
            rates_parts.append(info.hex())

        elif tag_id == TAG_EXT_RATES:
            rates_parts.append(info.hex())

        elif tag_id == TAG_HT_CAPABILITIES:
            out['ht_capabilities'] = info.hex()

        elif tag_id == TAG_VHT_CAPABILITIES:
            out['vht_capabilities'] = info.hex()

        elif tag_id == TAG_EXT_CAPABILITIES:
            out['ext_capabilities'] = info.hex()

        elif tag_id == TAG_HE_CAPABILITIES:
            if length >= 1 and info[0] == HE_EXT_ID_CAPABILITIES:
                out['he_capabilities'] = info.hex()

        elif tag_id == TAG_VENDOR_SPECIFIC:
            # OUI = erste 3 Bytes des Vendor-IE (Organizationally Unique ID)
            if length >= 3:
                oui = info[:3].hex()
                vendor_ouis.append(oui)

    if rates_parts:
        out['supported_rates'] = ",".join(rates_parts)

    if vendor_ouis:
        out['vendor_ouis'] = json.dumps(vendor_ouis)
        out['vendor_oui_set'] = json.dumps(sorted(set(vendor_ouis)))

    # tagged_params_hash: Reihenfolge und Längen aller Tags.
    tag_seq_str = ",".join(f"{tid}:{ln}" for tid, ln in tag_sequence)
    out['tagged_params_hash'] = hashlib.sha256(
        tag_seq_str.encode("utf-8")
    ).hexdigest()

    # ie_fingerprint NUR berechnen, wenn mindestens ein Whitelist-Tag
    # vorhanden war. Sonst würde ein "leeres" Probe-Request (nur SSID
    # + Vendor-IEs, keine Capabilities) den SHA-256 der leeren Eingabe
    # liefern und verschiedene Geräte in einen Cluster werfen das nicht echt ist.
    # None-Fingerprints werden dann auch in aggregate_bursts.py gefiltert.
    if ie_full_sequence:
        h = hashlib.sha256()
        for tid, ln, data in ie_full_sequence:
            h.update(tid.to_bytes(1, "big"))
            h.update(ln.to_bytes(2, "big"))
            h.update(data)
        out['ie_fingerprint'] = h.hexdigest()
    else:
        out['ie_fingerprint'] = None

    return out


def is_random_mac(mac):
    # Prüft das Locally-Administered-Bit im ersten Oktett der MAC.
    try:
        first_octet = int(mac.split(":")[0], 16)
        return 1 if (first_octet & 0b10) else 0
    except (ValueError, IndexError):
        return 0


# PAKET-CALLBACK
def handle_packet(pkt):
    # Es wird von Scapy für jedes Paket aufgerufen.
    # Filtert auf Probe-Requests, extrahiert Metadaten und IEs,
    # übergibt den Datensatz an den DBHandler.
    if not pkt.haslayer(Dot11ProbeReq):
        return

    # Zusätzlicher Subtype-Check: Probe-Request = Type 0, Subtype 4
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None or dot11.type != 0 or dot11.subtype != 4:
        return

    # Absender-MAC
    mac = dot11.addr2
    if mac is None:
        return

    # RSSI aus RadioTap-Header
    rssi = None
    if pkt.haslayer(RadioTap):
        rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)

    # 802.11-Sequenznummer und Retry-Flag
    seq_num = None
    retry_flag = 0
    sc = getattr(dot11, "SC", None)
    if sc is not None:
        seq_num = sc >> 4  # obere 12 Bit = Sequenznummer, untere 4 = Fragment
    fcf = getattr(dot11, "FCfield", 0)
    if fcf is not None:
        retry_flag = 1 if (int(fcf) & 0x08) else 0

    # Information Elements parsen
    ie_data = parse_information_elements(pkt)

    with state.lock:
        ch = state.current_channel
        hop_id = state.current_hop_session_id

    record = {
        'mac': mac,
        'timestamp': datetime.now(timezone.utc).isoformat(timespec='microseconds'),
        'rssi': rssi,
        'channel': ch,
        'ssid': ie_data['ssid'],
        'is_broadcast': ie_data['is_broadcast'],
        'is_random_mac': is_random_mac(mac),
        'seq_num': seq_num,
        'retry_flag': retry_flag,
        'ie_fingerprint': ie_data['ie_fingerprint'],
        'tagged_params_hash': ie_data['tagged_params_hash'],
        'ht_capabilities': ie_data['ht_capabilities'],
        'ext_capabilities': ie_data['ext_capabilities'],
        'vht_capabilities': ie_data['vht_capabilities'],
        'he_capabilities': ie_data['he_capabilities'],
        'supported_rates': ie_data['supported_rates'],
        'vendor_ouis': ie_data['vendor_ouis'],
        'vendor_oui_set': ie_data['vendor_oui_set'],
        'hop_session_id': hop_id,
    }

    db.insert_packet(record)
    state.packet_counter += 1


# LIFECYCLE
def shutdown(signum=None, frame=None):
    # Signal-Handler für sauberes Beenden.
    print("\n[!] Shutdown angefordert ...")
    state.stop_event.set()


def main():
    global db

    init_db(DB_PATH)
    print(f"[i] WiFi-Scanner startet auf {INTERFACE}, Kanaele {CHANNELS}")

    db = DBHandler(DB_PATH, batch_size=BATCH_SIZE, flush_interval=FLUSH_INTERVAL)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Channel-Hopper in eigenem Thread
    hopper_thread = threading.Thread(target=channel_hopper, daemon=True)
    hopper_thread.start()

    # Periodischer Flush, damit Pakete zuverlässig in die DB gelangen
    def periodic_flush():
        while not state.stop_event.is_set():
            time.sleep(FLUSH_INTERVAL)
            db.flush()

    flush_thread = threading.Thread(target=periodic_flush, daemon=True)
    flush_thread.start()

    try:
        sniff(
            iface=INTERFACE,
            prn=handle_packet,
            store=False,       # Pakete nicht im RAM sammeln
            stop_filter=lambda _p: state.stop_event.is_set(),
        )
    except PermissionError:
        print("[!] Permission denied: mit sudo starten.")
    except OSError as e:
        print(f"[!] Interface-Fehler: {e}")
        print(f"    Ist {INTERFACE} im Monitor-Mode? Check mit:  iw dev")
    finally:
        state.stop_event.set()
        hopper_thread.join(timeout=2.0)
        flush_thread.join(timeout=2.0)
        db.close()
        print(f"[i] {db.total_inserted} Pakete in DB geschrieben.")


if __name__ == "__main__":
    main()