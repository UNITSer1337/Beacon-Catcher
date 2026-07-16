#!/usr/bin/env python3
"""
ble_aggregate_bursts.py
-----------------------
Aggregation von Roh-Paketen zu Bursts.
"""

import json
import math
import sqlite3
import time
from collections import Counter
from datetime import datetime
from itertools import groupby

from config import DB_PATH, BLE_BURST_GAP_SECONDS
from init_db import init_db


INSERT_SQL = """
INSERT INTO ble_bursts (
    mac, mac_address_type, is_random_mac, mac_top_two_bits,
    started_at, ended_at, duration_seconds, packet_count,
    rssi_min, rssi_max, rssi_avg, rssi_stddev,
    primary_manufacturer_id, manufacturer_ids, manufacturer_subtypes,
    service_uuids_set, service_data_keys_set, ad_types_set,
    tx_power_modal, tx_power_consistent, appearance, local_name,
    ad_payload_length_avg, ad_payload_length_stddev
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


# HILFSFUNKTIONEN
def parse_ts(ts_str: str) -> float:
    # ISO-Timestamp -> Unix-Sekunden, wichtig für später
    try:
        return datetime.fromisoformat(ts_str).timestamp()
    except Exception:
        return 0.0


def safe_json_load(s):
    # Lädt einen JSON-String aus einer DB-Spalte (None bei Fehler).
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def stddev(values):
    # Populations-Standardabweichung (0.0 bei < 2 Werten).
    if not values or len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(var)


def modal_value(values):
    # Häufigster Wert (Modus) einer Liste, None-Werte ignoriert.
    cleaned = [v for v in values if v is not None]
    if not cleaned:
        return None
    return Counter(cleaned).most_common(1)[0][0]


def union_of_lists(json_strings):
    # Vereinigt mehrere als JSON gespeicherte Listen zu einer sortierten. Für Service-UUIDs, Service-Data-Keys und AD-Types genutzt, um alle im Burst beobachteten Werte zu einem stabilen Merkmal zu bündeln.
    s = set()
    for js in json_strings:
        lst = safe_json_load(js)
        if isinstance(lst, list):
            for item in lst:
                s.add(item)
    if not s:
        return None
    try:
        return sorted(s)
    except TypeError:
        return sorted(s, key=str)


def extract_manufacturer_subtypes(manufacturer_data_json_strings):
    # Extrahiert je Company-ID nur die ersten zwei Bytes der herstellerspezifischen Daten. Dies sind bei manchen ein Sub-Protokoll-Identifier (etwa Apple iBeacon oder Nearby-Info).
    subtypes = set()
    for js in manufacturer_data_json_strings:
        d = safe_json_load(js)
        if not isinstance(d, dict):
            continue
        for cid_str, hex_str in d.items():
            if not hex_str:
                continue
            try:
                cid_norm = str(int(cid_str))
            except (ValueError, TypeError):
                continue
            # 4 Hex-Stellen = 2 Bytes
            if len(hex_str) >= 4:
                bytes2 = hex_str[:4].lower()
            elif len(hex_str) >= 2:
                bytes2 = (hex_str[:2] + "00").lower()
            else:
                continue
            subtypes.add(f"{cid_norm}:{bytes2}")
    return sorted(subtypes) if subtypes else None


# BURST-BILDUNG
def build_bursts_for_mac(packets):
    # Fasst die (bereits zeitlich sortierten) Pakete EINER MAC zu Bursts zusammen. Ein neuer Burst beginnt, sobald die Pause zum vorherigen Paket BLE_BURST_GAP_SECONDS ueberschreitet.
    bursts = []
    current = []
    last_ts = None
    for pkt in packets:
        ts = pkt["_ts_unix"]
        # Pause göesser als Schwelle -> aktuellen Burst abschliessen
        if last_ts is not None and (ts - last_ts) > BLE_BURST_GAP_SECONDS:
            bursts.append(current)
            current = []
        current.append(pkt)
        last_ts = ts
    if current:
        bursts.append(current)
    return bursts


def aggregate_burst(packets):
    # Aggregiert Pakete eines Bursts zu einer einzigen Zeile mit aggregierten Statistiken.
    mac = packets[0]["mac"]   # Hash, innerhalb des Bursts konstant
    addr_type = modal_value([p["mac_address_type"] for p in packets])
    is_random = int(any(p["is_random_mac"] for p in packets))
    top_two = modal_value([p["mac_top_two_bits"] for p in packets])

    timestamps = [p["timestamp"] for p in packets]
    ts_unix = [p["_ts_unix"] for p in packets]
    started_at = min(timestamps)
    ended_at = max(timestamps)
    duration = max(ts_unix) - min(ts_unix)
    pkt_count = len(packets)

    # Signalstärke-Statistik
    rssi_values = [p["rssi"] for p in packets if p["rssi"] is not None]
    if rssi_values:
        rssi_min = min(rssi_values)
        rssi_max = max(rssi_values)
        rssi_avg = sum(rssi_values) / len(rssi_values)
        rssi_sd = stddev(rssi_values)
    else:
        rssi_min = rssi_max = None
        rssi_avg = rssi_sd = None

    # Hersteller-Merkmale
    mfr_ids = [p["manufacturer_id"] for p in packets if p["manufacturer_id"] is not None]
    primary_mfr = modal_value(mfr_ids)
    mfr_set = sorted(set(mfr_ids)) if mfr_ids else None
    mfr_subtypes = extract_manufacturer_subtypes(
        [p["manufacturer_data"] for p in packets]
    )

    # Service- und AD-Type-Mengen über den ganzen Burst vereinigen
    svc_uuids = union_of_lists([p["service_uuids"] for p in packets])
    svc_data_keys = union_of_lists([p["service_data_keys"] for p in packets])
    ad_types = union_of_lists([p["ad_types"] for p in packets])

    # TX-Power: häufigster Wert + Konsistenz-Flag (alle Werte gleich?)
    tx_powers = [p["tx_power"] for p in packets if p["tx_power"] is not None]
    tx_modal = modal_value(tx_powers)
    tx_consistent = int(len(set(tx_powers)) == 1) if tx_powers else None

    appearance = modal_value([p["appearance"] for p in packets])
    local_name = modal_value([p["local_name"] for p in packets if p["local_name"]])

    # Payload-Laenge: Mittel und Streuung
    payload_lengths = [p["ad_payload_length"] for p in packets if p["ad_payload_length"] is not None]
    if payload_lengths:
        pl_avg = sum(payload_lengths) / len(payload_lengths)
        pl_sd = stddev(payload_lengths)
    else:
        pl_avg = pl_sd = None

    return (
        mac, addr_type, is_random, top_two,
        started_at, ended_at, duration, pkt_count,
        rssi_min, rssi_max, rssi_avg, rssi_sd,
        primary_mfr,
        json.dumps(mfr_set) if mfr_set else None,
        json.dumps(mfr_subtypes) if mfr_subtypes else None,
        json.dumps(svc_uuids) if svc_uuids else None,
        json.dumps(svc_data_keys) if svc_data_keys else None,
        json.dumps(ad_types) if ad_types else None,
        tx_modal, tx_consistent, appearance, local_name,
        pl_avg, pl_sd,
    )


# MAIN
def main():
    print(f"[i] BLE Burst-Aggregation (Gap {BLE_BURST_GAP_SECONDS:.1f}s)", flush=True)
    t0 = time.monotonic()

    init_db(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()

    # Idempotenz: bestehende Bursts verwerfen und neu aufbauen
    cur.execute("DELETE FROM ble_bursts")
    conn.commit()

    total_packets = cur.execute("SELECT COUNT(*) FROM ble_packets").fetchone()[0]
    if total_packets == 0:
        print("Keine Pakete. Abbruch.", flush=True)
        conn.close()
        return

    # Pakete nach (MAC, Zeit) sortiert laden, damit groupby je MAC greift
    cur.execute("""
        SELECT mac, mac_address_type, is_random_mac, mac_top_two_bits,
               rssi, timestamp,
               manufacturer_id, manufacturer_data,
               service_uuids, service_data_keys, ad_types,
               tx_power, appearance, local_name, ad_payload_length
        FROM ble_packets
        WHERE mac IS NOT NULL
        ORDER BY mac, timestamp
    """)
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]

    packets = []
    for r in rows:
        pkt = dict(zip(cols, r))
        pkt["_ts_unix"] = parse_ts(pkt["timestamp"])
        packets.append(pkt)

    # Pro MAC die Bursts bilden und aggregieren
    inserts = []
    n_macs = 0
    n_bursts = 0
    for mac, group in groupby(packets, key=lambda p: p["mac"]):
        mac_packets = list(group)
        bursts = build_bursts_for_mac(mac_packets)
        n_macs += 1
        n_bursts += len(bursts)
        for burst in bursts:
            inserts.append(aggregate_burst(burst))

    cur.executemany(INSERT_SQL, inserts)
    conn.commit()
    conn.close()

    elapsed = time.monotonic() - t0
    avg = total_packets / n_bursts if n_bursts else 0
    print(f"[i] {n_macs} unique MACs -> {n_bursts} Bursts "
          f"({avg:.2f} Pakete/Burst, {elapsed:.2f}s)", flush=True)


if __name__ == "__main__":
    main()