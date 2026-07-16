#!/usr/bin/env python3
"""
ble_cluster_3a.py
-----------------
Fingerprint-basiertes Bucketing.

Aufruf:
    python3 ble_cluster_3a.py
"""

import hashlib
import json
import sqlite3
import time
from collections import defaultdict

from config import DB_PATH
from init_db import init_db


# FINGERPRINT-BILDUNG
def normalize_json_list(json_str):
    # Lädt eine als JSON gespeicherte Liste und gibt sie sortiert zurück. Sortierung, damit Reihenfolge der Elemente den Fingerprint-Hash nicht beeinflusst.
    if not json_str:
        return ""
    try:
        lst = json.loads(json_str)
        if not isinstance(lst, list):
            return ""
        try:
            lst_sorted = sorted(lst)
        except TypeError:
            lst_sorted = sorted(lst, key=str)
        return json.dumps(lst_sorted, separators=(",", ":"))
    except Exception:
        return ""


def compute_fingerprint(burst):
    # Berechnet den Geraete-Fingerprint eines Bursts aus den sieben stabilen Merkmalen.
    components = {
        "mfr_id":         burst["primary_manufacturer_id"],
        "mfr_subtypes":   normalize_json_list(burst["manufacturer_subtypes"]),
        "service_uuids":  normalize_json_list(burst["service_uuids_set"]),
        "ad_types":       normalize_json_list(burst["ad_types_set"]),
        # TX-Power nur übernehmen, wenn sie im Burst konstant war
        "tx_power":       (burst["tx_power_modal"]
                           if burst["tx_power_consistent"] == 1 else None),
        "payload_length": (round(burst["ad_payload_length_avg"])
                           if burst["ad_payload_length_avg"] is not None else None),
        "local_name":     burst["local_name"],
    }
    canon = json.dumps(components, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]
    return h, components

# MAIN
def main():
    print("[i] BLE Stage 3a: Fingerprint-Bucketing", flush=True)
    t0 = time.monotonic()

    init_db(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()

    # Idempotenz: bestehende 3a-Zuordnung und Cluster verwerfen
    cur.execute("UPDATE ble_bursts SET cluster_id_3a = NULL")
    cur.execute("DELETE FROM ble_clusters_3a")
    cur.execute("DELETE FROM sqlite_sequence WHERE name='ble_clusters_3a'")
    conn.commit()

    cur.execute("""
        SELECT id, mac, mac_address_type, packet_count,
               started_at, ended_at, rssi_min, rssi_max, rssi_avg,
               primary_manufacturer_id, manufacturer_subtypes,
               service_uuids_set, ad_types_set,
               tx_power_modal, tx_power_consistent,
               ad_payload_length_avg, local_name
        FROM ble_bursts
    """)
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]

    if not rows:
        print("Keine Bursts vorhanden. Abbruch.", flush=True)
        conn.close()
        return

    # Jeden Burst nach seinem Fingerprint-Hash in einen Bucket einsortieren
    buckets = defaultdict(list)
    components_by_hash = {}
    for r in rows:
        burst = dict(zip(cols, r))
        h, components = compute_fingerprint(burst)
        buckets[h].append(burst)
        components_by_hash[h] = components

    # Pro Bucket (= 3a-Cluster) die aggregierten Kennzahlen berechnen
    cluster_inserts = []
    for h, members in buckets.items():
        macs = {m["mac"] for m in members}
        addr_types = sorted({m["mac_address_type"] for m in members
                             if m["mac_address_type"]})
        # Bursts mit nur einem Paket gelten als "low quality" (flüchtig)
        n_low_q = sum(1 for m in members if m["packet_count"] <= 1)
        rssi_mins = [m["rssi_min"] for m in members if m["rssi_min"] is not None]
        rssi_maxs = [m["rssi_max"] for m in members if m["rssi_max"] is not None]
        rssi_avgs = [m["rssi_avg"] for m in members if m["rssi_avg"] is not None]
        starts = [m["started_at"] for m in members]
        ends = [m["ended_at"] for m in members]
        total_pkts = sum(m["packet_count"] for m in members)
        primary_mfr = members[0]["primary_manufacturer_id"]

        cluster_inserts.append((
            h,
            json.dumps(components_by_hash[h], sort_keys=True),
            primary_mfr,
            len(members),
            len(macs),
            len(addr_types),
            json.dumps(addr_types) if addr_types else None,
            n_low_q,
            min(starts),
            max(ends),
            min(rssi_mins) if rssi_mins else None,
            max(rssi_maxs) if rssi_maxs else None,
            sum(rssi_avgs) / len(rssi_avgs) if rssi_avgs else None,
            total_pkts,
        ))

    cur.executemany("""
        INSERT INTO ble_clusters_3a (
            fingerprint_hash, fingerprint_components, primary_manufacturer_id,
            n_bursts, n_unique_macs, n_unique_addr_types, address_types,
            n_low_quality, first_seen, last_seen,
            rssi_min, rssi_max, rssi_avg, total_packets
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, cluster_inserts)
    conn.commit()

    # Jeden Burst mit der ID seines 3a-Clusters zurückverknüpfen, um zu sehen ob es korrekt funktioniert hat
    cur.execute("SELECT cluster_id, fingerprint_hash FROM ble_clusters_3a")
    hash_to_id = {h: cid for cid, h in cur.fetchall()}

    updates = []
    for h, members in buckets.items():
        cid = hash_to_id[h]
        for m in members:
            updates.append((cid, m["id"]))
    cur.executemany(
        "UPDATE ble_bursts SET cluster_id_3a = ? WHERE id = ?",
        updates,
    )
    conn.commit()
    conn.close()

    elapsed = time.monotonic() - t0
    bpc = len(rows) / len(buckets) if buckets else 0
    print(f"[i] {len(rows)} Bursts -> {len(buckets)} Cluster "
          f"({bpc:.2f} Bursts/Cluster, {elapsed:.2f}s)", flush=True)


if __name__ == "__main__":
    main()