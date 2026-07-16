#!/usr/bin/env python3
"""
cluster_matching_3b.py
----------------------
Stufe 3 - Hard-Cuts auf den Buckets aus 3a.

Verfeinert die naiven (ie_fingerprint, vendor_oui_set)-Buckets aus 3a:
Splittet sie weiter, wenn physische Evidenz dagegen spricht.

Hard-Cut-Regeln innerhalb eines Buckets:
  - Regel 1/2: gleicher Fingerprint + gleicher Vendor-Set
               (bereits durch die Bucket-Definition aus 3a gegeben)
  - Regel 3:   zeitlich nah UND große RSSI-Differenz
               → können nicht dasselbe Gerät sein (ein Gerät kann nicht
                 gleichzeitig an zwei Orten sein)
  - Regel 4:   zwei verschiedene ECHTE (nicht-random) MACs
               → zwei verschiedene Geräte (echte MACs sind hardware-eindeutig)
  - Regel 5:   anomale MACs (z. B. 02:00:00:00:00:00) bekommen ein
               eigenes Cluster pro (Bucket, anomale MAC)

    ECHTE und RANDOM MACs werden in 3b NICHT zusammengeführt!!!

Aufruf:
    python3 cluster_matching_3b.py --rebuild
"""

import argparse
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from config import DB_PATH
from init_db import init_db

METHOD = "fingerprint_hardcut"

# Default-Parameter
DEFAULT_TIME_WINDOW_S = 5.0     # Sekunden — Bursts näher als das gelten als "gleichzeitig"
DEFAULT_RSSI_THRESHOLD = 25     # dB — Bursts mit größerer Spanne sind "nicht am selben Ort"

# Anomale MACs: Default-Random-MAC, die manche Plattformen statt eines
# echten zufälligen Werts senden. Nicht eindeutig zuordenbar → eigenes Cluster.
DEFAULT_ANOMALOUS_MACS = {
    "02:00:00:00:00:00",
}


# SCHEMA-ERWEITERUNG (idempotent)
def ensure_schema(conn):
    # Legt die Spalte bursts.cluster_id_hardcut an, falls sie noch fehlt
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(bursts)")
    cols = {row[1] for row in cur.fetchall()}

    if "cluster_id_hardcut" not in cols:
        cur.execute("ALTER TABLE bursts ADD COLUMN cluster_id_hardcut INTEGER")
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_bursts_cluster_hardcut "
            "ON bursts(cluster_id_hardcut)"
        )
        conn.commit()
    else:
        # Index auch dann sicherstellen, wenn die Spalte bereits existiert
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_bursts_cluster_hardcut "
            "ON bursts(cluster_id_hardcut)"
        )
        conn.commit()

def parse_ts(s):
    # ISO8601 → datetime (None bei Fehler).
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def conflicts_rule3(burst_a, burst_b, time_window_s, rssi_threshold):
    # Prüft Regel 3: Zwei Bursts schließen sich aus, wenn sie zeitlich nah beieinander liegen, sich aber deutlich in der Signalstärke unterscheiden.
    a_rssi = burst_a["rssi_avg"]
    b_rssi = burst_b["rssi_avg"]
    if a_rssi is None or b_rssi is None:
        return False

    a_ts = burst_a["ts"]
    b_ts = burst_b["ts"]
    if a_ts is None or b_ts is None:
        return False

    dt = abs((a_ts - b_ts).total_seconds())
    if dt >= time_window_s:
        return False   # zeitlich zu weit auseinander → kein Konflikt

    return abs(a_rssi - b_rssi) > rssi_threshold


# BUCKET-PARTITIONIERUNG
def partition_bucket(bursts, time_window_s, rssi_threshold, anomalous_macs):
    # Splittet einen (fp, vendor_oui_set)-Bucket nach den Hard-Cut-Regeln.
    # Liefert eine Liste von Sub-Clustern, jedes als dict: { 'bursts': [...], 'reason': str } 'reason' hält fest, welche Regel das Sub-Cluster erzeugt hat. Werden für 3c gebraucht.
    sub_clusters = []

    # Bursts in drei Kategorien einteilen: anomale MACs, echte MACs, Randoms
    anomalous = defaultdict(list)
    real_by_mac = defaultdict(list)
    randoms = []

    for b in bursts:
        if b["mac"] in anomalous_macs:
            anomalous[b["mac"]].append(b)
        elif not b["is_random"]:
            real_by_mac[b["mac"]].append(b)
        else:
            randoms.append(b)

    # Regel 5: anomale MACs separieren (ein Cluster pro anomaler MAC).
    for mac, blist in anomalous.items():
        sub_clusters.append({
            "bursts": blist,
            "reason": f"anomalous_mac:{mac}",
        })

    # Regel 4: jede unique echte MAC bildet ein eigenes Cluster.
    for mac, blist in real_by_mac.items():
        sub_clusters.append({
            "bursts": blist,
            "reason": f"real_mac:{mac}",
        })

    # Regel 3: Random-MACs greedy partitionieren (Zeit + RSSI)
    # Sortierung nach (started_at, id): ein neuer Burst kann nur mit zeitlich nahen Bursts kollidieren, daher genügt Greedy-First-Fit.
    randoms.sort(key=lambda x: (x["ts"] or datetime.min, x["id"]))

    random_subs = []   # Liste von Sub-Listen
    for b in randoms:
        placed = False
        for sub in random_subs:
            # Kollidiert der Burst mit irgendeinem bereits im Sub?
            if not any(conflicts_rule3(b, o, time_window_s, rssi_threshold)
                       for o in sub):
                sub.append(b)
                placed = True
                break
        # Passt der Burst in keine bestehende Untergruppe → neue eröffnen
        if not placed:
            random_subs.append([b])

    for idx, sub in enumerate(random_subs):
        sub_clusters.append({
            "bursts": sub,
            "reason": f"random_group_{idx}",
        })

    return sub_clusters


# CLUSTER-AGGREGATE BERECHNEN
def aggregate_sub(sub_bursts):
    # Berechnet die Cluster-Statistiken eines Sub-Clusters aus seinen Bursts: Anzahlen, Zeitspanne und Signalstärke-Kennwerte.
    burst_count = len(sub_bursts)
    macs = {b["mac"] for b in sub_bursts}
    mac_count = len(macs)
    random_macs = {b["mac"] for b in sub_bursts if b["is_random"]}
    real_macs = {b["mac"] for b in sub_bursts if not b["is_random"]}
    packet_count = sum(b["packet_count"] for b in sub_bursts)

    starts = [b["started_at"] for b in sub_bursts if b["started_at"]]
    ends = [b["ended_at"] for b in sub_bursts if b["ended_at"]]
    first_seen = min(starts) if starts else None
    last_seen = max(ends) if ends else None

    duration_seconds = None
    if first_seen and last_seen:
        t1 = parse_ts(first_seen)
        t2 = parse_ts(last_seen)
        if t1 and t2:
            duration_seconds = (t2 - t1).total_seconds()

    rssi_mins = [b["rssi_min"] for b in sub_bursts if b["rssi_min"] is not None]
    rssi_maxs = [b["rssi_max"] for b in sub_bursts if b["rssi_max"] is not None]
    rssi_avgs = [b["rssi_avg"] for b in sub_bursts if b["rssi_avg"] is not None]

    rssi_min = min(rssi_mins) if rssi_mins else None
    rssi_max = max(rssi_maxs) if rssi_maxs else None
    rssi_avg = sum(rssi_avgs) / len(rssi_avgs) if rssi_avgs else None

    return {
        "burst_count": burst_count,
        "mac_count": mac_count,
        "packet_count": packet_count,
        "random_mac_count": len(random_macs),
        "real_mac_count": len(real_macs),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": duration_seconds,
        "rssi_min": rssi_min,
        "rssi_max": rssi_max,
        "rssi_avg": rssi_avg,
    }

# HAUPT-LOGIK
def build_hardcut_clusters(conn, time_window_s, rssi_threshold,
                           anomalous_macs, rebuild=False):
    """
    Kern der 3b-Verarbeitung: lädt alle Bursts mit Fingerprint, gruppiert
    sie zu denselben Buckets wie 3a, wendet auf jeden Bucket die
    Hard-Cut-Regeln an und schreibt die entstandenen Sub-Cluster.
    """
    cur = conn.cursor()

    if rebuild:
        cur.execute("DELETE FROM device_clusters WHERE method = ?", (METHOD,))
        cur.execute("UPDATE bursts SET cluster_id_hardcut = NULL")
        conn.commit()

    # Run-Tracking
    run_started = datetime.now(timezone.utc).isoformat(timespec='microseconds')
    notes = (f"time_window_s={time_window_s}, rssi_threshold={rssi_threshold}, "
             f"anomalous_macs={sorted(anomalous_macs)}")
    cur.execute(
        "INSERT INTO clustering_runs (started_at, method, notes) VALUES (?, ?, ?)",
        (run_started, METHOD, notes),
    )
    run_id = cur.lastrowid
    conn.commit()

    # Alle Bursts mit Fingerprint laden.
    cur.execute("""
        SELECT id, mac, is_random_mac, started_at, ended_at, packet_count,
               rssi_min, rssi_max, rssi_avg,
               ie_fingerprint, vendor_oui_set
        FROM bursts
        WHERE ie_fingerprint IS NOT NULL
    """)

    buckets = defaultdict(list)
    for row in cur.fetchall():
        (bid, mac, is_random, started_at, ended_at, pkt_count,
         rssi_min, rssi_max, rssi_avg, fp, vset) = row
        # Sentinel '__none__' statt NULL, damit Bursts ohne Vendor-IE
        # konsistent in denselben Bucket fallen
        vkey = vset if vset is not None else "__none__"
        buckets[(fp, vkey)].append({
            "id": bid,
            "mac": mac,
            "is_random": bool(is_random),
            "started_at": started_at,
            "ended_at": ended_at,
            "ts": parse_ts(started_at),
            "packet_count": pkt_count or 0,
            "rssi_min": rssi_min,
            "rssi_max": rssi_max,
            "rssi_avg": rssi_avg,
        })

    clusters_created = 0
    bursts_assigned = 0
    splits_introduced = 0   # Bucket → mehrere Cluster (für die Auswertung)

    for (fp, vkey), bucket_bursts in buckets.items():
        vendor_for_db = None if vkey == "__none__" else vkey

        # Kern der Stufe: Bucket nach den Hard-Cut-Regeln aufteilen
        sub_clusters = partition_bucket(
            bucket_bursts, time_window_s, rssi_threshold, anomalous_macs
        )

        if len(sub_clusters) > 1:
            splits_introduced += 1

        for sub in sub_clusters:
            sub_bursts = sub["bursts"]
            if not sub_bursts:
                continue

            stats = aggregate_sub(sub_bursts)
            note = sub["reason"]

            cur.execute("""
                INSERT INTO device_clusters (
                    ie_fingerprint, vendor_oui_set,
                    burst_count, mac_count, packet_count,
                    random_mac_count, real_mac_count,
                    first_seen, last_seen, duration_seconds,
                    rssi_min, rssi_max, rssi_avg,
                    method, confidence_score, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                fp, vendor_for_db,
                stats["burst_count"], stats["mac_count"], stats["packet_count"],
                stats["random_mac_count"], stats["real_mac_count"],
                stats["first_seen"], stats["last_seen"], stats["duration_seconds"],
                stats["rssi_min"], stats["rssi_max"], stats["rssi_avg"],
                METHOD, None, note,   # 3b vergibt keinen Konfidenzwert
            ))
            new_cluster_id = cur.lastrowid
            clusters_created += 1

            # Bursts dem neuen Hardcut-Cluster zuweisen
            burst_ids = [b["id"] for b in sub_bursts]
            cur.executemany(
                "UPDATE bursts SET cluster_id_hardcut = ? WHERE id = ?",
                [(new_cluster_id, bid) for bid in burst_ids],
            )
            bursts_assigned += len(burst_ids)

        # Pro Bucket committen — hält die Transaktionen klein
        conn.commit()

    # Run-Tracking abschließen
    cur.execute("""
        UPDATE clustering_runs
        SET ended_at = ?, bursts_processed = ?, clusters_created = ?
        WHERE id = ?
    """, (
        datetime.now(timezone.utc).isoformat(timespec='microseconds'),
        bursts_assigned,
        clusters_created,
        run_id,
    ))
    conn.commit()

    return {
        "clusters_created": clusters_created,
        "bursts_assigned": bursts_assigned,
        "buckets_total": len(buckets),
        "buckets_split": splits_introduced,
    }

# CLI
def main():
    init_db(DB_PATH)

    parser = argparse.ArgumentParser(
        description="Schritt 3b: Hard-Cut-Cluster-Verfeinerung"
    )
    parser.add_argument("--rebuild", action="store_true",
                        help="Bestehende fingerprint_hardcut-Cluster löschen")
    parser.add_argument("--db", type=str, default=DB_PATH,
                        help=f"DB-Pfad (default: {DB_PATH})")
    parser.add_argument("--time-window", type=float, default=DEFAULT_TIME_WINDOW_S,
                        help=f"Zeitfenster in Sekunden für Regel 3 "
                             f"(default: {DEFAULT_TIME_WINDOW_S})")
    parser.add_argument("--rssi-threshold", type=int, default=DEFAULT_RSSI_THRESHOLD,
                        help=f"RSSI-Schwelle in dB für Regel 3 "
                             f"(default: {DEFAULT_RSSI_THRESHOLD})")
    parser.add_argument("--anomalous-mac", action="append", default=None,
                        help="Anomale MAC (Regel 5), mehrfach angebbar. "
                             f"Default: {sorted(DEFAULT_ANOMALOUS_MACS)}")
    args = parser.parse_args()

    anomalous = (set(args.anomalous_mac)
                 if args.anomalous_mac is not None
                 else set(DEFAULT_ANOMALOUS_MACS))

    try:
        conn = sqlite3.connect(args.db)
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error as e:
        print(f"[!] DB-Fehler: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        ensure_schema(conn)
        result = build_hardcut_clusters(
            conn,
            time_window_s=args.time_window,
            rssi_threshold=args.rssi_threshold,
            anomalous_macs=anomalous,
            rebuild=args.rebuild,
        )
        print(f"[i] {result['clusters_created']} Cluster gebildet, "
              f"{result['bursts_assigned']} Bursts zugeordnet, "
              f"{result['buckets_split']}/{result['buckets_total']} "
              f"Buckets aus 3a gesplittet.")
    except KeyboardInterrupt:
        print("\n[!] Abbruch durch Benutzer.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()