#!/usr/bin/env python3
"""
cluster_matching.py
-------------------
Fingerprint-Bucketing.

Bildet Cluster aus Bursts, die denselben (ie_fingerprint, vendor_oui_set) teilen.

Aufruf:
    python3 cluster_matching.py             # inkrementell
    python3 cluster_matching.py --rebuild   # alles neu aufbauen
"""

import argparse
import sqlite3
import sys
from datetime import datetime, timezone
from config import DB_PATH
from init_db import init_db

METHOD = "fingerprint_bucket" # Signalisiert, dass Stufe 3a gemacht wurde


# CLUSTER-BILDUNG
def build_clusters(conn, rebuild=False):
    """
    Schritt 3a: Bildet ein Cluster pro (ie_fingerprint, vendor_oui_set).
    Schreibt die entstandene cluster_id in bursts.cluster_id zurück, zum Nachverfolgen!
    """
    cur = conn.cursor()

    if rebuild:
        cur.execute("DELETE FROM device_clusters WHERE method = ?", (METHOD,))
        cur.execute("UPDATE bursts SET cluster_id = NULL")
        conn.commit()

    # Run-Tracking
    run_started = datetime.now(timezone.utc).isoformat(timespec='microseconds')
    cur.execute(
        """
        INSERT INTO clustering_runs (started_at, method)
        VALUES (?, ?)
        """,
        (run_started, METHOD),
    )
    run_id = cur.lastrowid
    conn.commit()

    # Alle (ie_fingerprint, vendor_oui_set)-Buckets ermitteln.
    # NULL-Werte für vendor_oui_set werden zu '__none__' normalisiert, damit sie konsistent gruppiert werden.
    # random_cnt / real_cnt zählen UNIQUE MACs (nicht Bursts).
    # COUNT(DISTINCT CASE WHEN ... THEN mac END) ignoriert NULL automatisch
    # random_mac_count + real_mac_count == mac_count
    cur.execute("""
        SELECT
            ie_fingerprint,
            COALESCE(vendor_oui_set, '__none__') AS vset,
            COUNT(*) AS burst_cnt,
            COUNT(DISTINCT mac) AS mac_cnt,
            SUM(packet_count) AS pkt_cnt,
            COUNT(DISTINCT CASE WHEN is_random_mac=1 THEN mac END) AS random_cnt,
            COUNT(DISTINCT CASE WHEN is_random_mac=0 THEN mac END) AS real_cnt,
            MIN(started_at) AS first_seen,
            MAX(ended_at) AS last_seen,
            MIN(rssi_min) AS rssi_min,
            MAX(rssi_max) AS rssi_max,
            AVG(rssi_avg) AS rssi_avg
        FROM bursts
        WHERE ie_fingerprint IS NOT NULL
        GROUP BY ie_fingerprint, vset
    """)
    buckets = cur.fetchall()

    # Cluster anlegen und Zuweisungen für den Burst sammeln
    cluster_assignments = []   # (cluster_id, ie_fingerprint, vendor_set_or_none)
    clusters_created = 0

    for bucket in buckets:
        (fp, vset, burst_cnt, mac_cnt, pkt_cnt,
         random_cnt, real_cnt, first_seen, last_seen,
         rssi_min, rssi_max, rssi_avg) = bucket

        # Zeitspanne des Clusters berechnen
        duration_sec = None
        if first_seen and last_seen:
            try:
                t1 = datetime.fromisoformat(first_seen)
                t2 = datetime.fromisoformat(last_seen)
                duration_sec = (t2 - t1).total_seconds()
            except (ValueError, TypeError):
                duration_sec = None

        # Sentinel '__none__' zurück zu NULL für die DB-Speicherung
        vendor_for_db = None if vset == '__none__' else vset

        cur.execute("""
            INSERT INTO device_clusters (
                ie_fingerprint, vendor_oui_set,
                burst_count, mac_count, packet_count,
                random_mac_count, real_mac_count,
                first_seen, last_seen, duration_seconds,
                rssi_min, rssi_max, rssi_avg,
                method, confidence_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            fp, vendor_for_db,
            burst_cnt, mac_cnt, pkt_cnt,
            random_cnt, real_cnt,
            first_seen, last_seen, duration_sec,
            rssi_min, rssi_max, rssi_avg,
            METHOD, None,   # Stufe 3a vergibt keinen Konfidenzwert
        ))
        cluster_id = cur.lastrowid
        cluster_assignments.append((cluster_id, fp, vendor_for_db))
        clusters_created += 1

    conn.commit()

    # Bursts den Clustern zuweisen.
    # NULL-Vendor und tatsächlicher Vendor werden getrennt behandelt, da SQL "= NULL" nie true ergibt.
    for cluster_id, fp, vendor_for_db in cluster_assignments:
        if vendor_for_db is None:
            cur.execute("""
                UPDATE bursts
                SET cluster_id = ?
                WHERE ie_fingerprint = ? AND vendor_oui_set IS NULL
            """, (cluster_id, fp))
        else:
            cur.execute("""
                UPDATE bursts
                SET cluster_id = ?
                WHERE ie_fingerprint = ? AND vendor_oui_set = ?
            """, (cluster_id, fp, vendor_for_db))

    conn.commit()

    # Run-Tracking finalisieren
    cur.execute(
        "SELECT SUM(burst_count) FROM device_clusters WHERE method = ?",
        (METHOD,)
    )
    total_bursts_clustered = cur.fetchone()[0] or 0

    cur.execute("""
        UPDATE clustering_runs
        SET ended_at = ?, bursts_processed = ?, clusters_created = ?
        WHERE id = ?
    """, (
        datetime.now(timezone.utc).isoformat(timespec='microseconds'),
        total_bursts_clustered,
        clusters_created,
        run_id,
    ))
    conn.commit()

    return clusters_created, total_bursts_clustered

# MAIN
def main():
    init_db(DB_PATH)

    parser = argparse.ArgumentParser(
        description="Schritt 3a: Cluster-Bucketing"
    )
    parser.add_argument("--rebuild", action="store_true",
                        help="Bestehende Cluster loeschen und neu aufbauen")
    parser.add_argument("--db", type=str, default=DB_PATH,
                        help=f"DB-Pfad (default: {DB_PATH})")
    args = parser.parse_args()

    try:
        conn = sqlite3.connect(args.db)
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error as e:
        print(f"[!] DB-Fehler: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        clusters, bursts = build_clusters(conn, rebuild=args.rebuild)
        print(f"[i] {clusters} Cluster gebildet, {bursts} Bursts zugeordnet.")
    except KeyboardInterrupt:
        print("\n[!] Abbruch durch Benutzer.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()