#!/usr/bin/env python3
"""
ble_cluster_3c.py
-----------------
Stufe 3c der BLE-Pipeline - Track-Bildung.
"""

import json
import sqlite3
import statistics
import time
from collections import defaultdict
from datetime import datetime

from config import (
    DB_PATH,
    BLE_RSSI_TOLERANCE_DB_DEFAULT, BLE_RSSI_TOLERANCE_DB_GENERIC,
    BLE_GAP_TIGHT_S, BLE_GAP_LOOSE_S, BLE_GAP_GENERIC_S,
    BLE_TRACK_SPAN_MAX_SECONDS,
    BLE_APPLE_MIXED_PENALTY, BLE_GENERIC_MIXED_PENALTY,
)
from init_db import init_db


APPLE_MFR         = 76
MICROSOFT_MFR_SET = {6, 61679}
GOOGLE_SVC_UUID_SUFFIXES = (
    "0000fcf1-0000-1000-8000-00805f9b34fb",
    "0000fef3-0000-1000-8000-00805f9b34fb",
)


# HILFSFUNKTIONEN
def parse_ts(ts):
    # ISO-Timestamp -> Unix-Sekunden.
    return datetime.fromisoformat(ts).timestamp()


def is_thin_cluster(fc_json):
    # Word True, wenn ein Cluster zu merkmalsarm ist, um sichere Tracks zu bilden (keine Hersteller-ID, keine Service-UUID, höchstens ein AD-Type).
    try:
        fc = json.loads(fc_json) if fc_json else {}
    except Exception:
        return True
    has_mfr = fc.get("mfr_id") is not None
    has_service = bool(fc.get("service_uuids", "").strip("[]"))
    ad_types_raw = fc.get("ad_types", "")
    try:
        n_ad_types = len(json.loads(ad_types_raw)) if ad_types_raw else 0
    except Exception:
        n_ad_types = 0
    return not (has_mfr or has_service or n_ad_types > 1)


def gap_for_burst(burst, generic):
    # Liefert die maximal erlaubte Zeitlücke zwischen zwei Bursts, damit sie noch als dasselbe Gerät gelten.
    if generic:
        return BLE_GAP_GENERIC_S
    mfr = burst["primary_manufacturer_id"]
    if mfr == APPLE_MFR or mfr in MICROSOFT_MFR_SET:
        return BLE_GAP_TIGHT_S
    svc = burst.get("service_uuids_set") or ""
    for s in GOOGLE_SVC_UUID_SUFFIXES:
        if s in svc:
            return BLE_GAP_TIGHT_S
    return BLE_GAP_LOOSE_S


def overlaps(b1, b2):
    # True, wenn sich zwei Bursts zeitlich überlappen.
    return not (b1["_end"] < b2["_start"] or b2["_end"] < b1["_start"])


def time_gap(b1, b2):
    # Pause in Sekunden zwischen zwei nicht-überlappenden Bursts.
    if b1["_end"] < b2["_start"]:
        return b2["_start"] - b1["_end"]
    if b2["_end"] < b1["_start"]:
        return b1["_start"] - b2["_end"]
    return 0.0


def compute_match_score(b1, b2, gap_seconds, max_gap, rssi_tol):
    # Bewertet, wie gut zwei Bursts als dasselbe Gerät zusammenpassen --> je kleiner die Zeitlücke und je ähnlicher die Signalstärke, desto höher der Score.
    rssi_diff = abs((b1["rssi_avg"] or 0) - (b2["rssi_avg"] or 0))
    gap_score = 1.0 - (gap_seconds / max_gap)
    rssi_score = 1.0 - (rssi_diff / rssi_tol)
    return 0.5 * gap_score + 0.5 * rssi_score


# UNION-FIND (mit Score-Sammlung pro Komponente)
class UnionFind:
    # Union-Find, das zusätzlich die Match-Scores der akzeptierten Verbindungen je Komponente sammelt (für die spätere Konfidenz).

    def __init__(self, n):
        self.parent = list(range(n))
        self.scores = defaultdict(list)

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]   # Path Compression
            x = self.parent[x]
        return x

    def union(self, i, j, score=None):
        ri, rj = self.find(i), self.find(j)
        if ri == rj:
            return False
        self.parent[ri] = rj
        # Scores der aufgelösten Wurzel an die neue Wurzel übertragen
        if ri in self.scores:
            self.scores[rj].extend(self.scores[ri])
            del self.scores[ri]
        if score is not None:
            self.scores[rj].append(score)
        return True

    def components_with_scores(self, n):
        comps = defaultdict(list)
        for i in range(n):
            comps[self.find(i)].append(i)
        result = []
        for root, members in comps.items():
            collected = list(self.scores.get(root, []))
            result.append((members, collected))
        return result


# TRACK-ZUWEISUNG (Kern der Stufe 3c)
def assign_tracks_in_cluster(bursts, generic):
    """
    Teilt die Bursts eines 3a-Clusters in Tracks auf.

    Ablauf:
      1. Zeitlich überlappende Burst-Paare als "forbidden" markieren
         (ein Gerät kann nicht gleichzeitig zwei Adressen senden).
      2. Bursts derselben MAC automatisch zusammenführen.
      3. Match-Kandidaten (verschiedene MAC, kein Overlap, Gap und RSSI
         innerhalb der Toleranz) nach Score absteigend abarbeiten.
      4. Vor jedem Merge prüfen, dass weder ein Forbidden-Paar noch die
         maximale Track-Spanne verletzt wird.
    """
    n = len(bursts)
    if n == 0:
        return []
    if n == 1:
        return [([0], [])]

    rssi_tol = (BLE_RSSI_TOLERANCE_DB_GENERIC if generic
                else BLE_RSSI_TOLERANCE_DB_DEFAULT)
    uf = UnionFind(n)

    # 1. Forbidden Pairs: zeitlich überlappende Bursts
    forbidden = set()
    for i in range(n):
        for j in range(i + 1, n):
            if overlaps(bursts[i], bursts[j]):
                forbidden.add((i, j))

    # 2. Bursts derselben (gehashten) MAC direkt zusammenführen
    by_mac = defaultdict(list)
    for idx, b in enumerate(bursts):
        by_mac[b["mac"]].append(idx)
    for mac_indices in by_mac.values():
        for k in range(1, len(mac_indices)):
            uf.union(mac_indices[0], mac_indices[k], score=None)

    # 3. Match-Kandidaten zwischen verschiedenen MACs generieren
    candidates = []
    for i in range(n):
        for j in range(i + 1, n):
            bi, bj = bursts[i], bursts[j]
            if bi["mac"] == bj["mac"]:
                continue
            if (i, j) in forbidden:
                continue
            max_gap = min(gap_for_burst(bi, generic), gap_for_burst(bj, generic))
            gap = time_gap(bi, bj)
            if gap > max_gap:
                continue
            if bi["rssi_avg"] is None or bj["rssi_avg"] is None:
                continue
            if abs(bi["rssi_avg"] - bj["rssi_avg"]) > rssi_tol:
                continue
            score = compute_match_score(bi, bj, gap, max_gap, rssi_tol)
            candidates.append((score, i, j))

    candidates.sort(reverse=True)   # stärkste Verbindungen zuerst

    # WARNING 1: würde der Merge ein zeitlich überlappendes Paar in dieselbe
    # Komponente bringen?
    def violates_forbidden(i, j):
        ri, rj = uf.find(i), uf.find(j)
        if ri == rj:
            return False
        comp_i = [k for k in range(n) if uf.find(k) == ri]
        comp_j = [k for k in range(n) if uf.find(k) == rj]
        for ci in comp_i:
            for cj in comp_j:
                a, b = (ci, cj) if ci < cj else (cj, ci)
                if (a, b) in forbidden:
                    return True
        return False

    # WARNING 2: würde die zusammengeführte Komponente die maximale
    # Track-Spanne überschreiten?
    def violates_span(i, j):
        ri, rj = uf.find(i), uf.find(j)
        if ri == rj:
            return False
        comp_i = [k for k in range(n) if uf.find(k) == ri]
        comp_j = [k for k in range(n) if uf.find(k) == rj]
        all_idx = comp_i + comp_j
        starts = [bursts[k]["_start"] for k in all_idx]
        ends = [bursts[k]["_end"] for k in all_idx]
        return (max(ends) - min(starts)) > BLE_TRACK_SPAN_MAX_SECONDS

    # 4. Kandidaten abarbeiten, WARNINGS beachten
    for score, i, j in candidates:
        if uf.find(i) == uf.find(j):
            continue
        if violates_forbidden(i, j):
            continue
        if violates_span(i, j):
            continue
        uf.union(i, j, score=score)

    return uf.components_with_scores(n)


# KONFIDENZ-BERECHNUNG
def address_type_mix_penalty(members, primary_mfr):
    """
    Bestimmt einen Strafe, wenn ein Track public- und Random-Adressen
    mischt. Der Faktor hängt vom Hersteller ab:

      - Microsoft: gemischte Typen sind erwartbar -> keine Strafe.
      - Apple: die als "public" klassifizierten Adressen werden über ihre
        mac_top_two_bits geprüft. Tragen sie das Bit-Muster von RPAs
        (0b01/0b11), ist es ein bekanntes Klassifikations-Artefakt und wird
        NICHT bestraft; nur ein echtes 0b00-Muster führt zur Strafe.
      - andere/unbekannte Hersteller: moderate Strafe.
    """
    types = {m["mac_address_type"] for m in members if m["mac_address_type"]}
    has_random = bool(types & {"rpa", "nrpa", "static_random"})
    has_public = "public" in types

    if not (has_random and has_public):
        return 1.0, ""

    if primary_mfr in MICROSOFT_MFR_SET:
        return 1.0, "ms_mixed_addr_types_expected"

    if primary_mfr == APPLE_MFR:
        # Top-2-Bits direkt aus der Burst-Row lesen (kein MAC-Parsing nötig)
        public_top_twos = {
            m["mac_top_two_bits"]
            for m in members
            if m["mac_address_type"] == "public"
               and m["mac_top_two_bits"] is not None
        }
        if public_top_twos and public_top_twos.issubset({0b01, 0b11}):
            return 1.0, "apple_heuristic_artifact_no_penalty"
        if 0b00 in public_top_twos:
            return BLE_APPLE_MIXED_PENALTY, "apple_real_mixed_addr_types"
        return 0.7, "apple_mixed_addr_types_uncertain"

    if primary_mfr is not None:
        return 0.85, "other_vendor_mixed_addr_types"

    return BLE_GENERIC_MIXED_PENALTY, "generic_mixed_addr_types"


def compute_confidence(members, accepted_match_scores, primary_mfr):
    """
    Berechnet den Konfidenzwert eines Tracks. Single-MAC-Tracks sind sicher
    (1.0). Sonst setzt sich die Konfidenz zusammen aus:
      - mittlerer Match-Score der akzeptierten Verbindungen (Gewicht 0.5)
      - RSSI-Stabilität über die Bursts (Gewicht 0.3)
      - Aktiv-Verhältnis: gesendete Zeit / Gesamtspanne (Gewicht 0.2)
    Das Ergebnis wird mit dem Adresstyp-Mix-Straffaktor multipliziert.
    """
    macs = {m["mac"] for m in members}
    if len(macs) <= 1:
        return 1.0, ""
    if not accepted_match_scores:
        return 0.0, "no_match_scores"

    avg_match = statistics.mean(accepted_match_scores)

    rssi_vals = [m["rssi_avg"] for m in members if m["rssi_avg"] is not None]
    if len(rssi_vals) >= 2:
        rssi_sd = statistics.stdev(rssi_vals)
        rssi_stab = max(0.0, 1.0 - rssi_sd / 10.0)
    else:
        rssi_stab = 1.0

    durations = [m["duration_seconds"] or 0 for m in members]
    starts = [m["_start"] for m in members]
    ends = [m["_end"] for m in members]
    span = max(ends) - min(starts)
    active = sum(durations)
    active_ratio = (active / span) if span > 0 else 1.0
    active_ratio = min(1.0, active_ratio)

    base = 0.5 * avg_match + 0.3 * rssi_stab + 0.2 * active_ratio
    penalty, note = address_type_mix_penalty(members, primary_mfr)
    return base * penalty, note


# MAIN
# Räumt alle alten Tracks weg und holt alle 3a Cluster.
# Dann is_thin_cluster() --> assign_tracks_in_cluster() --> compute_confidence() --> address_type_mix_penalty()
def main():
    print("[i] BLE Stage 3c: Track-Building", flush=True)
    t0 = time.monotonic()

    init_db(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()

    # Bestehende Track-Zuordnung und Tracks verwerfen
    cur.execute("UPDATE ble_bursts SET track_id_3c = NULL")
    cur.execute("DELETE FROM ble_tracks_3c")
    cur.execute("DELETE FROM sqlite_sequence WHERE name='ble_tracks_3c'")
    conn.commit()

    cur.execute("""
        SELECT cluster_id, fingerprint_components, primary_manufacturer_id
        FROM ble_clusters_3a
    """)
    clusters = cur.fetchall()
    if not clusters:
        print("Keine Cluster. 3a vorher laufen lassen.", flush=True)
        conn.close()
        return

    n_thin_clusters = 0
    n_thin_bursts = 0
    n_tracks_total = 0
    n_bursts_processed = 0

    for cluster_id, fc_json, primary_mfr in clusters:
        # Alle Bursts dieses 3a-Clusters laden
        cur.execute("""
            SELECT id, mac, mac_address_type, mac_top_two_bits,
                   started_at, ended_at, duration_seconds, packet_count,
                   rssi_min, rssi_max, rssi_avg,
                   primary_manufacturer_id, service_uuids_set
            FROM ble_bursts
            WHERE cluster_id_3a = ?
        """, (cluster_id,))
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        bursts = [dict(zip(cols, r)) for r in rows]
        if not bursts:
            continue
        for b in bursts:
            b["_start"] = parse_ts(b["started_at"])
            b["_end"] = parse_ts(b["ended_at"])

        # Merkmalsarme Cluster überspringen (kein sicherer Track möglich)
        if is_thin_cluster(fc_json):
            n_thin_clusters += 1
            n_thin_bursts += len(bursts)
            continue

        generic = (primary_mfr is None)
        components = assign_tracks_in_cluster(bursts, generic)
        n_bursts_processed += len(bursts)

        # Jede Union-Find-Komponente wird ein Track
        for member_indices, scores in components:
            members = [bursts[i] for i in member_indices]
            macs = sorted({m["mac"] for m in members})
            starts = [m["_start"] for m in members]
            ends = [m["_end"] for m in members]
            durations = [m["duration_seconds"] or 0 for m in members]
            rssi_mins = [m["rssi_min"] for m in members if m["rssi_min"] is not None]
            rssi_maxs = [m["rssi_max"] for m in members if m["rssi_max"] is not None]
            rssi_avgs = [m["rssi_avg"] for m in members if m["rssi_avg"] is not None]
            total_pkts = sum(m["packet_count"] for m in members)
            first_seen = min(m["started_at"] for m in members)
            last_seen = max(m["ended_at"] for m in members)
            span = max(ends) - min(starts)
            total_active = sum(durations)
            rssi_sd = statistics.stdev(rssi_avgs) if len(rssi_avgs) >= 2 else None
            confidence, note = compute_confidence(members, scores, primary_mfr)

            cur.execute("""
                INSERT INTO ble_tracks_3c (
                    cluster_id_3a, n_bursts, n_unique_macs, macs,
                    first_seen, last_seen, span_seconds, total_active_seconds,
                    rssi_min, rssi_max, rssi_avg, rssi_stddev, total_packets,
                    primary_manufacturer_id, confidence_score, confidence_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cluster_id, len(members), len(macs), json.dumps(macs),
                first_seen, last_seen, span, total_active,
                min(rssi_mins) if rssi_mins else None,
                max(rssi_maxs) if rssi_maxs else None,
                sum(rssi_avgs) / len(rssi_avgs) if rssi_avgs else None,
                rssi_sd, total_pkts, primary_mfr, confidence, note or None,
            ))
            tid = cur.lastrowid
            cur.executemany(
                "UPDATE ble_bursts SET track_id_3c = ? WHERE id = ?",
                [(tid, m["id"]) for m in members],
            )
            n_tracks_total += 1

    conn.commit()
    conn.close()

    elapsed = time.monotonic() - t0
    print(f"[i] {len(clusters)} Cluster, {n_thin_clusters} zu duenn (skipped), "
          f"{n_bursts_processed} Bursts verarbeitet -> "
          f"{n_tracks_total} Tracks ({elapsed:.2f}s)", flush=True)


if __name__ == "__main__":
    main()
