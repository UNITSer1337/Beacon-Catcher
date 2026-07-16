#!/usr/bin/env python3
"""
cluster_matching_3c.py
----------------------
Stufe 3 - Soft-Score-Matching auf den 3b-Clustern.

Wo 3b strikt geschnitten hat, prüft 3c paarweise, ob zwei Cluster mit hoher Konfidenz dasselbe Gerät repräsentieren.

- Real-MAC- und anomale Cluster werden 1:1 durchgereicht.

Score-Modell (Default-Gewichte):
    score = 0.4 * temporal_score
          + 0.3 * rssi_score
          + 0.2 * vendor_score
          + 0.1 * ssid_score
  - temporal_score: 0 bei zeitlicher Überlappung, sonst exp(-gap/tau) mit tau = 30 min
  - rssi_score:     1 - min(1, |Δrssi_avg|/sigma) mit sigma = 15 dB
  - vendor_score:   Ähnlichkeit der vendor_oui_sets
  - ssid_score:     Ähnlichkeit der geprobten SSIDs

Schwelle: 0.7 (Cluster werden gemerged, wenn score >= 0.7).

Konfidenz pro 3c-Cluster:
  - Pass-through (1:1 von 3b): NULL
  - Gemerged: Mittelwert der Scores aller Paare, die zur Komponente
    beigetragen haben.

Aufruf:
    python3 cluster_matching_3c.py --rebuild
"""

import argparse
import json
import math
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean
from config import DB_PATH
from init_db import init_db

METHOD = "fingerprint_scored"
PRIOR_METHOD = "fingerprint_hardcut"

# Score-Parameter, per CLI überschreibbar
DEFAULT_THRESHOLD      = 0.70
DEFAULT_TEMPORAL_TAU_S = 1800.0   # 30 Minuten
DEFAULT_RSSI_SIGMA_DB  = 15.0     # dB

# Score-Gewichte (Summe = 1.0)
WEIGHT_TEMPORAL = 0.4
WEIGHT_RSSI     = 0.3
WEIGHT_VENDOR   = 0.2
WEIGHT_SSID     = 0.1

# UNION-FIND
class UnionFind:
    # Verwaltet die Zugehörigkeit der Cluster zu Komponenten, jede Komponente wird am Ende ein 3c-Cluster.

    def __init__(self, ids):
        self.parent = {i: i for i in ids}
        self.rank = {i: 0 for i in ids}

    def find(self, x):
        # Sucht die Wurzel und verkürzt dabei den Pfad.
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]   # Path Compression
            x = self.parent[x]
        return x

    def union(self, x, y):
        # Vereint zwei Komponenten --> False, wenn bereits verbunden.
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return False
        # Kleineren Baum an größeren hängen (Union by Rank), damit die Bäume flach bleiben
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1
        return True

    def components(self):
        # Liefert die Zusammenhangskomponenten als Liste von Listen.
        groups = defaultdict(list)
        for x in self.parent:
            groups[self.find(x)].append(x)
        return list(groups.values())


# HILFSFUNKTIONEN
def parse_ts(s):
    # ISO8601 → datetime (None bei Fehler).
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def parse_oui_set(s):
    # vendor_oui_set ist als JSON-Array gespeichert oder NULL.
    if not s:
        return set()
    try:
        data = json.loads(s)
        return set(data) if isinstance(data, list) else set()
    except (json.JSONDecodeError, TypeError):
        return set()


def jaccard(set_a, set_b):
    """
    Jaccard-Ähnlichkeit zweier Mengen: Schnittmenge geteilt durch
    Vereinigungsmenge. Sind beide Mengen leer, ist keine Aussage möglich → 0.5 als neutraler Wert, damit fehlende Daten weder belohnt noch bestraft werden.
    """
    if not set_a and not set_b:
        return 0.5
    union_size = len(set_a | set_b)
    if union_size == 0:
        return 0.5
    return len(set_a & set_b) / union_size


# SCORE-FUNKTIONEN
def temporal_score(a_first, a_last, b_first, b_last, tau_s):
    # Bewertet den zeitlichen Abstand zweier Cluster. --> 0.0 bei Überlappung der Intervalle, denn ein Gerät kann nicht gleichzeitig zwei Cluster bedienen.
    af, al = parse_ts(a_first), parse_ts(a_last)
    bf, bl = parse_ts(b_first), parse_ts(b_last)
    if not (af and al and bf and bl):
        return 0.0

    # Intervalle überlappen sich → VETO
    if af <= bl and bf <= al:
        return 0.0

    # Breite der Lücke zwischen den beiden Intervallen
    if al < bf:
        gap_s = (bf - al).total_seconds()
    else:
        gap_s = (af - bl).total_seconds()

    return math.exp(-gap_s / tau_s)


def rssi_score(a_rssi_avg, b_rssi_avg, sigma_db):
    # Bewertet die Ähnlichkeit der Signalstärke: 1 - min(1, |Δrssi|/sigma).
    if a_rssi_avg is None or b_rssi_avg is None:
        return 0.5
    delta = abs(a_rssi_avg - b_rssi_avg)
    return 1.0 - min(1.0, delta / sigma_db)


def vendor_score(a_vendor_set, b_vendor_set):
    # Jaccard-Ähnlichkeit der vendor_oui_sets beider Cluster.
    return jaccard(parse_oui_set(a_vendor_set), parse_oui_set(b_vendor_set))


def ssid_score(a_ssids, b_ssids):
    # Jaccard-Ähnlichkeit der gesucht Netzwerknamen. Geräte, die dieselben Netze suchen, gehören wahrscheinlich zusammen
    return jaccard(a_ssids, b_ssids)


def combined_score(a, b, tau_s, sigma_db):
    # Berechnet alle vier Teilscores und den gewichteten Gesamtscore.
    # Bei zeitlicher Überlappung wird der Gesamtscore explizit auf 0 gesetzt egal, wie gut die übrigen Kriterien passen.
    t = temporal_score(a['first_seen'], a['last_seen'],
                       b['first_seen'], b['last_seen'], tau_s)
    r = rssi_score(a['rssi_avg'], b['rssi_avg'], sigma_db)
    v = vendor_score(a['vendor_oui_set'], b['vendor_oui_set'])
    s = ssid_score(a['ssids_set'], b['ssids_set'])

    if t == 0.0:
        score = 0.0
    else:
        score = (WEIGHT_TEMPORAL * t
                 + WEIGHT_RSSI    * r
                 + WEIGHT_VENDOR  * v
                 + WEIGHT_SSID    * s)

    breakdown = {
        't': round(t, 4),
        'r': round(r, 4),
        'v': round(v, 4),
        's': round(s, 4),
        'score': round(score, 4),
    }
    return score, breakdown


# SCHEMA-ERWEITERUNG
def ensure_schema(conn):
    # Legt die Spalte bursts.cluster_id_scored an, falls sie noch fehlt.
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(bursts)")
    cols = {row[1] for row in cur.fetchall()}

    if "cluster_id_scored" not in cols:
        cur.execute("ALTER TABLE bursts ADD COLUMN cluster_id_scored INTEGER")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_bursts_cluster_scored "
        "ON bursts(cluster_id_scored)"
    )
    conn.commit()


# DATEN LADEN
def load_3b_clusters_with_metadata(conn):
    # Lädt alle 3b-Cluster mit ihren Statistiken.
    cur = conn.cursor()

    cur.execute("""
        SELECT id, ie_fingerprint, vendor_oui_set,
               burst_count, mac_count, packet_count,
               random_mac_count, real_mac_count,
               first_seen, last_seen, duration_seconds,
               rssi_min, rssi_max, rssi_avg,
               notes
        FROM device_clusters
        WHERE method = ?
    """, (PRIOR_METHOD,))

    clusters = {}
    for row in cur.fetchall():
        (cid, fp, vset, bcnt, mcnt, pcnt, rcnt, recnt,
         fs, ls, dur, rmin, rmax, ravg, notes) = row
        clusters[cid] = {
            'id': cid,
            'ie_fingerprint': fp,
            'vendor_oui_set': vset,
            'burst_count': bcnt,
            'mac_count': mcnt,
            'packet_count': pcnt,
            'random_mac_count': rcnt,
            'real_mac_count': recnt,
            'first_seen': fs,
            'last_seen': ls,
            'duration_seconds': dur,
            'rssi_min': rmin,
            'rssi_max': rmax,
            'rssi_avg': ravg,
            'notes': notes or "",
            'burst_ids': [],
            'ssids_set': set(),
        }

    # Burst-Zuordnung und geprobte SSIDs je Cluster einsammeln
    cur.execute("""
        SELECT id, cluster_id_hardcut, ssids_probed
        FROM bursts
        WHERE cluster_id_hardcut IS NOT NULL
    """)
    for bid, cid, ssids_json in cur.fetchall():
        if cid not in clusters:
            continue
        clusters[cid]['burst_ids'].append(bid)
        if ssids_json:
            try:
                ssids = json.loads(ssids_json)
                if isinstance(ssids, list):
                    clusters[cid]['ssids_set'].update(ssids)
            except (json.JSONDecodeError, TypeError):
                pass

    return list(clusters.values())


# AGGREGATION FÜR MERGE-CLUSTER
def aggregate_from_burst_ids(conn, burst_ids):
    # Berechnet die Cluster-Statistiken neu aus den ursts.
    if not burst_ids:
        return None

    cur = conn.cursor()
    placeholders = ",".join("?" * len(burst_ids))
    cur.execute(f"""
        SELECT
            COUNT(*) AS bursts,
            COUNT(DISTINCT mac) AS macs,
            SUM(packet_count) AS pkts,
            COUNT(DISTINCT CASE WHEN is_random_mac=1 THEN mac END) AS rand_macs,
            COUNT(DISTINCT CASE WHEN is_random_mac=0 THEN mac END) AS real_macs,
            MIN(started_at) AS first,
            MAX(ended_at) AS last,
            MIN(rssi_min) AS rmin,
            MAX(rssi_max) AS rmax,
            AVG(rssi_avg) AS ravg
        FROM bursts
        WHERE id IN ({placeholders})
    """, burst_ids)
    row = cur.fetchone()

    bursts, macs, pkts, rand_macs, real_macs, first, last, rmin, rmax, ravg = row

    duration = None
    if first and last:
        t1, t2 = parse_ts(first), parse_ts(last)
        if t1 and t2:
            duration = (t2 - t1).total_seconds()

    return {
        'burst_count': bursts,
        'mac_count': macs,
        'packet_count': pkts,
        'random_mac_count': rand_macs,
        'real_mac_count': real_macs,
        'first_seen': first,
        'last_seen': last,
        'duration_seconds': duration,
        'rssi_min': rmin,
        'rssi_max': rmax,
        'rssi_avg': ravg,
    }


def stats_from_3b(c):
    # Statistiken eines unveränderten 3b-Clusters (für Pass-Through).
    return {k: c[k] for k in (
        'burst_count', 'mac_count', 'packet_count',
        'random_mac_count', 'real_mac_count',
        'first_seen', 'last_seen', 'duration_seconds',
        'rssi_min', 'rssi_max', 'rssi_avg',
    )}


# 3C-CLUSTER SCHREIBEN
def insert_3c_cluster(conn, fp, vendor_set, stats, confidence, notes_str):
    # Legt einen neuen 3c-Cluster in device_clusters an.
    cur = conn.cursor()
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
        fp, vendor_set,
        stats['burst_count'], stats['mac_count'], stats['packet_count'],
        stats['random_mac_count'], stats['real_mac_count'],
        stats['first_seen'], stats['last_seen'], stats['duration_seconds'],
        stats['rssi_min'], stats['rssi_max'], stats['rssi_avg'],
        METHOD, confidence, notes_str,
    ))
    return cur.lastrowid


def assign_bursts(conn, burst_ids, cluster_id):
    # Setzt cluster_id_scored für alle Bursts eines 3c-Clusters.
    cur = conn.cursor()
    cur.executemany(
        "UPDATE bursts SET cluster_id_scored = ? WHERE id = ?",
        [(cluster_id, bid) for bid in burst_ids],
    )


def passthrough_cluster(conn, c):
    # Erzeugt ein 3c-Cluster, das exakt einem 3b-Cluster entspricht (kein Merge). Der Konfidenzwert bleibt NULL, da keine Zusammenführung.
    notes_str = json.dumps({
        "type": "passthrough",
        "from_3b_id": c['id'],
        "from_3b_notes": c['notes'],
    })
    new_id = insert_3c_cluster(
        conn,
        c['ie_fingerprint'], c['vendor_oui_set'],
        stats_from_3b(c), None, notes_str,
    )
    assign_bursts(conn, c['burst_ids'], new_id)
    return new_id


# HAUPT-LOGIK
def build_scored_clusters(conn, threshold, tau_s, sigma_db, rebuild=False):
    """
    Kern der 3c-Verarbeitung:
      1. Lädt alle 3b-Cluster
      2. Reicht Real-MAC- und anomale Cluster 1:1 durch
      3. Gruppiert Random-Cluster nach vendor_oui_set
      4. Berechnet paarweise Scores und merged mit Union-Find
    """
    cur = conn.cursor()

    if rebuild:
        cur.execute("DELETE FROM device_clusters WHERE method = ?", (METHOD,))
        cur.execute("UPDATE bursts SET cluster_id_scored = NULL")
        conn.commit()

    # Run-Tracking: Schwellen und Gewichte des Laufs festhalten
    run_started = datetime.now(timezone.utc).isoformat(timespec='microseconds')
    notes_str = (f"threshold={threshold}, tau_s={tau_s}, sigma_db={sigma_db}, "
                 f"weights=t{WEIGHT_TEMPORAL}/r{WEIGHT_RSSI}/"
                 f"v{WEIGHT_VENDOR}/s{WEIGHT_SSID}")
    cur.execute(
        "INSERT INTO clustering_runs (started_at, method, notes) VALUES (?, ?, ?)",
        (run_started, METHOD, notes_str),
    )
    run_id = cur.lastrowid
    conn.commit()

    clusters_3b = load_3b_clusters_with_metadata(conn)
    if not clusters_3b:
        print("[!] Keine 3b-Cluster (fingerprint_hardcut) in der DB.")
        print("    Bitte zuerst cluster_matching_3b.py laufen lassen.")
        return {'clusters_created': 0, 'bursts_assigned': 0, 'merges_performed': 0}

    # Kategorisieren anhand der von 3b hinterlassenen notes
    real_clusters = []
    anomalous_clusters = []
    random_clusters = []
    for c in clusters_3b:
        if c['notes'].startswith('real_mac:'):
            real_clusters.append(c)
        elif c['notes'].startswith('anomalous_mac:'):
            anomalous_clusters.append(c)
        elif c['notes'].startswith('random_group_'):
            random_clusters.append(c)
        else:
            # Unbekannte Kategorie --> als Pass-Through behandeln
            real_clusters.append(c)

    clusters_created = 0
    bursts_assigned = 0
    merges_performed = 0
    merges_vetoed_transitively = 0

    # Real- und anomale Cluster kommen für ein Merging nicht in Frage und werden unverändert übernommen
    for c in real_clusters + anomalous_clusters:
        passthrough_cluster(conn, c)
        clusters_created += 1
        bursts_assigned += len(c['burst_ids'])
    conn.commit()

    # Random-Cluster nach vendor_oui_set gruppieren.
    vendor_groups = defaultdict(list)
    for c in random_clusters:
        vkey = c['vendor_oui_set'] if c['vendor_oui_set'] is not None else "__none__"
        vendor_groups[vkey].append(c)

    pairs_evaluated = 0

    for vkey, group in vendor_groups.items():
        # Nur ein Cluster in dieser Vendor-Gruppe → nichts zu mergen
        if len(group) == 1:
            passthrough_cluster(conn, group[0])
            clusters_created += 1
            bursts_assigned += len(group[0]['burst_ids'])
            continue

        # UNION-FIND - Erklärung in Bachelorarbeit unter Implementierung (3c-Soft-Score-Matching)
        ids = [c['id'] for c in group]
        by_id = {c['id']: c for c in group}
        uf = UnionFind(ids)

        # Schritt 1: alle Paare scoren und die Overlap-Information merken
        all_pairs = []
        overlap_map = {}   # (a_id, b_id) → True bei zeitlicher Überlappung
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a, b = group[i], group[j]
                score, breakdown = combined_score(a, b, tau_s, sigma_db)
                pairs_evaluated += 1
                overlaps = (breakdown['t'] == 0.0)
                overlap_map[(a['id'], b['id'])] = overlaps
                overlap_map[(b['id'], a['id'])] = overlaps
                all_pairs.append((score, breakdown, a['id'], b['id']))

        # Schritt 2: nur Kandidaten über der Schwelle, absteigend sortiert (die sichersten Zusammenführungen zuerst).
        candidates = sorted(
            [(s, br, ai, bi) for s, br, ai, bi in all_pairs if s >= threshold],
            key=lambda x: (-x[0], x[2], x[3]),
        )

        # Schritt 3: Kanten mit Veto-Prüfung abarbeiten
        component_members = {cid: {cid} for cid in ids}
        applied_merges = []
        redundant_merges = []   # Kanten innerhalb bereits verbundener Komponenten

        for score, breakdown, a_id, b_id in candidates:
            root_a = uf.find(a_id)
            root_b = uf.find(b_id)

            if root_a == root_b:
                redundant_merges.append({'a': a_id, 'b': b_id, **breakdown})
                continue

            # Würde die Vereinigung ein zeitlich überlappendes Paar in dieselbe Komponente bringen?
            members_a = component_members[root_a]
            members_b = component_members[root_b]
            has_transitive_overlap = any(
                overlap_map.get((ma, mb), False)
                for ma in members_a for mb in members_b
            )

            if has_transitive_overlap:
                merges_vetoed_transitively += 1
                continue   # transitiver Veto → Merge unterdrücken

            # Sicher zu mergen: vereinen und die Mitgliederliste der neuen Wurzel fortschreiben
            uf.union(a_id, b_id)
            new_root = uf.find(a_id)
            other_root = root_b if new_root == root_a else root_a
            component_members[new_root] = members_a | members_b
            if other_root != new_root and other_root in component_members:
                del component_members[other_root]

            merges_performed += 1
            applied_merges.append({'a': a_id, 'b': b_id, **breakdown})

        # Für die Konfidenz zählen alle Kanten innerhalb der Endkomponente
        all_merge_records = applied_merges + redundant_merges

        # Komponenten in die Datenbank schreiben
        for component_ids in uf.components():
            members = [by_id[cid] for cid in component_ids]

            if len(members) == 1:
                # Cluster blieb allein → unverändert durchreichen
                passthrough_cluster(conn, members[0])
                clusters_created += 1
                bursts_assigned += len(members[0]['burst_ids'])
            else:
                # Mehrere 3b-Cluster in einer Komponente → ein 3c-Cluster.
                all_burst_ids = []
                for m in members:
                    all_burst_ids.extend(m['burst_ids'])
                stats = aggregate_from_burst_ids(conn, all_burst_ids)

                # Konfidenz = Mittel aller Score-Kanten dieser Komponente
                comp_set = set(component_ids)
                relevant = [m for m in all_merge_records
                            if m['a'] in comp_set and m['b'] in comp_set]
                avg_score = (round(mean(m['score'] for m in relevant), 4)
                             if relevant else None)

                # Als repräsentativen Fingerprint den des größten beteiligten Clusters übernehmen
                largest = max(members, key=lambda m: m['burst_count'])
                vendor_for_db = members[0]['vendor_oui_set']

                # Vollständige Nachvollziehbarkeit: welche 3b-Cluster und welche Fingerprints sind eingeflossen, mit welchen Scores.
                merged_notes = json.dumps({
                    "type": "merged",
                    "merged_3b_ids": sorted(component_ids),
                    "merged_3b_fps": sorted(
                        {m['ie_fingerprint'] for m in members}
                    ),
                    "merges": relevant,
                    "avg_score": avg_score,
                })

                new_id = insert_3c_cluster(
                    conn,
                    largest['ie_fingerprint'], vendor_for_db,
                    stats, avg_score, merged_notes,
                )
                assign_bursts(conn, all_burst_ids, new_id)
                clusters_created += 1
                bursts_assigned += len(all_burst_ids)

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
        'clusters_created': clusters_created,
        'bursts_assigned': bursts_assigned,
        'merges_performed': merges_performed,
        'merges_vetoed_transitively': merges_vetoed_transitively,
        'pairs_evaluated': pairs_evaluated,
    }


# CLI
def main():
    init_db(DB_PATH)

    parser = argparse.ArgumentParser(
        description="Schritt 3c: Soft-Score-Matching"
    )
    parser.add_argument("--rebuild", action="store_true",
                        help="Bestehende fingerprint_scored-Cluster löschen")
    parser.add_argument("--db", type=str, default=DB_PATH)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Score-Schwelle für Merge "
                             f"(default: {DEFAULT_THRESHOLD})")
    parser.add_argument("--tau", type=float, default=DEFAULT_TEMPORAL_TAU_S,
                        help=f"tau für Temporal-Score in Sekunden "
                             f"(default: {DEFAULT_TEMPORAL_TAU_S})")
    parser.add_argument("--sigma", type=float, default=DEFAULT_RSSI_SIGMA_DB,
                        help=f"sigma für RSSI-Score in dB "
                             f"(default: {DEFAULT_RSSI_SIGMA_DB})")
    args = parser.parse_args()

    try:
        conn = sqlite3.connect(args.db)
        conn.execute("PRAGMA foreign_keys = ON;")
    except sqlite3.Error as e:
        print(f"[!] DB-Fehler: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        ensure_schema(conn)
        result = build_scored_clusters(
            conn,
            threshold=args.threshold,
            tau_s=args.tau,
            sigma_db=args.sigma,
            rebuild=args.rebuild,
        )
        print(f"[i] {result['clusters_created']} Cluster gebildet, "
              f"{result['bursts_assigned']} Bursts zugeordnet, "
              f"{result['merges_performed']} Merges aus "
              f"{result.get('pairs_evaluated', 0)} evaluierten Paaren "
              f"({result.get('merges_vetoed_transitively', 0)} transitiv vetoed).")
    except KeyboardInterrupt:
        print("\n[!] Abbruch durch Benutzer.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
