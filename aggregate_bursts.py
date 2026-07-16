#!/usr/bin/env python3
"""
aggregate_bursts.py
-------------------
Aggregation der rohen Probe-Requests (wifi_packets) zu Bursts.

Falls MAC + gleicher ie_fingerprint + zeitliche Abstand über über BURST_TIMEOUT_MS --> neuer Burst.
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from statistics import mean
from config import DB_PATH
from init_db import init_db

BURST_TIMEOUT_MS = 1500   # Max. Pause innerhalb eines Bursts


# HILFSFUNKTIONEN
def parse_ts(ts_str):
    return datetime.fromisoformat(ts_str)


def ts_diff_ms(t1, t2):
    return (t2 - t1).total_seconds() * 1000.0


# BURST-ACCUMULATOR
class BurstAccumulator:
    """
    Sammelt Pakete eines Bursts und aggregiert sie zu Statistiken.
    Ein Burst kann nur um Pakete erweitert werden, die dieselbe MAC,
    denselben ie_fingerprint und einen zeitlichen Abstand
    <= BURST_TIMEOUT_MS zum letzten Paket haben.
    """

    def __init__(self, first_packet):
        p = first_packet
        ts = parse_ts(p['timestamp'])

        # Identitäts-Felder (im Burst konstant)
        self.mac = p['mac']
        self.ie_fingerprint = p['ie_fingerprint']
        self.is_random_mac = p['is_random_mac']
        self.tagged_params_hash = p['tagged_params_hash']

        # Capability-Felder werden vom ersten Paket übernommen
        self.ht_capabilities = p['ht_capabilities']
        self.ext_capabilities = p['ext_capabilities']
        self.vht_capabilities = p['vht_capabilities']
        self.he_capabilities = p['he_capabilities']
        self.supported_rates = p['supported_rates']
        self.vendor_ouis = p['vendor_ouis']
        self.vendor_oui_set = p['vendor_oui_set']

        # Zeitgrenzen und Paket-Referenzen
        self.started_at = ts
        self.ended_at = ts
        self.last_ts = ts
        self.first_packet_id = p['id']
        self.last_packet_id = p['id']

        # Aggregierte Statistiken
        self.packet_count = 1
        self.retry_count = 1 if p['retry_flag'] else 0
        self.has_broadcast = 1 if p['is_broadcast'] else 0
        self._seq_nums = [p['seq_num']] if p['seq_num'] is not None else []
        self._rssi_values = [p['rssi']] if p['rssi'] is not None else []
        self._channels = set()
        if p['channel'] is not None:
            self._channels.add(p['channel'])
        self._ssids = set()
        if p['ssid']:
            self._ssids.add(p['ssid'])

    # Prüft ob ein Paket zum offenen Burst gehört.
    def can_add(self, packet, ts):
        if packet['mac'] != self.mac:
            return False
        if packet['ie_fingerprint'] != self.ie_fingerprint:
            return False
        if ts_diff_ms(self.last_ts, ts) > BURST_TIMEOUT_MS:
            return False
        return True

    # Fügt ein Paket in den offenen Burst ein.
    def add(self, packet, ts):
        self.ended_at = ts
        self.last_ts = ts
        self.last_packet_id = packet['id']
        self.packet_count += 1

        if packet['retry_flag']:
            self.retry_count += 1
        if packet['is_broadcast']:
            self.has_broadcast = 1
        if packet['seq_num'] is not None:
            self._seq_nums.append(packet['seq_num'])
        if packet['rssi'] is not None:
            self._rssi_values.append(packet['rssi'])
        if packet['channel'] is not None:
            self._channels.add(packet['channel'])
        if packet['ssid']:
            self._ssids.add(packet['ssid'])

    # Berechnet die finalen Aggregatation.
    def to_row(self):
        duration_ms = int(ts_diff_ms(self.started_at, self.ended_at))

        seq_first = self._seq_nums[0] if self._seq_nums else None
        seq_last = self._seq_nums[-1] if self._seq_nums else None
        seq_min = min(self._seq_nums) if self._seq_nums else None
        seq_max = max(self._seq_nums) if self._seq_nums else None

        rssi_min = min(self._rssi_values) if self._rssi_values else None
        rssi_max = max(self._rssi_values) if self._rssi_values else None
        rssi_avg = round(mean(self._rssi_values), 2) if self._rssi_values else None

        channels_json = json.dumps(sorted(self._channels)) if self._channels else None
        ssids_json = json.dumps(sorted(self._ssids)) if self._ssids else None

        return (
            self.mac,
            self.is_random_mac,
            self.started_at.isoformat(timespec='microseconds'),
            self.ended_at.isoformat(timespec='microseconds'),
            duration_ms,
            self.packet_count,
            seq_first, seq_last, seq_min, seq_max,
            rssi_min, rssi_max, rssi_avg,
            channels_json,
            ssids_json,
            self.has_broadcast,
            self.retry_count,
            self.ie_fingerprint,
            self.tagged_params_hash,
            self.ht_capabilities,
            self.ext_capabilities,
            self.vht_capabilities,
            self.he_capabilities,
            self.supported_rates,
            self.vendor_ouis,
            self.vendor_oui_set,
            self.first_packet_id,
            self.last_packet_id,
        )

# INSERT-STATEMENT in die DB
INSERT_BURST_SQL = """
    INSERT INTO bursts (
        mac, is_random_mac,
        started_at, ended_at, duration_ms, packet_count,
        seq_num_first, seq_num_last, seq_num_min, seq_num_max,
        rssi_min, rssi_max, rssi_avg,
        channels_seen, ssids_probed, has_broadcast, retry_count,
        ie_fingerprint, tagged_params_hash,
        ht_capabilities, ext_capabilities, vht_capabilities, he_capabilities,
        supported_rates, vendor_ouis, vendor_oui_set,
        first_packet_id, last_packet_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

# HAUPT-AGGREGATION
def aggregate(conn, since_ts=None, rebuild=False):
    """
    - rebuild=True: bestehende Bursts löschen und komplett neu aufbauen.
    - since_ts: nur Pakete nach diesem Timestamp verarbeiten!!

    Pakete werden nach (mac, ie_fingerprint, timestamp) sortiert eingelesen,
    sodass alle Pakete eines potenziellen Bursts zusammenhängend anliegen.
    Der BurstAccumulator sammelt die dann, bis das Zeit- oder Identitäts-Kriterium
    einen neuen Burst erzwingt.
    """
    cur = conn.cursor()

    if rebuild:
        cur.execute("DELETE FROM bursts")
        cur.execute("DELETE FROM aggregation_runs")
        conn.commit()
        since_ts = None

    # Inkrementeller Modus: bei letztem Burst-Ende fortsetzen
    if since_ts is None and not rebuild:
        cur.execute("SELECT MAX(ended_at) FROM bursts")
        row = cur.fetchone()
        if row and row[0]:
            since_ts = row[0]

    # Run-Tracking DB insert
    run_started = datetime.now(timezone.utc).isoformat(timespec='microseconds')
    cur.execute(
        """
        INSERT INTO aggregation_runs (started_at, burst_timeout_ms, range_from)
        VALUES (?, ?, ?)
        """,
        (run_started, BURST_TIMEOUT_MS, since_ts),
    )
    run_id = cur.lastrowid
    conn.commit()

    # Pakete laden, sortiert nach Burst-Kriterium
    where = ""
    params = []
    if since_ts:
        where = "WHERE timestamp > ?"
        params.append(since_ts)

    sql = f"""
        SELECT id, mac, timestamp, rssi, channel, ssid,
               is_broadcast, is_random_mac, seq_num, retry_flag,
               ie_fingerprint, tagged_params_hash,
               ht_capabilities, ext_capabilities,
               vht_capabilities, he_capabilities,
               supported_rates, vendor_ouis, vendor_oui_set
        FROM wifi_packets
        {where}
        ORDER BY mac, ie_fingerprint, timestamp
    """
    cur.execute(sql, params)

    open_burst = None
    finished_bursts = []
    packets_processed = 0
    range_from = None
    range_to = None

    for row in cur:
        pkt = {
            'id': row[0],
            'mac': row[1],
            'timestamp': row[2],
            'rssi': row[3],
            'channel': row[4],
            'ssid': row[5],
            'is_broadcast': row[6],
            'is_random_mac': row[7],
            'seq_num': row[8],
            'retry_flag': row[9],
            'ie_fingerprint': row[10],
            'tagged_params_hash': row[11],
            'ht_capabilities': row[12],
            'ext_capabilities': row[13],
            'vht_capabilities': row[14],
            'he_capabilities': row[15],
            'supported_rates': row[16],
            'vendor_ouis': row[17],
            'vendor_oui_set': row[18],
        }

        # Pakete ohne Fingerprint (leere Whitelist-Tags) überspringen:
        # sie können keinem Cluster zugeordnet werden.
        if pkt['ie_fingerprint'] is None:
            continue

        ts = parse_ts(pkt['timestamp'])

        # Verarbeiteten Zeitbereich für Run-Tracking mitschreiben
        if range_from is None or pkt['timestamp'] < range_from:
            range_from = pkt['timestamp']
        if range_to is None or pkt['timestamp'] > range_to:
            range_to = pkt['timestamp']

        # Burst weiterführen oder neuen beginnen
        if open_burst is None:
            open_burst = BurstAccumulator(pkt)
        elif open_burst.can_add(pkt, ts):
            open_burst.add(pkt, ts)
        else:
            finished_bursts.append(open_burst.to_row())
            open_burst = BurstAccumulator(pkt)

        packets_processed += 1

        # Zwischen-Commit, um Speicherverbrauch zu begrenzen
        if len(finished_bursts) >= 500:
            conn.executemany(INSERT_BURST_SQL, finished_bursts)
            conn.commit()
            finished_bursts.clear()

    # Letzten offenen Burst abschliessen
    if open_burst is not None:
        finished_bursts.append(open_burst.to_row())
    if finished_bursts:
        conn.executemany(INSERT_BURST_SQL, finished_bursts)
        conn.commit()

    # Run-Tracking finalisieren
    cur.execute("SELECT COUNT(*) FROM bursts")
    total_bursts_now = cur.fetchone()[0]

    cur.execute(
        """
        UPDATE aggregation_runs
        SET ended_at = ?, packets_processed = ?, bursts_created = ?,
            range_from = ?, range_to = ?
        WHERE id = ?
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec='microseconds'),
            packets_processed,
            total_bursts_now,
            range_from,
            range_to,
            run_id,
        ),
    )
    conn.commit()

    return packets_processed, total_bursts_now


# ZUSAMMENFASSUNG - OUTPUT KONSOLE
def print_summary(conn, packets_processed, total_bursts):
    # Gibt die zentralen Aggregationszahlen aus.
    cur = conn.cursor()

    print(f"Pakete verarbeitet    : {packets_processed:,}")
    print(f"Bursts in DB (gesamt) : {total_bursts:,}")

    if total_bursts == 0:
        return

    cur.execute("SELECT COUNT(DISTINCT mac) FROM bursts")
    macs = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT ie_fingerprint) FROM bursts")
    fps = cur.fetchone()[0]
    cur.execute("""
        SELECT AVG(packet_count), AVG(duration_ms), MAX(packet_count)
        FROM bursts
    """)
    avg_pkts, avg_dur, max_pkts = cur.fetchone()
    cur.execute("SELECT COUNT(*) FROM bursts WHERE is_random_mac = 1")
    random_bursts = cur.fetchone()[0]

    print(f"Unique MACs                : {macs:,}")
    print(f"Unique IE-Fingerprints     : {fps:,}")
    print(f"Ø Pakete pro Burst         : {avg_pkts:.1f}")
    print(f"Ø Burst-Dauer              : {avg_dur:.0f} ms")
    print(f"Max. Pakete in einem Burst : {max_pkts}")
    print(f"Bursts mit Random-MAC      : {random_bursts:,} "
          f"({100*random_bursts/total_bursts:.1f}%)")


# CLI
def main():
    init_db(DB_PATH)

    parser = argparse.ArgumentParser(
        description="Aggregate WiFi probe requests into bursts"
    )
    parser.add_argument("--rebuild", action="store_true",
                        help="Bestehende bursts loeschen und neu aufbauen")
    parser.add_argument("--since", type=str, default=None,
                        help="Nur Pakete nach diesem ISO-Timestamp verarbeiten")
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
        packets, total_bursts = aggregate(
            conn,
            since_ts=args.since,
            rebuild=args.rebuild,
        )
        print_summary(conn, packets, total_bursts)
    except KeyboardInterrupt:
        print("\n[!] Abbruch durch Benutzer.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()