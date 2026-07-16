"""
db_insert.py
------------
SQLite-Anbindung für den WiFi-Scanner:
- Batch-Inserts statt Einzel-Commits (schont die SD-Karte)
- Verwaltet hop_sessions
- DSGVO-konforme Speicherung: MAC und SSID werden mit salted SHA-256 gehasht.
"""

import sqlite3
import threading
from datetime import datetime, timezone

from crypto import get_hasher


class DBHandler:
    # Pakete werden in einem Puffer gesammelt und gebündelt geschrieben. 
    # Ein Flush wird ausgelöst, sobald entweder die Batch-Größe erreicht oder das Flush-Intervall abgelaufen ist. 
    # Alle DB-Zugriffe sind über ein Lock serialisiert, da mehrere Threads gleichzeitig zugreifen.

    INSERT_PACKET_SQL = """
        INSERT INTO wifi_packets (
            mac, timestamp, rssi, channel, ssid,
            is_broadcast, is_random_mac, seq_num, retry_flag,
            ie_fingerprint, tagged_params_hash,
            ht_capabilities, ext_capabilities, vht_capabilities, he_capabilities,
            supported_rates, vendor_ouis, vendor_oui_set, hop_session_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    def __init__(self, db_path, batch_size=50, flush_interval=2.0):
        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self._buffer = []
        self._lock = threading.Lock()
        self._last_flush = datetime.now()
        self._total_inserted = 0

        # Hasher beim Init laden — Salt-Datei wird hier automatisch
        # angelegt, falls noch nicht vorhanden.
        self._hasher = get_hasher()

        # check_same_thread=False, da mehrere Threads dieselbe Verbindung nutzen.
        # WAL erlaubt paralleles Lesen während des Schreibens (Dashboard),
        # synchronous=NORMAL reduziert die Schreibzyklen auf der SD-Karte.
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10.0)
        self.conn.execute("PRAGMA journal_mode = WAL;")
        self.conn.execute("PRAGMA synchronous = NORMAL;")
        self.conn.execute("PRAGMA foreign_keys = ON;")

    def start_hop_session(self, cycle_id, hop_index, channel, dwell_ms):
        # Legt eine neue Hop-Session an und gibt deren ID zurück.
        # Jedes Paket wird über diese ID seinem Empfangskanal zugeordnet.
        ts = datetime.now(timezone.utc).isoformat(timespec='microseconds')
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO hop_sessions
                    (cycle_id, hop_index, channel, dwell_ms, started_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (cycle_id, hop_index, channel, dwell_ms, ts),
            )
            self.conn.commit()
            return cur.lastrowid

    def end_hop_session(self, session_id):
        # Schließt eine Hop-Session ab, indem ended_at gesetzt wird.
        if session_id is None:
            return
        ts = datetime.now(timezone.utc).isoformat(timespec='microseconds')
        with self._lock:
            self.conn.execute(
                "UPDATE hop_sessions SET ended_at = ? WHERE id = ?",
                (ts, session_id),
            )
            self.conn.commit()

    def insert_packet(self, p):
        """
        Nimmt ein Paket in den Puffer auf und schreibt gebündelt, sobald
        eine der beiden Bedingungen erfüllt ist: Batch-Größe erreicht oder
        Flush-Intervall abgelaufen. Die Doppel-Bedingung stellt sicher, dass
        auch bei niedriger Paketrate regelmäßig persistiert wird.
        """
        with self._lock:
            self._buffer.append(p)
            should_flush = (
                len(self._buffer) >= self.batch_size
                or (datetime.now() - self._last_flush).total_seconds()
                >= self.flush_interval
            )
            if should_flush:
                self._flush_locked()

    def _flush_locked(self):
        # Schreibt den Puffer in die Datenbank.

        if not self._buffer:
            return 0

        # WICHTIG: MAC und SSID werden HIER gehasht, nicht im Scanner.
        # Damit bleibt is_random_mac im Scanner für U/L-Bit Berechnung erhalten — der Klartext der MAC verlässt nie diese Funktion.
        # Wildcard-Probes (ssid=None oder leer) bleiben None, damit man weiterhin sieht, dass es ein Wildcard war.
        rows = [
            (
                self._hasher.hash_mac(p['mac']),
                p['timestamp'], p['rssi'], p['channel'],
                self._hasher.hash_ssid(p['ssid']),
                p['is_broadcast'], p['is_random_mac'], p['seq_num'], p['retry_flag'],
                p['ie_fingerprint'], p['tagged_params_hash'],
                p['ht_capabilities'], p['ext_capabilities'],
                p['vht_capabilities'], p['he_capabilities'],
                p['supported_rates'], p['vendor_ouis'], p['vendor_oui_set'],
                p['hop_session_id'],
            )
            for p in self._buffer
        ]

        # Ein einziger executemany-Commit für den gesamten Batch
        try:
            self.conn.executemany(self.INSERT_PACKET_SQL, rows)
            self.conn.commit()
        except sqlite3.Error as e:
            # Fehler nicht durchreichen: der Scanner soll weiterlaufen,
            # auch wenn ein einzelner Batch scheitert.
            print(f"[DB] Insert error: {e}")
            return 0

        count = len(self._buffer)
        self._buffer.clear()
        self._last_flush = datetime.now()
        self._total_inserted += count
        return count

    def flush(self):
        with self._lock:
            return self._flush_locked()

    @property
    def total_inserted(self):
        # Gesamtzahl der bisher geschriebenen Pakete.
        return self._total_inserted

    def close(self):
        # Schreibt den Rest-Puffer und schließt die Verbindung.
        try:
            self.flush()
        finally:
            self.conn.close()