#!/usr/bin/env python3
"""
ble_db_insert.py
"""

import json
import sqlite3
import threading
import time

from crypto import get_hasher


COLUMNS = (
    "mac", "mac_address_type", "is_random_mac", "mac_top_two_bits",
    "rssi", "timestamp",
    "manufacturer_id", "manufacturer_data", "service_uuids",
    "service_data", "service_data_keys",
    "tx_power", "appearance", "ad_types", "ad_payload_length",
    "local_name", "platform_data",
)
PLACEHOLDERS = ",".join("?" * len(COLUMNS))
INSERT_SQL = f"INSERT INTO ble_packets ({','.join(COLUMNS)}) VALUES ({PLACEHOLDERS})"


class BLEDBHandler:
    # Batched SQLite Writer für BLE-Pakete mit echtem Hash-only-Storage.

    def __init__(self, db_path: str, batch_size: int = 100,
                 flush_interval: float = 1.0):
        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")

        # Hasher laden. Crash hier wenn Salt-Datei Probleme hat..
        self.hasher = get_hasher()

        self._lock = threading.Lock()
        self._buffer = []
        self._last_flush = time.monotonic()
        self.total_inserted = 0

    def insert(self, packet: dict) -> None:
        row = self._row_from_packet(packet)
        with self._lock:
            self._buffer.append(row)
            now = time.monotonic()
            if (len(self._buffer) >= self.batch_size
                    or (now - self._last_flush) >= self.flush_interval):
                self._flush_locked()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def close(self) -> None:
        try:
            self.flush()
        finally:
            self.conn.close()

    def _row_from_packet(self, packet: dict) -> tuple:
        # Hasht mac und local_name.
        mac_hash = self.hasher.hash_mac(packet.get("_raw_mac"))
        # Hash local_name
        local_name_hash = self.hasher.hash_local_name(packet.get("_raw_local_name"))

        return (
            mac_hash,
            packet.get("mac_address_type"),
            int(bool(packet.get("is_random_mac", 0))),
            packet.get("mac_top_two_bits"),
            packet.get("rssi"),
            packet.get("timestamp"),
            packet.get("manufacturer_id"),
            json.dumps(packet["manufacturer_data"]) if packet.get("manufacturer_data") else None,
            json.dumps(packet["service_uuids"])     if packet.get("service_uuids")     else None,
            json.dumps(packet["service_data"])      if packet.get("service_data")      else None,
            json.dumps(packet["service_data_keys"]) if packet.get("service_data_keys") else None,
            packet.get("tx_power"),
            packet.get("appearance"),
            json.dumps(packet["ad_types"])          if packet.get("ad_types")          else None,
            packet.get("ad_payload_length"),
            local_name_hash,
            json.dumps(packet["platform_data"])     if packet.get("platform_data")     else None,
        )

    def _flush_locked(self) -> None:
        if not self._buffer:
            self._last_flush = time.monotonic()
            return
        try:
            self.conn.executemany(INSERT_SQL, self._buffer)
            self.conn.commit()
            self.total_inserted += len(self._buffer)
            self._buffer.clear()
            self._last_flush = time.monotonic()
        except Exception as e:
            print(f"[DB ERROR] Flush failed ({len(self._buffer)} pkts queued): {e}",
                  flush=True)