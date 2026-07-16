#!/usr/bin/env python3
"""
config.py
---------
Zentrale Konfiguration für Beacon-Catcher-Skripte.

Skripte importieren die Konstanten über:

    from config import DB_PATH
"""

import os

# DATENBANK
DB_PATH = "/home/beacon1337/scripts/beacon.db"

# HARDWARE
WIFI_INTERFACE = "wlan1mon"
BLE_HCI_DEVICE = "hci0"       

# PFADE

SCRIPTS_DIR  = os.path.dirname(os.path.abspath(__file__))
SQL_DIR      = os.path.join(SCRIPTS_DIR, "sql")
LOG_DIR      = "/var/log/beacon"        # wird im systemd-Setup angelegt
BACKUP_DIR   = "/mnt/beacon-backup"     # Mount-Point fuer USB-Stick

# BLE SCANNER
BLE_BATCH_SIZE     = 200
BLE_FLUSH_INTERVAL = 5.0
BLE_LOG_EVERY      = 50

# BLE BURST AGGREGATION
BLE_BURST_GAP_SECONDS = 60.0

# BLE STAGE 3c PARAMETER
BLE_RSSI_TOLERANCE_DB_DEFAULT  = 7
BLE_RSSI_TOLERANCE_DB_GENERIC  = 5
BLE_GAP_TIGHT_S    = 900
BLE_GAP_LOOSE_S    = 1800
BLE_GAP_GENERIC_S  = 600
BLE_TRACK_SPAN_MAX_SECONDS = 3600
BLE_APPLE_MIXED_PENALTY    = 0.4
BLE_GENERIC_MIXED_PENALTY  = 0.7