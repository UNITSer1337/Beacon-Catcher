#!/usr/bin/env python3
"""
ble_scanner.py
--------------
Empfängt passiv die Advertising-Pakete der Umgebung und gibt sie an den BLEDBHandler.
"""

import asyncio
import signal
import sys
import time
from datetime import datetime, timezone

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from ble_db_insert import BLEDBHandler
from config import (
    DB_PATH, BLE_HCI_DEVICE,
    BLE_BATCH_SIZE, BLE_FLUSH_INTERVAL,
)
from init_db import init_db


# AD-Type-IDs gemäss Bluetooth-Assigned-Numbers
AD_TYPE_COMPLETE_16BIT_UUIDS  = 0x03
AD_TYPE_COMPLETE_128BIT_UUIDS = 0x07
AD_TYPE_COMPLETE_LOCAL_NAME   = 0x09
AD_TYPE_TX_POWER              = 0x0A
AD_TYPE_SERVICE_DATA_16BIT    = 0x16
AD_TYPE_SERVICE_DATA_128BIT   = 0x21
AD_TYPE_MANUFACTURER          = 0xFF

# Suffix der Bluetooth-Base-UUID: unterscheidet 16-Bit- von 128-Bit-UUIDs
BT_BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


# MAC-HELFER (von der Roh-MAC genommen, nur das Ergebnis wird gespeichert, nicht die Roh-MAC)
def mac_top_two_bits(mac: str):
    # Bringt mir die oberen zwei Bits des ersten Oktetts.
    # Wird in Stufe 3c benötigt, um Adresstyp-Heuristik zu erkennen.
    try:
        return (int(mac.split(":")[0], 16) >> 6) & 0b11
    except (ValueError, IndexError, AttributeError):
        return None


def detect_mac_address_type(mac: str) -> str:
    # Random-Adressen haben das Locally-Administered-Bit gesetzt -->  oberen zwei Bits entscheiden über den Subtyp (static_random / rpa / nrpa).
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError, AttributeError):
        return "unknown"

    locally_admin = (first_octet >> 1) & 0b1
    top_two = (first_octet >> 6) & 0b11

    if not locally_admin:
        return "public"
    if top_two == 0b11:
        return "static_random"
    if top_two == 0b01:
        return "rpa"      # Resolvable Private Address
    if top_two == 0b00:
        return "nrpa"     # Non-Resolvable Private Address
    return "public"


def is_random_address(addr_type: str) -> bool:
    # True für alle drei Random-Subtypen, False für public.
    return addr_type in ("rpa", "nrpa", "static_random")


# AD-TYPE-REKONSTRUKTION
def reconstruct_ad_types(adv_data: AdvertisementData) -> list:
    # Rekonstruiert die Menge der Advertising-Datentypen (AD-Types).
    # Da bleak das Advertisement bereits geparst gibt gehen die ursprünglichen AD-Type-Bezeichner verloren. 
    # Da die Menge der AD-Types ein gerätestabiles Fingerprint-Merkmal ist, wird sie zurückgewonnen --> Ist ein Feld gefuellt, muss das Paket den zugehörigen AD-Type enthalten haben.
    types = set()
    if adv_data.local_name:
        types.add(AD_TYPE_COMPLETE_LOCAL_NAME)
    if adv_data.manufacturer_data:
        types.add(AD_TYPE_MANUFACTURER)
    if adv_data.tx_power is not None:
        types.add(AD_TYPE_TX_POWER)
    if adv_data.service_uuids:
        # 16-Bit- und 128-Bit-UUIDs anhand des Base-UUID-Suffix unterscheiden
        for u in adv_data.service_uuids:
            us = str(u).lower()
            if us.endswith(BT_BASE_UUID_SUFFIX):
                types.add(AD_TYPE_COMPLETE_16BIT_UUIDS)
            else:
                types.add(AD_TYPE_COMPLETE_128BIT_UUIDS)
    if adv_data.service_data:
        for u in adv_data.service_data.keys():
            us = str(u).lower()
            if us.endswith(BT_BASE_UUID_SUFFIX):
                types.add(AD_TYPE_SERVICE_DATA_16BIT)
            else:
                types.add(AD_TYPE_SERVICE_DATA_128BIT)
    return sorted(types)


def estimate_payload_length(adv_data: AdvertisementData) -> int:
    # Advertisement-Länge aus den geparsten Feldern. Payload-Länge ist ein weiteres Fingerprint-Merkmal.
    total = 0
    if adv_data.local_name:
        total += 2 + len(adv_data.local_name.encode("utf-8"))
    if adv_data.manufacturer_data:
        for _cid, data in adv_data.manufacturer_data.items():
            total += 4 + len(data)
    if adv_data.tx_power is not None:
        total += 3
    if adv_data.service_uuids:
        for u in adv_data.service_uuids:
            us = str(u).lower()
            total += 4 if us.endswith(BT_BASE_UUID_SUFFIX) else 18
    if adv_data.service_data:
        for u, data in adv_data.service_data.items():
            us = str(u).lower()
            header_uuid = 4 if us.endswith(BT_BASE_UUID_SUFFIX) else 18
            total += header_uuid + len(data)
    return total


# SCANNER-ZUSTAND
class ScannerStats:
    def __init__(self):
        self.packet_counter = 0
        self.start_time = time.monotonic()


stats = ScannerStats()
db: BLEDBHandler = None


# CALLBACK
def detection_callback(device: BLEDevice, adv_data: AdvertisementData) -> None:
    # Wird von bleak für jedes empfangene Advertisement aufgerufen.
    # Setzt den Zeitstempel, Adresstyp und Top-2-Bits, extrahiert Hersteller-Daten, Service-UUIDs, AD-Types und Payload-Länge und gibt an den DBHandler.
    try:
        ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        raw_mac = (device.address or "").lower()
        addr_type = detect_mac_address_type(raw_mac)
        top_two_bits = mac_top_two_bits(raw_mac)

        # Hersteller-Daten: primäre Company-ID und vollständiges Dict
        primary_mfr = None
        mfr_dict = None
        if adv_data.manufacturer_data:
            mfr_dict = {
                str(cid): data.hex()
                for cid, data in adv_data.manufacturer_data.items()
            }
            primary_mfr = next(iter(adv_data.manufacturer_data.keys()))

        svc_uuids = sorted(str(u).lower() for u in (adv_data.service_uuids or []))

        svc_data_dict = None
        svc_data_keys = None
        if adv_data.service_data:
            svc_data_dict = {
                str(u).lower(): data.hex()
                for u, data in adv_data.service_data.items()
            }
            svc_data_keys = sorted(svc_data_dict.keys())

        ad_types_list = reconstruct_ad_types(adv_data)
        payload_len = estimate_payload_length(adv_data)

        # Optionale Zusatzfelder aus den BlueZ-Properties (falls vorhanden)
        appearance = None
        platform_data_json = None
        try:
            details = device.details or {}
            props = details.get("props") if isinstance(details, dict) else None
            if isinstance(props, dict):
                if "Appearance" in props:
                    appearance = int(props["Appearance"])
                adv_data_prop = props.get("AdvertisingData")
                if adv_data_prop is not None:
                    try:
                        platform_data_json = {
                            "advertising_data_hex": (
                                adv_data_prop.hex()
                                if hasattr(adv_data_prop, "hex")
                                else str(adv_data_prop)
                            )
                        }
                    except Exception:
                        pass
        except Exception:
            pass

        rssi = adv_data.rssi if adv_data.rssi is not None else getattr(device, "rssi", None)

        # Roh-MAC und Roh-Name werden an db_insert weitergegeben und dort gehasht, wie bei WIFI.
        packet = {
            "_raw_mac":          raw_mac,
            "_raw_local_name":   adv_data.local_name,
            "mac_address_type":  addr_type,
            "is_random_mac":     is_random_address(addr_type),
            "mac_top_two_bits":  top_two_bits,
            "rssi":              rssi,
            "timestamp":         ts,
            "manufacturer_id":   primary_mfr,
            "manufacturer_data": mfr_dict,
            "service_uuids":     svc_uuids if svc_uuids else None,
            "service_data":      svc_data_dict,
            "service_data_keys": svc_data_keys,
            "tx_power":          adv_data.tx_power,
            "appearance":        appearance,
            "ad_types":          ad_types_list if ad_types_list else None,
            "ad_payload_length": payload_len if payload_len > 0 else None,
            "platform_data":     platform_data_json,
        }

        db.insert(packet)
        stats.packet_counter += 1
    except Exception as e:
        print(f"[CALLBACK ERROR] {e}", flush=True)


async def periodic_flush_task(interval: float = 5.0):
    # Schreibt den Batch-Puffer in die DB, damit auch bei niedriger Paketrate regelmässig persistiert wird (schont die SD-Karte durch gebuendelte Schreibzugriffe und nicht alles einzeln).
    while True:
        try:
            await asyncio.sleep(interval)
            db.flush()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[PERIODIC FLUSH ERROR] {e}", flush=True)


# MAIN
async def main():
    global db

    init_db(DB_PATH)
    print(f"[i] BLE-Scanner startet auf {BLE_HCI_DEVICE}", flush=True)

    db = BLEDBHandler(DB_PATH,
                      batch_size=BLE_BATCH_SIZE,
                      flush_interval=BLE_FLUSH_INTERVAL)

    stop_event = asyncio.Event()

    def handle_signal(*_):
        print("\n[SIGNAL] Shutdown angefordert...", flush=True)
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    scanner = BleakScanner(
        detection_callback=detection_callback,
        adapter=BLE_HCI_DEVICE,
    )

    flush_task = asyncio.create_task(periodic_flush_task(5.0))

    try:
        await scanner.start()
        print("[START] Scanner läuft... Strg-C zum Beenden.", flush=True)
        await stop_event.wait()
    finally:
        print("[STOP] Beende Scanner...", flush=True)
        try:
            await scanner.stop()
        except Exception as e:
            print(f"[STOP ERROR] {e}", flush=True)
        flush_task.cancel()
        try:
            await flush_task
        except asyncio.CancelledError:
            pass
        db.close()
        print(f"[i] Pakete empfangen: {stats.packet_counter}, "
              f"DB-Inserts: {db.total_inserted}", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
