#!/usr/bin/env python3
"""
main_ble.py
-----------
Startet ble_scanner.py als asyncio-Task und überwacht ihn:
- Falls der Scanner crashed, automatischer Neustart nach RESTART_DELAY_S
- Sauberer Shutdown bei SIGINT/SIGTERM (von systemd-stop)
- Strukturiertes Logging in /var/log/beacon/ble.log

Aufruf (selber):
    sudo /home/beacon1337/beacon-env/bin/python3 main_ble.py

Aufruf (via systemd):
    sudo systemctl start beacon-ble
"""

import asyncio
import logging
import logging.handlers
import os
import signal
import sys
import time

from config import LOG_DIR

# Wir importieren ble_scanner als Modul und rufen sein main() auf --> Vorteil: schneller Restart, weniger Overhead, gemeinsames Logging.
import ble_scanner


RESTART_DELAY_S = 10
MAX_RESTARTS_PER_HOUR = 30   # Check: wenn der Scanner ständig crashed

# LOGGING
def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, "ble.log")

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotierende Datei: 10 MB pro File, 10 alte Versionen behalten = 100 MB max
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=10,
    )
    file_handler.setFormatter(fmt)

    # Stdout für interaktiven Aufruf / journalctl
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Entferne ggf. vorherige Handler (bei Re-Import)
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)


# RUNNER
async def run_scanner_with_restart(stop_event: asyncio.Event):
    # Startet ble_scanner.main() in einer Schleife mit Restart-Logik.
    log = logging.getLogger("main_ble")
    restart_times = []

    while not stop_event.is_set():
        log.info("Starte BLE-Scanner...")
        try:
            await ble_scanner.main()
            log.info("BLE-Scanner sauber beendet.")
            return   # bei sauberem Exit nicht neu starten
        except asyncio.CancelledError:
            log.info("Cancellation empfangen.")
            return
        except Exception as e:
            log.exception(f"BLE-Scanner crashed: {e}")

        if stop_event.is_set():
            return

        # Restart-Rate-Limit prüfen
        now = time.monotonic()
        restart_times = [t for t in restart_times if now - t < 3600]
        restart_times.append(now)
        if len(restart_times) > MAX_RESTARTS_PER_HOUR:
            log.error(
                f"Zu viele Restarts ({len(restart_times)} in 1h). "
                f"Beende Orchestrator. systemd wird ihn ggf. neu starten."
            )
            return

        log.info(f"Restart in {RESTART_DELAY_S}s "
                 f"(Restarts in letzter Stunde: {len(restart_times)})")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=RESTART_DELAY_S)
            return   # stop_event wurde gesetzt während wir warteten
        except asyncio.TimeoutError:
            pass     # Restart


# MAIN
async def main_async():
    setup_logging()
    log = logging.getLogger("main_ble")
    log.info("=" * 60)
    log.info("main_ble.py gestartet")
    log.info("=" * 60)

    stop_event = asyncio.Event()

    def handle_signal(signum, _frame=None):
        log.info(f"Signal {signum} empfangen, leite Shutdown ein.")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: handle_signal(s))

    try:
        await run_scanner_with_restart(stop_event)
    finally:
        log.info("main_ble.py beendet.")


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()