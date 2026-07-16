#!/usr/bin/env python3
"""
main_wifi.py
------------
Startet wifi_scanner.py und überwacht ihn.
- Falls der Scanner crashed, automatischer Neustart nach RESTART_DELAY_S
- Sauberer Shutdown bei SIGINT/SIGTERM (von systemd-stop)
- Strukturiertes Logging in /var/log/beacon/wifi.log

Aufruf:
    sudo /home/beacon1337/beacon-env/bin/python3 main_wifi.py
"""

import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import time

from config import LOG_DIR, SCRIPTS_DIR


SCANNER_PATH = os.path.join(SCRIPTS_DIR, "wifi_scanner.py")
PYTHON_BIN   = "/home/beacon1337/beacon-env/bin/python3"

RESTART_DELAY_S = 10        # Wartezeit vor einem Neustart
MAX_RESTARTS_PER_HOUR = 30  # Schutz gegen Endlos-Restart-Schleifen


# LOGGING
def setup_logging():
    # Die Datei rotiert bei 10 MB und behält 10 Generationen, damit die SD-Karte im mehrwöchigen Dauerbetrieb nicht volläuft.

    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, "wifi.log")

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=10,
    )
    file_handler.setFormatter(fmt)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)

    # Bestehende Handler entfernen, damit Log-Zeilen nicht doppelt erscheinen
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)


# MAIN
def main():
    setup_logging()
    log = logging.getLogger("main_wifi")
    log.info("=" * 60)
    log.info("main_wifi.py gestartet")
    log.info("=" * 60)

    # Dict statt bool, damit der Signal-Handler den Wert ändern kann
    stop_requested = {"flag": False}

    def handle_signal(signum, _frame):
        log.info(f"Signal {signum} empfangen, leite Shutdown ein.")
        stop_requested["flag"] = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    restart_times = []
    current_proc = None

    try:
        while not stop_requested["flag"]:
            log.info(f"Starte WiFi-Scanner: {SCANNER_PATH}")
            try:
                # -u erzwingt ungepufferte Ausgabe, damit die Scanner-Zeilen
                # sofort im Log erscheinen und nicht erst beim Beenden.
                current_proc = subprocess.Popen(
                    [PYTHON_BIN, "-u", SCANNER_PATH],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    universal_newlines=True,
                )
            except Exception as e:
                log.exception(f"Konnte Scanner nicht starten: {e}")
                time.sleep(RESTART_DELAY_S)
                continue

            # Output des Prozesses zeilenweise in unser Log umleiten.
            # Diese Schleife blockiert, solange der Scanner läuft — sie
            # endet erst, wenn er sich beendet oder stdout schließt.
            try:
                for line in current_proc.stdout:
                    if stop_requested["flag"]:
                        break
                    log.info(f"[scanner] {line.rstrip()}")
            except Exception as e:
                log.exception(f"Fehler beim Lesen vom Scanner-Output: {e}")

            # Beim Shutdown Scanner ordentlich beenden:
            if stop_requested["flag"] and current_proc.poll() is None:
                log.info("Sende SIGTERM an Scanner...")
                current_proc.terminate()
                try:
                    current_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    log.warning("Scanner reagiert nicht, sende SIGKILL.")
                    current_proc.kill()
                    current_proc.wait()

            returncode = current_proc.wait()
            log.info(f"Scanner beendet mit Code {returncode}.")

            if stop_requested["flag"]:
                break

            # Restart-Rate-Limit: nur Restarts der letzten Stunde zählen.
            # Wird das Limit überschritten, liegt ein dauerhaftes Problem vor (z.B. defekter Adapter)
            now = time.monotonic()
            restart_times = [t for t in restart_times if now - t < 3600]
            restart_times.append(now)
            if len(restart_times) > MAX_RESTARTS_PER_HOUR:
                log.error(
                    f"Zu viele Restarts ({len(restart_times)} in 1h). "
                    f"Beende Orchestrator. systemd wird ihn ggf. neu starten."
                )
                break

            log.info(f"Restart in {RESTART_DELAY_S}s "
                     f"(Restarts in letzter Stunde: {len(restart_times)})")
            for _ in range(RESTART_DELAY_S):
                if stop_requested["flag"]:
                    break
                time.sleep(1)
    finally:
        if current_proc is not None and current_proc.poll() is None:
            current_proc.terminate()
            try:
                current_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                current_proc.kill()
        log.info("main_wifi.py beendet.")


if __name__ == "__main__":
    main()