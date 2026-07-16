"""
crypto.py
---------
Salt-Management und SHA-256-Hashing für DSGVO-konforme Speicherung.

Verwendet einen einmal erzeugten, persistierten Salt aus einer Datei
außerhalb der DB. Der Salt wird beim ersten Lauf automatisch
generiert (32 zufällige Bytes), bei späteren Läufen geladen.

Verwendung für MAC, SSID und Local_Name
"""

import hashlib
import os
import secrets
import stat
import sys
from pathlib import Path


DEFAULT_SALT_PATH = Path.home() / ".beacon_salt"
SALT_ENV_VAR = "BEACON_SALT_PATH"
SALT_BYTES = 32


class Hasher:
    """
    Hash-Helfer mit geladenem Salt.
    Eine Instanz pro Prozess (rein lesend nach Init).
    """

    def __init__(self, salt: bytes):
        if not isinstance(salt, bytes) or len(salt) < 16:
            raise ValueError("Salt muss bytes mit mindestens 16 Byte sein")
        self._salt = salt

    def hash_mac(self, mac: str) -> str:
        """
        Hasht eine MAC-Adresse. Eingabe wird normalisiert (lowercase und getrimmt).
        Gibt 64 Hex-Zeichen zurück, oder None falls Eingabe None bzw. leer.
        """
        if not mac:
            return None
        normalized = mac.strip().lower()
        h = hashlib.sha256()
        h.update(self._salt)
        h.update(b":mac:")
        h.update(normalized.encode("utf-8"))
        return h.hexdigest()

    def hash_ssid(self, ssid: str) -> str:
        """
        Hasht eine SSID (WiFi). Wildcard-Probes (ssid=None) bleiben None,
        damit man im Code weiterhin sehen kann, dass es ein Wildcard war.
        """
        if ssid is None or ssid == "":
            return None
        h = hashlib.sha256()
        h.update(self._salt)
        h.update(b":ssid:")
        h.update(ssid.encode("utf-8"))
        return h.hexdigest()

    def hash_local_name(self, name: str) -> str:
        """
        Hasht einen BLE local_name.
        Geräte ohne Namen liefern None bzw. "" -> None.
        Domain-Separator ':local_name:' ist eigener Namespace, damit ein
        SSID "iPhone" und ein BLE-Name "iPhone" nicht zum gleichen Hash führen.
        Somit wird aus:
        SHA-256(salt + "iPhone")
        SHA-256(salt + "iPhone")
        dann:
        SHA-256(salt + ":ssid:" + "iPhone")
        SHA-256(salt + ":local_name:" + "iPhone")
        """
        if name is None or name == "":
            return None
        h = hashlib.sha256()
        h.update(self._salt)
        h.update(b":local_name:")
        h.update(name.encode("utf-8"))
        return h.hexdigest()


def _resolve_salt_path() -> Path:
    """Entscheidet wo Salt Path liegt, Env-Var oder Default."""
    custom = os.environ.get(SALT_ENV_VAR)
    if custom:
        return Path(custom).expanduser()
    return DEFAULT_SALT_PATH


def _load_or_create_salt(path: Path) -> bytes:
    """
    Lädt Salt aus dem Path. Erstellt ihn, falls die Datei nicht existiert.
    Permissions werden in beiden Fällen auf 0600 erzwungen.
    """
    if path.exists():
        st_mode = path.stat().st_mode
        if st_mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            print(f"[!] WARNUNG: Salt-Datei {path} ist für Gruppe/Welt lesbar.",
                  file=sys.stderr)
            print(f"    Korrigiere Permissions auf 0600 ...", file=sys.stderr)
            path.chmod(0o600)

        with open(path, "rb") as f:
            salt = f.read()
        if len(salt) < 16:
            raise RuntimeError(
                f"Salt-Datei {path} enthaelt weniger als 16 Byte - "
                f"vermutlich beschaedigt. Manuell pruefen.")
        return salt

    print(f"[i] Salt-Datei nicht gefunden, erzeuge neuen Salt: {path}",
          file=sys.stderr)
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(SALT_BYTES)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(salt)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise

    print(f"[+] Salt mit {SALT_BYTES} Byte erzeugt. Permissions 0600.",
          file=sys.stderr)
    print(f"    WICHTIG: Datei NICHT versehentlich committen oder verschieben.",
          file=sys.stderr)
    return salt


_hasher_singleton: Hasher = None # Damit nur eine Hasher-Instanz im ganzen Prozess gibt


def get_hasher() -> Hasher:
    """
    Liefert die Hasher-Instanz.
    Beim ersten Aufruf wird der Salt geladen oder erzeugt.
    """
    global _hasher_singleton
    if _hasher_singleton is None:
        path = _resolve_salt_path()
        salt = _load_or_create_salt(path)
        _hasher_singleton = Hasher(salt)
    return _hasher_singleton