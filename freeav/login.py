# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Yassine

"""Connexion locale a la fenetre de FreeAV : pseudo, mot de passe et code a usage unique (OTP).

Tout reste sur ce PC : pas de compte en ligne, rien n'est envoye, aucune connexion reseau.
Les donnees sont dans une base SQLite, ~/.freeav/freeav.db, que l'on peut ouvrir avec DBeaver
(ou tout autre outil SQLite). Rien n'y est lisible en clair :
  - table comptes : le pseudo, l'empreinte scrypt du mot de passe (jamais le mot de passe
    lui-meme), la cle des codes OTP chiffree par Windows (DPAPI : illisible ailleurs que dans
    cette session Windows), le dernier pas OTP accepte (un code ne sert qu'une fois), les essais
    rates qui imposent une attente croissante, la date de creation et de derniere connexion ;
  - table codes_secours : l'empreinte scrypt de chaque code de secours et la date ou il a servi ;
  - table historique : les evenements de la connexion (reussites, echecs, changements), sans
    aucun mot de passe ni code.

Les codes OTP suivent la RFC 6238 : 6 chiffres toutes les 30 secondes, comme Google ou
Microsoft Authenticator. « Mot de passe oublie » : un code de l'application d'authentification,
ou un code de secours, permet de choisir un nouveau mot de passe.

Limite : c'est un verrou pour la fenetre de FreeAV (contre quelqu'un qui utiliserait votre
session Windows), pas un coffre-fort. La protection en arriere-plan continue sans connexion, et
quelqu'un qui peut modifier vos fichiers peut retirer ce verrou en supprimant freeav.db.
"""

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time
import unicodedata
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from .paths import APP_DIR, ensure_private_dir

LOGIN_DB = APP_DIR / "freeav.db"
HISTORY_KEEP = 200  # evenements gardes dans la table historique
ISSUER = "FreeAV"
NICKNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD, MAX_PASSWORD = 12, 128
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}          # mot de passe (environ 0,1 s par essai)
SCRYPT_RECOVERY = {"n": 2 ** 14, "r": 8, "p": 1}  # codes de secours (8 a verifier au pire)
RECOVERY_CODES = 8
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sans 0/O ni 1/I, faciles a recopier
OTP_STEP, OTP_DIGITS = 30, 6
MAX_FAILURES = 5      # ensuite, attente croissante avant chaque nouvel essai
BASE_DELAY = 30       # secondes, doublee a chaque nouvel echec...
MAX_DELAY = 15 * 60   # ... sans depasser 15 minutes
GENERIC_ERROR = "Pseudo ou mot de passe incorrect."
CODE_ERROR = "Code incorrect ou expiré."
COMMON_PASSWORDS = {
    "motdepasse123", "motdepasse1234", "123456789012", "1234567890123", "azertyuiop12",
    "azertyuiop123", "qwertyuiop12", "qwertyuiop123", "password1234", "password12345",
    "administrateur", "freeav123456", "freeavfreeav", "bonjour123456", "soleil123456",
}


class LoginError(Exception):
    """Refus a montrer tel quel a l'utilisateur."""


class CodeRequired(LoginError):
    """Pseudo et mot de passe corrects : il faut maintenant le code OTP."""

    def __init__(self):
        super().__init__("Entrez le code de votre application d'authentification.")


class StorageError(LoginError):
    """Base illisible ou occupee (par exemple par DBeaver en pleine modification)."""


class Locked(LoginError):
    def __init__(self, wait: int):
        self.wait = wait
        super().__init__(f"Trop d'essais. Réessayez dans {_duration(wait)}.")


def _duration(seconds: int) -> str:
    if seconds < 90:
        return f"{seconds} secondes"
    return f"{(seconds + 59) // 60} minutes"


@dataclass
class Account:
    nickname: str
    password: dict
    otp_secret: str = ""
    otp_last: int = -1  # dernier pas de 30 secondes accepte : un code ne sert qu'une fois
    recovery: list = field(default_factory=list)  # empreintes des codes de secours inutilises
    failures: int = 0
    locked_until: float = 0.0
    created: str = ""
    last_login: str = ""
    # cle OTP telle qu'en base (chiffree) et en clair au chargement : reecrite seulement si
    # elle change, pour ne pas perdre une cle que cette session Windows ne sait pas dechiffrer
    stored_otp: str = field(default="", repr=False, compare=False)
    loaded_otp: str = field(default="", repr=False, compare=False)

    @property
    def otp(self) -> bool:
        return bool(self.otp_secret)


@dataclass
class Unlock:
    account: Account
    recovery_used: bool = False

    @property
    def recovery_left(self) -> int:
        return len(self.account.recovery)


# -- mots de passe ----------------------------------------------------------------------

def _normalize(text: str) -> bytes:
    return unicodedata.normalize("NFKC", text).encode("utf-8")


def _scrypt(secret: bytes, salt: bytes, params: dict) -> bytes:
    return hashlib.scrypt(secret, salt=salt, maxmem=128 * 1024 * 1024, dklen=32, **params)


def _hash(secret: bytes, params: dict, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    return {"alg": "scrypt", **params, "salt": salt.hex(), "hash": _scrypt(secret, salt, params).hex()}


def _check(secret: bytes, stored: dict) -> bool:
    try:
        params = {k: int(stored[k]) for k in ("n", "r", "p")}
        expected = bytes.fromhex(stored["hash"])
        salt = bytes.fromhex(stored["salt"])
        if stored.get("alg") != "scrypt" or not 2 ** 10 <= params["n"] <= 2 ** 20:
            return False  # parametres trafiques dans la base
        candidate = _scrypt(secret, salt, params)
    except (KeyError, ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(candidate, expected)


def hash_password(password: str, salt: bytes | None = None, params: dict | None = None) -> dict:
    return _hash(_normalize(password), dict(params or SCRYPT), salt)


def check_password(password: str, stored: dict) -> bool:
    return _check(_normalize(password), stored)


def pack_hash(stored: dict) -> str:
    """Empreinte en une ligne pour la base : scrypt$n=32768,r=8,p=1$sel$empreinte."""
    try:
        return "{alg}$n={n},r={r},p={p}${salt}${hash}".format(**stored)
    except KeyError:
        return ""  # empreinte deja illisible : reste illisible


def unpack_hash(text: str) -> dict:
    try:
        alg, params, salt, digest = text.split("$")
        values = dict(item.split("=", 1) for item in params.split(","))
        return {"alg": alg, **{k: int(values[k]) for k in ("n", "r", "p")}, "salt": salt,
                "hash": digest}
    except (ValueError, KeyError, AttributeError):
        return {}  # illisible : ne correspond a rien


def password_problem(password: str, nickname: str = "") -> str | None:
    """Pourquoi ce mot de passe est refuse, ou None."""
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        return f"Le mot de passe doit faire de {MIN_PASSWORD} à {MAX_PASSWORD} caractères."
    lowered = password.strip().lower()
    if nickname and lowered == nickname.strip().lower():
        return "Le mot de passe ne doit pas être votre pseudo."
    if len(set(password)) <= 2 or lowered in COMMON_PASSWORDS:
        return "Ce mot de passe est trop facile à deviner."
    return None


def strength(password: str, nickname: str = "") -> int:
    """Solidite estimee, de 0 (refuse) a 4 (excellent), pour la jauge de l'interface."""
    if password_problem(password, nickname):
        return 0
    pool = sum(size for test, size in (
        (str.islower, 26), (str.isupper, 26), (str.isdigit, 10),
        (lambda c: not c.isalnum(), 33)) if any(test(c) for c in password))
    bits = len(password) * max(pool, 10).bit_length()
    if len(set(password)) < len(password) / 2:
        bits *= 0.6  # beaucoup de caracteres repetes
    if nickname and nickname.lower() in password.lower():
        bits *= 0.6
    return 1 if bits < 60 else 2 if bits < 75 else 3 if bits < 95 else 4


# -- codes OTP (TOTP, RFC 6238) ---------------------------------------------------------

def new_otp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp(secret: str, at: float | None = None, digits: int = OTP_DIGITS) -> str:
    counter = int((time.time() if at is None else at) // OTP_STEP)
    return _hotp(secret, counter, digits)


def _hotp(secret: str, counter: int, digits: int = OTP_DIGITS) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))  # binascii.Error si cle fausse
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def _clean_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code or "").upper()


def totp_counter(secret: str, code: str, at: float | None = None) -> int | None:
    """Pas de temps du code s'il est valide (une periode de tolerance de chaque cote, pour une
    horloge de telephone un peu decalee), sinon None."""
    code = _clean_code(code)
    if not re.fullmatch(r"\d{%d}" % OTP_DIGITS, code):
        return None
    now = int((time.time() if at is None else at) // OTP_STEP)
    found = None
    try:
        for counter in (now - 1, now, now + 1):
            if hmac.compare_digest(_hotp(secret, counter), code):
                found = counter
    except (binascii.Error, ValueError):  # cle illisible (base copiee d'un autre PC...)
        return None
    return found


def check_totp(secret: str, code: str, at: float | None = None) -> bool:
    return totp_counter(secret, code, at) is not None


def otp_uri(secret: str, nickname: str) -> str:
    """Adresse otpauth:// a mettre dans le QR code (ou a saisir a la main). SHA-1, 6 chiffres
    et 30 secondes sont les valeurs par defaut des applications : les omettre donne un QR code
    plus petit, donc plus facile a scanner."""
    label = quote(f"{ISSUER}:{nickname}", safe=":")
    return f"otpauth://totp/{label}?secret={secret}&issuer={ISSUER}"


def format_secret(secret: str) -> str:
    """Cle lisible a recopier a la main : groupes de 4 caracteres."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# -- codes de secours -------------------------------------------------------------------

def new_recovery_codes() -> list[str]:
    return ["-".join("".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(4))
                     for _ in range(2)) for _ in range(RECOVERY_CODES)]


def _hash_recovery(code: str) -> dict:
    return _hash(_clean_code(code).encode("ascii"), dict(SCRYPT_RECOVERY))


def _find_recovery(account: Account, code: str) -> dict | None:
    clean = _clean_code(code)
    if not re.fullmatch(r"[A-Z0-9]{8}", clean):
        return None
    found = None
    for entry in account.recovery:  # toutes les empreintes sont calculees : meme duree
        if _check(clean.encode("ascii"), entry):
            found = entry
    return found


# -- protection de la cle OTP -------------------------------------------------------------

# La cle OTP doit pouvoir etre relue pour verifier les codes : elle ne peut pas etre hachee.
# Sous Windows, elle est chiffree par DPAPI (CryptProtectData), liee a la session Windows :
# illisible dans DBeaver, et inutilisable si la base est copiee sur un autre compte ou un autre
# PC. Ailleurs (tests, developpement), elle est gardee telle quelle, prefixee « clair: ».
DPAPI_ENTROPY = b"FreeAV - cle OTP de la connexion"


def _dpapi(data: bytes, encrypt: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(raw: bytes):
        buf = ctypes.create_string_buffer(raw, len(raw))
        return Blob(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    func = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData
    func.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob), ctypes.c_void_p,
                     ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    func.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    data_in, _keep = blob(data)
    entropy, _keep2 = blob(DPAPI_ENTROPY)
    out = Blob()
    if not func(ctypes.byref(data_in), None, ctypes.byref(entropy), None, None,
                0x1, ctypes.byref(out)):  # CRYPTPROTECT_UI_FORBIDDEN
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def protect_secret(secret: str) -> str:
    if not secret:
        return ""
    if os.name == "nt":
        return "dpapi:" + base64.b64encode(_dpapi(secret.encode("ascii"), True)).decode("ascii")
    return "clair:" + secret


def unprotect_secret(stored: str) -> str:
    """Cle OTP en clair ; leve ValueError ou OSError si cette session ne peut pas la lire."""
    scheme, _, value = stored.partition(":")
    if not stored:
        return ""
    if scheme == "dpapi" and os.name == "nt":
        return _dpapi(base64.b64decode(value), False).decode("ascii")
    if scheme == "clair":
        return value
    raise ValueError("cle OTP illisible ici")


# -- base SQLite ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS comptes (
    id INTEGER PRIMARY KEY CHECK (id = 1),      -- un seul compte par session Windows
    pseudo TEXT NOT NULL,
    mot_de_passe TEXT NOT NULL,                 -- empreinte scrypt, jamais le mot de passe
    otp_cle TEXT NOT NULL DEFAULT '',           -- chiffree par Windows (DPAPI), vide sans OTP
    otp_dernier_pas INTEGER NOT NULL DEFAULT -1,
    essais_rates INTEGER NOT NULL DEFAULT 0,
    bloque_jusqu_a REAL NOT NULL DEFAULT 0,     -- heure Unix de fin d'attente apres des echecs
    cree_le TEXT NOT NULL,
    derniere_connexion TEXT
);
CREATE TABLE IF NOT EXISTS codes_secours (
    id INTEGER PRIMARY KEY,
    compte_id INTEGER NOT NULL REFERENCES comptes (id) ON DELETE CASCADE,
    empreinte TEXT NOT NULL,                    -- empreinte scrypt, jamais le code
    utilise_le TEXT                             -- vide tant que le code n'a pas servi
);
CREATE TABLE IF NOT EXISTS historique (
    id INTEGER PRIMARY KEY,
    date TEXT NOT NULL,
    evenement TEXT NOT NULL
);
PRAGMA user_version = 1;
"""


def _path(path) -> Path:
    return Path(path or LOGIN_DB)


def _stamp(now: float | None = None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))


def _connect(path, create: bool) -> sqlite3.Connection | None:
    """Connexion a la base (None si elle n'existe pas et qu'on ne fait que lire)."""
    path = _path(path)
    if not create and not path.is_file():
        return None
    if create:
        ensure_private_dir(path.parent)
    try:
        conn = sqlite3.connect(path, timeout=5)
        if os.name == "posix":
            path.chmod(0o600)
        conn.execute("PRAGMA foreign_keys = ON")
        if create:
            conn.executescript(SCHEMA)
    except sqlite3.Error as exc:
        raise _storage_error(path, exc) from exc
    return conn


def _storage_error(path: Path, exc: Exception) -> StorageError:
    return StorageError(f"Base de la connexion illisible ou occupée ({exc}). Si DBeaver "
                        f"l'utilise, fermez-le puis réessayez. Pour retirer la connexion, "
                        f"supprimez {path}.")


def load(path: Path | None = None) -> Account | None:
    """Le compte, ou None si la connexion n'est pas activee. Leve StorageError si la base
    existe mais ne peut pas etre lue."""
    conn = _connect(path, create=False)
    if conn is None:
        return None
    with closing(conn):
        try:
            row = conn.execute(
                "SELECT pseudo, mot_de_passe, otp_cle, otp_dernier_pas, essais_rates, "
                "bloque_jusqu_a, cree_le, derniere_connexion FROM comptes WHERE id = 1").fetchone()
            codes = conn.execute("SELECT id, empreinte FROM codes_secours "
                                 "WHERE utilise_le IS NULL ORDER BY id").fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):
                return None
            raise _storage_error(_path(path), exc) from exc
        except sqlite3.Error as exc:
            raise _storage_error(_path(path), exc) from exc
    if row is None:
        return None
    nickname, password, stored_otp, otp_last, failures, locked_until, created, last = row
    try:
        otp_secret = unprotect_secret(stored_otp or "")
    except (ValueError, OSError, binascii.Error, UnicodeDecodeError):
        otp_secret = "?"  # OTP active mais illisible ici : seuls les codes de secours marchent
    return Account(nickname=str(nickname), password=unpack_hash(str(password)),
                   otp_secret=otp_secret, otp_last=int(otp_last), failures=int(failures),
                   recovery=[{**unpack_hash(str(h)), "id": i} for i, h in codes],
                   locked_until=float(locked_until or 0), created=str(created or ""),
                   last_login=str(last or ""), stored_otp=stored_otp or "",
                   loaded_otp=otp_secret)


def enabled(path: Path | None = None) -> bool:
    """La connexion est-elle activee ? Une base illisible compte comme activee : l'ecran de
    connexion s'affiche alors et explique quoi faire, plutot que d'ouvrir FreeAV sans rien."""
    try:
        return load(path) is not None
    except StorageError:
        return True


def _log(conn: sqlite3.Connection, event: str, now: float | None = None) -> None:
    conn.execute("INSERT INTO historique (date, evenement) VALUES (?, ?)", (_stamp(now), event))
    conn.execute("DELETE FROM historique WHERE id <= (SELECT MAX(id) FROM historique) - ?",
                 (HISTORY_KEEP,))


def save(account: Account, path: Path | None = None, event: str | None = None,
         replace_codes: bool = False, now: float | None = None, new: bool = False) -> None:
    """Enregistre le compte (new : remplace tout compte precedent). Les codes de secours
    absents de account.recovery sont notes comme utilises, ou effaces si replace_codes (de
    nouveaux codes remplacent les anciens)."""
    path = _path(path)
    if account.otp_secret == account.loaded_otp and account.stored_otp:
        stored_otp = account.stored_otp
    else:
        stored_otp = protect_secret(account.otp_secret)
    conn = _connect(path, create=True)
    try:
        with closing(conn), conn:  # une seule transaction : tout ou rien
            if new:
                conn.execute("DELETE FROM comptes")  # et ses codes de secours (cascade)
            conn.execute(
                "INSERT INTO comptes (id, pseudo, mot_de_passe, otp_cle, otp_dernier_pas, "
                "essais_rates, bloque_jusqu_a, cree_le, derniere_connexion) "
                "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET "
                "pseudo = excluded.pseudo, mot_de_passe = excluded.mot_de_passe, "
                "otp_cle = excluded.otp_cle, otp_dernier_pas = excluded.otp_dernier_pas, "
                "essais_rates = excluded.essais_rates, bloque_jusqu_a = excluded.bloque_jusqu_a, "
                "derniere_connexion = excluded.derniere_connexion",
                (account.nickname, pack_hash(account.password), stored_otp, account.otp_last,
                 account.failures, account.locked_until, account.created or _stamp(now),
                 account.last_login or None))
            if replace_codes:
                conn.execute("DELETE FROM codes_secours")
            else:
                kept = {entry.get("id") for entry in account.recovery}
                for (code_id,) in conn.execute(
                        "SELECT id FROM codes_secours WHERE utilise_le IS NULL").fetchall():
                    if code_id not in kept:
                        conn.execute("UPDATE codes_secours SET utilise_le = ? WHERE id = ?",
                                     (_stamp(now), code_id))
            for entry in account.recovery:
                if "id" not in entry:
                    stored = {k: v for k, v in entry.items() if k != "id"}
                    cur = conn.execute("INSERT INTO codes_secours (compte_id, empreinte) "
                                       "VALUES (1, ?)", (pack_hash(stored),))
                    entry["id"] = cur.lastrowid
            if event:
                _log(conn, event, now)
    except sqlite3.Error as exc:
        raise _storage_error(path, exc) from exc
    account.stored_otp, account.loaded_otp = stored_otp, account.otp_secret


def disable(path: Path | None = None) -> None:
    """Retire la connexion : FreeAV s'ouvre de nouveau sans mot de passe. Le compte et ses
    codes sont effaces ; l'historique reste."""
    path = _path(path)
    conn = _connect(path, create=False)
    if conn is None:
        return
    try:
        with closing(conn), conn:
            conn.executescript(SCHEMA)
            conn.execute("DELETE FROM codes_secours")
            conn.execute("DELETE FROM comptes")
            _log(conn, "Connexion retirée")
    except sqlite3.Error as exc:
        raise _storage_error(path, exc) from exc


def history(path: Path | None = None, limit: int = 50) -> list[tuple[str, str]]:
    """Derniers evenements (date, evenement), du plus recent au plus ancien."""
    conn = _connect(path, create=False)
    if conn is None:
        return []
    with closing(conn):
        try:
            return conn.execute("SELECT date, evenement FROM historique ORDER BY id DESC "
                                "LIMIT ?", (limit,)).fetchall()
        except sqlite3.Error:
            return []


def nickname_problem(nickname: str) -> str | None:
    if not NICKNAME_RE.match(nickname.strip()):
        return "Le pseudo doit faire 3 à 32 caractères : lettres, chiffres, point, tiret ou _."
    return None


def create(nickname: str, password: str, otp_secret: str = "", otp_code: str = "",
           path: Path | None = None, now: float | None = None) -> list[str]:
    """Active la connexion. Si une cle OTP est donnee, le code de l'application doit
    correspondre. Retourne les codes de secours, a montrer une seule fois."""
    nickname = nickname.strip()
    if problem := nickname_problem(nickname) or password_problem(password, nickname):
        raise LoginError(problem)
    account = Account(nickname, hash_password(password), created=_stamp(now))
    if otp_secret:
        counter = totp_counter(otp_secret, otp_code, now)
        if counter is None:
            raise LoginError("Code incorrect. Vérifiez que l'heure du téléphone est juste.")
        account.otp_secret, account.otp_last = otp_secret, counter
    codes = new_recovery_codes()
    account.recovery = [_hash_recovery(c) for c in codes]
    save(account, path, "Connexion activée" + (" avec code OTP" if otp_secret else ""),
         now=now, new=True)
    return codes


# -- connexion --------------------------------------------------------------------------

def wait_time(account: Account, now: float | None = None) -> int:
    """Secondes a attendre avant un nouvel essai (0 si on peut essayer)."""
    now = time.time() if now is None else now
    return max(0, int(account.locked_until - now + 0.999))


def _guard(path, now: float) -> Account:
    account = load(path)
    if account is None:
        raise LoginError("La connexion n'est pas activée.")
    if wait := wait_time(account, now):
        raise Locked(wait)
    return account


def _failed(account: Account, path, now: float, message: str, event: str) -> None:
    account.failures += 1
    if account.failures >= MAX_FAILURES:
        delay = min(BASE_DELAY * 2 ** (account.failures - MAX_FAILURES), MAX_DELAY)
        account.locked_until = now + delay
        event += f" (attente imposée : {_duration(delay)})"
    save(account, path, event, now=now)
    if account.locked_until > now:
        raise Locked(wait_time(account, now))
    raise LoginError(message)


def _succeeded(account: Account, path, now: float, event: str, recovery: dict | None = None,
               counter: int | None = None) -> Unlock:
    account.failures, account.locked_until = 0, 0.0
    if counter is not None:
        account.otp_last = counter
    if recovery is not None:
        account.recovery.remove(recovery)
        event += " avec un code de secours"
    elif counter is not None:
        event += " avec un code OTP"
    account.last_login = _stamp(now)
    save(account, path, event, now=now)
    return Unlock(account, recovery_used=recovery is not None)


def _second_factor(account: Account, code: str, now: float):
    """(pas OTP, code de secours) correspondant au code, ou (None, None)."""
    if account.otp:
        counter = totp_counter(account.otp_secret, code, now)
        if counter is not None and counter > account.otp_last:
            return counter, None
    return None, _find_recovery(account, code)


def verify(nickname: str, password: str, code: str | None = None,
           path: Path | None = None, now: float | None = None) -> Unlock:
    """Verifie pseudo et mot de passe, puis le code OTP (ou un code de secours) si l'OTP est
    active. Leve CodeRequired s'il manque le code, LoginError sinon."""
    now = time.time() if now is None else now
    account = _guard(path, now)
    ok_password = check_password(password, account.password)  # calcule meme si le pseudo est faux
    ok_nickname = hmac.compare_digest(nickname.strip().lower().encode(),
                                      account.nickname.lower().encode())
    if not (ok_nickname and ok_password):
        _failed(account, path, now, GENERIC_ERROR,
                "Échec de connexion : pseudo ou mot de passe incorrect")
    if not account.otp:
        return _succeeded(account, path, now, "Connexion réussie")
    if not code:
        raise CodeRequired()
    counter, recovery = _second_factor(account, code, now)
    if counter is None and recovery is None:
        _failed(account, path, now, CODE_ERROR, "Échec de connexion : code incorrect")
    return _succeeded(account, path, now, "Connexion réussie", recovery, counter)


def reset_password(nickname: str, code: str, new_password: str,
                   path: Path | None = None, now: float | None = None) -> Unlock:
    """Mot de passe oublie : un code OTP ou un code de secours (qui est alors consomme)."""
    now = time.time() if now is None else now
    account = _guard(path, now)
    if problem := password_problem(new_password, nickname or account.nickname):
        raise LoginError(problem)
    ok_nickname = hmac.compare_digest(nickname.strip().lower().encode(),
                                      account.nickname.lower().encode())
    counter, recovery = _second_factor(account, code, now)
    if not ok_nickname or (counter is None and recovery is None):
        _failed(account, path, now, "Pseudo ou code incorrect.",
                "Échec de « mot de passe oublié » : pseudo ou code incorrect")
    account.password = hash_password(new_password)
    return _succeeded(account, path, now, "Mot de passe oublié : nouveau mot de passe choisi",
                      recovery, counter)


# -- reglages (apres une nouvelle verification du mot de passe dans l'interface) ----------

def _require(path) -> Account:
    account = load(path)
    if account is None:
        raise LoginError("La connexion n'est pas activée.")
    return account


def change_password(new_password: str, path: Path | None = None) -> None:
    account = _require(path)
    if problem := password_problem(new_password, account.nickname):
        raise LoginError(problem)
    account.password = hash_password(new_password)
    save(account, path, "Mot de passe changé")


def enable_otp(secret: str, code: str, path: Path | None = None,
               now: float | None = None) -> None:
    account = _require(path)
    counter = totp_counter(secret, code, now)
    if counter is None:
        raise LoginError("Code incorrect. Vérifiez que l'heure du téléphone est juste.")
    account.otp_secret, account.otp_last = secret, counter
    save(account, path, "Code OTP activé", now=now)


def disable_otp(path: Path | None = None) -> None:
    account = _require(path)
    account.otp_secret, account.otp_last = "", -1
    save(account, path, "Code OTP désactivé")


def renew_recovery_codes(path: Path | None = None) -> list[str]:
    """Nouveaux codes de secours ; les anciens ne marchent plus."""
    account = _require(path)
    codes = new_recovery_codes()
    account.recovery = [_hash_recovery(c) for c in codes]
    save(account, path, "Nouveaux codes de secours (les anciens ne marchent plus)",
         replace_codes=True)
    return codes
