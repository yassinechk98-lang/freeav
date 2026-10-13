# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Yassine

"""Connexion locale a FreeAV : pseudo, mot de passe, code OTP, codes de secours."""

import os
import sqlite3

import pytest

from freeav import login, qrcode
from freeav.login import CodeRequired, Locked, LoginError

PASSWORD = "cheval-batterie-agrafe"
NEW_PASSWORD = "nouveau-mot-de-passe-1"


@pytest.fixture
def path(tmp_path, monkeypatch):
    # Empreintes rapides pour les tests (les vraies valeurs sont verifiees a part)
    monkeypatch.setattr(login, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1})
    monkeypatch.setattr(login, "SCRYPT_RECOVERY", {"n": 2 ** 10, "r": 8, "p": 1})
    return tmp_path / "freeav.db"


def other_code(secret, at):
    """Un code a 6 chiffres qui n'est valide a aucun pas autour de `at`."""
    valid = {login.totp(secret, at + d * 30) for d in (-1, 0, 1)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


def test_totp_matches_rfc6238_vectors():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890" (RFC 6238, SHA-1)
    assert login.totp(secret, at=59, digits=8) == "94287082"
    assert login.totp(secret, at=1111111109, digits=8) == "07081804"
    assert login.totp(secret, at=2000000000, digits=8) == "69279037"
    code = login.totp(secret, at=1000)
    assert login.check_totp(secret, code, at=1000) and login.check_totp(secret, code, at=1025)
    assert login.check_totp(secret, code[:3] + " " + code[3:], at=1000)  # espaces toleres
    assert not login.check_totp(secret, code, at=1100)
    assert not login.check_totp(secret, "abc", at=1000)


def test_password_is_never_stored_in_clear(path):
    codes = login.create("Yassine", PASSWORD, path=path)
    data = path.read_bytes()
    assert PASSWORD.encode() not in data and b"scrypt$n=" in data
    assert not any(c.encode() in data or c.replace("-", "").encode() in data for c in codes)


def rows(path, query):
    with sqlite3.connect(path) as conn:
        return conn.execute(query).fetchall()


def test_database_can_be_read_with_dbeaver(path):
    """La base est un fichier SQLite ordinaire : tables lisibles, rien de secret en clair."""
    secret = login.new_otp_secret()
    codes = login.create("Yassine", PASSWORD, secret, login.totp(secret, 5000), path=path,
                         now=5000)
    login.verify("Yassine", PASSWORD, codes[2], path=path)
    with pytest.raises(LoginError):
        login.verify("Yassine", "pas-le-bon-mot-de-passe", path=path)
    tables = {name for (name,) in rows(path, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert tables == {"comptes", "codes_secours", "historique"}
    [(pseudo, password, otp_key, failures, last_login)] = rows(
        path, "SELECT pseudo, mot_de_passe, otp_cle, essais_rates, derniere_connexion FROM comptes")
    assert pseudo == "Yassine" and password.startswith("scrypt$n=")
    assert failures == 1 and last_login
    assert otp_key.startswith("dpapi:" if os.name == "nt" else "clair:")
    used = rows(path, "SELECT utilise_le FROM codes_secours WHERE utilise_le IS NOT NULL")
    assert len(rows(path, "SELECT id FROM codes_secours")) == login.RECOVERY_CODES
    assert len(used) == 1 and all(e.startswith("scrypt$") for (e,) in rows(
        path, "SELECT empreinte FROM codes_secours"))
    events = [e for _, e in login.history(path)]
    assert events == ["Échec de connexion : pseudo ou mot de passe incorrect",
                      "Connexion réussie avec un code de secours",
                      "Connexion activée avec code OTP"]
    login.disable(path)
    assert not login.enabled(path) and rows(path, "SELECT * FROM codes_secours") == []
    assert login.history(path)[0][1] == "Connexion retirée"


@pytest.mark.skipif(os.name != "nt", reason="chiffrement DPAPI de Windows")
def test_otp_key_is_encrypted_by_windows(path):
    secret = login.new_otp_secret()
    login.create("Yassine", PASSWORD, secret, login.totp(secret, 5000), path=path, now=5000)
    assert secret.encode() not in path.read_bytes()
    assert login.load(path).otp_secret == secret
    assert login.unprotect_secret(login.protect_secret(secret)) == secret


def test_otp_key_unreadable_here_leaves_the_recovery_codes(path):
    """Base copiee depuis une autre session Windows : la cle OTP ne se dechiffre pas, mais un
    code de secours permet toujours d'entrer."""
    secret = login.new_otp_secret()
    codes = login.create("Yassine", PASSWORD, secret, login.totp(secret, 5000), path=path,
                         now=5000)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE comptes SET otp_cle = 'dpapi:AAAA' WHERE id = 1")
    with pytest.raises(LoginError, match="Code incorrect"):
        login.verify("Yassine", PASSWORD, login.totp(secret), path=path)
    assert login.verify("Yassine", PASSWORD, codes[0], path=path).recovery_used
    assert rows(path, "SELECT otp_cle FROM comptes") == [("dpapi:AAAA",)]  # rien d'ecrase


def test_real_hash_parameters_are_strong():
    assert login.SCRYPT == {"n": 2 ** 17, "r": 8, "p": 1}  # minimum recommande par l'OWASP
    assert login.SCRYPT_RECOVERY["n"] >= 2 ** 14
    stored = login.hash_password(PASSWORD)
    assert login.check_password(PASSWORD, stored) and not login.check_password("autre", stored)
    assert not login.check_password(PASSWORD, {**stored, "n": 2 ** 30})  # fichier trafique


def test_old_weaker_hash_is_upgraded_at_login(path):
    weak = {"n": 2 ** 10, "r": 4, "p": 1}  # comme une base creee par une version plus ancienne
    account = login.Account("Yassine", login.hash_password(PASSWORD, params=weak), created="x")
    login.save(account, path, new=True)
    login.verify("Yassine", PASSWORD, path=path)
    stored = login.load(path).password
    assert {k: stored[k] for k in "nrp"} == login.SCRYPT
    assert login.check_password(PASSWORD, stored)
    login.verify("Yassine", PASSWORD, path=path)  # toujours le meme mot de passe


def test_login_with_nickname_and_password(path):
    login.create("Yassine", PASSWORD, path=path)
    assert login.verify("yassine ", PASSWORD, path=path).account.nickname == "Yassine"
    with pytest.raises(LoginError, match="incorrect"):
        login.verify("Yassine", "mauvais-mot-de-passe", path=path)
    with pytest.raises(LoginError, match="incorrect") as unknown:  # meme message
        login.verify("autre", PASSWORD, path=path)
    assert str(unknown.value) == login.GENERIC_ERROR


def test_weak_password_or_bad_nickname_refused(path):
    with pytest.raises(LoginError, match="12"):
        login.create("Yassine", "court", path=path)
    with pytest.raises(LoginError, match="pseudo"):
        login.create("Yassine12345", "Yassine12345", path=path)
    with pytest.raises(LoginError, match="deviner"):
        login.create("Yassine", "aaaaaaaaaaaaaa", path=path)
    with pytest.raises(LoginError, match="pseudo"):
        login.create("a b", PASSWORD, path=path)
    assert not login.enabled(path)


def test_strength_meter():
    assert login.strength("court") == 0
    assert login.strength("abcdefghijkl") < login.strength("Cheval-Batterie-Agrafe-7")
    assert login.strength("Cheval-Batterie-Agrafe-7") == 4


def test_repeated_failures_lock_for_a_growing_while(path):
    login.create("Yassine", PASSWORD, path=path)
    for _ in range(login.MAX_FAILURES - 1):
        with pytest.raises(LoginError, match="incorrect"):
            login.verify("Yassine", "faux-faux-faux", path=path, now=1000)
    with pytest.raises(Locked) as locked:
        login.verify("Yassine", "faux-faux-faux", path=path, now=1000)
    assert locked.value.wait == login.BASE_DELAY
    with pytest.raises(Locked):  # meme le bon mot de passe attend
        login.verify("Yassine", PASSWORD, path=path, now=1001)
    with pytest.raises(Locked) as again:
        login.verify("Yassine", "faux-faux-faux", path=path, now=1000 + login.BASE_DELAY + 1)
    assert again.value.wait == 2 * login.BASE_DELAY
    later = 1000 + 10 * login.BASE_DELAY
    login.verify("Yassine", PASSWORD, path=path, now=later)
    assert login.load(path).failures == 0


def test_lock_never_exceeds_the_maximum(path):
    login.create("Yassine", PASSWORD, path=path)
    account = login.load(path)
    account.failures = 40
    login.save(account, path)
    with pytest.raises(Locked) as locked:
        login.verify("Yassine", "faux-faux-faux", path=path, now=1000)
    assert locked.value.wait == login.MAX_DELAY and "minutes" in str(locked.value)


def test_otp_second_step_and_single_use(path):
    secret = login.new_otp_secret()
    with pytest.raises(LoginError, match="Code incorrect"):
        login.create("Yassine", PASSWORD, secret, other_code(secret, 5000), path=path, now=5000)
    login.create("Yassine", PASSWORD, secret, login.totp(secret, 5000), path=path, now=5000)
    assert login.load(path).otp
    with pytest.raises(CodeRequired):
        login.verify("Yassine", PASSWORD, path=path, now=5100)
    with pytest.raises(LoginError, match="incorrect"):  # mauvais mot de passe : pas d'etape 2
        login.verify("Yassine", "faux-faux-faux", login.totp(secret, 5100), path=path, now=5100)
    with pytest.raises(LoginError, match="Code incorrect"):
        login.verify("Yassine", PASSWORD, other_code(secret, 5100), path=path, now=5100)
    code = login.totp(secret, 5100)
    assert not login.verify("Yassine", PASSWORD, code, path=path, now=5100).recovery_used
    with pytest.raises(LoginError, match="Code incorrect"):  # un code ne sert qu'une fois
        login.verify("Yassine", PASSWORD, code, path=path, now=5110)
    login.verify("Yassine", PASSWORD, login.totp(secret, 5130), path=path, now=5130)


def test_recovery_code_replaces_the_otp_once(path):
    secret = login.new_otp_secret()
    codes = login.create("Yassine", PASSWORD, secret, login.totp(secret, 5000), path=path,
                         now=5000)
    assert len(codes) == login.RECOVERY_CODES and len(set(codes)) == len(codes)
    assert all(len(c) == 9 and c[4] == "-" for c in codes)
    result = login.verify("Yassine", PASSWORD, codes[0].lower().replace("-", " "), path=path)
    assert result.recovery_used and result.recovery_left == login.RECOVERY_CODES - 1
    with pytest.raises(LoginError):
        login.verify("Yassine", PASSWORD, codes[0], path=path)


def test_forgot_password_needs_a_single_use_recovery_code_not_the_phone(path):
    secret = login.new_otp_secret()
    codes = login.create("Yassine", PASSWORD, secret, login.totp(secret, 7000), path=path,
                         now=7000)
    with pytest.raises(LoginError, match="code de secours"):  # le telephone seul ne suffit pas
        login.reset_password("Yassine", login.totp(secret, 7030), NEW_PASSWORD, path, now=7030)
    assert login.verify("Yassine", PASSWORD, login.totp(secret, 7060), path=path, now=7060)
    login.reset_password("yassine", codes[0], "nouveau-mot-de-passe-2", path)
    with pytest.raises(LoginError):  # code de secours deja utilise
        login.reset_password("Yassine", codes[0], "nouveau-mot-de-passe-3", path)
    with pytest.raises(LoginError):
        login.reset_password("Yassine", "ABCD-EFGH", "nouveau-mot-de-passe-3", path)
    with pytest.raises(LoginError, match="Pseudo ou code"):
        login.reset_password("autre", codes[1], "nouveau-mot-de-passe-3", path)
    with pytest.raises(LoginError, match="12"):
        login.reset_password("Yassine", codes[1], "court", path)
    assert login.verify("Yassine", "nouveau-mot-de-passe-2", codes[1], path=path)


def test_forgot_password_without_otp_uses_a_recovery_code(path):
    codes = login.create("Yassine", PASSWORD, path=path)
    with pytest.raises(LoginError):
        login.reset_password("Yassine", "123456", NEW_PASSWORD, path)
    login.reset_password("Yassine", codes[3], NEW_PASSWORD, path)
    assert login.verify("Yassine", NEW_PASSWORD, path=path)


def test_settings_change_password_otp_and_codes(path):
    old = login.create("Yassine", PASSWORD, path=path)
    login.change_password(NEW_PASSWORD, path)
    assert login.verify("Yassine", NEW_PASSWORD, path=path)
    with pytest.raises(LoginError):
        login.change_password("Yassine", path)
    secret = login.new_otp_secret()
    with pytest.raises(LoginError):
        login.enable_otp(secret, other_code(secret, 9000), path, now=9000)
    login.enable_otp(secret, login.totp(secret, 9000), path, now=9000)
    with pytest.raises(CodeRequired):
        login.verify("Yassine", NEW_PASSWORD, path=path)
    login.disable_otp(path)
    assert login.verify("Yassine", NEW_PASSWORD, path=path)
    fresh = login.renew_recovery_codes(path)
    with pytest.raises(LoginError):
        login.reset_password("Yassine", old[0], PASSWORD, path)
    login.reset_password("Yassine", fresh[0], PASSWORD, path)
    login.disable(path)
    assert not login.enabled(path)


def test_damaged_database_keeps_the_login_screen(path):
    assert not login.enabled(path) and login.load(path) is None  # pas de base : pas de connexion
    path.write_bytes(b"ceci n'est pas une base SQLite" * 100)
    with pytest.raises(login.StorageError, match="supprimez"):
        login.load(path)
    assert login.enabled(path)  # l'ecran de connexion explique quoi faire
    with pytest.raises(login.StorageError):
        login.verify("Yassine", PASSWORD, path=path)


def test_otp_uri_and_its_qr_code():
    secret = login.new_otp_secret()
    uri = login.otp_uri(secret, "Yassine")
    assert uri == f"otpauth://totp/FreeAV:Yassine?secret={secret}&issuer=FreeAV"
    assert (login.OTP_DIGITS, login.OTP_STEP) == (6, 30)  # les valeurs par defaut omises
    assert len(qrcode.make(uri)) == 37  # version 5 : gros modules, facile a scanner
    assert len(login.format_secret(secret).split()) == 8
    matrix = qrcode.make(login.otp_uri(secret, "x" * 32))
    assert len(matrix) <= 4 * qrcode.MAX_VERSION + 17


# Matrices de reference produites par un encodeur QR independant (reportlab). Le module
# qrcode de FreeAV donne exactement les memes, pour les 8 masques et les versions 1 a 10
# (verifie a l'ecriture du module) : ces deux exemples gardent ce resultat.
HELLO_MASK_2 = """
#######....#..#######
#.....#...#.#.#.....#
#.###.#.##....#.###.#
#.###.#.#.#.#.#.###.#
#.###.#.##..#.#.###.#
#.....#.####..#.....#
#######.#.#.#.#######
........##...........
#.#####...##..#####..
.##.##.#.######..##..
..#####.#...#.##.###.
.##.#....######..##..
.#.######...#..#..#.#
........#.#.#..#.#...
#######..###.#..#.##.
#.....#.#.#....#####.
#.###.#.##.#.#..#.##.
#.###.#.##.#####.#...
#.###.#.##..#.##..#..
#.....#..######.###..
#######.##..#...#.##.
"""
URI_MASK_5_SHA256 = "7f00a2e810ec7789734a3511f9f9fde4272940a14204e4254a8b8af05bf61594"
URI = ("otpauth://totp/FreeAV:Yassine?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=FreeAV"
       "&algorithm=SHA1&digits=6&period=30")


def as_text(matrix):
    return "\n".join("".join("#" if dark else "." for dark in row) for row in matrix)


def test_qr_code_matches_an_independent_encoder():
    import hashlib
    assert as_text(qrcode.make("HELLO", mask=2)) == HELLO_MASK_2.strip()
    matrix = qrcode.make(URI, mask=5)
    assert len(matrix) == 45  # version 7 : avec le bloc d'information de version
    assert hashlib.sha256(as_text(matrix).encode()).hexdigest() == URI_MASK_5_SHA256


def test_qr_code_structure():
    matrix = qrcode.make("HELLO")
    assert len(matrix) == 21 and all(len(row) == 21 for row in matrix)
    for x, y in ((0, 0), (14, 0), (0, 14)):  # reperes des trois coins
        assert all(matrix[y][x + i] and matrix[y + 6][x + i] for i in range(7))
        assert matrix[y + 3][x + 3] and not matrix[y + 1][x + 1]
    assert [matrix[6][x] for x in range(8, 13)] == [True, False, True, False, True]
    assert qrcode.capacity(10) == 213
    with pytest.raises(ValueError):
        qrcode.make("x" * 214)
