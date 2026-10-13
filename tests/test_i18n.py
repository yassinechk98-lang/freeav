import ast
import string
from pathlib import Path

import pytest

from freeav import i18n, login, privacy, updater

GUI = Path(i18n.__file__).with_name("gui.py")
LOGIN_GUI = Path(i18n.__file__).with_name("login_gui.py")
LOGIN = Path(i18n.__file__).with_name("login.py")


@pytest.fixture
def config(tmp_path, monkeypatch):
    """Reglages dans un dossier temporaire (jamais le vrai ~/.freeav), langue relue."""
    cfg = tmp_path / "config.json"
    monkeypatch.setattr(updater, "CONFIG_FILE", cfg)
    monkeypatch.setattr(i18n, "_lang", None)
    return cfg


def gui_strings(path=GUI, names=("_", "N_", "translate")):
    """Chaque texte litteral passe a _(), N_() ou i18n.translate() dans ce fichier."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name in names and isinstance(node.args[0], ast.Constant):
            found.append(node.args[0].value)
    return found


def test_french_is_the_default(config):
    assert i18n.current() == "fr"
    assert i18n._("Analyse rapide") == "Analyse rapide"
    assert i18n._("Texte sans traduction") == "Texte sans traduction"
    assert not config.exists()


def test_english_returns_translations(config):
    i18n.set_language("en")
    assert updater.load_setting(i18n.LANG_SETTING, None, config) == "en"
    assert i18n.current() == "en"
    assert i18n._("Analyse rapide") == "Quick scan"
    assert i18n._("Analyse : {path}").format(path="C:\\a") == "Scanning: C:\\a"
    assert i18n._(privacy.SUMMARY).startswith("FreeAV has no account")
    assert i18n._("Texte sans traduction") == "Texte sans traduction"


def test_language_is_read_once(config):
    assert i18n._("Analyse rapide") == "Analyse rapide"
    i18n.set_language("en")
    assert i18n._("Analyse rapide") == "Analyse rapide"  # applique au prochain demarrage


@pytest.mark.parametrize("value", ["de", "", 3, None, ["en"]])
def test_unknown_language_falls_back_to_french(config, value):
    updater.save_setting(i18n.LANG_SETTING, value, config)
    assert i18n.current() == "fr"
    assert i18n._("Analyse rapide") == "Analyse rapide"


def test_set_language_rejects_unknown_code(config):
    with pytest.raises(ValueError):
        i18n.set_language("de")


def test_french_template_is_unchanged():
    assert i18n.translate("Analyse : {path}", "fr").format(path="x") == "Analyse : x"
    assert i18n.translate(privacy.SUMMARY, "fr") is privacy.SUMMARY


def test_every_gui_string_has_an_english_translation():
    strings = gui_strings()
    assert len(strings) > 100
    missing = sorted({s for s in strings if s not in i18n.EN})
    assert not missing, missing


def test_translations_keep_the_same_placeholders():
    def fields(text):
        return sorted(f for _, f, _, _ in string.Formatter().parse(text) if f is not None)

    for french, english in i18n.EN.items():
        assert english.strip(), french
        assert fields(french) == fields(english), french


def test_every_login_gui_string_has_an_english_translation():
    strings = gui_strings(LOGIN_GUI)
    assert len(strings) > 50
    missing = sorted({s for s in strings if s not in i18n.EN})
    assert not missing, missing


def test_every_login_message_has_an_english_translation():
    """Les refus de login.py (login.Message) que l'ecran de connexion affiche."""
    strings = gui_strings(LOGIN, names=("Message",))
    assert len(strings) > 10
    missing = sorted({s for s in strings if s not in i18n.EN})
    assert not missing, missing


def test_login_errors_shown_by_the_gui_are_translated(config):
    login_gui = pytest.importorskip("freeav.login_gui")
    i18n.set_language("en")
    error = login.LoginError(login.GENERIC_ERROR)
    assert str(error) == "Pseudo ou mot de passe incorrect."
    assert login_gui.tr(error.message) == "Incorrect nickname or password."
    locked = login.Locked(45)
    assert str(locked) == "Trop d'essais. Réessayez dans 45 secondes."
    assert login_gui.tr(locked.message) == "Too many attempts. Try again in 45 seconds."
    assert login_gui.tr(login.Locked(600).message) == "Too many attempts. Try again in 10 minutes."
    problem = login.password_problem("court")
    assert problem == "Le mot de passe doit faire de 12 à 128 caractères."
    assert login_gui.tr(problem) == "The password must be 12 to 128 characters long."


def test_login_messages_stay_french_by_default(config):
    login_gui = pytest.importorskip("freeav.login_gui")
    assert login_gui.tr(login.Locked(45).message) == "Trop d'essais. Réessayez dans 45 secondes."
