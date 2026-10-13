"""Acces au systeme pour le module de reparation : registre Windows, commandes, fichiers.

Tout passe par la classe System, que les tests remplacent par un faux systeme : on peut
ainsi verifier les diagnostics et reparations Windows sans toucher a une vraie machine.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import winreg
except ImportError:  # hors Windows
    winreg = None

IS_WINDOWS = sys.platform == "win32"


class RegistryError(OSError):
    pass


class WinRegistry:
    """Lecture et ecriture du registre Windows, avec des noms de ruche lisibles ("HKCU")."""

    def _hive(self, hive: str):
        return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive]

    def values(self, hive: str, key: str) -> list[tuple[str, object, int]]:
        try:
            with winreg.OpenKey(self._hive(hive), key) as handle:
                result, i = [], 0
                while True:
                    try:
                        result.append(winreg.EnumValue(handle, i))
                    except OSError:
                        return result
                    i += 1
        except FileNotFoundError:
            return []

    def get(self, hive: str, key: str, name: str):
        """Retourne (valeur, type) ou None si la valeur n'existe pas."""
        try:
            with winreg.OpenKey(self._hive(hive), key) as handle:
                return winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return None

    def set(self, hive: str, key: str, name: str, value, kind: int) -> None:
        try:
            with winreg.CreateKeyEx(self._hive(hive), key, 0, winreg.KEY_SET_VALUE) as handle:
                winreg.SetValueEx(handle, name, 0, kind, value)
        except PermissionError as exc:
            raise RegistryError("droits administrateur necessaires") from exc

    def delete(self, hive: str, key: str, name: str) -> None:
        try:
            with winreg.OpenKey(self._hive(hive), key, 0, winreg.KEY_SET_VALUE) as handle:
                winreg.DeleteValue(handle, name)
        except FileNotFoundError:
            pass
        except PermissionError as exc:
            raise RegistryError("droits administrateur necessaires") from exc


    def delete_key(self, hive: str, key: str) -> None:
        """Supprime une cle et toutes ses sous-cles (sans erreur si elle n'existe pas)."""
        try:
            with winreg.OpenKey(self._hive(hive), key, 0,
                                winreg.KEY_READ | winreg.KEY_SET_VALUE) as handle:
                while True:
                    try:
                        child = winreg.EnumKey(handle, 0)
                    except OSError:
                        break
                    self.delete_key(hive, key + "\\" + child)
            winreg.DeleteKey(self._hive(hive), key)
        except FileNotFoundError:
            pass
        except PermissionError as exc:
            raise RegistryError("droits administrateur necessaires") from exc


class System:
    def __init__(self, registry=None, runner=None, hosts_path: Path | None = None,
                 environ: dict | None = None, is_windows: bool = IS_WINDOWS,
                 is_admin: bool | None = None, home: Path | None = None):
        self.is_windows = is_windows
        self.registry = registry if registry is not None else (
            WinRegistry() if is_windows and winreg else None)
        self.runner = runner or _run
        self.environ = environ if environ is not None else dict(os.environ)
        self.home = Path(home) if home else Path.home()
        if hosts_path is None:
            root = self.environ.get("SystemRoot", r"C:\Windows")
            hosts_path = Path(root, "System32", "drivers", "etc", "hosts") if is_windows \
                else Path("/etc/hosts")
        self.hosts_path = Path(hosts_path)
        self.is_admin = _is_admin() if is_admin is None else is_admin

    def run(self, args: list[str], timeout: float = 60) -> subprocess.CompletedProcess:
        return self.runner(args, timeout)

    def expand(self, value: str) -> str:
        """Remplace %APPDATA% et consorts par leur valeur."""
        out = value
        for name, val in self.environ.items():
            out = out.replace(f"%{name}%", val).replace(f"%{name.upper()}%", val)
        return out

    def temp_dirs(self) -> list[Path]:
        dirs = [Path(tempfile.gettempdir())]
        if self.is_windows:
            dirs = [Path(self.environ[n]) for n in ("TEMP",) if n in self.environ] or dirs
            if "SystemRoot" in self.environ:
                dirs.append(Path(self.environ["SystemRoot"], "Temp"))
        return list(dict.fromkeys(dirs))


# Outils de Windows lances par FreeAV, toujours par leur chemin complet dans System32. Avec un
# nom nu (« sfc »), Windows cherche d'abord dans le dossier de FreeAV.exe (souvent
# Telechargements), puis dans le dossier courant : un faux sfc.exe pose la serait lance a la
# place du vrai, avec les droits administrateur si FreeAV en a.
SYSTEM_TOOLS = {"powershell": r"WindowsPowerShell\v1.0\powershell.exe", "schtasks": "schtasks.exe",
                "netsh": "netsh.exe", "sfc": "sfc.exe", "dism": "Dism.exe",
                "ipconfig": "ipconfig.exe"}


def _system_dir() -> Path:
    """C:\\Windows\\System32, donne par Windows (pas par une variable d'environnement)."""
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    size = ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf))
    if not 0 < size < len(buf):
        raise OSError("dossier System32 introuvable")
    return Path(buf.value)


def resolve_tool(args: list[str], system_dir=_system_dir) -> list[str]:
    """Remplace le nom nu d'un outil de Windows par son chemin dans System32 ; refuse tout
    autre programme sans chemin complet."""
    if not args or Path(args[0]).is_absolute():
        return list(args)
    name = Path(args[0])
    tool = SYSTEM_TOOLS.get(name.stem.lower())
    if tool is None or str(name) != name.name or name.suffix.lower() not in ("", ".exe"):
        raise OSError(f"programme sans chemin complet refuse : {args[0]}")
    return [str(system_dir() / tool), *args[1:]]


def _run(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    kwargs = {}
    if IS_WINDOWS:
        args = resolve_tool(args)
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if args and Path(args[0]).stem.lower() == "powershell":
            # Lance depuis PowerShell 7, Windows PowerShell 5 herite de modules incompatibles
            env = dict(os.environ)
            env.pop("PSModulePath", None)
            kwargs["env"] = env
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace", **kwargs)


def _is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0
