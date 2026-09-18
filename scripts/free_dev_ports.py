"""Detecta + mata procesos huérfanos de `npm run dev` que bloquean los
puertos del dashboard (:8000 backend FastAPI, :5173 frontend Vite).

Caso de uso real: el usuario hace `Ctrl+Z` en `sudo npm run dev` en vez de
`Ctrl+C`. Los procesos quedan en state `T+` (stopped), pero el kernel les
mantiene los puertos asignados. La siguiente vez que se lanza `npm run dev`,
uvicorn falla con `[Errno 98] Address already in use` y `concurrently
--kill-others-on-fail` se carga todo.

Política conservadora:
  • Solo mata procesos cuya cmdline coincide con `uvicorn.*api.main:app` o
    `vite` lanzado desde `frontend/`. Nunca mata procesos arbitrarios que
    casualmente escuchen en esos puertos.
  • Requiere `sudo` si los procesos a matar son de otro UID (típicamente
    sudo-uvicorn dejado por el dashboard).
  • Reporta sin pedirlo si encuentra procesos de OTRO origen — para que el
    usuario decida.

Diseñado para ejecutarse como `predev` antes de `start_langfuse.py`. Nunca
devuelve código != 0 — si no puede liberar el puerto, simplemente loguea y
deja que uvicorn falle con el mensaje claro de `concurrently`.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
from typing import List, Tuple

DEV_PORTS = {
    8000: "FastAPI backend",
    5173: "Vite frontend",
}

# Patrones que reconocemos como "nuestros" (seguros para matar)
OWN_PROCESS_PATTERNS = (
    re.compile(r"uvicorn.*api\.main:app"),
    re.compile(r"vite.*frontend"),
    re.compile(r"node.*frontend.*vite"),
)


def _colour(s: str, code: str) -> str:
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s


def info(msg: str) -> None:
    print(f"{_colour('[ports]', '36')} {msg}")


def warn(msg: str) -> None:
    print(f"{_colour('[ports]', '33')} {msg}")


def ok(msg: str) -> None:
    print(f"{_colour('[ports]', '32')} {msg}")


def _port_is_bound(port: int) -> bool:
    """True si HAY algo escuchando en `port` (sin importar el PID)."""
    try:
        out = subprocess.check_output(
            ["ss", "-ltn", f"sport = :{port}"],
            stderr=subprocess.DEVNULL, text=True, timeout=3,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
    # Cada línea no-header con LISTEN cuenta. La cabecera es "State ...".
    for line in out.splitlines():
        if line.startswith("LISTEN") or " LISTEN " in line:
            return True
    return False


def _processes_on_port(port: int) -> List[Tuple[int, str]]:
    """Devuelve (pid, cmdline) para cada proceso que escucha en `port`.
    Funciona en Linux/macOS. Lee /proc/<pid>/cmdline directamente cuando hay
    que evitar `sudo lsof` (que pediría password de forma interactiva).
    """
    # Estrategia 1: ss (sin sudo solo ve PIDs del usuario actual)
    try:
        out = subprocess.check_output(
            ["ss", "-ltnp", f"sport = :{port}"],
            stderr=subprocess.DEVNULL, text=True, timeout=3,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        out = ""

    pids: set[int] = set()
    for line in out.splitlines():
        m = re.findall(r"pid=(\d+)", line)
        pids.update(int(p) for p in m)

    # Estrategia 2 (fallback): lsof si está disponible
    if not pids and shutil.which("lsof"):
        try:
            out = subprocess.check_output(
                ["lsof", "-iTCP", f"-i:{port}", "-sTCP:LISTEN", "-t"],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            pids.update(int(p) for p in out.split() if p.isdigit())
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Estrategia 3 (último recurso): grep en /proc/*/net/tcp matcheando puerto
    # hexadecimal. Funciona sin privilegios y siempre detecta el inodo del socket,
    # luego mapeamos a PID mirando /proc/*/fd/* socket inodes.
    if not pids:
        pids = _pids_via_proc_scan(port)

    results: List[Tuple[int, str]] = []
    for pid in pids:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode("utf-8", errors="replace").replace("\x00", " ").strip()
        except (FileNotFoundError, PermissionError, OSError):
            cmdline = "<inaccessible>"
        results.append((pid, cmdline))
    return results


def _pids_via_proc_scan(port: int) -> set[int]:
    """Detecta PIDs escuchando en `port` parseando /proc/net/tcp + /proc/<pid>/fd/.
    No requiere sudo para detectar el inodo; el mapeo inodo→PID sí puede fallar
    para procesos de otros UIDs (no podemos leer /proc/<otro_uid>/fd/) — en ese
    caso devolvemos set vacío y el caller usa _port_is_bound() para reportar.
    """
    port_hex = f"{port:04X}"
    target_inodes: set[str] = set()
    for proc_net in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc_net, "r") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if len(cols) < 10:
                        continue
                    local = cols[1]
                    state = cols[3]
                    if state != "0A":  # 0A = LISTEN
                        continue
                    if not local.endswith(":" + port_hex):
                        continue
                    target_inodes.add(cols[9])
        except OSError:
            continue
    if not target_inodes:
        return set()

    pids: set[int] = set()
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            fd_dir = f"/proc/{entry}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(f"{fd_dir}/{fd}")
                    except OSError:
                        continue
                    # link tiene formato "socket:[12345]"
                    if link.startswith("socket:["):
                        inode = link[len("socket:["):-1]
                        if inode in target_inodes:
                            pids.add(int(entry))
                            break
            except (PermissionError, FileNotFoundError):
                continue
    except OSError:
        pass
    return pids


def _looks_like_our_process(cmdline: str) -> bool:
    return any(p.search(cmdline) for p in OWN_PROCESS_PATTERNS)


def _kill_pid(pid: int, cmdline: str) -> bool:
    """Intenta SIGTERM, luego SIGKILL si sigue vivo. Devuelve True si murió."""
    for sig, name in [(signal.SIGTERM, "TERM"), (signal.SIGKILL, "KILL")]:
        try:
            os.kill(pid, sig)
            info(f"  → sent SIG{name} to pid={pid}")
        except ProcessLookupError:
            return True
        except PermissionError:
            warn(f"  → permission denied (pid={pid}, requires sudo). "
                 f"Run manually: sudo kill -9 {pid}")
            return False
        # Brief wait + check
        import time
        time.sleep(0.4)
        if not _is_alive(pid):
            return True
    return False


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        # PermissionError significa que sigue vivo pero no tenemos permiso (otro UID).
        return isinstance(sys.exc_info()[1], PermissionError)


def main() -> int:
    any_action = False
    for port, label in DEV_PORTS.items():
        procs = _processes_on_port(port)
        bound = _port_is_bound(port)
        if not procs and not bound:
            continue
        any_action = True

        if procs:
            info(f"puerto {port} ({label}) ocupado por: {[p[0] for p in procs]}")
            for pid, cmdline in procs:
                short_cmd = cmdline[:120] + ("..." if len(cmdline) > 120 else "")
                if _looks_like_our_process(cmdline):
                    info(f"  pid={pid} es uvicorn/vite del dashboard — liberando…")
                    if _kill_pid(pid, cmdline):
                        ok(f"  pid={pid} terminado")
                    else:
                        warn(f"  pid={pid} no se pudo matar. cmdline: {short_cmd}")
                else:
                    warn(f"  pid={pid} NO coincide con uvicorn/vite del dashboard. "
                         f"No lo toco. cmdline: {short_cmd}")
                    warn(f"  Si quieres liberarlo manualmente: kill -9 {pid}")
        else:
            # Puerto ocupado pero PID invisible (otro UID + sin sudo).
            warn(f"puerto {port} ({label}) está ocupado pero no veo el PID "
                 f"(probablemente proceso de root). Ejecuta:")
            warn(f"  sudo ss -ltnp 'sport = :{port}'    # ver PID")
            warn(f"  sudo kill -9 <PID>                 # liberar")
            warn(f"  o relanza este comando con sudo:")
            warn(f"  sudo ./venv/bin/python scripts/free_dev_ports.py")

    if not any_action:
        return 0

    # Re-verificar tras kills
    still_blocked = [port for port in DEV_PORTS if _port_is_bound(port)]
    if still_blocked:
        warn(f"puertos todavía ocupados: {still_blocked} — uvicorn fallará "
             "con 'Address already in use'")
    else:
        ok("puertos del dashboard liberados")
    return 0


if __name__ == "__main__":
    sys.exit(main())
