"""Propiedad y permisos de los artefactos que el agente persiste.

Dos hechos del entorno se combinaban en un fallo silencioso:

1. El agente se ejecuta con `sudo`, porque `nmap` necesita root para el escaneo
   SYN/UDP (decisión de diseño asumida del proyecto).
2. `tempfile.NamedTemporaryFile` y `tempfile.mkstemp` crean los ficheros con modo
   **0600 por diseño**, y `os.replace` **conserva ese modo** al mover el temporal
   sobre el destino final. Es decir: la escritura atómica, que se introdujo para no
   corromper los ficheros ante un `kill -9`, arrastraba de propina unos permisos
   restrictivos.

Resultado combinado: `data/kb.json` y `data/nvd_cache.json` quedaban `root:root`
con modo `0600`, de modo que **ni el dashboard ni ninguna ejecución sin `sudo`
podían leerlos**. La KB persistente que sostiene el aprendizaje entre auditorías
(OM2) y la caché NVD en disco quedaban desactivadas de hecho, y el único aviso era
una línea de log a nivel WARNING («using empty KB»).

Este módulo centraliza la corrección: tras escribir un artefacto se fijan permisos
legibles y, si el proceso corre bajo `sudo`, se devuelve la propiedad al usuario
que invocó el comando. Todo es *best-effort*: un fallo al ajustar permisos nunca
debe tumbar una auditoría ya completada.
"""
from __future__ import annotations

import os
from typing import Optional, Tuple

from loguru import logger

FILE_MODE = 0o644
DIR_MODE = 0o755


def sudo_owner() -> Optional[Tuple[int, int]]:
    """(uid, gid) del usuario que invocó `sudo`, o None si no aplica.

    Devuelve None cuando el proceso no es root o cuando no se ejecutó vía `sudo`
    (en ese caso el propietario ya es el correcto y no hay nada que devolver).
    """
    if os.geteuid() != 0:
        return None
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid:
        return None
    try:
        return int(uid), int(gid) if gid else int(uid)
    except ValueError:
        return None


def publish_artifact(path: str, mode: int = FILE_MODE) -> None:
    """Deja un fichero legible por el usuario real tras un run con `sudo`.

    Idempotente y silencioso ante fallos: si el fichero no existe o el sistema no
    permite el cambio, se registra en debug y se sigue.
    """
    if not path or not os.path.exists(path):
        return
    try:
        os.chmod(path, mode)
    except OSError as e:
        logger.debug(f"[FS] chmod {path} falló: {e}")
    owner = sudo_owner()
    if owner is None:
        return
    try:
        os.chown(path, owner[0], owner[1])
    except OSError as e:
        logger.debug(f"[FS] chown {path} falló: {e}")


def publish_dir(path: str) -> None:
    """Como `publish_artifact` pero con permisos de directorio (traversable).

    Necesario además para que una ejecución **sin** `sudo` pueda escribir en un
    directorio creado por una ejecución **con** `sudo` (caso `reports/` y `data/`).
    """
    if not path:
        return
    publish_artifact(path, mode=DIR_MODE)
