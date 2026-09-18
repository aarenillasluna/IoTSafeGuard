"""Arranque idempotente del stack Langfuse antes de `npm run dev`.

Política:
  - Si todos los containers del stack están UP → no hace nada, retorna 0.
  - Si faltan containers y existe `.env.langfuse` con valores REALES → llama
    a `docker compose up -d`.
  - Si faltan containers y solo existe `.env.langfuse.example` con placeholders
    → muestra instrucciones y retorna 0 (no rompe `npm run dev`).
  - Si docker no está instalado → warning, retorna 0.

Diseño: nunca falla con código != 0 para no bloquear el flujo de desarrollo
del dashboard. Langfuse es observabilidad opcional — el agente y el
dashboard funcionan sin él (cliente con try/except).

Ejecutar:
    ./venv/bin/python scripts/start_langfuse.py        # arranque automático
    ./venv/bin/python scripts/start_langfuse.py --down # parar el stack
    ./venv/bin/python scripts/start_langfuse.py --status
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE_FILE = os.path.join(REPO_ROOT, "docker-compose.langfuse.yml")
ENV_FILE = os.path.join(REPO_ROOT, ".env.langfuse")
ENV_EXAMPLE = os.path.join(REPO_ROOT, ".env.langfuse.example")

# Servicios esperados (deben coincidir con docker-compose.langfuse.yml)
EXPECTED_SERVICES = ("langfuse-web", "langfuse-worker", "postgres",
                     "clickhouse", "redis", "minio")

LANGFUSE_URL = "http://localhost:3000"


def _colour(s: str, code: str) -> str:
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s


def info(msg: str) -> None:
    print(f"{_colour('[langfuse]', '36')} {msg}")


def warn(msg: str) -> None:
    print(f"{_colour('[langfuse]', '33')} {msg}")


def ok(msg: str) -> None:
    print(f"{_colour('[langfuse]', '32')} {msg}")


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _compose_cmd() -> list[str]:
    """Devuelve el prefijo `docker compose -f <yml>`. Sin --env-file: se
    añade sólo cuando sabemos que el fichero tiene valores reales."""
    return ["docker", "compose", "-f", COMPOSE_FILE]


def _running_services() -> set[str]:
    """Devuelve los nombres de servicio que están UP según docker compose."""
    try:
        out = subprocess.check_output(
            _compose_cmd() + ["ps", "--status", "running", "--services"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return {line.strip() for line in out.splitlines() if line.strip()}
    except subprocess.CalledProcessError:
        return set()
    except FileNotFoundError:
        return set()


def _env_file_has_real_values(path: str) -> bool:
    """True si el fichero existe y no contiene marcadores `REPLACE_WITH_...`."""
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return "REPLACE_WITH_" not in content


def cmd_status() -> int:
    if not _docker_available():
        warn("docker no instalado")
        return 0
    running = _running_services()
    missing = set(EXPECTED_SERVICES) - running
    if not missing:
        ok(f"stack UP ({len(running)} servicios) → {LANGFUSE_URL}")
    elif running:
        warn(f"stack PARCIAL — corriendo: {sorted(running)} · faltan: {sorted(missing)}")
    else:
        warn("stack DOWN")
    return 0


def cmd_down() -> int:
    if not _docker_available():
        warn("docker no instalado — nada que parar")
        return 0
    info("parando stack...")
    subprocess.run(_compose_cmd() + ["down"], cwd=REPO_ROOT)
    return 0


def cmd_up() -> int:
    if not _docker_available():
        warn("docker no instalado — saltando arranque (el agente funcionará sin Langfuse)")
        return 0
    if not os.path.isfile(COMPOSE_FILE):
        warn(f"falta {os.path.basename(COMPOSE_FILE)} — saltando")
        return 0

    running = _running_services()
    missing = set(EXPECTED_SERVICES) - running

    if not missing:
        ok(f"ya corriendo ({len(running)} servicios) → {LANGFUSE_URL}")
        return 0

    # Hay servicios que arrancar — necesitamos un .env con valores reales.
    if _env_file_has_real_values(ENV_FILE):
        info(f"arrancando servicios faltantes: {sorted(missing)}")
        env_args = ["--env-file", ENV_FILE]
    elif os.path.isfile(ENV_EXAMPLE):
        warn(
            f".env.langfuse no existe — solo .env.langfuse.example con placeholders.\n"
            f"          Para arrancar el stack:\n"
            f"          1) cp .env.langfuse.example .env.langfuse\n"
            f"          2) rellena SALT, ENCRYPTION_KEY, NEXTAUTH_SECRET con "
            f"`openssl rand -hex 32`\n"
            f"          3) vuelve a lanzar `npm run dev`\n"
            f"          (el agente y dashboard funcionan sin Langfuse — solo "
            f"pierdes la observabilidad)"
        )
        return 0
    else:
        warn("ni .env.langfuse ni .env.langfuse.example — saltando")
        return 0

    # Levantar en background; no esperar a que healthcheck termine.
    proc = subprocess.run(
        _compose_cmd() + env_args + ["up", "-d"],
        cwd=REPO_ROOT,
    )
    if proc.returncode == 0:
        ok(f"stack arrancado → {LANGFUSE_URL} (puede tardar 30-60s en estar listo)")
    else:
        warn(f"docker compose up devolvió código {proc.returncode} — "
             "revisa logs con `npm run langfuse:logs`")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--down", action="store_true", help="Para el stack")
    p.add_argument("--status", action="store_true", help="Muestra estado")
    args = p.parse_args()

    if args.down:
        return cmd_down()
    if args.status:
        return cmd_status()
    return cmd_up()


if __name__ == "__main__":
    sys.exit(main())
