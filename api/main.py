"""FastAPI app: monta los routers y configura CORS para el dev server de Vite.

Lanzar (desde la raíz del repo):
    sudo ./venv/bin/python -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000

O vía `sudo npm run dev` (orquesta backend + frontend).
"""
from __future__ import annotations

import hmac
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from api.routes import audits, cves, devices, reports, scan

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Token opcional de acceso al backend.
#
# Este servicio lanza `run.py` con privilegios de root (nmap necesita `-O`/`-sU`)
# contra direcciones que elige quien llama. Es decir: quien alcance el puerto
# ejecuta escaneos privilegiados sobre la red del operador. Hasta ahora no había
# ninguna prueba de identidad, y la única contención era el bind a `127.0.0.1`
# —que protege frente a la red, pero no frente a cualquier proceso local ni
# frente a una página web que apunte al puerto—.
#
# Se mantiene OPCIONAL a propósito: es una herramienta local de un solo usuario y
# exigir un token en el flujo normal sería fricción sin destinatario. Pero
# cuando se define, se exige en todas las rutas; y cuando no, el arranque lo dice
# en voz alta, para que la ausencia sea una decisión y no un descuido.
_TOKEN_ENV = "IOTSG_DASHBOARD_TOKEN"
_EXEMPT_PATHS = ("/api/health", "/api/docs", "/api/openapi.json", "/")


def create_app() -> FastAPI:
    app = FastAPI(
        title="IoTSafeGuard Dashboard API",
        description=(
            "Backend del dashboard: lee reportes/KB del agente y expone "
            "lanzamiento de auditorías + descubrimiento de subnet."
        ),
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    # CORS sólo para el dev server de Vite. En producción ambos se sirven
    # bajo el mismo origen (uvicorn sirve el `frontend/dist/` estático).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def _require_token(request: Request, call_next):
        """Exige el token cuando está configurado. No-op si no lo está."""
        expected = os.getenv(_TOKEN_ENV)
        path = request.url.path
        if expected and path.startswith("/api") and path not in _EXEMPT_PATHS:
            supplied = (request.headers.get("X-API-Token")
                        or request.query_params.get("token") or "")
            # Comparación en tiempo constante: el token es un secreto y una
            # comparación normal filtra su prefijo por temporización.
            if not hmac.compare_digest(supplied, expected):
                return JSONResponse(
                    status_code=401,
                    content={"detail": (
                        "Token requerido. Envíalo en la cabecera X-API-Token "
                        f"(configurado en {_TOKEN_ENV}).")},
                )
        return await call_next(request)

    app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
    app.include_router(cves.router, prefix="/api/cves", tags=["cves"])
    app.include_router(audits.router, prefix="/api/audits", tags=["audits"])
    app.include_router(scan.router, prefix="/api/scan", tags=["scan"])

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "service": "iot-safeguard-api"}

    @app.get("/")
    def root() -> dict:
        """Pista para humanos que abren el backend directo: la UI vive en otro puerto."""
        return {
            "service": "iot-safeguard-api",
            "hint": "Este es el backend. Para la UI abre http://127.0.0.1:5173",
            "docs": "/api/docs",
            "health": "/api/health",
        }

    if os.getenv(_TOKEN_ENV):
        logger.info("[API] autenticación por token ACTIVA (X-API-Token)")
    else:
        logger.warning(
            "[API] sin autenticación: cualquier proceso que alcance este puerto "
            "puede lanzar escaneos con privilegios de root contra tu red. "
            "Aceptable si el backend está atado a 127.0.0.1 y la máquina es de "
            f"un solo usuario. Para exigir token: export {_TOKEN_ENV}=<secreto>"
        )
    logger.info(f"[API] booted — repo_root={REPO_ROOT}")
    return app


app = create_app()
