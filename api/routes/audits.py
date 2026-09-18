"""Routes: lanzar auditorías y streamearlas en vivo por WebSocket.

POST  /api/audits              — arranca un audit, devuelve audit_id
POST  /api/audits/batch        — arranca N audits concurrentes (una por target)
GET   /api/audits              — lista activos + históricos (en memoria)
GET   /api/audits/{id}         — estado de un audit concreto
GET   /api/audits/{id}/log     — texto plano del transcript (offline)
WS    /api/audits/{id}/stream  — tail en vivo + replay de lo ya emitido
"""
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from api.services import audit_runner
from api.services.audit_runner import MODOS_DE_TANDA

router = APIRouter()


def _check_ipv4(v: str) -> str:
    # El objetivo primario es que no se filtre ningún metacarácter de shell: esta
    # IP acaba en la línea de comandos de `run.py`. Se valida además el RANGO de
    # cada octeto, igual que hace `_validate_cidr` en la ruta de escaneo: rechazar
    # aquí un `999.999.999.999` cuesta nada y evita una auditoría que iba a morir
    # medio minuto después en nmap con un error peor de diagnosticar.
    import re
    v = (v or "").strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
        raise ValueError(f"'{v}' no es una IPv4 válida (ej. 192.168.1.1)")
    for octet in v.split("."):
        if not (0 <= int(octet) <= 255):
            raise ValueError(f"octeto fuera de rango en '{v}': {octet}")
    return v


def _check_model(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    import re
    if not re.match(r"^[A-Za-z0-9._:\-/]+$", v):
        raise ValueError("model contiene caracteres no permitidos")
    return v


# Flags de `run.py` que la API acepta reenviar. `target_ip` y `model` se validan
# con cuidado, pero `extra_args` viajaba como lista libre hasta la línea de
# comandos: no era ejecución de shell (se usa `exec`, no `shell=True`) pero sí
# un hueco en un borde que el resto del fichero trata como frontera de
# confianza. Sobre todo, permitía colar `--no-policy` por la puerta de atrás
# saltándose el campo explícito que existe para decidirlo.
_ALLOWED_EXTRA_FLAGS = {
    "--max-turns", "--timeout", "--thinking-budget", "--safety-rpm",
    "--reasoning-model", "--hint", "--no-safety",
}
_VALUELESS_EXTRA_FLAGS = {"--no-safety"}


def _check_extra_args(v: Optional[List[str]]) -> Optional[List[str]]:
    if not v:
        return v
    import re
    i = 0
    while i < len(v):
        flag = v[i]
        if flag not in _ALLOWED_EXTRA_FLAGS:
            raise ValueError(
                f"flag no permitido en extra_args: {flag!r}. "
                f"Permitidos: {sorted(_ALLOWED_EXTRA_FLAGS)}. "
                "Para desactivar el PolicyEngine usa el campo `disable_policy`."
            )
        i += 1
        if flag in _VALUELESS_EXTRA_FLAGS:
            continue
        if i >= len(v):
            raise ValueError(f"{flag} requiere un valor")
        value = v[i]
        if not re.match(r"^[\w.:\-/ ]{1,200}$", value):
            raise ValueError(f"valor no permitido para {flag}: {value!r}")
        i += 1
    return v


def _check_audit_id(v: str) -> str:
    """`audit_id` acaba componiendo una ruta de fichero (`_log_path`).

    Se restringe a la forma que genera `_make_audit_id` —timestamp con sufijo
    opcional de desempate— en lugar de confiar en que el prefijo y la extensión
    contengan la cadena. Coherente con el resto de fronteras de la API, donde la
    validación de entrada es una capa de contención y no una comodidad.
    """
    import re
    if not re.match(r"^\d{8}_\d{6}(_\d+)?$", v or ""):
        raise HTTPException(status_code=400,
                            detail=f"audit_id con formato inválido: {v!r}")
    return v


class StartAuditPayload(BaseModel):
    target_ip: str = Field(..., description="IP del dispositivo objetivo (ej. 192.168.1.1)")
    model: Optional[str] = Field(default=None, description="Modelo LLM (--model)")
    disable_policy: bool = Field(
        default=False,
        description=("Desactiva el PolicyEngine (--no-policy): MODO INVESTIGACIÓN. "
                     "El agente pasa a ejecutar con shell directo, sin allowlist. "
                     "Por defecto la política está ACTIVA."),
    )
    extra_args: Optional[List[str]] = Field(
        default=None,
        description="Args extra para run.py (lista de strings; ej: ['--max-turns', '50'])",
    )

    @field_validator("target_ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        return _check_ipv4(v)

    @field_validator("model")
    @classmethod
    def _validate_model(cls, v: Optional[str]) -> Optional[str]:
        return _check_model(v)

    @field_validator("extra_args")
    @classmethod
    def _validate_extra_args(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        return _check_extra_args(v)


class StartBatchPayload(BaseModel):
    target_ips: List[str] = Field(
        ..., min_length=1, max_length=16,
        description="IPs objetivo; se lanza una auditoría concurrente por cada una",
    )
    runs_per_target: int = Field(
        default=1, ge=1, le=10,
        description="Auditorías a lanzar por cada target (réplicas para análisis de varianza)",
    )
    model: Optional[str] = Field(default=None, description="Modelo LLM (--model), común a todas")
    disable_policy: bool = Field(
        default=False,
        description="Desactiva el PolicyEngine en todas las auditorías del lote "
                    "(modo investigación). Por defecto ACTIVO.",
    )
    modo: str = Field(
        default="secuencial",
        description=("Cómo se reparte la tanda. `secuencial`: una auditoría a "
                     "la vez, sea cual sea el objetivo — máxima comparabilidad "
                     "entre réplicas, es el modo con el que se midió la varianza "
                     "de la memoria. `por_dispositivo`: un run de cada aparato a "
                     "la vez y las réplicas de cada uno en orden — N veces más "
                     "rápido, a costa de que los runs compitan por la cuota del "
                     "proveedor LLM, la red y la CPU."),
    )
    concurrent: bool = Field(
        default=False,
        description="Alias histórico de modo='por_dispositivo'. Se conserva "
                    "para no romper clientes; usa `modo`.",
    )

    @field_validator("modo")
    @classmethod
    def _validate_modo(cls, v: str) -> str:
        if v not in MODOS_DE_TANDA:
            raise ValueError(
                f"modo desconocido: {v!r}; admitidos: {sorted(MODOS_DE_TANDA)}")
        return v
    extra_args: Optional[List[str]] = Field(
        default=None, description="Args extra para run.py, comunes a todas")

    @field_validator("target_ips")
    @classmethod
    def _validate_ips(cls, v: List[str]) -> List[str]:
        seen: List[str] = []
        for ip in v:
            _check_ipv4(ip)
            if ip not in seen:  # dedupe preservando orden
                seen.append(ip)
        return seen

    @field_validator("model")
    @classmethod
    def _validate_model(cls, v: Optional[str]) -> Optional[str]:
        return _check_model(v)

    @field_validator("extra_args")
    @classmethod
    def _validate_extra_args(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        return _check_extra_args(v)


@router.post("")
async def start_audit(payload: StartAuditPayload) -> dict:
    mgr = audit_runner.get_manager()
    audit = await mgr.enqueue(
        target_ip=payload.target_ip,
        model=payload.model,
        extra_args=payload.extra_args,
        policy_disabled=payload.disable_policy,
    )
    return audit.as_summary()


@router.post("/batch")
async def start_audits_batch(payload: StartBatchPayload) -> dict:
    """Lanza auditorías para los targets marcados en el dashboard.

    El reparto lo elige `modo`:

    · `secuencial` (por defecto) — **una auditoría a la vez**, sea cual sea el
      objetivo. Dos runs simultáneos contra el mismo dispositivo se interfieren,
      pero es que incluso contra dispositivos distintos comparten la cuota del
      proveedor LLM, la red del anfitrión y la base de conocimiento, y esa
      competencia degrada la comparabilidad entre réplicas —que es justo lo que
      el análisis de varianza necesita—.

    · `por_dispositivo` — un run de cada aparato a la vez, y las réplicas de
      cada uno estrictamente en orden. Con tres dispositivos por cinco réplicas
      pasa de quince tandas en serie a cinco rondas de tres. Nunca hay dos runs
      contra el MISMO aparato, que es la única interferencia física; lo que se
      acepta a cambio es la competencia por los recursos compartidos.

    Devuelve la primera auditoría de cada target; el resto aparece en
    GET /api/audits con su posición en la cola de su carril.
    """
    mgr = audit_runner.get_manager()
    audits = []
    for ip in payload.target_ips:
        audit = await mgr.start_replicas(
            ip, payload.runs_per_target,
            model=payload.model, extra_args=payload.extra_args,
            policy_disabled=payload.disable_policy,
            modo=("por_dispositivo" if payload.concurrent else payload.modo))
        audits.append(audit.as_summary())
    return {"audits": audits}


@router.get("")
async def list_audits() -> dict:
    mgr = audit_runner.get_manager()
    return {"audits": await mgr.list()}


@router.get("/{audit_id}")
async def get_audit(audit_id: str) -> dict:
    mgr = audit_runner.get_manager()
    audit = await mgr.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail=f"audit {audit_id} no encontrado")
    return audit.as_summary()


@router.post("/{audit_id}/stop")
async def stop_audit(audit_id: str) -> dict:
    """Detiene una auditoría en curso (mata run.py y todo su árbol de procesos)."""
    mgr = audit_runner.get_manager()
    audit = await mgr.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail=f"audit {audit_id} no encontrado")
    if audit.exit_code is not None:
        return audit.as_summary()  # ya había terminado: idempotente
    await mgr.stop(audit_id)
    return audit.as_summary()


@router.get("/{audit_id}/log", response_class=PlainTextResponse)
async def get_audit_log(audit_id: str) -> str:
    """Devuelve el log completo del audit (vivo o histórico) como texto plano."""
    path = audit_runner._log_path(_check_audit_id(audit_id))  # noqa: SLF001
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="log no encontrado")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@router.websocket("/{audit_id}/stream")
async def stream_audit(websocket: WebSocket, audit_id: str) -> None:
    """WS: replay del histórico + tail en vivo del subprocess.

    Mensajes:
      {"type": "line", "data": "<stdout line>", "n": int, "replay"?: true}
      {"type": "done", "exit_code": int, "elapsed_seconds": float, ...}
      {"type": "error", "data": str}
    """
    await websocket.accept()
    mgr = audit_runner.get_manager()
    audit = await mgr.attach(audit_id, websocket)
    if not audit:
        await websocket.send_json({"type": "error", "data": f"audit {audit_id} no existe"})
        await websocket.close(code=4004)
        return
    try:
        # Mantenemos la conexión viva hasta que el cliente cierre o el subprocess
        # termine. El broadcast es server-push; aquí sólo escuchamos disconnects.
        while True:
            try:
                await websocket.receive_text()  # ping/keepalive opcional del cliente
            except WebSocketDisconnect:
                break
    finally:
        await mgr.detach(audit_id, websocket)
