"""
Entry CLI: agente IoT autónomo sobre Claude (Anthropic / AWS Bedrock).

Uso:
  python run.py --target 192.168.1.36
  python run.py --target 192.168.1.36 --model claude-sonnet-4-6
  python run.py --target 192.168.1.36 --confirm
  python run.py --target 192.168.1.36 --max-turns 60

El bucle de razonamiento vive en `ClaudeAgent`, que implementa el contrato
común de `BaseReActAgent`: la capa de herramientas, la gobernanza de severidad
y el reporte son independientes del proveedor y no cambian si se añade otro.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from typing import Any, Dict

from dotenv import load_dotenv
from loguru import logger

# stdout line-buffered: cuando la salida NO va a una terminal (dashboard, fichero,
# `| tee`), Python bloquea-buffer stdout y el stream "bonito" (print) aparece a
# trozos DESPUÉS de los logs de loguru (stderr), dando la falsa impresión de que
# la auditoría se reinicia. Forzar line-buffering lo mantiene en orden y en vivo.
try:
    sys.stdout.reconfigure(line_buffering=True)
except (AttributeError, ValueError):
    pass

# Project root into sys.path para imports uniformes
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# IMPORTANTE: load_dotenv() ANTES de importar los módulos del agente.
# DEFAULT_MODEL se evalúa en tiempo de import (os.getenv("MODEL_NAME", ...)).
load_dotenv()

from core import tools as toolbox
from core.claude_agent import ClaudeAgent, ClaudeConfig
from core.claude_agent import DEFAULT_MODEL as CLAUDE_DEFAULT_MODEL

DEFAULT_MODEL = os.getenv("MODEL_NAME", CLAUDE_DEFAULT_MODEL)


class AbortadaPorSenal(BaseException):
    """Parada externa: Ctrl+C, o el SIGTERM del botón «detener» del panel.

    Hereda de `BaseException`, no de `Exception`, a propósito: el bucle del
    agente captura `Exception` en varios sitios para convertir fallos del
    proveedor en un `finish_reason` y seguir. Una parada del usuario no es un
    fallo recuperable y no debe caer en ninguna de esas redes.
    """


def _instalar_manejadores_de_parada() -> None:
    """Convierte SIGINT/SIGTERM en una excepción, para poder cerrar con orden.

    Sin esto, «detener» significaba perder el run: el panel manda `SIGTERM` al
    grupo de procesos y Python muere en el acto, sin escribir informe. Ahora la
    señal levanta `AbortadaPorSenal`, el envoltorio de `BaseReActAgent.run`
    rescata el informe con lo que haya, y el proceso sale por su propio pie.

    El manejador se rearma a SIG_DFL en cuanto dispara: si el cierre ordenado se
    atasca —una escritura lenta, un hijo que no muere— la SEGUNDA señal mata sin
    contemplaciones, que es lo que el usuario espera al pulsar dos veces. El
    panel escala a `SIGKILL` a los cinco segundos de todos modos.
    """
    def _manejador(signum, _frame):
        signal.signal(signum, signal.SIG_DFL)
        raise AbortadaPorSenal(signal.Signals(signum).name)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _manejador)
        except (ValueError, OSError):
            # `signal.signal` solo funciona en el hilo principal. Si el agente
            # se conduce embebido desde otro hilo, se sigue sin manejador.
            pass


def _human_confirm(tool_name: str, args: Dict[str, Any]) -> bool:
    """Modo --confirm: pregunta por stdin antes de cada tool sensible."""
    print(f"\n⚠️  Tool sensible: {tool_name}")
    print("    args:", json.dumps(args, indent=2, ensure_ascii=False)[:800])
    try:
        answer = input("    Aprobar ejecución? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes", "s", "si", "sí")


def build_goal(target_ip: str, extra_hint: str = "") -> str:
    hint = f"\n\nContexto adicional del usuario: {extra_hint}" if extra_hint else ""
    return (
        f"Objetivo de auditoría autorizada: dispositivo IoT en {target_ip}.\n\n"
        "Ejecuta el pipeline completo (recon → fingerprinting → CVE search → verificación → reporte). "
        "Registra cada CVE probado con record_finding (confirmed=true/false) y al finalizar llama a "
        "save_report seguido de done(summary).\n\n"
        "Planifica cada paso antes de llamar a una tool. Si una fuente no aporta, salta a la siguiente."
        f"{hint}"
    )


def _is_claude_model(model: str) -> bool:
    """Detecta modelos Claude: directo, Bedrock (anthropic.) o inference profile (us./eu./...).

    Ya no elige entre proveedores —solo hay uno— sino que valida la
    configuración: un `--model` que no sea de esta familia no lo va a atender
    nadie, y conviene decirlo con una línea legible en vez de dejar que falle
    dentro del SDK varios segundos después.
    """
    m = model.lower()
    return (
        m.startswith("claude-")
        or m.startswith("anthropic.")
        or m.startswith("us.anthropic.")
        or m.startswith("eu.anthropic.")
        or m.startswith("ap.anthropic.")
        or m.startswith("au.anthropic.")
        or m.startswith("jp.anthropic.")
        or m.startswith("global.anthropic.")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="IoT autonomous pentester (Claude)")
    parser.add_argument("--target", required=True, help="IP objetivo")
    parser.add_argument("--confirm", action="store_true",
                        help="Pedir confirmación humana antes de cada comando ofensivo.")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-aprobar todos los comandos sin pedir confirmación.")
    parser.add_argument("--no-policy", action="store_true",
                        help="MODO INVESTIGACIÓN: desactiva el PolicyEngine. El agente "
                             "ejecuta con shell=True y sin allowlist. Úsalo solo en "
                             "laboratorio y sabiendo que la contención de OE2 no aplica.")
    parser.add_argument("--no-safety", action="store_true",
                        help="Desactivar SafetyMonitor (rate-limit + kill-switch). "
                             "Útil para lab/CI donde el target tolera carga alta.")
    parser.add_argument("--safety-rpm", type=int, default=60,
                        help="Presupuesto de SafetyMonitor en requests/minuto (default 60).")
    parser.add_argument("--max-turns", type=int, default=150,
                        help="Límite de turnos (default 150). 0 = sin límite. "
                             "Las auditorías sanas de campo acaban entre 27 y 65 "
                             "turnos; 150 es techo, no presupuesto.")
    parser.add_argument("--timeout", type=int, default=7200,
                        help="Wall-clock timeout total en segundos (default 7200 = 2h).")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--reasoning-model", default=os.getenv("REASONING_MODEL") or None,
                        help="Modelo para planner+reflexión (p. ej. un Opus para razonar, "
                             "mientras --model barato corre las sondas). Mismo proveedor.")
    parser.add_argument("--thinking-budget", type=int, default=8000,
                        help="Tokens de thinking (Claude extended thinking).")
    parser.add_argument("--hint", default="", help="Pista libre para el agente.")
    args = parser.parse_args()

    # Log a consola simple
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="<level>{level}</level> {message}")

    # Configurar flags globales
    if args.no_policy:
        toolbox.set_no_policy(True)
        # El aviso es deliberadamente enfático: este flag aparecía en todos los
        # ejemplos de la documentación y en el lanzador del dashboard, de modo
        # que el modo excepcional se había vuelto el habitual sin que nadie lo
        # decidiera. Que se vea en la primera línea del log de cada run.
        print("=" * 68)
        print("⚠️  MODO INVESTIGACIÓN — PolicyEngine DESACTIVADO")
        print("    Los comandos se ejecutan con shell=True y SIN allowlist.")
        print("    Las garantías de contención (OE2) NO aplican en este run.")
        print("=" * 68)
        logger.warning("[RUN] PolicyEngine desactivado (--no-policy): shell directo")

    # Determinar callback de confirmación
    if args.auto:
        confirm_cb = lambda name, a: True
    elif args.confirm:
        confirm_cb = _human_confirm
    else:
        confirm_cb = None

    if not _is_claude_model(args.model):
        print(f"❌ Modelo no soportado: {args.model}")
        print("   El agente opera sobre Claude (Anthropic o AWS Bedrock).")
        print("   Ejemplos: claude-sonnet-4-6, us.anthropic.claude-haiku-4-5-20251001-v1:0")
        return 2

    # Bind session (target + findings accumulator)
    session = toolbox.AgentSession(target_ip=args.target)
    session.model_name = args.model
    session.provider = "Anthropic/Claude"
    toolbox.bind_session(session)

    # SafetyMonitor + Telemetry — defaults sensatos para auditorías reales.
    # Safety se activa salvo --no-safety. Telemetry siempre activa (overhead nulo).
    if not args.no_safety:
        toolbox.attach_safety_monitor(requests_per_minute=args.safety_rpm)
    toolbox.attach_telemetry()

    cfg = ClaudeConfig(
        model=args.model,
        reasoning_model=args.reasoning_model,
        max_turns=args.max_turns,
        wall_clock_seconds=args.timeout,
        thinking_budget=args.thinking_budget,
        confirm_callback=confirm_cb,
    )
    agent = ClaudeAgent(config=cfg)
    provider = "Anthropic/Claude"

    goal = build_goal(args.target, args.hint)
    print(f"🎯 Target:    {args.target}")
    print(f"🤖 Model:     {args.model}  [{provider}]")
    turns_str = str(args.max_turns) if args.max_turns else "∞"
    mode = "AUTO" if args.auto else ("CONFIRM" if args.confirm else "SILENT")
    policy_str = "OFF" if args.no_policy else "ON"
    print(f"⏱️  Budget:    {turns_str} turns / {args.timeout}s wall-clock")
    safety_str = "OFF" if args.no_safety else f"{args.safety_rpm} req/min"
    print(f"🔐 Policy:    {policy_str}  |  Confirm: {mode}  |  Safety: {safety_str}\n")

    _instalar_manejadores_de_parada()

    try:
        result = agent.run(goal)
    except AbortadaPorSenal as e:
        # El informe ya lo ha rescatado `BaseReActAgent.run` antes de propagar.
        print("\n" + "=" * 60)
        print(f"⏹  Auditoría detenida por {e} — informe guardado con lo obtenido.")
        try:
            saved = toolbox.get_session().report_saved_path
            if saved:
                print(f"📄 {saved}.[json|md|html|sarif]")
        except RuntimeError:
            pass
        return 130  # convenio: 128 + SIGINT

    print("\n" + "=" * 60)
    print(f"✅ finish_reason: {result['finish_reason']}")
    print(f"📊 turns: {result['turns']}  elapsed: {result['elapsed_seconds']:.1f}s")
    print(f"🔍 findings: {len(result['findings'])}")
    if result["credentials"]:
        print(f"🔑 credentials: {len(result['credentials'])}")
    if result["summary"]:
        print(f"\n📝 Summary:\n{result['summary']}")
    return 0 if result["finish_reason"] == "done_called" else 1


if __name__ == "__main__":
    raise SystemExit(main())
