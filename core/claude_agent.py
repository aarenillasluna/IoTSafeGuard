"""
Agente autónomo Claude (Anthropic) — loop tool-use con extended thinking.

Implementa el contrato de `BaseReActAgent`: `run(goal) -> dict`.

Particularidades de este SDK, que son la razón de que el bucle de tool use no
se abstraiga en la clase base:
  - Cliente `anthropic.Anthropic` (o `AnthropicBedrock` según credencial).
  - Historial: lista de dicts {role, content}.
  - Tool use: bloques `tool_use` / `tool_result`.
  - Extended thinking: parámetro `thinking={"type":"enabled","budget_tokens":N}`.
  - System prompt: kwarg `system=` en messages.create(), no en el historial.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import anthropic
from anthropic import AnthropicBedrock
from loguru import logger

from core import tools as toolbox
from core.base_agent import BaseReActAgent
from core.agent_guards import (
    RepetitionDetector,
    SterileStreakDetector,
    build_repetition_warning,
    build_sterile_warning,
    build_validation_hint,
    looks_like_validation_error,
)
from core.knowledge_base import get_kb
from core.observability import get_observer
from core.prompts import get_phase_prompt, get_planner_prompt
from core.severity import compute_risk_score, is_confirmed_vuln
from core.reflection import (
    apply_reflection_to_kb,
    generate_reflection,
    persist_reflection,
)


DEFAULT_MODEL = os.getenv("MODEL_NAME", "claude-sonnet-4-6")
FALLBACK_MODEL = "claude-haiku-4-5-20251001"

INITIAL_PHASE = "recon"

# Modelos que soportan extended thinking.
_THINKING_CAPABLE = ("claude-opus", "claude-sonnet", "claude-haiku", "anthropic.claude")


def _supports_thinking(model: str) -> bool:
    return any(model.startswith(p) for p in _THINKING_CAPABLE)


def _is_bedrock_model(model: str) -> bool:
    """Detecta si hay que usar AnthropicBedrock: por prefijo de modelo o vars AWS."""
    m = model.lower()
    has_aws_prefix = (
        m.startswith("anthropic.")
        or m.startswith("us.anthropic.")
        or m.startswith("eu.anthropic.")
        or m.startswith("ap.anthropic.")
        or m.startswith("au.anthropic.")
        or m.startswith("jp.anthropic.")
        or m.startswith("global.anthropic.")
    )
    has_aws_env = bool(
        os.getenv("AWS_BEARER_TOKEN_BEDROCK") or os.getenv("AWS_ACCESS_KEY_ID")
    )
    return has_aws_prefix or has_aws_env


def _bedrock_fallback(model: str) -> str:
    """Infiere el modelo fallback Bedrock preservando el prefijo de región."""
    prefix = ""
    for p in ("us.", "eu.", "ap."):
        if model.startswith(p):
            prefix = p
            break
    return f"{prefix}anthropic.claude-3-5-haiku-20241022-v1:0"


def _make_client(model: str, api_key: Optional[str]) -> Any:
    """Crea cliente Anthropic directo o AnthropicBedrock según el entorno.

    Prioridad para Bedrock:
      1. AWS_BEARER_TOKEN_BEDROCK  → API key de larga duración (sin IAM)
      2. AWS_ACCESS_KEY_ID + SECRET → credenciales IAM clásicas
    """
    if _is_bedrock_model(model):
        aws_region = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION", "us-east-1")
        bearer = os.getenv("AWS_BEARER_TOKEN_BEDROCK")
        aws_key = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")

        if bearer:
            # API key de larga duración — el SDK la lee del env automáticamente
            logger.info(f"[AGENT] usando AnthropicBedrock con bearer token (región: {aws_region})")
            return AnthropicBedrock(aws_region=aws_region)
        elif aws_key and aws_secret:
            logger.info(f"[AGENT] usando AnthropicBedrock con IAM (región: {aws_region})")
            return AnthropicBedrock(
                aws_access_key=aws_key,
                aws_secret_key=aws_secret,
                aws_region=aws_region,
            )
        else:
            raise RuntimeError(
                "Para usar Bedrock necesitas AWS_BEARER_TOKEN_BEDROCK "
                "(API key larga duración) o AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (IAM)"
            )
    # Cliente directo Anthropic
    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY no configurada")
    return anthropic.Anthropic(api_key=key)


def _mark_last_message_cache(messages: list) -> list:
    """Devuelve `messages` con un *cache breakpoint* en el último mensaje, sin
    mutar el historial. Permite que el prefijo creciente (turnos anteriores) se
    sirva desde caché en el siguiente turno. Defensivo: si el contenido del
    último mensaje contiene objetos del SDK (no dicts), no lo toca.
    """
    if not messages:
        return messages
    last = messages[-1]
    content = last.get("content")
    try:
        if isinstance(content, str):
            new_content = [{"type": "text", "text": content,
                            "cache_control": {"type": "ephemeral"}}]
        elif isinstance(content, list) and content and all(
                isinstance(b, dict) for b in content):
            new_content = [dict(b) for b in content]
            new_content[-1] = {**new_content[-1],
                               "cache_control": {"type": "ephemeral"}}
        else:
            return messages  # contiene bloques del SDK → no marcar (seguro)
        return messages[:-1] + [{**last, "content": new_content}]
    except Exception:
        return messages


@dataclass
class ClaudeConfig:
    model: str = DEFAULT_MODEL
    # Modelo para los pasos de RAZONAMIENTO (planner + reflexión): puede ser más
    # capaz que el del bucle (p. ej. Opus para planificar/reflexionar y Haiku,
    # barato, para las sondas mecánicas). Si None, usa `model`.
    reasoning_model: Optional[str] = None
    max_turns: int = 0
    wall_clock_seconds: int = 7200
    thinking_budget: int = 8000
    confirm_callback: Optional[Callable[[str, dict], bool]] = None
    enable_planner: bool = True
    repetition_threshold: int = 3
    # Guarda de esterilidad: turnos consecutivos sin información nueva. Aviso a
    # los 10, corte a los 25. Los valores salen de la tanda de campo: las
    # réplicas sanas dieron entre 27 y 65 turnos EN TOTAL con los hallazgos
    # repartidos, mientras que la réplica atascada encadenó 234 turnos estériles
    # seguidos. 25 deja margen de sobra a un barrido legítimo que no encuentra
    # nada, y queda muy por debajo de la patología.
    sterile_warn_after: int = 10
    sterile_stop_after: int = 25
    enable_validation_hints: bool = True
    initial_phase: str = INITIAL_PHASE
    enable_kb: bool = True
    enable_reflection: bool = True


class ClaudeAgent(BaseReActAgent):
    def __init__(self, api_key: Optional[str] = None, config: Optional[ClaudeConfig] = None):
        self.cfg = config or ClaudeConfig()
        self.client = _make_client(self.cfg.model, api_key)
        # Cliente/modelo de razonamiento (planner + reflexión). Si se pidió un
        # modelo distinto, se crea su propio cliente (soporta otro proveedor).
        if self.cfg.reasoning_model and self.cfg.reasoning_model != self.cfg.model:
            self.reasoning_model = self.cfg.reasoning_model
            try:
                self.reasoning_client = _make_client(self.reasoning_model, api_key)
                logger.info(f"[AGENT] razonamiento (planner+reflexión) → {self.reasoning_model}")
            except Exception as e:
                logger.warning(f"[AGENT] reasoning_model no disponible ({e}); uso {self.cfg.model}")
                self.reasoning_model = self.cfg.model
                self.reasoning_client = self.client
        else:
            self.reasoning_model = self.cfg.model
            self.reasoning_client = self.client
        self.observer = get_observer()
        self.current_phase: str = self.cfg.initial_phase
        self._tools_invoked: List[str] = []
        self._cve_search_results: List[str] = []
        self.kb = get_kb() if self.cfg.enable_kb else None

    # ------------------------------------------------------------------
    # LLM call helper — builds kwargs depending on thinking support
    # ------------------------------------------------------------------
    def _create_kwargs(self, messages: list, system: str) -> dict:
        """Construye los kwargs para messages.create() según el modelo.

        **Prompt caching**: marca `cache_control: ephemeral` en el prefijo estable
        (system + tools) y en el último mensaje, de modo que el prefijo repetido
        —system prompt + las ~25 tool-schemas + el historial acumulado— se sirva
        desde caché (~90% más barato) en lugar de re-facturarse como input nuevo
        en CADA turno. Es lo que hace que el coste de input no crezca de forma
        brutal en runs largos (decenas de turnos).
        """
        tools = toolbox.list_claude_tools(phase=self.current_phase)
        if tools:  # cache_control en la última tool → cachea TODO el bloque de tools
            tools = list(tools)
            tools[-1] = {**tools[-1], "cache_control": {"type": "ephemeral"}}
        base: dict = {
            "model": self.cfg.model,
            # system como bloque con cache_control (en vez de string suelto)
            "system": [{"type": "text", "text": system,
                        "cache_control": {"type": "ephemeral"}}],
            "tools": tools,
            "messages": _mark_last_message_cache(messages),
        }
        if _supports_thinking(self.cfg.model):
            base["thinking"] = {
                "type": "enabled",
                "budget_tokens": self.cfg.thinking_budget,
            }
            # Con thinking activado la temperatura debe ser 1 (valor por defecto).
            base["max_tokens"] = self.cfg.thinking_budget + 8192
        else:
            base["temperature"] = 0.2
            base["max_tokens"] = 8192
        return base

    # ------------------------------------------------------------------
    # Planner: llamada sin tools para generar plan inicial
    # ------------------------------------------------------------------
    def _plan(self, goal: str) -> str:
        prompt = get_planner_prompt(goal)
        try:
            with self.observer.generation(
                name="planner",
                model=self.reasoning_model,
                input=prompt,
                metadata={"phase": "planning"},
            ) as gen:
                resp = self.reasoning_client.messages.create(
                    model=self.reasoning_model,
                    max_tokens=512,
                    temperature=1,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = resp.content[0].text if resp.content else ""
                u = getattr(resp, "usage", None)
                if u is not None:
                    gen.update(usage_details={
                        "input": getattr(u, "input_tokens", 0) or 0,
                        "output": getattr(u, "output_tokens", 0) or 0,
                    })
                gen.update(output=text)
            return text.strip()
        except Exception as e:
            logger.warning(f"[PLANNER] error: {e}")
            return ""

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    # run() y los helpers _extract_device_metadata /
    # _append_reflection_link_to_latest_report viven en BaseReActAgent (iter_10).

    def _run_inner(self, goal: str, root_trace) -> dict:
        # Historial: lista de dicts {role, content}
        messages: List[Dict[str, Any]] = [
            {"role": "user", "content": goal}
        ]

        # ---- Plan opcional ----
        if self.cfg.enable_planner:
            plan = self._plan(goal)
            if plan:
                print(f"\n📋 [PLAN]\n{plan}\n")
                plan_msg = f"Plan de auditoría:\n{plan}\n\nProcedo con la fase 1."
                messages.append({"role": "assistant", "content": plan_msg})

        repetition = RepetitionDetector(threshold=self.cfg.repetition_threshold)
        sterility = SterileStreakDetector(
            threshold=self.cfg.sterile_warn_after,
            hard_limit=self.cfg.sterile_stop_after)
        t_start = time.time()
        turns = 0
        finish_reason = "budget_exhausted"
        summary = ""
        self._consecutive_text_only = 0
        self._quota_retries = 0
        self._quota_hits_total = 0
        self._connection_retries = 0

        while self.cfg.max_turns == 0 or turns < self.cfg.max_turns:
            if time.time() - t_start > self.cfg.wall_clock_seconds:
                finish_reason = "wall_clock_timeout"
                break

            turns += 1
            # El turno se publica en la sesión turno a turno, no al final: si el
            # run se corta a mitad, el informe de rescate necesita saber cuántos
            # llegó a dar, y solo el bucle lo sabe.
            self._publish_turn(turns)
            # La sesión debe conocer la fase activa: de ella dependen las
            # restricciones deterministas por fase (solo lectura en recon).
            toolbox.set_phase(self.current_phase)
            system_prompt = get_phase_prompt(self.current_phase)

            try:
                with self.observer.generation(
                    name=f"llm_turn_{turns}",
                    model=self.cfg.model,
                    input={"turn": turns, "history_len": len(messages)},
                    metadata={"turn": turns, "phase": self.current_phase},
                ) as gen:
                    kwargs = self._create_kwargs(messages, system_prompt)
                    resp = self.client.messages.create(**kwargs)
                    # Reportar uso de tokens a Langfuse (input/output + caché).
                    u = getattr(resp, "usage", None)
                    if u is not None:
                        gen.update(usage_details={
                            "input": getattr(u, "input_tokens", 0) or 0,
                            "output": getattr(u, "output_tokens", 0) or 0,
                            "cache_read_input_tokens":
                                getattr(u, "cache_read_input_tokens", 0) or 0,
                            "cache_creation_input_tokens":
                                getattr(u, "cache_creation_input_tokens", 0) or 0,
                        })
                    gen.update(metadata={
                        "stop_reason": resp.stop_reason,
                        "phase": self.current_phase,
                    })
            except anthropic.RateLimitError as e:
                logger.error(f"[AGENT] rate limit turn {turns}: {e}")
                self._quota_retries += 1
                total = self._record_rate_limit_hit()
                m = re.search(r"retry.after[^\d]*(\d+(?:\.\d+)?)", str(e), re.IGNORECASE)
                delay = self._backoff_seconds(
                    self._quota_retries, float(m.group(1)) if m else None)
                if self._quota_retries <= 6:
                    logger.warning(
                        f"[AGENT] rate limit: esperando {delay}s "
                        f"({self._quota_retries}/6, {total} en el run)")
                    time.sleep(delay)
                    turns -= 1
                    continue
                fallback = _bedrock_fallback(self.cfg.model) if _is_bedrock_model(self.cfg.model) else FALLBACK_MODEL
                if self.cfg.model != fallback:
                    logger.warning(f"[AGENT] switching to fallback {fallback}")
                    self.cfg.model = fallback
                    turns -= 1
                    continue
                finish_reason = f"rate_limit: {e}"
                break
            except anthropic.AuthenticationError as e:
                logger.error(f"[AGENT] autenticación fallida: {e}")
                logger.error("[AGENT] Verifica ANTHROPIC_API_KEY en tu .env")
                finish_reason = f"auth_error: {e}"
                break
            except anthropic.APIStatusError as e:
                err_str = str(e)
                logger.error(f"[AGENT] API error turn {turns}: {e}")
                is_overload = e.status_code == 529 or "overloaded" in err_str.lower()
                if is_overload:
                    self._quota_retries += 1
                    if self._quota_retries <= 6:
                        logger.warning(f"[AGENT] overloaded: esperando 10s ({self._quota_retries}/6)")
                        time.sleep(10)
                        turns -= 1
                        continue
                # 401/403 son fallo de CREDENCIAL, no del modelo. El SDK los
                # entrega como `APIStatusError` genérico cuando vienen de
                # Bedrock —`AuthenticationError` solo cubre el 401 directo— así
                # que caían en la rama de abajo y disparaban el cambio al modelo
                # de reserva. Cambiar de modelo con la misma clave no puede
                # funcionar: en campo, una clave caducada produjo 403, salto al
                # fallback, y 403 otra vez, gastando dos llamadas para llegar al
                # mismo sitio. Se corta aquí y con un mensaje que dice qué mirar.
                if e.status_code in (401, 403):
                    finish_reason = f"auth_error: {e}"
                    logger.error(
                        "[AGENT] la credencial del proveedor fue rechazada "
                        f"({e.status_code}). No se reintenta ni se cambia de "
                        "modelo: el fallback usaría la misma clave. Revisa "
                        "AWS_BEARER_TOKEN_BEDROCK / ANTHROPIC_API_KEY en .env")
                    break
                fallback = _bedrock_fallback(self.cfg.model) if _is_bedrock_model(self.cfg.model) else FALLBACK_MODEL
                if self.cfg.model != fallback:
                    logger.warning(f"[AGENT] switching to fallback {fallback}")
                    self.cfg.model = fallback
                    turns -= 1
                    continue
                finish_reason = f"api_error: {e}"
                break
            except anthropic.APIConnectionError as e:
                # Un corte de red transitorio abortaba la auditoría entera. Es
                # el error MÁS probable de todos —wifi, DNS, proxy— y era el
                # único sin reintento: una auditoría de dos horas se perdía por
                # un parpadeo de la conexión. Retroceso exponencial acotado.
                self._connection_retries += 1
                if self._connection_retries <= 5:
                    delay = min(2 ** self._connection_retries, 30)
                    logger.warning(
                        f"[AGENT] error de conexión ({e}); reintento "
                        f"{self._connection_retries}/5 en {delay}s"
                    )
                    time.sleep(delay)
                    turns -= 1
                    continue
                finish_reason = f"connection_error: {e}"
                break
            except Exception as e:
                logger.error(f"[AGENT] unexpected error turn {turns}: {e}")
                finish_reason = f"error: {e}"
                break

            # Turno completado sin incidencias: los contadores de reintento se
            # ponen a cero. Sin esto son ACUMULATIVOS durante todo el run, de
            # modo que seis rate-limits repartidos a lo largo de dos horas
            # degradaban el modelo al fallback de forma permanente aunque entre
            # medias hubiera habido cientos de turnos correctos.
            self._quota_retries = 0
            self._connection_retries = 0

            # ---- Parse response ----
            text_parts: List[str] = []
            tool_use_blocks: List[Any] = []

            for block in resp.content:
                btype = getattr(block, "type", None)
                if btype == "thinking":
                    thought = (getattr(block, "thinking", "") or "").strip()
                    if thought:
                        print(f"\n💭 [THOUGHT turn {turns}]")
                        print(thought)
                elif btype == "text":
                    txt = getattr(block, "text", "") or ""
                    if txt:
                        text_parts.append(txt)
                elif btype == "tool_use":
                    tool_use_blocks.append(block)

            if text_parts:
                print(f"\n📝 [turn {turns}] {''.join(text_parts).strip()}")

            # Append assistant turn to history
            messages.append({"role": "assistant", "content": resp.content})

            # ---- Text-only recovery (sin tool_call) ----
            if not tool_use_blocks:
                self._consecutive_text_only += 1
                if self._consecutive_text_only <= 1:
                    reminder = (
                        "⚠️ Tu turno anterior fue solo texto sin tool_call. "
                        "Recuerda: cada turno debe incluir EXACTAMENTE UNA tool_call.\n\n"
                        "Si tu plan involucra ejecutar varias probes, hazlo una a una "
                        "(una por turno). Llama AHORA la PRIMERA tool de tu plan.\n\n"
                        "Si has completado todos los probes recomendados, llama "
                        "transition_phase(phase='exploit'). Si has terminado la "
                        "auditoría completa, llama done(summary=...)."
                    )
                    messages.append({"role": "user", "content": reminder})
                    print(f"\n⚠️  [GUARD] turno {turns} sin tool_call. Recordatorio inyectado.")
                    logger.info(f"[GUARD] text-only retry {self._consecutive_text_only}/1")
                    turns -= 1
                    continue
                finish_reason = "end_turn_no_tools"
                summary = "".join(text_parts)
                break

            self._consecutive_text_only = 0

            # ---- Execute tool calls ----
            tool_result_content: List[Dict[str, Any]] = []

            for tool_use in tool_use_blocks:
                name: str = tool_use.name
                args: dict = dict(tool_use.input or {})
                logger.info(f"[AGENT] turn {turns} → tool {name}({list(args.keys())})")

                if name not in self._tools_invoked:
                    self._tools_invoked.append(name)

                repeated = repetition.observe(name, args)

                # Human confirmation
                if (
                    toolbox.requires_confirmation(name)
                    and self.cfg.confirm_callback is not None
                ):
                    approved = self.cfg.confirm_callback(name, args)
                    if not approved:
                        tool_result_content.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use.id,
                            "content": json.dumps({
                                "ok": False, "declined": True, "reason": "user_declined"
                            }),
                        })
                        print(f"🚫 Tool '{name}' rechazada por el usuario.")
                        continue

                print(f"\n🔧 [tool {name}] args={args}")

                with self.observer.span(
                    name=f"tool:{name}",
                    input={"args": args},
                    metadata={"turn": turns, "tool": name, "phase": self.current_phase},
                ) as sp:
                    hallazgos_antes = len(toolbox.get_session().findings)
                    result = toolbox.dispatch(name, args)
                    sp.update(output={
                        "ok": result.get("ok"),
                        "elapsed_ms": result.get("_elapsed_ms"),
                        "error": result.get("error"),
                    })

                preview = str(result)[:300].replace("\n", " ")
                print(f"   → {preview}")

                if name == "cve_search":
                    for c in result.get("cves") or []:
                        cve_id = c.get("id")
                        if cve_id and cve_id not in self._cve_search_results:
                            self._cve_search_results.append(cve_id)

                if self.cfg.enable_validation_hints and looks_like_validation_error(result):
                    hint = build_validation_hint(name, args, result)
                    result = dict(result)
                    result["_hint"] = hint
                    logger.info(f"[GUARD] validation hint inyectado para {name}")

                if repeated:
                    warning = build_repetition_warning(
                        name, args, repetition.consecutive,
                        reason=repetition.last_reason or "repetition",
                        cycle_length=repetition.cycle_length)
                    result = dict(result)
                    result["_warning"] = warning
                    logger.warning(f"[GUARD] repetición detectada en {name}")
                    print(f"\n{warning}")

                veredicto = sterility.observe(
                    name, args, result,
                    gained_finding=len(toolbox.get_session().findings) > hallazgos_antes)
                if veredicto:
                    aviso = build_sterile_warning(
                        name, sterility.streak, sterility.last_reason or "sterile_streak")
                    result = dict(result)
                    result["_warning"] = aviso
                    logger.warning(
                        f"[GUARD] esterilidad ({sterility.last_reason}) en {name}: "
                        f"racha={sterility.streak}")
                    print(f"\n{aviso}")
                if veredicto == "stop":
                    # Se le avisó a los `threshold` y siguió enumerando hasta
                    # `hard_limit`. No se le pide otra vez: el bucle termina y el
                    # informe se rescata con lo que haya. Cortar aquí es lo que
                    # convierte un run perdido en un artefacto utilizable.
                    finish_reason = "sterile_enumeration"
                    summary = (
                        f"Auditoría cortada por la guarda de esterilidad tras "
                        f"{sterility.streak} llamadas consecutivas sin información "
                        f"nueva ({sterility.total} en el run).")

                next_phase = result.get("_transition_to")
                if next_phase and next_phase != self.current_phase:
                    logger.success(f"[AGENT] phase: {self.current_phase} → {next_phase}")
                    print(f"\n🔀 [PHASE] {self.current_phase} → {next_phase}")
                    self.current_phase = next_phase
                    repetition.reset()
                    sterility.reset()

                tool_result_content.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": json.dumps(result, ensure_ascii=False, default=str),
                })

                if result.get("_finish"):
                    finish_reason = "done_called"
                    summary = result.get("summary", "")

            messages.append({"role": "user", "content": tool_result_content})

            if finish_reason in ("done_called", "sterile_enumeration"):
                break

        elapsed = time.time() - t_start
        logger.success(
            f"[AGENT] finalizado: reason={finish_reason} turns={turns} elapsed={elapsed:.1f}s"
        )
        session = toolbox.get_session()
        findings = list(session.findings)
        result_dict = {
            "finish_reason": finish_reason,
            "turns": turns,
            "elapsed_seconds": elapsed,
            "summary": summary,
            "findings": findings,
            "credentials": list(session.credentials),
        }
        try:
            root_trace.update(output={
                "finish_reason": finish_reason,
                "turns": turns,
                "findings_count": len(findings),
                "final_phase": self.current_phase,
            })
        except Exception:
            pass

        try:
            self._post_run_self_improvement(goal, result_dict, session)
        except Exception as e:
            logger.warning(f"[AGENT] post-run self-improvement failed: {e}")

        return result_dict

    # ------------------------------------------------------------------
    # Self-improvement: reflexión + KB al cierre de la auditoría.
    # ------------------------------------------------------------------
    def _post_run_self_improvement(self, goal: str, result_dict: dict, session) -> None:
        if not (self.cfg.enable_kb or self.cfg.enable_reflection):
            return

        findings = result_dict["findings"]
        scan = session.scan_cache or {}
        vendor, device_model, firmware = self._extract_device_metadata(findings, scan)
        target_ip = session.target_ip

        risk = compute_risk_score(findings)

        report = None
        if self.cfg.enable_reflection:
            try:
                logger.info("[REFLECTION] generando análisis post-run...")
                report = generate_reflection(
                    client=self.reasoning_client,
                    model=self.reasoning_model,
                    goal=goal,
                    target_ip=target_ip,
                    finish_reason=result_dict["finish_reason"],
                    turns=result_dict["turns"],
                    elapsed=result_dict["elapsed_seconds"],
                    findings=findings,
                    risk_score=risk,
                    tools_invoked=self._tools_invoked,
                    probes_executed=list(session.executed_probes),
                    probes_recommended=list(session.recommended_probes),
                    vendor=vendor,
                    device_model=device_model,
                    firmware=firmware,
                    cve_search_results=self._cve_search_results,
                )
                if report:
                    persist_reflection(report)
                    logger.success(f"[REFLECTION] guardado en {report.json_path}")
                    print(f"\n🪞 [REFLECTION] {report.executive_summary[:200]}")
                    try:
                        session.reflection_report_path = report.md_path or report.json_path
                    except AttributeError:
                        pass
                    self._append_reflection_link_to_latest_report(report.md_path)
            except Exception as e:
                logger.warning(f"[REFLECTION] error: {e}")

        if self.kb is not None and self.cfg.enable_kb:
            try:
                # MAC de las OTRAS interfaces del mismo aparato, extraídas de
                # la evidencia. Sin esto, el televisor que hoy va por cable y
                # mañana por wifi se aprende como dos dispositivos distintos.
                from modules.fingerprint import harvest_macs
                also = [m for m in harvest_macs(scan, session.interrogator_evidence)
                        if m != (scan.get("mac") or "").upper()]
                self.kb.upsert_device(target_ip, {
                    "vendor": vendor,
                    "model": device_model,
                    "firmware": firmware,
                    "mac": scan.get("mac"),
                    "also_macs": also,
                    "os_match": scan.get("os_match"),
                    "ports": [
                        p.get("port") for p in scan.get("ports", [])
                        if isinstance(p, dict)
                    ],
                }, findings)

                if vendor:
                    self.kb.upsert_vendor_profile(
                        vendor,
                        ports_seen=[
                            p.get("port") for p in scan.get("ports", [])
                            if isinstance(p, dict) and p.get("port")
                        ],
                        useful_probes=[
                            p for p in session.executed_probes
                            if p.startswith("probe_")
                        ],
                    )

                # Severidad EFECTIVA (`is_confirmed_vuln`), no el campo crudo
                # `confirmed`: un CVE descartado que el modelo registra como
                # INFO/confirmed=True —«comprobado que NO aplica»— es un
                # resultado NEGATIVO. Darlo por confirmado borraba el CVE de
                # `patched_cves` y hacía que la KB desaprendiese lo que el run
                # acababa de demostrar.
                for f in findings:
                    cve_id = f.get("cve_id") or ""
                    if cve_id.startswith("CVE-"):
                        self.kb.record_cve_test(
                            cve_id,
                            confirmed=is_confirmed_vuln(f),
                            vendor=vendor,
                        )

                self.kb.increment_run_stats(
                    findings=len(findings),
                    confirmed=sum(1 for f in findings if is_confirmed_vuln(f)),
                )

                if report:
                    apply_reflection_to_kb(report, self.kb, vendor=vendor)

                self.kb.save()
                snap = self.kb.snapshot()
                logger.info(
                    f"[KB] persisted — total runs: {snap['runs_total']}, "
                    f"vendors known: {snap['vendors_known']}"
                )
            except Exception as e:
                logger.warning(f"[KB] update failed: {e}")
