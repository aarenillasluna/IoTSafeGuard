"""
Generador de reflection report tras cada run del agente.

Este módulo es la base de la capacidad **auto-mejorativa** del sistema:
tras cada auditoría, se hace UNA llamada LLM adicional (no parte del loop
agente) que analiza el run completo y produce feedback estructurado.

El reporte se persiste en `reports/reflections/<timestamp>.json` y `.md`.
La KB indexa la lista de reflections para análisis acumulado.

Pipeline:
  1. Recopilamos contexto: goal, findings, tools usadas, vendor detectado, etc.
  2. Llamada al LLM con un prompt específico de "auditor reviewer".
  3. Parseo del JSON output, validación de schema mínimo.
  4. Persistencia + actualización del KB.

Este es el bucle de meta-aprendizaje: el agente NO lo lee directamente, pero
operaciones futuras (tu próximo PR, otros runs) pueden usar las suggestions
acumuladas como roadmap.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from loguru import logger

from core.fsutil import publish_artifact, publish_dir
from core.severity import effective_severity, is_confirmed_vuln


# Prompt en inglés, como el resto de la superficie que ve el modelo (§4.4).
#
# Con una cautela que este cambio hace obligatoria: el reporte de reflexión es
# un ARTEFACTO que se archiva y se lee, igual que el informe de auditoría. Sin
# la directiva de idioma explícita, traducir el prompt habría traducido en
# silencio la salida —exactamente el efecto que iter_18 documenta y que la
# directiva `<output_language>` de los prompts de fase existe para evitar—. El
# agente razona en inglés; el contenido del reporte se escribe en español.
REFLECTION_PROMPT = """You are a senior reviewer of autonomous IoT security audits. You have just
received the summarised log of an agent run. Your task: produce a structured
report that serves as feedback to improve the system.

RUN DATA:
  - goal: {goal}
  - target_ip: {target_ip}
  - finish_reason: {finish_reason}
  - turns: {turns}
  - elapsed_seconds: {elapsed}
  - vendor_detected: {vendor}
  - model_detected: {model}
  - firmware_detected: {firmware}
  - findings_total: {findings_total}
  - findings_confirmed: {findings_confirmed}
  - risk_score: {risk_score}
  - tools_invoked: {tools_invoked}
  - probes_executed: {probes_executed}
  - probes_recommended_but_skipped: {probes_skipped}
  - cve_search_results: {cve_search_results}

FINDINGS:
{findings_summary}

Note on the findings above: a finding is marked CONFIRMED only when the
governance layer accepts it as a vulnerability. `LOW←CRITICAL` means the agent
claimed CRITICAL and the policy capped it to LOW for lack of a demonstrated
impact class or of practical proof — that gap is worth calling out.

OUTPUT LANGUAGE:
Reason in English, but write every human-readable value of the JSON below in
**Spanish**: this report is archived alongside the Spanish-language audit
report and is read by the operator. Keep the JSON keys, the enum values
("high|medium|low", the `area` values) and every identifier (CVE-…, probe_…)
exactly as specified — those are data, not prose.

INSTRUCTIONS:
Return EXCLUSIVELY valid JSON with this structure. Do not add text before or
after it. Do not use markdown code blocks.

{{
  "executive_summary": "2-3 sentences with the technical verdict of the run",
  "what_worked": [
    "specific point that worked well",
    "..."
  ],
  "what_failed": [
    "specific point that failed or was suboptimal, with root cause if identifiable"
  ],
  "gaps_detected": [
    "area of the target the agent did NOT explore but should have"
  ],
  "suggested_improvements": [
    {{
      "priority": "high|medium|low",
      "area": "probes|prompts|tools|knowledge_base|workflow",
      "description": "concrete, actionable improvement"
    }}
  ],
  "new_pocs_to_add": [
    {{
      "cve_id": "CVE-...",
      "vendor": "...",
      "rationale": "why it should be added to the knowledge base"
    }}
  ],
  "vendor_specific_observations": [
    "useful observation about the detected vendor for future runs"
  ],
  "kb_updates_proposed": {{
    "patched_cves_to_record": ["CVE-..."],
    "useful_probes_for_vendor": ["probe_..."],
    "fingerprint_markers": ["string that identifies the vendor"]
  }}
}}

Be concise, technical and actionable. Do not invent data. If a section does not
apply, leave the list empty."""


@dataclass
class ReflectionReport:
    """Wrapper estructurado del reporte generado por el LLM."""

    raw: Dict[str, Any]
    target_ip: str
    timestamp: str
    json_path: Optional[str] = None
    md_path: Optional[str] = None

    @property
    def executive_summary(self) -> str:
        return self.raw.get("executive_summary", "")

    @property
    def kb_updates(self) -> Dict[str, Any]:
        return self.raw.get("kb_updates_proposed", {})

    def is_valid(self) -> bool:
        """Schema mínimo: requiere al menos executive_summary."""
        return bool(self.executive_summary)


def _build_findings_summary(findings: List[Dict[str, Any]]) -> str:
    """Renderiza findings en texto compacto para inyectar en el prompt.

    El revisor debe ver la MISMA cifra que publica el informe: se muestra la
    severidad efectiva y se marca como confirmado solo lo que
    `is_confirmed_vuln` acepta. Enseñarle al revisor un ✓ CONFIRMED sobre un
    INFO —que es un resultado negativo verificado, no una vulnerabilidad— le
    hacía elogiar hallazgos inexistentes y proponer aprendizajes falsos a la KB.
    """
    if not findings:
        return "(sin findings registrados)"
    lines = []
    for f in findings:
        status = "✓ CONFIRMED" if is_confirmed_vuln(f) else "✗ unconfirmed"
        sev = effective_severity(f)
        claimed = (f.get("severity") or "INFO").upper()
        # Si la política topó la severidad, se muestran ambas: el revisor debe
        # poder señalar que el agente reclamó más de lo que demostró.
        sev_txt = sev if sev == claimed else f"{sev}←{claimed}"
        line = (
            f"  - [{sev_txt}] {status} "
            f"{f.get('cve_id') or f.get('title') or 'UNKNOWN'}: "
            f"{(f.get('evidence') or '')[:120]}"
        )
        lines.append(line)
    return "\n".join(lines)


def _try_repair_truncated_json(text: str) -> Optional[Dict[str, Any]]:
    """Heurística para reparar JSON cortado a mitad por max_output_tokens.

    Estrategia: cerrar string abierta + balancear braces/brackets pendientes.
    Si el texto termina dentro de un string ("..."), añadimos `"` antes de
    cerrar contenedores. Funciona para casos de truncation comunes pero no
    es robusto a corrupciones arbitrarias.
    """
    if not text:
        return None
    # Detectar si estamos dentro de un string (n_quotes impar, ignorando \" escapados)
    in_string = False
    escape = False
    for ch in text:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
    repaired = text
    if in_string:
        repaired += '"'
    # Balancear } y ] pendientes contando los que quedan abiertos.
    open_braces = repaired.count("{") - repaired.count("}")
    open_brackets = repaired.count("[") - repaired.count("]")
    # Cerrar trailing comma si lo hay justo antes del cierre forzado
    repaired = re.sub(r",\s*$", "", repaired.rstrip())
    repaired += "]" * max(open_brackets, 0) + "}" * max(open_braces, 0)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        return None


def _extract_json_block(text: str) -> Optional[Dict[str, Any]]:
    """Extrae el primer bloque JSON válido del texto.

    Tolerante a:
      - Markdown fences ```json ... ```
      - Texto explicativo antes/después
      - Truncation por token budget (intenta reparar cerrando contenedores)
    """
    # Si viene en bloque markdown, extraer entre ```
    fence = re.search(r"```(?:json)?\s*(\{.+?\})\s*```", text, re.DOTALL)
    if fence:
        candidate = fence.group(1)
    else:
        # Buscar el primer `{` y intentar parsear desde ahí
        start = text.find("{")
        if start == -1:
            return None
        candidate = text[start:]

    # Intento 1: parse directo
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # Intento 2: truncar al último `}` balanceado (heurística clásica)
    last_brace = candidate.rfind("}")
    if last_brace > 0:
        try:
            return json.loads(candidate[:last_brace + 1])
        except json.JSONDecodeError:
            pass

    # Intento 3: reparar truncation (cerrar string + braces)
    repaired = _try_repair_truncated_json(candidate)
    if repaired is not None:
        return repaired

    return None


def _call_llm_text(client: Any, model: str, prompt: str) -> str:
    """Llama al LLM para generación de texto.

    Se comprueba la forma del cliente en vez de asumirla: la reflexión recibe
    el cliente ya construido por el agente, y un cliente que no expone
    `messages.create()` no es el que esta función sabe usar. Fallar aquí con un
    mensaje legible es preferible a un `AttributeError` a mitad del cierre de
    la auditoría, cuando el informe ya está escrito y lo único que se pierde
    es la reflexión.
    """
    if not (hasattr(client, "messages") and hasattr(client.messages, "create")):
        raise TypeError(
            "cliente LLM no soportado por la reflexión: se espera un cliente "
            "con `messages.create()` (Anthropic / Bedrock)")
    resp = client.messages.create(
        model=model,
        max_tokens=8192,
        temperature=1,  # Anthropic recomienda 1 cuando no se usa thinking
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text if resp.content else ""


def generate_reflection(
    *,
    client: Any,
    model: str,
    goal: str,
    target_ip: str,
    finish_reason: str,
    turns: int,
    elapsed: float,
    findings: List[Dict[str, Any]],
    risk_score: Optional[Dict[str, Any]] = None,
    tools_invoked: Optional[List[str]] = None,
    probes_executed: Optional[List[str]] = None,
    probes_recommended: Optional[List[str]] = None,
    vendor: Optional[str] = None,
    device_model: Optional[str] = None,
    firmware: Optional[str] = None,
    cve_search_results: Optional[List[str]] = None,
    timeout: int = 30,
) -> Optional[ReflectionReport]:
    """Llama al LLM una vez para generar el reflection report.

    Args:
      client: cliente Anthropic (`anthropic.Anthropic` o `AnthropicBedrock`).
      model: nombre del modelo.
      ... resto: contexto del run.

    Returns:
      ReflectionReport o None si la generación falla.
    """
    probes_skipped = sorted(set(probes_recommended or []) - set(probes_executed or []))

    prompt = REFLECTION_PROMPT.format(
        goal=goal[:200],
        target_ip=target_ip,
        finish_reason=finish_reason,
        turns=turns,
        elapsed=f"{elapsed:.1f}",
        vendor=vendor or "unknown",
        model=device_model or "unknown",
        firmware=firmware or "unknown",
        findings_total=len(findings),
        findings_confirmed=sum(1 for f in findings if is_confirmed_vuln(f)),
        risk_score=json.dumps(risk_score or {}, ensure_ascii=False),
        tools_invoked=json.dumps(tools_invoked or [], ensure_ascii=False),
        probes_executed=json.dumps(probes_executed or [], ensure_ascii=False),
        probes_skipped=json.dumps(probes_skipped, ensure_ascii=False),
        cve_search_results=json.dumps(cve_search_results or [], ensure_ascii=False),
        findings_summary=_build_findings_summary(findings),
    )

    try:
        text = _call_llm_text(client, model, prompt)
    except Exception as e:
        logger.warning(f"[REFLECTION] LLM call failed: {e}")
        return None

    if not text.strip():
        logger.warning("[REFLECTION] empty LLM response")
        return None

    parsed = _extract_json_block(text)
    if not parsed:
        logger.warning(f"[REFLECTION] failed to parse JSON from response (head: {text[:200]!r})")
        return None

    report = ReflectionReport(
        raw=parsed,
        target_ip=target_ip,
        timestamp=time.strftime("%Y%m%d_%H%M%S"),
    )
    if not report.is_valid():
        logger.warning("[REFLECTION] parsed JSON missing required fields")
        return None
    return report


def persist_reflection(report: ReflectionReport,
                       reflections_dir: str = "reports/reflections") -> ReflectionReport:
    """Guarda el reporte en disco como JSON + Markdown legible."""
    os.makedirs(reflections_dir, exist_ok=True)
    publish_dir(reflections_dir)
    base = f"reflection_{report.target_ip.replace('.', '_')}_{report.timestamp}"
    json_path = os.path.join(reflections_dir, f"{base}.json")
    md_path = os.path.join(reflections_dir, f"{base}.md")

    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report.raw, f, indent=2, ensure_ascii=False)
        publish_artifact(json_path)
        report.json_path = json_path
    except OSError as e:
        logger.warning(f"[REFLECTION] failed to write JSON: {e}")

    try:
        md = _render_markdown(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        publish_artifact(md_path)
        report.md_path = md_path
    except OSError as e:
        logger.warning(f"[REFLECTION] failed to write MD: {e}")

    return report


def _render_markdown(report: ReflectionReport) -> str:
    """Convierte el JSON del reflection en Markdown human-readable."""
    r = report.raw
    md = []
    md.append(f"# Reflection Report — {report.target_ip}")
    md.append(f"\n**Timestamp:** {report.timestamp}\n")
    md.append("## Executive Summary\n")
    md.append(r.get("executive_summary", "(no summary)"))
    md.append("")

    def _section(title: str, items: list, formatter=None) -> None:
        if not items:
            return
        md.append(f"## {title}\n")
        for it in items:
            if formatter:
                md.append(formatter(it))
            else:
                md.append(f"- {it}")
        md.append("")

    _section("What Worked", r.get("what_worked", []))
    _section("What Failed", r.get("what_failed", []))
    _section("Gaps Detected", r.get("gaps_detected", []))
    _section(
        "Suggested Improvements",
        r.get("suggested_improvements", []),
        formatter=lambda it: (
            f"- [{it.get('priority', '?').upper()}] **{it.get('area', '?')}**: "
            f"{it.get('description', '')}"
        ),
    )
    _section(
        "New PoCs To Add",
        r.get("new_pocs_to_add", []),
        formatter=lambda it: (
            f"- {it.get('cve_id', '?')} ({it.get('vendor', '?')}): "
            f"{it.get('rationale', '')}"
        ),
    )
    _section("Vendor-Specific Observations", r.get("vendor_specific_observations", []))

    kb = r.get("kb_updates_proposed", {}) or {}
    if any(kb.values()):
        md.append("## KB Updates Proposed\n")
        if kb.get("patched_cves_to_record"):
            md.append(f"- **Patched CVEs:** {', '.join(kb['patched_cves_to_record'])}")
        if kb.get("useful_probes_for_vendor"):
            md.append(f"- **Useful probes for vendor:** {', '.join(kb['useful_probes_for_vendor'])}")
        if kb.get("fingerprint_markers"):
            md.append(f"- **Fingerprint markers:** {', '.join(kb['fingerprint_markers'])}")
    return "\n".join(md) + "\n"


def apply_reflection_to_kb(report: ReflectionReport, kb,
                           vendor: Optional[str] = None) -> None:
    """Aplica las propuestas del reflection al KB de forma conservadora.

    Solo aplica claims explícitos del LLM, no inferencias. El usuario puede
    revisar el JSON/MD antes de un próximo run para más cambios manuales.
    """
    kb_updates = report.kb_updates
    if not kb_updates or not isinstance(kb_updates, dict):
        return
    if vendor:
        patched = kb_updates.get("patched_cves_to_record") or []
        useful = kb_updates.get("useful_probes_for_vendor") or []
        markers = kb_updates.get("fingerprint_markers") or []
        if patched or useful or markers:
            kb.upsert_vendor_profile(
                vendor,
                patched_cves=patched if isinstance(patched, list) else None,
                useful_probes=useful if isinstance(useful, list) else None,
                fingerprint_markers=markers if isinstance(markers, list) else None,
            )
    if report.json_path:
        kb.add_reflection_path(report.json_path)
