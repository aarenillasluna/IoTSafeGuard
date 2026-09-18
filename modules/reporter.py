"""
Reporter Profesional: genera informes de auditoría en JSON, Markdown, HTML y script .sh.
Integra MITRE ATT&CK mapping y gráficos de distribución de severidad.
"""
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from loguru import logger

from core.fsutil import publish_artifact, publish_dir


def repro_cmd_of(entry: Dict[str, Any]) -> str:
    """Comando de reproducción de un hallazgo, aceptando la clave legada.

    El campo se llamaba `executed_cmd`, un nombre que afirmaba una ejecución que
    no siempre ocurrió (a menudo contiene el nombre de la sonda que emitió el
    hallazgo). Se renombró a `repro_cmd`, pero los informes ya generados —que el
    dashboard sigue leyendo— llevan el nombre antiguo: se aceptan ambos.
    """
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("repro_cmd") or entry.get("executed_cmd") or "")

try:
    from core.mitre_attack import build_attack_narrative, get_tactic_summary
    _HAS_MITRE = True
except ImportError:
    _HAS_MITRE = False


class Reporter:
    """Generador de informes de auditoría multi-formato."""

    def __init__(self, report_dir: str = "reports"):
        self.findings: List[Dict[str, Any]] = []
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

    def add_entry(
        self,
        ip: str,
        os_match: str,
        ports: List[Dict],
        attack_plan: str,
        attack_results: List[Dict],
        system_cves: Optional[List[Dict]] = None,
        mqtt_results: Optional[List[Dict]] = None,
        # ---- Contexto enriquecido para reporting profesional ----
        device_identity: Optional[Dict[str, Any]] = None,
        risk_summary: Optional[Dict[str, Any]] = None,
        executed_tools: Optional[List[str]] = None,
        tested_cves: Optional[List[str]] = None,
        kb_context: Optional[Dict[str, Any]] = None,
        reflection_report_path: Optional[str] = None,
        run_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Añade una entrada al reporte con contexto opcional enriquecido.

        Los nuevos kwargs son **opcionales** para preservar backward compat
        con código que solo pase los originales:
          - device_identity: {vendor, model, firmware, mac}
          - risk_summary: output de `compute_risk_score` (risk_score, risk_label, severity_counts)
          - executed_tools: lista de tools efectivamente invocadas en el run
          - tested_cves: CVEs que fueron objeto de validación (no solo descubiertos)
          - kb_context: snapshot de la Knowledge Base (audit_count previo, etc.)
          - reflection_report_path: ruta al reflection report MD/JSON si existe
          - run_metadata: {turns, elapsed_seconds, finish_reason, summary}
        """
        system_cves = system_cves if system_cves is not None else []
        self.findings.append({
            "target_ip": ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "os_detected": os_match,
            "open_ports": ports,
            "system_cves": system_cves,
            "ai_plan": attack_plan,
            "attack_results": attack_results,
            "mqtt_results": mqtt_results or [],
            # Campos enriquecidos
            "device_identity": device_identity or {},
            "risk_summary": risk_summary or {},
            "executed_tools": executed_tools or [],
            "tested_cves": tested_cves or [],
            "kb_context": kb_context or {},
            "reflection_report_path": reflection_report_path,
            "run_metadata": run_metadata or {},
        })

    def generate_reports(self, executed_nodes: Optional[List[str]] = None) -> str:
        """Genera todos los formatos de reporte. Retorna el path base."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(self.report_dir, f"audit_report_{timestamp}")
        executed_nodes = executed_nodes or [
            "recon", "interrogate", "vulnerabilities", "exploit", "report"
        ]

        self._write_json(f"{base}.json")
        self._write_markdown(f"{base}.md")
        self._write_html(f"{base}.html", executed_nodes)
        self._write_pocs_script(f"{base}_pocs.sh")
        self._write_sarif(f"{base}.sarif")

        # Los informes se generan durante un run con sudo (nmap lo exige), así que
        # nacen como root: devolvemos la propiedad al usuario real para que el
        # dashboard y el propio autor puedan leerlos y versionarlos sin sudo.
        publish_dir(self.report_dir)
        for suffix in (".json", ".md", ".html", ".sarif", "_pocs.sh"):
            publish_artifact(f"{base}{suffix}")

        logger.info(f"[REPORT] Informes generados: {base}.*")
        print(f"\n[REPORT] Informes generados:")
        print(f"  → {base}.json")
        print(f"  → {base}.md")
        print(f"  → {base}.html")
        print(f"  → {base}.sarif")
        print(f"  → {base}_pocs.sh")
        return base

    # ─────────────────────────────────────────────────────────
    # JSON
    # ─────────────────────────────────────────────────────────
    def _write_json(self, path: str) -> None:
        output = {"findings": self.findings}
        if _HAS_MITRE:
            output["mitre_attack"] = {
                "tactics": get_tactic_summary(),
                "framework": "ATT&CK for Enterprise / ICS",
                "reference": "https://attack.mitre.org/",
            }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, ensure_ascii=False)

    # ─────────────────────────────────────────────────────────
    # Markdown
    # ─────────────────────────────────────────────────────────
    def _write_markdown(self, path: str) -> None:
        """Reporte Markdown profesional con executive summary, device ID, risk
        summary, findings deduplicados, remediación y MITRE filtrado."""
        with open(path, "w", encoding="utf-8") as f:
            self._md_header(f)
            for item in self.findings:
                self._md_target_section(f, item)
            self._md_global_appendix(f)

    # ─── Secciones Markdown ─────────────────────────────────────────────
    def _md_header(self, f) -> None:
        f.write("# Informe de Auditoría de Seguridad IoT\n\n")
        f.write(f"**Fecha:** {datetime.now().strftime('%d/%m/%Y %H:%M')}  \n")
        f.write(f"**Objetivos analizados:** {len(self.findings)}  \n")
        f.write("**Generador:** IoTSafeGuard agente autónomo\n\n")
        f.write("---\n")

    def _md_target_section(self, f, item: Dict[str, Any]) -> None:
        ip = item["target_ip"]
        identity = item.get("device_identity", {}) or {}
        risk = item.get("risk_summary", {}) or {}
        run_meta = item.get("run_metadata", {}) or {}
        kb_ctx = item.get("kb_context", {}) or {}

        # ── Header del target con identidad ────────────────────────────
        f.write(f"\n## 🎯 Objetivo: `{ip}`\n\n")
        if identity:
            vendor = identity.get("vendor") or "—"
            model = identity.get("model") or "—"
            firmware = identity.get("firmware") or "—"
            mac = identity.get("mac") or "—"
            f.write("### Identificación del dispositivo\n\n")
            f.write(f"| Campo | Valor |\n|---|---|\n")
            f.write(f"| **Vendor** | {vendor} |\n")
            f.write(f"| **Modelo** | {model} |\n")
            f.write(f"| **Firmware** | {firmware} |\n")
            f.write(f"| **MAC** | `{mac}` |\n")
            f.write(f"| **OS detectado** | {item['os_detected']} |\n")
            f.write("\n")
        else:
            f.write(f"- **Identidad:** {item['os_detected']}\n\n")

        # ── Executive summary del run ──────────────────────────────────
        if run_meta or risk:
            f.write("### Resumen ejecutivo\n\n")
            risk_label = risk.get("risk_label", "—")
            risk_score = risk.get("risk_score", 0)
            counts = risk.get("severity_counts", {})
            confirmed = risk.get("confirmed_count", 0)
            total = risk.get("total_findings", len(item.get("attack_results", [])))
            badge = _severity_badge(risk_label)
            f.write(f"**Riesgo agregado:** {badge} {risk_label} (score **{risk_score}/100**)  \n")
            f.write(
                f"**Hallazgos:** {total} totales — "
                f"**{confirmed}** confirmados.  \n"
            )
            # Separar CONFIRMADOS de CANDIDATOS: el conteo total (severity_counts)
            # sobre-cuenta CVEs sin confirmar (p. ej. "27 HIGH" cuando solo ~5 lo son).
            # El titular debe ser la severidad CONFIRMADA (prueba práctica); los
            # candidatos se listan aparte para no engañar al lector.
            confirmed_counts = risk.get("confirmed_severity_counts", counts)
            conf_line = " · ".join(
                f"{_severity_badge(sev)} {sev}: {n}"
                for sev, n in confirmed_counts.items() if n
            )
            cand_line = " · ".join(
                f"{sev}: {counts.get(sev, 0) - confirmed_counts.get(sev, 0)}"
                for sev in counts
                if (counts.get(sev, 0) - confirmed_counts.get(sev, 0)) > 0
            )
            if conf_line:
                f.write(f"**Severidad confirmada:** {conf_line}  \n")
            elif total:
                f.write("**Severidad confirmada:** ninguno confirmado con prueba práctica  \n")
            if cand_line:
                f.write(
                    f"**Candidatos sin confirmar** (CVEs por versión/banner, no explotados): "
                    f"{cand_line}  \n"
                )
            if run_meta.get("turns") or run_meta.get("elapsed_seconds"):
                f.write(
                    f"**Métricas del run:** {run_meta.get('turns', 0)} turnos · "
                    f"{run_meta.get('elapsed_seconds', 0):.1f}s · "
                    f"finish_reason=`{run_meta.get('finish_reason', '?')}`  \n"
                )
            if run_meta.get("summary"):
                f.write(f"\n> {run_meta['summary'][:600]}\n\n")
            else:
                f.write("\n")

        # ── KB context (si hay histórico previo) ───────────────────────
        if kb_ctx:
            prev = kb_ctx.get("previous_audit", {})
            vendor_p = kb_ctx.get("vendor_profile", {})
            if prev or vendor_p:
                f.write("### 🧠 Contexto histórico (Knowledge Base)\n\n")
                if prev and prev.get("audit_count"):
                    f.write(
                        f"- Este dispositivo ha sido auditado "
                        f"**{prev['audit_count']}** veces previamente "
                        f"(primera vez: {prev.get('first_seen', '?')[:10]})\n"
                    )
                if vendor_p and vendor_p.get("patched_cves_known"):
                    f.write(
                        f"- CVEs históricamente parcheados para "
                        f"**{vendor_p.get('vendor')}**: "
                        f"`{', '.join(vendor_p['patched_cves_known'])}`\n"
                    )
                f.write("\n")

        # ── Superficie de ataque ───────────────────────────────────────
        f.write("### Superficie de ataque\n\n")
        if item["open_ports"]:
            f.write("| Puerto | Proto | Servicio | Producto | Versión |\n")
            f.write("|---|---|---|---|---|\n")
            for p in item["open_ports"]:
                proto = p.get("protocol") or p.get("proto") or "tcp"
                f.write(
                    f"| **{p['port']}** | {proto} | "
                    f"{p.get('service_name') or p.get('service', '')} | "
                    f"{p.get('product', '')} | {p.get('version', '')} |\n"
                )
            f.write("\n")

        # ── CVEs sistema (si los hay) ──────────────────────────────────
        if item.get("system_cves"):
            f.write("### Vulnerabilidades catalogadas (NVD)\n\n")
            f.write("| CVE | CVSS | Severidad | Descripción |\n|---|---|---|---|\n")
            for cve in item["system_cves"]:
                desc = (cve.get("description", "") or "")[:120].replace("\n", " ")
                f.write(
                    f"| {cve['id']} | {cve.get('score', 0)} | "
                    f"{cve.get('severity', '?')} | {desc}... |\n"
                )
            f.write("\n")

        # ── MQTT (si fue probado) ──────────────────────────────────────
        for mqtt in item.get("mqtt_results", []) or []:
            if mqtt.get("anonymous_access") or mqtt.get("error") is None:
                f.write(f"### MQTT broker ({mqtt.get('port', 1883)})\n\n")
                f.write(f"- Acceso anónimo: **{'SÍ' if mqtt.get('anonymous_access') else 'NO'}**\n")
                f.write(f"- Suscripción wildcard `#`: **{'SÍ' if mqtt.get('wildcard_subscribe') else 'NO'}**\n")
                f.write(f"- Publicación anónima: **{'SÍ' if mqtt.get('publish_allowed') else 'NO'}**\n\n")

        # ── Findings (deduplicados + remediación) ──────────────────────
        attack_results = item.get("attack_results", []) or []
        if attack_results:
            f.write("### Findings detallados\n\n")
            grouped = _group_attack_results(attack_results)
            # Separar confirmados (cuerpo, completos) de candidatos descartados
            # (apéndice colapsable, pero con TODA la info dentro). Un grupo cuenta
            # como confirmado si CUALQUIER entry lo está (no enterrar confirmados).
            confirmed_groups = [
                g for g in grouped
                if any(e.get("vuln_found") for e in g.get("entries", [g.get("primary", {})]))
            ]
            unconfirmed_groups = [g for g in grouped if g not in confirmed_groups]
            for group in confirmed_groups:
                self._md_render_finding_group(f, group, target_ip=ip)
            if not confirmed_groups:
                f.write("_Sin hallazgos confirmados con prueba práctica en este objetivo._\n\n")

            # ── Apéndice: CVEs evaluados y descartados (info COMPLETA, colapsada) ──
            if unconfirmed_groups:
                f.write(
                    f"\n### 📋 CVEs evaluados y descartados ({len(unconfirmed_groups)})\n\n"
                )
                f.write(
                    "Candidatos por versión/banner que el agente evaluó y **no confirmó** "
                    "(no cuentan en el risk score). Cada entrada conserva su evidencia y "
                    "motivo completos — despliega para verlos:\n\n"
                )
                for group in unconfirmed_groups:
                    self._md_render_unconfirmed_compact(f, group, target_ip=ip)

        # ── Reflection report linkage ──────────────────────────────────
        ref_path = item.get("reflection_report_path")
        if ref_path:
            md_path = ref_path.replace(".json", ".md") if ref_path.endswith(".json") else ref_path
            f.write(f"\n### 🪞 Reflection report (auto-generado)\n\n")
            f.write(
                f"Análisis post-run automático con sugerencias de mejora "
                f"acumulables en la Knowledge Base.\n\n"
            )
            f.write(f"📄 [`{os.path.basename(md_path)}`]({md_path})\n\n")

        f.write("---\n")

    def _md_render_finding_group(self, f, group: Dict[str, Any],
                                 target_ip: Optional[str] = None) -> None:
        """Renderiza un finding (o grupo de findings deduplicados) con
        evidencia, remediación y referencias.

        Args:
          target_ip: IP del target (para resolver placeholders en KB cmds).
        """
        from modules.remediation_kb import get_remediation

        primary = group["primary"]
        rid = primary.get("cve_id") or primary.get("service") or "FINDING"
        sev = (primary.get("severity") or "INFO").upper()
        confirmed = bool(primary.get("vuln_found"))
        kb = get_remediation(rid) or {}

        # Status: CONFIRMED, NOT EXPLOITABLE, EXPOSED, INFO
        if confirmed and sev in ("INFO", "LOW"):
            status = "EXPOSED"
        elif confirmed:
            status = "CONFIRMED"
        elif sev == "INFO":
            status = "OBSERVED"
        else:
            status = "NOT EXPLOITABLE"

        title = kb.get("title") or primary.get("title") or rid
        f.write(f"\n#### {_severity_badge(sev)} `{rid}` — {title}\n\n")
        f.write(f"**Estado:** `{status}` · **Severidad:** `{sev}`")

        cvss = kb.get("cvss_v3", {}) or {}
        if cvss.get("score"):
            f.write(f" · **CVSS v3:** `{cvss['score']}`")
            if cvss.get("vector"):
                f.write(f" (`{cvss['vector']}`)")
        if kb.get("cwe"):
            f.write(f" · **CWE:** [`{kb['cwe']}`](https://cwe.mitre.org/data/definitions/{kb['cwe'].replace('CWE-', '')}.html)")
        f.write("\n\n")

        # Dependents indicator si el grupo tiene varios entries
        if len(group["entries"]) > 1:
            dependents = [e.get("cve_id") or e.get("service") for e in group["entries"][1:]]
            f.write(
                f"> **CVEs dependientes (heredan estado):** "
                f"{', '.join(f'`{d}`' for d in dependents if d)}\n\n"
            )

        # ── Output del dispositivo (datos REALES) vs Interpretación (reasoning) ──
        # Separación visual clara: datos verificables vs opinion del agente.
        raw = primary.get("raw_output") or ""
        interp = primary.get("interpretation") or ""
        legacy_evidence = primary.get("output_log") or ""

        # Backward compat: si solo hay evidence legacy, va a interpretation
        if not raw and not interp and legacy_evidence:
            interp = legacy_evidence

        if raw:
            raw = _normalize_newlines(raw)
            req_part, resp_part = _split_request_response(raw)
            if req_part:
                f.write("**📨 Petición enviada:**\n```\n")
                f.write(req_part + "\n```\n\n")
                f.write("**📡 Respuesta del dispositivo:**\n")
                lang = "json" if resp_part.strip().startswith("{") else ""
                f.write(f"```{lang}\n{resp_part}\n```\n\n")
            else:
                f.write("<details open><summary>📡 <b>Output del dispositivo</b></summary>\n\n")
                lang = "json" if raw.strip().startswith("{") else ""
                f.write(f"```{lang}\n{raw}\n```\n")
                f.write("</details>\n\n")

        if interp:
            interp = _normalize_newlines(interp)
            f.write("<details open><summary>🧠 <b>Interpretación del agente</b> (reasoning)</summary>\n\n")
            f.write(f"> {interp}\n")
            f.write("</details>\n\n")

        # Comando de reproducción — preferimos en orden:
        # 1. verification_cmd del propio probe (real shell command)
        # 2. KB verification_cmds template (resuelto con ip/port del entry)
        # 3. repro_cmd como último recurso (suele ser nombre del tool, no shell)
        repro_lines = self._resolve_repro_cmds(primary, target_ip=target_ip)
        if repro_lines:
            f.write("**Reproducción manual:**\n```bash\n")
            for line in repro_lines:
                f.write(line + "\n")
            f.write("```\n\n")

        # Remediación
        if kb.get("remediation"):
            f.write("**Remediación:**\n\n")
            for step in kb["remediation"]:
                f.write(f"- {step}\n")
            f.write("\n")

        # Referencias
        if kb.get("references"):
            f.write("**Referencias:**\n\n")
            for ref in kb["references"]:
                f.write(f"- {ref}\n")
            f.write("\n")

    def _md_render_unconfirmed_compact(self, f, group: Dict[str, Any],
                                       target_ip: Optional[str] = None) -> None:
        """Renderiza un candidato NO confirmado de forma compacta: un `<details>`
        colapsado (resumen en una línea) que al desplegarlo muestra TODA la info,
        sin perder NADA respecto al render completo — raw_output, interpretación,
        comando de reproducción Y el bloque KB (CVSS, CWE, remediación, referencias).
        Solo cambia la presentación (colapsado), no el contenido.
        """
        from modules.remediation_kb import get_remediation

        primary = group["primary"]
        rid = primary.get("cve_id") or primary.get("service") or "FINDING"
        sev = (primary.get("severity") or "INFO").upper()
        kb = get_remediation(rid) or {}
        title = kb.get("title") or primary.get("title") or rid
        raw = _normalize_newlines(primary.get("raw_output") or "")
        interp = _normalize_newlines(
            primary.get("interpretation") or primary.get("output_log") or ""
        )

        f.write(
            f"<details><summary>{_severity_badge(sev)} <code>{rid}</code> · "
            f"{sev} · {title}</summary>\n\n"
        )
        f.write("**Estado:** `NO CONFIRMADO`")
        cvss = kb.get("cvss_v3", {}) or {}
        if cvss.get("score"):
            f.write(f" · **CVSS v3:** `{cvss['score']}`")
            if cvss.get("vector"):
                f.write(f" (`{cvss['vector']}`)")
        if kb.get("cwe"):
            f.write(f" · **CWE:** [`{kb['cwe']}`](https://cwe.mitre.org/data/definitions/{kb['cwe'].replace('CWE-', '')}.html)")
        f.write("\n\n")

        # CVEs dependientes del grupo (heredan estado) — conservar la traza completa
        if len(group.get("entries", [])) > 1:
            deps = [e.get("cve_id") or e.get("service") for e in group["entries"][1:]]
            deps = [d for d in deps if d]
            if deps:
                f.write(
                    f"> **CVEs dependientes (heredan estado):** "
                    f"{', '.join(f'`{d}`' for d in deps)}\n\n"
                )
        if raw:
            lang = "json" if raw.strip().startswith("{") else ""
            f.write(f"**📡 Output del dispositivo:**\n\n```{lang}\n{raw}\n```\n\n")
        if interp:
            f.write(f"**🧠 Motivo / interpretación:**\n\n> {interp}\n\n")
        repro = self._resolve_repro_cmds(primary, target_ip=target_ip)
        if repro:
            f.write("**Reproducción:**\n\n```bash\n" + "\n".join(repro) + "\n```\n\n")
        if kb.get("remediation"):
            f.write("**Remediación:**\n\n")
            for step in kb["remediation"]:
                f.write(f"- {step}\n")
            f.write("\n")
        if kb.get("references"):
            f.write("**Referencias:**\n\n")
            for ref in kb["references"]:
                f.write(f"- {ref}\n")
            f.write("\n")
        f.write("</details>\n\n")

    @staticmethod
    def _resolve_repro_cmds(entry: Dict[str, Any],
                            target_ip: Optional[str] = None) -> List[str]:
        """Resuelve la lista de comandos shell reproductibles para un finding.

        Estrategia (en orden de preferencia):
          1. `verification_cmd` capturado del propio probe (preciso, contextual).
          2. Plantillas en remediation_kb resueltas con ip/port del finding.
          3. `repro_cmd` (o el legado `executed_cmd`), que a menudo es solo el
             nombre de la herramienta y por tanto el menos útil de los tres.

        Devuelve lista vacía si no hay nada útil que mostrar (mejor que un
        comando engañoso como 'batch_dismiss').
        """
        from modules.remediation_kb import render_verification_cmds

        # 1. verification_cmd del probe — string o lista
        vc = entry.get("verification_cmd")
        if isinstance(vc, list) and vc:
            return [str(line) for line in vc if line]
        if isinstance(vc, str) and vc.strip():
            return [vc]

        # 2. KB templates con substitución ip/port
        finding_id = entry.get("cve_id") or entry.get("service") or ""
        ip = target_ip or entry.get("target_ip") or entry.get("ip")
        port = entry.get("port")
        if finding_id and ip:
            kb_cmds = render_verification_cmds(finding_id, ip, port)
            if kb_cmds:
                return kb_cmds

        # 3. repro_cmd (último recurso) — solo si parece un comando real
        # Filtrar nombres de tool del agente que NO son shell-executable
        cmd = repro_cmd_of(entry)
        if cmd and cmd not in ("N/A", "batch_dismiss"):
            # Detectar si es nombre de tool del agente (probe_*, cve_search, etc.)
            tool_pattern_starts = ("probe_", "cve_search", "recommend_", "nmap_scan",
                                   "mac_vendor_lookup", "http_interrogate",
                                   "execute_websocket(", "execute_command(",
                                   "execute_chain(", "transition_phase",
                                   "record_finding", "save_report", "done")
            if any(cmd.startswith(p) for p in tool_pattern_starts):
                return []  # Skip nombres de tool del agente
            return [cmd[:600]]
        return []

    def _md_global_appendix(self, f) -> None:
        """Apéndices globales: MITRE ATT&CK filtrado + glosario."""
        if not _HAS_MITRE:
            return
        # Recoger todas las tools efectivamente usadas across all entries
        all_tools: List[str] = []
        for item in self.findings:
            for t in item.get("executed_tools", []) or []:
                if t not in all_tools:
                    all_tools.append(t)

        if not all_tools:
            return  # Sin info de tools no podemos filtrar honestamente

        try:
            from core.mitre_attack import get_tactic_summary_for_tools
            tactics = get_tactic_summary_for_tools(all_tools)
        except ImportError:
            tactics = {}
        if not tactics:
            return

        f.write("\n## Mapeo MITRE ATT&CK (técnicas efectivamente usadas)\n\n")
        f.write(
            f"_Filtrado a las técnicas que mapean a las **{len(all_tools)} tools "
            f"realmente invocadas** en este run. NO se incluyen técnicas "
            f"genéricas no ejercitadas._\n\n"
        )
        f.write("| Táctica | Técnica | ID | Tools que la activan |\n")
        f.write("|---|---|---|---|\n")
        try:
            from core.mitre_attack import TOOL_TO_TECHNIQUES
        except ImportError:
            TOOL_TO_TECHNIQUES = {}
        for tactic_data in tactics.values():
            for t in tactic_data["techniques"]:
                # Identificar qué tools del run mapean a esta técnica
                mapping_tools = [
                    tn for tn in all_tools
                    if t["id"] in TOOL_TO_TECHNIQUES.get(tn, [])
                ]
                tools_str = ", ".join(f"`{m}`" for m in mapping_tools[:4])
                if len(mapping_tools) > 4:
                    tools_str += f" (+{len(mapping_tools) - 4})"
                f.write(
                    f"| {tactic_data['tactic_name']} | "
                    f"[{t['name']}]({t['url']}) | `{t['id']}` | {tools_str} |\n"
                )
        f.write("\n> Framework: MITRE ATT&CK for Enterprise — https://attack.mitre.org/\n")

    # ─────────────────────────────────────────────────────────
    # HTML Profesional
    # ─────────────────────────────────────────────────────────
    def _write_html(self, path: str, executed_nodes: List[str]) -> None:
        # Preparar datos MITRE
        mitre_narrative = []
        if _HAS_MITRE:
            mitre_narrative = build_attack_narrative(executed_nodes)

        # Stats reales — contar findings ACTUALES (auto-register + LLM record_finding),
        # no system_cves[] que está vacío en el flow agente.
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        # confirmed_severity_counts: solo findings con vuln_found=True
        # Se usa en el gráfico para evitar que CVEs de catálogo sin probar inflen las cifras.
        confirmed_severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        total_findings = 0
        total_cves = 0          # findings con cve_id que parece CVE oficial
        total_confirmed = 0     # findings confirmed=true
        total_critical = 0      # CRITICAL severity (solo confirmados)
        for item in self.findings:
            risk = item.get("risk_summary") or {}
            if risk:
                rsev = risk.get("severity_counts") or {}
                for k, v in rsev.items():
                    if k in severity_counts:
                        severity_counts[k] += int(v or 0)
                total_findings += int(risk.get("total_findings", 0) or 0)
                total_confirmed += int(risk.get("confirmed_count", 0) or 0)
            # confirmed_severity_counts siempre desde attack_results (source of truth)
            for res in item.get("attack_results", []) or []:
                if res.get("vuln_found"):
                    sev = (res.get("severity") or res.get("details") or "INFO").upper()
                    if sev in confirmed_severity_counts:
                        confirmed_severity_counts[sev] += 1
                    if sev == "CRITICAL":
                        total_critical += 1
            if not risk:
                # Fallback: derivar totales de attack_results
                for res in item.get("attack_results", []) or []:
                    sev = (res.get("severity") or res.get("details") or "INFO").upper()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                    total_findings += 1
                    if res.get("vuln_found"):
                        total_confirmed += 1
            # CVEs reales (tested_cves del agent o derivado de attack_results)
            tested = item.get("tested_cves") or []
            if tested:
                total_cves += len(tested)
            else:
                for res in item.get("attack_results", []) or []:
                    cid = res.get("cve_id") or ""
                    if isinstance(cid, str) and cid.upper().startswith("CVE-"):
                        total_cves += 1

            # MQTT vulns (legacy path)
            if not risk:
                for mqtt in item.get("mqtt_results", []):
                    for v in mqtt.get("vulnerabilities", []):
                        sev = (v.get("severity") or "UNKNOWN").upper()
                        if sev in severity_counts:
                            severity_counts[sev] += 1
                        total_findings += 1

        now = datetime.now().strftime("%d/%m/%Y %H:%M")

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IoTSafeGuard — Informe de Auditoría</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
:root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --text-dim: #94a3b8; --accent: #38bdf8;
    --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #22c55e; --info: #6366f1;
    --border: #475569; --radius: 12px;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Inter','Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }}
.container {{ max-width:1200px; margin:0 auto; padding:2rem; }}
header {{ text-align:center; padding:3rem 0 2rem; border-bottom:1px solid var(--border); margin-bottom:2rem; }}
header h1 {{ font-size:2.2rem; font-weight:700; background:linear-gradient(135deg,var(--accent),#818cf8);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent; }}
header p {{ color:var(--text-dim); margin-top:.5rem; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin:2rem 0; }}
.stat {{ background:var(--surface); border-radius:var(--radius); padding:1.5rem; text-align:center; border:1px solid var(--border); }}
.stat .value {{ font-size:2rem; font-weight:700; color:var(--accent); }}
.stat .label {{ font-size:.85rem; color:var(--text-dim); margin-top:.25rem; }}
.card {{ background:var(--surface); border-radius:var(--radius); padding:1.5rem; margin:1.5rem 0; border:1px solid var(--border); }}
.card h2 {{ color:var(--accent); margin-bottom:1rem; font-size:1.3rem; }}
.card h3 {{ color:var(--text); margin:1.2rem 0 .6rem; font-size:1.1rem; }}
table {{ width:100%; border-collapse:collapse; margin:.5rem 0; font-size:.9rem; }}
th {{ background:var(--surface2); padding:.7rem .8rem; text-align:left; font-weight:600; border-bottom:2px solid var(--border); }}
td {{ padding:.6rem .8rem; border-bottom:1px solid var(--border); }}
tr:hover {{ background:rgba(56,189,248,0.05); }}
.severity {{ padding:.2rem .6rem; border-radius:6px; font-size:.75rem; font-weight:600; text-transform:uppercase; }}
.severity.critical {{ background:rgba(239,68,68,0.2); color:var(--critical); }}
.severity.high {{ background:rgba(249,115,22,0.2); color:var(--high); }}
.severity.medium {{ background:rgba(234,179,8,0.2); color:var(--medium); }}
.severity.low {{ background:rgba(34,197,94,0.2); color:var(--low); }}
.severity.info {{ background:rgba(99,102,241,0.2); color:var(--info); }}
.result-badge {{ display:inline-block; padding:.3rem .8rem; border-radius:6px; font-weight:600; font-size:.8rem; }}
.result-badge.vuln {{ background:rgba(239,68,68,0.2); color:var(--critical); }}
.result-badge.safe {{ background:rgba(34,197,94,0.2); color:var(--low); }}
code {{ background:var(--surface2); padding:.2rem .5rem; border-radius:4px; font-size:.85rem; font-family:'JetBrains Mono','Fira Code',monospace; }}
pre {{ background:#0d1117; padding:1rem; border-radius:8px; overflow-x:auto; font-size:.82rem; margin:.5rem 0; font-family:'JetBrains Mono','Fira Code',monospace; }}
pre.cmd {{ white-space:pre; overflow-x:auto; max-height:600px; overflow-y:auto; }}
.chart-container {{ max-width:400px; margin:1rem auto; }}
.mitre-phase {{ margin:.8rem 0; }}
.mitre-phase .phase-name {{ font-weight:600; color:var(--accent); text-transform:uppercase; font-size:.85rem; margin-bottom:.4rem; }}
.mitre-tag {{ display:inline-block; background:var(--surface2); padding:.2rem .6rem; border-radius:4px; margin:.2rem .3rem .2rem 0; font-size:.8rem; }}
.mitre-tag a {{ color:var(--text); text-decoration:none; }}
.mitre-tag a:hover {{ color:var(--accent); }}
.mqtt-result {{ margin:.5rem 0; padding:.5rem; background:var(--surface2); border-radius:6px; }}
footer {{ text-align:center; padding:2rem 0; color:var(--text-dim); font-size:.8rem; border-top:1px solid var(--border); margin-top:2rem; }}
/* Attack vector clusters */
.vector-cluster {{ border:1px solid var(--border); border-radius:var(--radius); margin:1.2rem 0; overflow:hidden; }}
.vector-header {{ display:flex; align-items:center; gap:1rem; padding:1rem 1.2rem;
    background:var(--surface2); border-bottom:1px solid var(--border); }}
.vector-header .vector-name {{ font-weight:700; font-size:1rem; flex:1; }}
.vector-header .vector-meta {{ font-size:.8rem; color:var(--text-dim); }}
.vector-header.confirmed {{ border-left:4px solid var(--critical); }}
.vector-header.unconfirmed {{ border-left:4px solid var(--border); }}
.vector-body {{ padding:1rem 1.2rem; }}
.vector-desc {{ color:var(--text-dim); font-size:.88rem; margin-bottom:.8rem; }}
.cve-badges {{ display:flex; flex-wrap:wrap; gap:.4rem; margin-bottom:.8rem; }}
.cve-badge {{ display:inline-flex; align-items:center; gap:.3rem; padding:.25rem .6rem;
    border-radius:6px; font-size:.78rem; font-family:monospace; border:1px solid var(--border); }}
.cve-badge.confirmed {{ background:rgba(239,68,68,.15); border-color:var(--critical); color:#fca5a5; }}
.cve-badge.unconfirmed {{ background:var(--surface2); color:var(--text-dim); }}
.confirm-dot {{ width:7px; height:7px; border-radius:50%; display:inline-block; }}
.confirm-dot.yes {{ background:var(--critical); }}
.confirm-dot.no  {{ background:var(--border); }}
/* Per-CVE expandable details */
.cve-detail {{ margin:.5rem 0; }}
.cve-detail-header {{ display:flex; align-items:center; gap:.4rem; flex-wrap:wrap; }}
.cve-detail summary {{ cursor:pointer; color:var(--text-dim); font-size:.78rem; margin-top:.3rem; margin-left:.5rem; user-select:none; }}
.cve-detail summary:hover {{ color:var(--accent); }}
.cve-detail details[open] summary {{ color:var(--accent); }}
.cve-detail-body {{ margin-left:.5rem; margin-top:.3rem; }}
</style>
</head>
<body>
<div class="container">
<header>
    <h1>🛡️ IoTSafeGuard — Informe de Auditoría</h1>
    <p>Generado: {now} | Objetivos: {len(self.findings)}</p>
</header>

<div class="stats">
    <div class="stat"><div class="value">{len(self.findings)}</div><div class="label">Objetivos analizados</div></div>
    <div class="stat"><div class="value">{total_findings}</div><div class="label">Findings totales</div></div>
    <div class="stat"><div class="value">{total_confirmed}</div><div class="label">Findings confirmados</div></div>
    <div class="stat"><div class="value">{total_cves}</div><div class="label">CVEs candidatos</div></div>
    <div class="stat"><div class="value">{total_critical}</div><div class="label">Críticos confirmados</div></div>
</div>

<div class="card">
    <h2>📊 Distribución de Severidad <span style="font-size:.75rem;color:var(--text-dim);font-weight:400">(solo findings confirmados)</span></h2>
    <div class="chart-container"><canvas id="sevChart"></canvas></div>
</div>
"""
        # ─── Por cada hallazgo ───
        for item in self.findings:
            identity = item.get("device_identity", {}) or {}
            risk = item.get("risk_summary", {}) or {}
            run_meta = item.get("run_metadata", {}) or {}

            # Device identification block (si tenemos data enriquecida)
            ident_block = ""
            if identity:
                ident_block = (
                    f'<table style="margin-top:8px"><tbody>'
                    f'<tr><th>Vendor</th><td>{_html_escape(identity.get("vendor") or "—")}</td></tr>'
                    f'<tr><th>Modelo</th><td>{_html_escape(identity.get("model") or "—")}</td></tr>'
                    f'<tr><th>Firmware</th><td>{_html_escape(identity.get("firmware") or "—")}</td></tr>'
                    f'<tr><th>MAC</th><td><code>{_html_escape(identity.get("mac") or "—")}</code></td></tr>'
                    f'</tbody></table>'
                )

            # Risk badge en el header del target
            risk_badge = ""
            if risk:
                label = risk.get("risk_label", "—")
                score = risk.get("risk_score", 0)
                color_map = {
                    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
                    "MEDIUM": "#ca8a04", "LOW": "#0891b2",
                    "NEGLIGIBLE": "#64748b",
                }
                color = color_map.get(label, "#64748b")
                risk_badge = (
                    f'<span style="display:inline-block;padding:4px 10px;'
                    f'background:{color};color:white;border-radius:4px;'
                    f'font-weight:600;margin-left:12px">'
                    f'Risk: {label} ({score}/100)</span>'
                )

            run_meta_str = ""
            if run_meta:
                run_meta_str = (
                    f' | {run_meta.get("turns", 0)} turnos · '
                    f'{run_meta.get("elapsed_seconds", 0):.1f}s'
                )

            html += f"""
<div class="card">
    <h2>🎯 {_html_escape(item['target_ip'])} {risk_badge}</h2>
    <p style="color:var(--text-dim)">Identidad: {_html_escape(item['os_detected'])} | {item['timestamp']}{run_meta_str}</p>
    {ident_block}

    <h3>🔌 Superficie de Ataque</h3>
    <table>
        <tr><th>Puerto</th><th>Servicio</th><th>Producto</th><th>Versión</th></tr>
"""
            for p in item.get("open_ports", []):
                html += (
                    "        <tr>"
                    f"<td>{_html_escape(str(p.get('port','')))}</td>"
                    f"<td>{_html_escape(str(p.get('service_name','')))}</td>"
                    f"<td>{_html_escape(str(p.get('product','')))}</td>"
                    f"<td>{_html_escape(str(p.get('version','')))}</td>"
                    "</tr>\n"
                )

            html += "    </table>\n"

            # CVEs
            if item.get("system_cves"):
                html += "    <h3>💣 Vulnerabilidades Identificadas</h3>\n    <table>\n"
                html += "        <tr><th>CVE</th><th>CVSS</th><th>Severidad</th><th>Descripción</th></tr>\n"
                for cve in item["system_cves"]:
                    sev = cve.get("severity", "UNKNOWN").upper()
                    sev_class = sev.lower() if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "info"
                    desc = cve.get("description", "")[:120].replace("\n", " ")
                    html += (
                        f'        <tr><td><code>{_html_escape(str(cve["id"]))}</code></td>'
                        f'<td>{_html_escape(str(cve.get("score", 0)))}</td>'
                        f'<td><span class="severity {sev_class}">{sev}</span></td>'
                        f'<td>{_html_escape(desc)}</td></tr>\n'
                    )
                html += "    </table>\n"

            # MQTT
            for mqtt in item.get("mqtt_results", []):
                if mqtt.get("vulnerabilities"):
                    html += (
                        f"    <h3>📡 MQTT Broker ("
                        f"{_html_escape(str(mqtt['ip']))}:{_html_escape(str(mqtt['port']))}"
                        ")</h3>\n"
                    )
                    for v in mqtt["vulnerabilities"]:
                        sev = v.get("severity", "INFO").upper()
                        sev_class = sev.lower() if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "info"
                        html += (
                            f'    <div class="mqtt-result"><span class="severity {sev_class}">{sev}</span> '
                            f'<strong>{_html_escape(str(v["id"]))}</strong> — '
                            f'{_html_escape(str(v["description"]))}</div>\n'
                        )

            # ── Resultados agrupados por vector de ataque ──
            attack_results = item.get("attack_results", [])
            clusters = _cluster_attack_results(attack_results)
            # Confirmados primero, candidatos descartados después (estable). Cada
            # cluster ya es colapsable per-CVE → info completa preservada, solo ordenada.
            clusters = sorted(clusters, key=lambda c: c["confirmed_count"] == 0)

            if clusters:
                total_vectors     = len(clusters)
                total_cves_tested = sum(len(c["cves"]) for c in clusters)

                # Contadores: finding-level vs CVE-level
                total_findings_cluster = sum(len(c["cves"]) for c in clusters)
                total_findings_confirmed = sum(c["confirmed_count"] for c in clusters)
                total_cves_confirmed = sum(c["cve_confirmed_count"] for c in clusters)

                html += f"""
    <h3>⚔️ Findings detallados</h3>
    <p style="color:var(--text-dim);font-size:.88rem;margin-bottom:1rem">
        <strong>{total_vectors}</strong> vectores de ataque &nbsp;·&nbsp;
        <strong>{total_findings_cluster}</strong> findings totales &nbsp;·&nbsp;
        <strong style="color:var(--critical)">{total_findings_confirmed}</strong> findings confirmados &nbsp;·&nbsp;
        <strong>{total_cves_tested}</strong> CVEs catalogados (NVD) &nbsp;·&nbsp;
        <strong style="color:var(--critical)">{total_cves_confirmed}</strong> CVEs confirmados
    </p>
"""
                for cluster in clusters:
                    has_confirmed = cluster["confirmed_count"] > 0
                    header_class  = "confirmed" if has_confirmed else "unconfirmed"
                    sev           = cluster["max_severity"].lower()
                    sev_class     = sev if sev in ("critical","high","medium","low") else "info"
                    sev_label     = cluster["max_severity"]
                    confirmed_txt = (
                        f'<span class="result-badge vuln">'
                        f'{cluster["confirmed_count"]} CONFIRMADO(S)</span>'
                        if has_confirmed
                        else '<span class="result-badge safe">NO CONFIRMADO</span>'
                    )

                    html += f"""
    <div class="vector-cluster">
        <div class="vector-header {header_class}">
            <span class="vector-name">{_html_escape(cluster["vector_name"])}</span>
            <span><span class="severity {sev_class}">{sev_label}</span></span>
            <span class="vector-meta">{confirmed_txt}</span>
        </div>
        <div class="vector-body">
            <p class="vector-desc">{_html_escape(cluster["vector_desc"])}</p>
"""
                    # Per-CVE expandable details — dual sections
                    target_ip = item.get("target_ip")
                    for cve_entry in cluster["cves"]:
                        badge_cls = "confirmed" if cve_entry["confirmed"] else "unconfirmed"
                        dot_cls   = "yes" if cve_entry["confirmed"] else "no"
                        cve_sev   = cve_entry["severity"].lower()
                        cve_sev_c = cve_sev if cve_sev in ("critical","high","medium","low") else "info"

                        # ── Comando reproducible — filtrar nombres de tool ──
                        # Reusamos la lógica del MD: verification_cmd > KB > legacy
                        repro_cmds = self._resolve_repro_cmds(
                            {
                                "cve_id": cve_entry.get("cve_id") or cve_entry.get("id"),
                                "service": cve_entry.get("id"),
                                "repro_cmd": cve_entry.get("cmd"),
                            },
                            target_ip=target_ip,
                        )
                        cve_cmd_block = "\n".join(repro_cmds) if repro_cmds else ""

                        # ── Datos del dispositivo (raw_output) vs Interpretación ──
                        raw = cve_entry.get("raw_output") or ""
                        interp = cve_entry.get("interpretation") or ""
                        legacy = cve_entry.get("output") or ""
                        # Backward compat: legacy → interpretation si nuevos vacíos
                        if not raw and not interp and legacy:
                            interp = legacy

                        # Normalizar \n literales → saltos de línea reales
                        raw = _normalize_newlines(raw)
                        interp = _normalize_newlines(interp)
                        # Pretty-print JSON sin truncar
                        raw = _pretty_json_or_truncate(raw, max_chars=99999)
                        # Interpretation sin truncar
                        interp = interp  # sin límite

                        cve_id_display = (
                            cve_entry.get("cve_id")
                            or cve_entry.get("id")
                            or "FINDING"
                        )

                        html += f'            <div class="cve-detail">\n'
                        html += f'              <div class="cve-detail-header">\n'
                        html += (
                            f'                <span class="cve-badge {badge_cls}">'
                            f'<span class="confirm-dot {dot_cls}"></span>'
                            f'<code>{_html_escape(cve_id_display)}</code>'
                            f'<span class="severity {cve_sev_c}" style="padding:.1rem .4rem">'
                            f'{cve_entry["severity"]}</span>'
                            f'</span>\n'
                        )
                        html += f'              </div>\n'

                        if raw or interp or cve_cmd_block:
                            html += f'              <details>\n'
                            html += f'                <summary>Ver detalle</summary>\n'
                            html += f'                <div class="cve-detail-body">\n'

                            # 📨 Petición + 📡 Respuesta (separadas) o bloque único
                            if raw:
                                req_part, resp_part = _split_request_response(raw)
                                if req_part:
                                    html += (
                                        '                  <div style="margin-bottom:.4rem">'
                                        '<strong>📨 Petición enviada</strong>'
                                        '</div>\n'
                                    )
                                    html += f'                  <pre class="cmd">{_html_escape(req_part)}</pre>\n'
                                    html += (
                                        '                  <div style="margin:.6rem 0 .4rem">'
                                        '<strong>📡 Respuesta del dispositivo</strong>'
                                        '</div>\n'
                                    )
                                    cls = "cmd" if resp_part.strip().startswith("{") else "cmd"
                                    html += f'                  <pre class="{cls}">{_html_escape(resp_part)}</pre>\n'
                                else:
                                    html += (
                                        '                  <div style="margin-bottom:.4rem">'
                                        '<strong>📡 Output del dispositivo</strong>'
                                        '</div>\n'
                                    )
                                    cls = "cmd" if raw.strip().startswith("{") else "cmd"
                                    html += f'                  <pre class="{cls}">{_html_escape(raw)}</pre>\n'

                            # 🧠 Interpretación (reasoning del agente)
                            if interp:
                                html += (
                                    '                  <div style="margin:.8rem 0 .4rem">'
                                    '<strong>🧠 Interpretación del agente</strong> '
                                    '<span style="color:var(--text-dim);font-size:.78rem">(reasoning)</span>'
                                    '</div>\n'
                                )
                                html += (
                                    f'                  <p style="color:var(--text-dim);'
                                    f'border-left:3px solid var(--accent);padding-left:.8rem">'
                                    f'{_html_escape(interp)}</p>\n'
                                )

                            # 🔧 Reproducción manual
                            if cve_cmd_block:
                                html += (
                                    '                  <div style="margin:.8rem 0 .4rem">'
                                    '<strong>🔧 Reproducción manual</strong>'
                                    '</div>\n'
                                )
                                html += f'                  <pre class="cmd">{_html_escape(cve_cmd_block)}</pre>\n'

                            html += f'                </div>\n'
                            html += f'              </details>\n'
                        html += f'            </div>\n'

                    html += "        </div>\n    </div>\n"

            html += "</div>\n"

        # ─── MITRE ATT&CK Section ───
        if _HAS_MITRE and mitre_narrative:
            html += """
<div class="card">
    <h2>🎯 MITRE ATT&CK — Narrativa de Ataque</h2>
    <p style="color:var(--text-dim)">Técnicas ejercitadas durante la auditoría, mapeadas al framework MITRE ATT&CK.</p>
"""
            for phase in mitre_narrative:
                html += (
                    f'    <div class="mitre-phase"><div class="phase-name">📌 '
                    f'{_html_escape(str(phase["phase"]))}</div>\n'
                )
                for tech in phase["techniques"]:
                    html += (
                        f'        <span class="mitre-tag">'
                        f'<a href="{_html_escape(str(tech["url"]))}" target="_blank" rel="noopener noreferrer">'
                        f'{_html_escape(str(tech["id"]))}</a> — '
                        f'{_html_escape(str(tech["name"]))} '
                        f'<em>({_html_escape(str(tech["tactic"]))})</em>'
                        f'</span>\n'
                    )
                html += "    </div>\n"
            html += "</div>\n"

        # ─── Chart.js + Footer ───
        html += f"""
<footer>
    <p>IoTSafeGuard-Agent — Framework de Pentesting IoT Autónomo</p>
    <p>Generado automáticamente el {now}</p>
</footer>
</div>

<script>
new Chart(document.getElementById('sevChart'), {{
    type: 'doughnut',
    data: {{
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{{
            data: [{confirmed_severity_counts['CRITICAL']}, {confirmed_severity_counts['HIGH']}, {confirmed_severity_counts['MEDIUM']}, {confirmed_severity_counts['LOW']}, {confirmed_severity_counts['INFO']}],
            backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#6366f1'],
            borderColor: '#1e293b',
            borderWidth: 2
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{ position: 'bottom', labels: {{ color: '#e2e8f0', padding: 15 }} }}
        }}
    }}
}});
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    # ─────────────────────────────────────────────────────────
    # SARIF 2.1.0
    # ─────────────────────────────────────────────────────────
    def _write_sarif(self, path: str) -> None:
        sarif_log = _build_sarif(self.findings)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2, ensure_ascii=False)

    # ─────────────────────────────────────────────────────────
    # PoC Script
    # ─────────────────────────────────────────────────────────
    def _write_pocs_script(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Script de Reproducción — {datetime.now()}\n")
            f.write("# PRECAUCIÓN: Solo en entornos autorizados.\n\n")

            for item in self.findings:
                f.write(f"# {'='*60}\n# Objetivo: {item['target_ip']} | {item['os_detected']}\n# {'='*60}\n")
                for res in item.get("attack_results", []):
                    cmd = repro_cmd_of(res)
                    if cmd and cmd != "N/A":
                        vuln = "[VULNERABLE]" if res.get("vuln_found") else "[SAFE]"
                        f.write(f"\n# {res.get('service','?')} — {vuln}\n{cmd}\n")
                f.write("\n")


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _sarif_level(severity: str) -> str:
    """Map internal severity to SARIF level: error | warning | note."""
    s = (severity or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


def _build_sarif(findings: List[Dict[str, Any]], tool_version: str = "1.0.0") -> Dict[str, Any]:
    """
    Produces a SARIF 2.1.0 log from the reporter's findings.
    Each CVE and each attack_result becomes one `result`. A rule is declared
    once per unique CVE/probe id so CI tooling (GitHub Advanced Security,
    DefectDojo, etc.) can deduplicate across runs.
    """
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    def _register_rule(rid: str, name: str, desc: str, severity: str) -> None:
        if rid in rules_by_id:
            return
        rules_by_id[rid] = {
            "id": rid,
            "name": name[:120] or rid,
            "shortDescription": {"text": (name or rid)[:240]},
            "fullDescription": {"text": (desc or name or rid)[:1500]},
            "defaultConfiguration": {"level": _sarif_level(severity)},
            "properties": {"severity": (severity or "INFO").upper()},
        }

    for finding in findings:
        target = finding.get("target_ip", "unknown")
        target_uri = f"iot-host://{target}"

        for cve in finding.get("system_cves", []) or []:
            rid = cve.get("id") or "CVE-UNKNOWN"
            desc = cve.get("description", "")
            sev = cve.get("severity", "INFO")
            _register_rule(rid, rid, desc, sev)
            results.append({
                "ruleId": rid,
                "level": _sarif_level(sev),
                "message": {
                    "text": f"{rid} on {target}: {desc[:500]}" if desc else f"{rid} on {target}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target_uri}
                    }
                }],
                "properties": {
                    "cvss": cve.get("score", 0),
                    "severity": (sev or "INFO").upper(),
                    "targetIp": target,
                    "kind": "candidate",
                },
            })

        for res in finding.get("attack_results", []) or []:
            service = res.get("service") or "UNKNOWN"
            confirmed = bool(res.get("vuln_found"))
            cmd = repro_cmd_of(res)
            out = res.get("output_log") or res.get("details") or ""
            sev = res.get("severity") or ("HIGH" if confirmed else "INFO")
            _register_rule(service, service, cmd or service, sev)
            kind = "fail" if confirmed else "pass"
            msg_prefix = "CONFIRMED" if confirmed else "NOT CONFIRMED"
            results.append({
                "ruleId": service,
                "level": _sarif_level(sev),
                "kind": kind,
                "message": {
                    "text": f"[{msg_prefix}] {service} on {target}. Cmd: {cmd[:200]}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target_uri}
                    }
                }],
                "properties": {
                    "severity": (sev or "INFO").upper(),
                    "targetIp": target,
                    "confirmed": confirmed,
                    "commandPreview": cmd[:400],
                    "outputPreview": out[:400],
                },
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "IoTSafeGuard-Agent",
                    "version": tool_version,
                    # URI informativa de la herramienta. Aquí figuraba un
                    # repositorio de Anthropic que no existe y que este proyecto
                    # no es: un SARIF se consume en cadenas de CI ajenas, así
                    # que atribuir el informe a un tercero es incorrecto además
                    # de inútil para quien lo lea.
                    "informationUri": "https://github.com/arelun/IoTSafeGuard-Agent",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
        }],
    }


def _pretty_json_or_truncate(s: str, max_chars: int = 2500) -> str:
    """Si s es JSON parseable, prettify (indent=2) + filtrar claves admin.
    Si no es JSON, devolver truncado en max_chars.
    Helper específico para el render del reporter — el cleanup de admin keys
    también se aplica acá como defensa en profundidad por si _record_finding
    no lo hizo (legacy data).
    """
    if not s:
        return ""
    try:
        import json as _json
        parsed = _json.loads(s)
    except (ValueError, TypeError):
        return s[:max_chars] + ("…" if len(s) > max_chars else "")
    # Limpiar claves admin igual que _clean_raw_output
    admin_keys = frozenset({
        "_auto_registered_findings", "_elapsed_ms",
        "ok", "error", "error_type", "ip", "port",
        "service", "protocol_confirmed", "vulnerabilities",
    })
    if isinstance(parsed, dict):
        cleaned = {k: v for k, v in parsed.items() if k not in admin_keys}
        # Si solo queda `details`, promover su contenido
        if list(cleaned.keys()) == ["details"] and isinstance(cleaned["details"], dict):
            cleaned = cleaned["details"]
        if cleaned:
            parsed = cleaned
    pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
    if len(pretty) > max_chars:
        pretty = pretty[:max_chars] + "\n…(truncated)"
    return pretty


def _html_escape(text: str) -> str:
    """Escape HTML básico para evitar XSS en el reporte."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _normalize_newlines(text: str) -> str:
    """Convierte secuencias de escape literales \\n, \\t a caracteres reales."""
    return text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "")


def _split_request_response(text: str):
    """Separa el texto de evidencia en (petición, respuesta).

    Busca marcadores habituales que el agente usa para separar lo que envió
    del output que recibió. Devuelve (request_part, response_part).
    Si no puede separar, devuelve ("", text) — todo va a respuesta.
    """
    if not text:
        return ("", "")

    # Marcadores explícitos que el agente escribe
    RESPONSE_MARKERS = [
        "\nRespuesta:",
        "\nRespuesta HTTP",
        "\nResultado:",
        "\nOutput:",
        "\nResponse:",
        "\nHTTP/1.0 ",
        "\nHTTP/1.1 ",
        "\nHTTP/2 ",
    ]
    for marker in RESPONSE_MARKERS:
        idx = text.find(marker)
        if idx > 10:
            req = text[:idx].strip()
            # Saltar el marcador completo para no repetir la etiqueta en la respuesta
            resp = text[idx + len(marker):].strip()
            return (req, resp)

    # Sin marcador explícito: buscar línea en blanco seguida de respuesta
    lines = text.split("\n")
    http_methods = ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "curl ")
    first = lines[0].strip() if lines else ""
    if any(first.startswith(m) for m in http_methods):
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "" and i < len(lines) - 1:
                next_line = lines[i + 1].strip()
                if (next_line.startswith("HTTP/")
                        or next_line.startswith("{")
                        or next_line.startswith("<")
                        or next_line.startswith("[")):
                    req = "\n".join(lines[:i]).strip()
                    resp = "\n".join(lines[i + 1:]).strip()
                    return (req, resp)

    # No se puede separar: todo es respuesta
    return ("", text)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers de presentación profesional
# ─────────────────────────────────────────────────────────────────────────────
_SEVERITY_BADGES = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
    "NEGLIGIBLE": "⚪",
}


def _severity_badge(severity: Optional[str]) -> str:
    """Devuelve emoji + label normalizado para severidad."""
    if not severity:
        return "⚪"
    return _SEVERITY_BADGES.get(severity.upper(), "⚪")


def _group_attack_results(attack_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Agrupa attack_results por evidencia idéntica para deduplicar.

    Caso típico (visto en runs reales): batch_dismiss marca 4 CVEs dependientes
    con la misma evidencia textual. Sin agrupación, el reporte repite la misma
    explicación 4 veces. Con agrupación, mostramos 1 finding "principal" + lista
    de "dependents" que heredan el estado.

    Estrategia:
      - Key de agrupación: (output_log, severity, vuln_found)
      - Si hash de evidencia colisiona → mismo grupo
      - El primer entry del grupo es el "primary"; el resto son "dependents"
      - Si la evidencia es vacía o muy corta, NO agrupar (cada finding único)
    """
    groups: List[Dict[str, Any]] = []
    by_key: Dict[Any, Dict[str, Any]] = {}

    for entry in attack_results:
        evidence = (entry.get("output_log") or "").strip()
        # Solo dedupe si evidencia ≥80 chars (umbral conservador)
        if len(evidence) >= 80:
            key = (
                evidence,
                entry.get("details", entry.get("severity", "")),
                bool(entry.get("vuln_found")),
            )
        else:
            # Evidencia corta o vacía → cada entry es su propio grupo
            key = id(entry)

        if key in by_key:
            by_key[key]["entries"].append(entry)
        else:
            group = {"primary": entry, "entries": [entry]}
            by_key[key] = group
            groups.append(group)
    return groups


# ─────────────────────────────────────────────────────────────────────────────
# Agrupación de resultados por vector de ataque
# ─────────────────────────────────────────────────────────────────────────────

_VECTOR_RULES: List[Dict[str, Any]] = [
    # (pattern_in_cmd, vector_name, description)
    {"pat": r"PROBE:telnet|nc.*\b23\b|\btelnet\b",
     "name": "Telnet — Credenciales por defecto / Backdoor",
     "desc": "Acceso al servicio Telnet mediante credenciales hardcoded o por defecto. "
             "Un atacante en la misma red podría obtener un shell root sin autenticación."},
    {"pat": r"PROBE:snmp|snmpwalk|snmpget",
     "name": "SNMP — Community string por defecto",
     "desc": "El servicio SNMP acepta la community string pública estándar, "
             "exponiendo la configuración del dispositivo sin autenticación."},
    {"pat": r"PROBE:ftp|ftp://",
     "name": "FTP — Acceso anónimo",
     "desc": "El servidor FTP permite el acceso anónimo, potencialmente exponiendo "
             "ficheros de firmware, configuración o logs."},
    {"pat": r"PROBE:dnsmasq|PROBE:dns_",
     "name": "DNS/DHCP — Desbordamiento de buffer (dnsmasq)",
     "desc": "El servicio dnsmasq puede ser vulnerable a un desbordamiento de heap/pila "
             "mediante paquetes DNS o DHCP malformados."},
    {"pat": r"PROBE:mdns",
     "name": "mDNS/Bonjour — Enumeración de servicios",
     "desc": "El dispositivo anuncia servicios vía mDNS/Bonjour, revelando información "
             "de inventario (impresoras, HomeKit, Chromecast, etc.) sin autenticación."},
    {"pat": r"PROBE:coap",
     "name": "CoAP — Descubrimiento de recursos (/.well-known/core)",
     "desc": "El servicio CoAP expone su tabla de recursos sin autenticación, "
             "permitiendo enumerar endpoints IoT potencialmente vulnerables."},
    {"pat": r"getcfg\.php",
     "name": "HTTP — Divulgación de credenciales (getcfg.php)",
     "desc": "El endpoint /getcfg.php devuelve credenciales de administración en texto "
             "claro sin requerir autenticación válida."},
    {"pat": r"xmlset_roodkcableoj28840ybtide|User-Agent.*backdoor|hidden.*user.agent",
     "name": "HTTP — Bypass de autenticación (User-Agent backdoor)",
     "desc": "El firmware contiene una cadena User-Agent oculta que omite la "
             "autenticación, permitiendo acceso directo a recursos protegidos."},
    {"pat": r"hedwig\.cgi|cgi-bin.*inject|ping_ipaddr|cmd=|command=",
     "name": "HTTP CGI — Inyección de comandos",
     "desc": "Parámetros de CGIs del firmware permiten inyectar comandos del sistema "
             "operativo sin autenticación previa."},
    {"pat": r"captcha\.cgi|buffer.*overflow|AAAA{10,}|--data-payload",
     "name": "HTTP CGI — Desbordamiento de buffer (web)",
     "desc": "Un CGI del firmware es vulnerable a desbordamiento de buffer mediante "
             "entradas excesivamente largas, pudiendo causar DoS o ejecución de código."},
    {"pat": r"SOAPAction|UPnP|AddPortMapping|urn:schemas",
     "name": "UPnP/SOAP — Inyección de comandos",
     "desc": "La interfaz UPnP no valida los parámetros de entrada, permitiendo "
             "inyección de comandos a través de acciones SOAP."},
    {"pat": r"mosquitto|mqtt|1883",
     "name": "MQTT — Acceso no autenticado",
     "desc": "El broker MQTT no requiere autenticación, permitiendo suscribirse "
             "o publicar en cualquier topic."},
    {"pat": r"websocat|wss?://",
     "name": "WebSocket — Ataque de protocolo",
     "desc": "La interfaz WebSocket expone funcionalidad sensible sin "
             "autenticación o con controles insuficientes."},
    {"pat": r"nc -u|socat.*UDP",
     "name": "UDP — Abuso de protocolo",
     "desc": "Un servicio UDP expuesto permite enviar tráfico arbitrario "
             "sin autenticación (SSDP, UPnP discovery, etc.)."},
    {"pat": r"nmap",
     "name": "Enumeración de servicios",
     "desc": "Escaneo de puertos y detección de versiones de servicios expuestos."},
]

_VECTOR_DEFAULT = {
    "name": "Otro — Ataque web / protocolo",
    "desc": "Vector de ataque identificado pero no clasificado en categorías principales.",
}


# Mapping cve_id/finding_id → vector (más fiable que regex sobre cmd)
_FINDING_ID_TO_VECTOR: Dict[str, Dict[str, str]] = {
    "DIAL-EXPOSED": {
        "name": "DIAL — App enumeration y launch sin auth",
        "desc": "Servicio DIAL (Discovery and Launch) expone descripción del "
                "dispositivo y permite enumerar/lanzar apps remotamente sin auth.",
    },
    "LG-WEBOS-EXPOSED": {
        "name": "LG WebOS — Pairing endpoint expuesto",
        "desc": "Servicio WebSocket de pairing detectado. Requiere PIN del usuario "
                "para registro completo (mitigación nativa).",
    },
    "LG-WEBOS-CVE-2023-6317": {
        "name": "LG WebOS — Bypass de autenticación PIN (CVE-2023-6317)",
        "desc": "El bypass del prompt PIN funciona: client-key obtenido sin "
                "interacción del usuario. Acceso privilegiado al TV.",
    },
    "MQTT-ANON-ACCESS": {
        "name": "MQTT — Conexión anónima permitida",
        "desc": "El broker MQTT acepta CONNECT sin credenciales, exponiendo "
                "potencialmente todos los topics.",
    },
    "MQTT-WILDCARD-SUB": {
        "name": "MQTT — Subscribe wildcard `#`",
        "desc": "Cliente anónimo puede suscribirse a TODOS los topics, "
                "interceptando datos de telemetría/control IoT.",
    },
    "MODBUS-NO-AUTH-FC17": {
        "name": "Modbus TCP — FC17 sin autenticación",
        "desc": "PLC/RTU industrial responde a Report Slave ID sin auth.",
    },
    "MODBUS-NO-AUTH-READCOILS": {
        "name": "Modbus TCP — Lectura de coils sin auth",
        "desc": "Equipo industrial expone estado de coils a cualquier IP.",
    },
    "RTSP-NO-AUTH": {
        "name": "RTSP — Stream sin autenticación",
        "desc": "Cámara IP o equipo de streaming expone media sin login.",
    },
    "RTSP-DEFAULT-CRED": {
        "name": "RTSP — Credenciales por defecto",
        "desc": "Stream RTSP accesible con admin/admin u otros pares default.",
    },
    "TELNET-EXPOSED": {
        "name": "Telnet — Servicio expuesto sin TLS",
        "desc": "Telnet legacy abierto, transmite credenciales en claro.",
    },
    "TELNET-DEFAULT-CRED": {
        "name": "Telnet — Credenciales default Mirai",
        "desc": "Telnet acepta credenciales del catálogo Mirai (root/xc3511, etc.).",
    },
    "TELNET-MIRAI-BUSYBOX": {
        "name": "Telnet — Banner BusyBox (Mirai vector)",
        "desc": "Banner Telnet coincide con dispositivo IoT vulnerable a Mirai.",
    },
    "FTP-ANON-LOGIN": {
        "name": "FTP — Acceso anónimo permitido",
        "desc": "Servidor FTP acepta USER anonymous, posible exposición de firmware/config.",
    },
    "SMB-V1-EXPOSED": {
        "name": "SMBv1 — Protocolo deprecated (EternalBlue)",
        "desc": "SMBv1 expuesto. Vector primario de WannaCry/NotPetya.",
    },
    "TFTP-ANON-DOWNLOAD": {
        "name": "TFTP — Descarga anónima de firmware/config",
        "desc": "Servidor TFTP permite descarga anónima de archivos sensibles.",
    },
    "CWMP-ROMPAGER-CVE-2014-9222": {
        "name": "CWMP/RomPager — Misfortune Cookie",
        "desc": "Servidor RomPager <4.34 vulnerable a memory corruption vía Cookie.",
    },
    "CWMP-MIRAI-CVE-2017-17215": {
        "name": "CWMP/Huawei HG532 — SOAP injection (Mirai)",
        "desc": "Router Huawei vulnerable a inyección SOAP. Vector Mirai 2017.",
    },
    "BACNET-NO-AUTH-WHOIS": {
        "name": "BACnet/IP — Who-Is sin auth",
        "desc": "Equipo de building automation responde sin autenticación.",
    },
    "CHROMECAST-INFO-DISCLOSURE": {
        "name": "Chromecast — Información expuesta vía Eureka API",
        "desc": "API local de Chromecast expone build, MAC, SSID, redes vecinas.",
    },
    "UPNP-IGD-EXPOSED": {
        "name": "UPnP IGD — AddPortMapping sin auth",
        "desc": "Router permite abrir port-forwards arbitrarios desde la LAN.",
    },
    "OPCUA-EXPOSED": {
        "name": "OPC-UA — Servicio industrial expuesto",
        "desc": "Endpoint industrial responde sin filtrado IP.",
    },
    "MDNS-EXPOSED": {
        "name": "mDNS — Service discovery (información del dispositivo)",
        "desc": "Bonjour/Zeroconf publica metadata del dispositivo en la LAN: "
                "modelo, firmware, MAC, serial. Útil para fingerprint.",
    },
    "WEAK-CREDENTIALS": {
        "name": "Credenciales por defecto — Acceso admin",
        "desc": "Interfaz web autenticada con credenciales triviales/por defecto. "
                "Acceso administrativo completo sin restricción.",
    },
    "SSH-DROPBEAR-OLD": {
        "name": "SSH — Dropbear obsoleto con CVEs históricos",
        "desc": "Versión Dropbear sshd desactualizada. Vector de ataque para "
                "exploits históricos de autenticación y ejecución remota.",
    },
}


def _detect_vector(cmd: str, cve_id: Optional[str] = None,
                   service: Optional[str] = None) -> Dict[str, str]:
    """Devuelve el vector. Prioriza cve_id/service (mapping explícito) sobre
    regex del cmd (fragil porque cmd suele ser nombre de tool).
    """
    import re

    # 1. Match exacto por cve_id/service
    for candidate in (cve_id, service):
        if candidate and candidate in _FINDING_ID_TO_VECTOR:
            return _FINDING_ID_TO_VECTOR[candidate].copy()

    # 2. CVE oficial: agrupa todos los CVE-* en su propio vector
    if cve_id and isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
        return {
            "name": f"CVE catalogados (NVD)",
            "desc": "Vulnerabilidades reportadas en NVD aplicables al "
                    "dispositivo según vendor/modelo identificado.",
        }

    # 3. Regex sobre cmd (legacy)
    cmd_lower = (cmd or "").lower()
    for rule in _VECTOR_RULES:
        if re.search(rule["pat"], cmd_lower, re.IGNORECASE):
            return {"name": rule["name"], "desc": rule["desc"]}
    return _VECTOR_DEFAULT.copy()


def _cluster_attack_results(attack_results: List[Dict]) -> List[Dict]:
    """
    Agrupa los resultados de explotación por vector de ataque.

    Retorna una lista de clusters ordenados por: confirmados primero, luego por severidad.
    Cada cluster contiene:
      - vector_name, vector_desc
      - cves: lista de dicts con id, severity, score, confirmed
      - confirmed_count
      - max_severity, max_score
      - representative_cmd, representative_output (del primer resultado confirmado)
      - all_results
    """
    # Construir mapa vectorName → cluster
    clusters: Dict[str, Dict] = {}

    for res in attack_results:
        cmd    = repro_cmd_of(res)
        # Priorizar cve_id/service para detección de vector (más fiable)
        vector = _detect_vector(
            cmd,
            cve_id=res.get("cve_id"),
            service=res.get("service"),
        )
        vname  = vector["name"]

        if vname not in clusters:
            clusters[vname] = {
                "vector_name": vname,
                "vector_desc": vector["desc"],
                "cves": [],
                "confirmed_count": 0,      # finding-level (cualquier vuln_found)
                "cve_confirmed_count": 0,  # solo CVE-* con vuln_found
                "max_score": 0.0,
                "max_severity": "INFO",
                "representative_cmd": None,
                "representative_output": None,
                "all_results": [],
            }

        c = clusters[vname]
        cve_id    = res.get("cve_id")
        is_real_cve = bool(cve_id) and str(cve_id).upper().startswith("CVE-")
        vuln_found = res.get("vuln_found", False)
        # confirmed: finding-level — DIAL-EXPOSED, MDNS-EXPOSED, etc. cuentan
        confirmed = bool(vuln_found)
        # cve_confirmed: solo si es CVE oficial (CVE-YYYY-NNNN) confirmado
        cve_confirmed = bool(vuln_found and is_real_cve)
        service   = res.get("service", "?")
        score     = float(res.get("score", 0) or 0)
        raw_sev   = res.get("severity") or res.get("details") or "INFO"
        severity  = raw_sev.upper() if raw_sev.upper() in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") else "INFO"
        output    = res.get("output_log", "") or ""

        c["cves"].append({
            "id": service,
            "cve_id": cve_id,
            "severity": severity,
            "score": score,
            "confirmed": confirmed,
            "cve_confirmed": cve_confirmed,
            "cmd": cmd,
            "output": output,
            # Nueva arquitectura: datos vs interpretación
            "raw_output": res.get("raw_output", "") or "",
            "interpretation": res.get("interpretation", "") or "",
        })
        c["all_results"].append(res)

        if confirmed:
            c["confirmed_count"] += 1
            if c["representative_cmd"] is None:
                c["representative_cmd"]    = cmd
                c["representative_output"] = output
        if cve_confirmed:
            c["cve_confirmed_count"] += 1

        if score > c["max_score"]:
            c["max_score"] = score
        # Severidad: actualizar si la nueva es más alta (independiente del score)
        _SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if _SEV_RANK.get(severity, 0) > _SEV_RANK.get(c["max_severity"], 0):
            c["max_severity"] = severity

    # Ordenar: primero los que tienen confirmaciones, luego por score descendente
    result = sorted(
        clusters.values(),
        key=lambda x: (-(x["confirmed_count"] > 0), -x["max_score"]),
    )
    return result