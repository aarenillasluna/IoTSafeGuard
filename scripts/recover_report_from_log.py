#!/usr/bin/env python3
"""
Recupera el audit report (HTML/JSON/MD/SARIF) desde un log de run cuando el
agente registró findings pero NO llamó a save_report antes de done().

Failure mode observado: algunos modelos (p.ej. Claude Haiku 4.5) escriben el
informe como texto y llaman done() saltándose save_report → no se generan los
artefactos. Este script reconstruye la sesión a partir de las líneas
`🔧 [tool record_finding] args=...` / `record_findings_batch_unconfirmed` del
log y regenera el reporte.

NOTA: el fix permanente está en core.tools._done (auto-guarda si save_report no
se llamó). Este script es solo para recuperar runs ANTERIORES al fix.

Uso:
    sudo ./venv/bin/python scripts/recover_report_from_log.py \
        reports/audit_run_20260524_011102.log --target 172.30.0.10
    # opcional: --out-dir reports  --mac dc:a6:32:1b:ad:01
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import tools as toolbox

# Línea de tool-call en el log: "🔧 [tool <name>] args={...}"
_TOOL_RE = re.compile(r"\[tool (record_finding|record_findings_batch_unconfirmed)\] args=(\{.*)$")


def _parse_args_dict(raw: str) -> dict | None:
    """Parsea el dict Python del log. Tolera truncado: recorta al último '}'."""
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        end = raw.rfind("}")
        if end == -1:
            return None
        try:
            return ast.literal_eval(raw[: end + 1])
        except (ValueError, SyntaxError):
            return None


def recover(log_path: str, target_ip: str, out_dir: str, mac: str | None) -> int:
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    session = toolbox.AgentSession(target_ip=target_ip)
    if mac:
        # scan_cache mínimo para que el reporter pueble identidad/vendor.
        from modules import fingerprint as fp
        vendor = fp._OUI_TO_CANONICAL.get(fp._mac_prefix(mac))
        session.scan_cache = {"mac": mac, "vendor": vendor}
    toolbox.bind_session(session)

    n_calls = 0
    for line in lines:
        m = _TOOL_RE.search(line)
        if not m:
            continue
        name, raw = m.group(1), m.group(2)
        args = _parse_args_dict(raw)
        if args is None:
            print(f"  ⚠️  no se pudo parsear una línea {name} (truncada)")
            continue
        toolbox.dispatch(name, args)
        n_calls += 1

    findings = len(session.findings)
    print(f"Replay: {n_calls} tool-calls → {findings} findings reconstruidos")
    if findings == 0:
        print("Nada que reportar. ¿Log correcto?")
        return 1

    result = toolbox.dispatch("save_report", {"out_dir": out_dir})
    if result.get("ok"):
        print(f"✅ Report regenerado: {result['path']}.*")
        print(f"   risk: {result.get('risk_label')} ({result.get('risk_score')}/100) "
              f"· findings={result['findings']}")
        return 0
    print(f"❌ save_report falló: {result}")
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description="Recupera audit report desde un log de run")
    p.add_argument("log", help="Ruta al audit_run_*.log")
    p.add_argument("--target", required=True, help="IP objetivo del run")
    p.add_argument("--out-dir", default="reports", help="Directorio de salida (default reports)")
    p.add_argument("--mac", default=None, help="MAC del target para identidad/vendor (opcional)")
    a = p.parse_args()
    if not os.path.isfile(a.log):
        print(f"No existe: {a.log}")
        return 2
    return recover(a.log, a.target, a.out_dir, a.mac)


if __name__ == "__main__":
    raise SystemExit(main())
