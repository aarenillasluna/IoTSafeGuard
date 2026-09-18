#!/usr/bin/env python3
"""Precision / Recall / F1 del agente sobre el lab, contra `lab/ground_truth.yml`.

Convierte la afirmación cualitativa «el agente cubre los vectores plantados» en
una métrica estándar de detección, usando la verdad de campo del lab (8 vectores
deliberadamente inseguros, Anexo C). Como el baseline (`scripts/baseline_scan.py`)
emite el MISMO esquema de informe, este harness puntúa a ambos por igual → el
cara a cara escáner↔agente queda en números propios (alimenta §5.2/§5.9).

Definición (estándar en detección de vulnerabilidades):
  TP = vector plantado detectado (≥1 confirmado que casa con `match`)
  FN = vector plantado no detectado
  FP = confirmado que no casa con ningún vector plantado (alerta espuria)
  precision = TP/(TP+FP)   recall = TP/(TP+FN)   F1 = 2PR/(P+R)

Un confirmado = `vuln_found=True` con severidad ≠ INFO (misma regla que el resto
del proyecto: un INFO es nota/negativo, no vulnerabilidad).

Uso:
    ./venv/bin/python scripts/lab_scoring.py reports/audit_report_XX';.json
    ./venv/bin/python scripts/lab_scoring.py --agent <agente.json> --baseline <baseline.json>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

import yaml

# El arnés se lanza como script suelto (`python scripts/lab_scoring.py …`), de
# modo que la raíz del proyecto no está en el path y `core.severity` —donde vive
# la definición de qué cuenta— no se puede importar. Sin esto, el arnés tendría
# que llevar su propia copia del criterio, que es exactamente cómo se llega a
# dos gobernanzas distintas para la misma pregunta.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_GT = os.path.join(_ROOT, "lab", "ground_truth.yml")


def load_ground_truth(path: str = _DEFAULT_GT) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _detected_signatures(report: Dict[str, Any]) -> List[str]:
    """Firmas de lo que el sistema DETECTÓ, que no es lo mismo que confirmó.

    Esta distinción tardó en aparecer y es metodológicamente relevante. El resto
    del trabajo insiste en separar **candidato** de **confirmado**: solo cuenta
    como hallazgo lo que se ha demostrado explotable, y por eso los `*-EXPOSED`
    —que únicamente reafirman que el servicio está ahí— dejaron de contar como
    vulnerabilidad confirmada (§4.8.5).

    Pero esta función no mide vulnerabilidad: mide **cobertura de detección**
    contra un ground-truth de vectores plantados. Y para saber si el agente
    *encontró* el endpoint CWMP del laboratorio, que lo reporte como presente es
    exactamente la evidencia que hace falta; exigirle además haberlo explotado
    convertiría un recall en otra cosa. Reutilizar aquí el filtro de confirmados
    mezclaba las dos preguntas y habría convertido en falso negativo un vector
    correctamente detectado.

    Se excluyen los negativos comprobados (`SOCKS5-AUTH-REQUIRED` y familia):
    haber probado que algo NO es explotable tampoco es detectar un vector.
    """
    from core.severity import _CONFIRMED_NEGATIVE_IDS, is_surface_only

    sigs: List[str] = []
    findings = report.get("findings")
    if not isinstance(findings, list):
        return sigs
    for entry in findings:
        for a in entry.get("attack_results", []) or []:
            if not a.get("vuln_found"):
                continue
            vid = str(a.get("cve_id") or "").upper()
            if vid in _CONFIRMED_NEGATIVE_IDS:
                continue
            sev = (a.get("severity") or "INFO").upper()
            # INFO no cuenta, SALVO cuando el INFO es precisamente «el servicio
            # está ahí»: eso es una detección positiva del vector plantado.
            if sev == "INFO" and not is_surface_only(vid):
                continue
            sig = (a.get("attack_type") or a.get("cve_id") or a.get("title") or "")
            sigs.append(str(sig).upper())
    return sigs



def score(report: Dict[str, Any], gt: Dict[str, Any]) -> Dict[str, Any]:
    vectors = gt.get("vectors", [])
    sigs = _detected_signatures(report)

    detected_vectors = set()
    matched_sig_idx = set()
    for vi, vec in enumerate(vectors):
        needles = [m.upper() for m in vec.get("match", [])]
        for si, sig in enumerate(sigs):
            if any(n in sig for n in needles):
                detected_vectors.add(vi)
                matched_sig_idx.add(si)

    tp = len(detected_vectors)
    fn = len(vectors) - tp
    fp = len([s for i, s in enumerate(sigs) if i not in matched_sig_idx])

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "vectors_total": len(vectors),
        "TP": tp, "FN": fn, "FP": fp,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "detected": sorted(vectors[i]["id"] for i in detected_vectors),
        "missed": sorted(vectors[i]["id"] for i in range(len(vectors))
                         if i not in detected_vectors),
        "spurious_signatures": [s for i, s in enumerate(sigs) if i not in matched_sig_idx],
    }


def _load(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _print_row(label: str, s: Dict[str, Any]) -> None:
    print(f"{label:24} | TP={s['TP']}/{s['vectors_total']} FN={s['FN']} FP={s['FP']} "
          f"| P={s['precision']} R={s['recall']} F1={s['f1']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Precision/Recall/F1 sobre el lab.")
    ap.add_argument("report", nargs="?", help="Informe JSON único a puntuar.")
    ap.add_argument("--agent", help="Informe del agente.")
    ap.add_argument("--baseline", help="Informe del baseline (para el cara a cara).")
    ap.add_argument("--ground-truth", default=_DEFAULT_GT)
    args = ap.parse_args()

    gt = load_ground_truth(args.ground_truth)
    print(f"[lab-scoring] ground-truth: {len(gt.get('vectors', []))} vectores "
          f"plantados (target {gt.get('target')})\n")

    any_done = False
    for label, path in (("AGENTE", args.agent or args.report), ("BASELINE", args.baseline)):
        rep = _load(path)
        if rep is None:
            continue
        any_done = True
        s = score(rep, gt)
        _print_row(label, s)
        if s["missed"]:
            print(f"    no detectados: {', '.join(s['missed'])}")
        if s["spurious_signatures"]:
            print(f"    espurios (FP): {', '.join(s['spurious_signatures'])}")

    if not any_done:
        ap.error("indica un informe (posicional) o --agent/--baseline")


if __name__ == "__main__":
    main()
