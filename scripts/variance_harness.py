#!/usr/bin/env python3
"""Variance harness — cuantifica la estabilidad del agente entre ejecuciones.

Convierte la afirmación cualitativa del Capítulo 5 («los hallazgos confirmados
son estables entre *runs*») en **números**, analizando los informes ya generados
en `reports/`. Para cada dispositivo (agrupado por su identidad `MAC` —la regla
de identidad del proyecto—, con respaldo a la IP) calcula, sobre sus N
ejecuciones:

  • nº de confirmados por run: media, desviación típica, min–max;
  • etiqueta de riesgo: distribución y moda;
  • **índice de estabilidad del conjunto confirmado**: |∩| / |∪| (Jaccard global)
    sobre los identificadores de hallazgo confirmados, y la media de Jaccard por
    pares;
  • **núcleo estable**: los hallazgos confirmados presentes en TODAS las
    ejecuciones del dispositivo.

Un confirmado cuenta igual que en el reporting del agente: `vuln_found=True` con
severidad distinta de INFO (un INFO/negativo verificado no es una vulnerabilidad
confirmada) y con la evidencia que exige la clase de impacto declarada (afirmar
ACCESS/EXFIL/EXEC/CRASH sin enseñar la respuesta del aparato cuenta como
candidato, no como confirmado).

Uso:
    ./venv/bin/python scripts/variance_harness.py
    ./venv/bin/python scripts/variance_harness.py --reports-dir reports --min-runs 2 \
        --out reports_baseline/VARIANZA.md
    ./venv/bin/python scripts/variance_harness.py --target 172.30.0.10

(Para *generar* nuevas ejecuciones y medir varianza sobre ellas, ejecútese el
agente N veces — `run.py --target <IP>` — y vuélvase a correr este harness; el
análisis es sobre los informes acumulados.)
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
from collections import Counter
from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple

# El arnés se ejecuta como script suelto (`python scripts/variance_harness.py`),
# así que la raíz del repo no está en `sys.path`. Antes el import de `core` era
# perezoso y el problema no se veía; al pasar a usar la función canónica de
# scoring —para no mantener una copia de la fórmula— se volvió de módulo y
# rompió la ejecución directa. Mismo bootstrap que `baseline_scan.py`.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from core.finding_ids import canonicalize_finding_id
from core.severity import (asserts_unproven_action, compute_risk_score,  # noqa: E402
                           is_confirmed_vuln)


def _sin_evidencia(f: Dict[str, Any]) -> bool:
    """Confirmado con los tres campos de evidencia en blanco: un cascarón.

    En campo el modelo registró el mismo hecho dos veces —una con el volcado de
    la sesión y otra vacía, bajo otro nombre—, y la vacía contaba igual.
    """
    return not any((f.get(k) or "").strip()
                   for k in ("raw_output", "interpretation", "evidence"))


def _confirmed_id(f: Dict[str, Any]) -> Optional[str]:
    """Identificador estable de un hallazgo confirmado (cve_id o título normalizado).

    El criterio de «confirmado» es el mismo que puntúa en `_recomputed_risk` y
    en el informe (`is_confirmed_vuln`), con el tope por clase de impacto
    desactivado por la misma razón retroactiva. Si el conjunto que se compara
    entre runs y el que se puntúa usaran reglas distintas, la métrica de
    coincidencia de §5.10.2 no estaría midiendo lo que dice medir.
    """
    if not is_confirmed_vuln({**f, "confirmed": bool(f.get("vuln_found"))},
                             apply_impact_cap=False):
        return None
    # Y además se exige lo mismo que se le exige al agente al ESCRIBIR: quien
    # declara una clase de impacto tiene que enseñar la evidencia de esa clase.
    # Aplicarlo aquí no es reescribir la historia, es medir el corpus con el
    # criterio vigente: los informes de una jornada se escribieron antes de que
    # la guarda cubriera los CVE fuera de la tabla de sondas, y sin esto la
    # tabla publicaría como confirmadas once coincidencias de versión que el
    # propio agente rotuló «candidatos … requieren verificación». Solo puede
    # hacerse porque el corpus lo permite: ninguna confirmación de sonda cae
    # (las sondas quedan exentas, y ninguna de las degradadas viene de una).
    if asserts_unproven_action({**f, "confirmed": True}):
        return None
    if _sin_evidencia(f):
        return None
    cid = (f.get("cve_id") or "").strip()
    if cid:
        # Canonizado también aquí, y no solo al registrarlo. Los informes ya
        # archivados llevan las grafías que el modelo eligió en su momento
        # —`UPNP-DESCRIPTOR-EXPOSURE`, `UPnP-DEVICE-DISCLOSURE`,
        # `UPNP-DEVICE-DESCRIPTOR-EXPOSURE` para el mismo descriptor del mismo
        # televisor—, y sin normalizarlas la métrica seguiría midiendo la
        # libertad léxica del modelo sobre toda la evidencia anterior. Es la
        # misma razón por la que el veredicto de riesgo se recalcula con la
        # fórmula final en vez de leerse del informe.
        return canonicalize_finding_id(cid) or cid.upper()
    title = (f.get("title") or "").strip().lower()
    return title[:60] if title else None


# Recálculo uniforme del veredicto (fórmula final, §4.8.5 de la memoria).
#
# Aquí vivía una COPIA de los pesos, el divisor y las etiquetas de
# `compute_risk_score`. El motivo era legítimo —la política de impacto topa a
# LOW cualquier confirmado MEDIUM+ sin campo `impact`, lo que penalizaría a los
# runs anteriores a su introducción, cuyos exploits reales (telnet/MQTT/Modbus
# del lab) no lo declaran— pero la solución era mala: duplicar la fórmula deja
# dos calibraciones que nadie mantiene sincronizadas, y recalibrar el divisor
# habría desalineado en silencio las cifras del Capítulo 5 respecto de los
# informes que las sustentan.
#
# La función canónica acepta ahora `apply_impact_cap=False`, que desactiva
# exactamente ese tope y conserva lo que SÍ es justo retroactivamente: el techo
# canónico y el **cap de alcanzabilidad**, ambos apoyados en datos presentes en
# todos los runs. Ese cap es el que corrige la inconsistencia observada en
# dispositivos como el Amazon Echo, donde runs pre-gobernanza marcaban
# SOCKS5/Nagios/TFTP "abiertos" como ACCESS/EXFIL (HIGH/CRITICAL) cuando hoy se
# reconocen como mera alcanzabilidad → NEGLIGIBLE.


def _recomputed_risk(ar: List[Dict[str, Any]]) -> Tuple[int, str]:
    """Veredicto recalculado con la MISMA función que usa el informe.

    Los informes guardan la severidad efectiva en `severity` y el confirmado en
    `vuln_found`; se traduce al esquema que espera la política y se delega.
    """
    findings = [
        {**f, "confirmed": bool(f.get("vuln_found"))
                           and not asserts_unproven_action({**f, "confirmed": True})
                           and not _sin_evidencia(f)}
        for f in ar
    ]
    risk = compute_risk_score(findings, apply_impact_cap=False)
    return risk["risk_score"], risk["risk_label"]


def _identity_key(entry: Dict[str, Any]) -> Tuple[str, str]:
    """Clave de agrupación: MAC si existe (regla de identidad del proyecto), si no IP.

    Devuelve (clave, etiqueta legible).
    """
    ident = entry.get("device_identity") or {}
    mac = (ident.get("mac") or "").strip().upper()
    vendor = (ident.get("vendor") or "").strip()
    model = (ident.get("model") or "").strip()
    ip = (entry.get("target_ip") or entry.get("ip") or "?").strip()
    if mac:
        label = " / ".join(x for x in (vendor or "?", model or "?", mac) if x)
        return mac, label
    return f"ip:{ip}", f"{vendor or '?'} @ {ip}"


def _es_artefacto(entry: Dict[str, Any]) -> bool:
    """¿Este informe es un residuo de las pruebas y no una auditoría?

    Una auditoría de verdad escanea: si no hay ni un puerto, el escaneo no
    llegó a ocurrir. Ese es el rasgo que distingue —sin listas de IPs, que
    envejecen— un informe real de los que dejaba la suite al ejercitar la rama
    de bloqueo por SAFETY del agente, que llamaba a `save_report` sin
    `out_dir` y escribía en la carpeta de evidencias del proyecto.

    Se habían acumulado 24. El arnés informaba de «53 ejecuciones en 5
    dispositivos» cuando las reales eran 30 en 3: dos aparatos inventados,
    `10.0.0.1` y `127.0.0.1`, con sus desviaciones típicas, a un paso de
    aparecer en una tabla de §5.10.

    La causa está corregida en `tests/conftest.py`, pero el filtro se queda:
    los informes viejos siguen en circulación y el arnés se ejecuta sobre
    carpetas que no siempre controla quien lo lanza. Nótese que una ejecución
    legítima del laboratorio en `127.0.0.1` SÍ trae puertos, así que este
    criterio no la toca.
    """
    return not (entry.get("open_ports") or [])


def _es_rescatado(entry: Dict[str, Any]) -> bool:
    """¿El informe salió de un run que NO terminó por su propio pie?

    Desde iter_20 el agente guarda informe pase lo que pase: si lo cancelas, si
    se agota el reloj, si el proveedor deja de responder, si se va la luz. Eso
    salva el trabajo —dos réplicas de la tanda del 2026-08-09 se perdieron
    enteras por no tenerlo— pero crea una pregunta nueva: ¿cuenta ese informe
    para la varianza?

    No, por defecto. Un run cortado en el turno 7 no recorrió el pipeline: sus
    hallazgos son un prefijo, no una medición, y meterlo en el conjunto hunde el
    índice de estabilidad por un motivo que no tiene nada que ver con el agente.
    Se excluye del cálculo y se cuenta aparte, que es la forma honesta: el dato
    existe, se dice cuántos hay, y no se cuela en la cifra que se publica.
    """
    meta = entry.get("run_metadata") or {}
    return bool(meta.get("interrupted"))


def load_runs(reports_dir: str, incluir_rescatados: bool = False) -> List[Dict[str, Any]]:
    """Normaliza cada informe a un registro de run comparable.

    Soporta las dos variantes con datos útiles:
      • informe completo  {findings:[entry,...]}  → confirmados como conjunto.
      • informe compacto  {ip, confirmed_count, risk_score, risk_label, ...}.
    """
    runs: List[Dict[str, Any]] = []
    rescatados: List[str] = []
    for path in sorted(glob.glob(os.path.join(reports_dir, "audit_report_*.json"))):
        # `_risk.json` y `_telemetry.json` son SIDECARS del informe completo, no
        # ejecuciones aparte. El glob los recogía y, como no llevan
        # `device_identity`, caían a una clave `ip:…` distinta de la clave por
        # MAC del informe real: cada run se contaba DOS veces y cada dispositivo
        # aparecía duplicado —una entrada por MAC y otra por IP—. Las cifras de
        # varianza de §5.10.2 salían infladas y con la agrupación partida, que es
        # justo lo que la regla de identidad por MAC existe para evitar.
        if path.endswith(("_risk.json", "_telemetry.json")):
            continue
        try:
            d = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue

        if d.get("findings"):
            for entry in d["findings"]:
                if _es_artefacto(entry):
                    continue
                if _es_rescatado(entry) and not incluir_rescatados:
                    rescatados.append(os.path.basename(path))
                    continue
                key, label = _identity_key(entry)
                superficie = frozenset(
                    o["port"] for o in (entry.get("open_ports") or [])
                    if isinstance(o, dict) and o.get("protocol") == "tcp" and o.get("port"))
                ar = entry.get("attack_results", []) or []
                confirmed = {cid for f in ar if (cid := _confirmed_id(f))}
                risk = entry.get("risk_summary") or {}
                rec_score, rec_label = _recomputed_risk(ar)
                runs.append({
                    "path": os.path.basename(path), "key": key, "label": label,
                    "confirmed_set": confirmed, "confirmed_count": len(confirmed),
                    # risk_label: recalculado con la fórmula final para que runs de
                    # distintas fases del desarrollo sean comparables entre sí.
                    # El valor que el run almacenó en su momento se conserva aparte.
                    "risk_score": rec_score, "risk_label": rec_label,
                    "risk_label_stored": risk.get("risk_label"),
                    "surface": superficie,
                    "has_set": True,
                })
        elif "confirmed_count" in d and ("ip" in d or "target_ip" in d):
            key, label = _identity_key(d)
            runs.append({
                "path": os.path.basename(path), "key": key, "label": label,
                "confirmed_set": None, "confirmed_count": d.get("confirmed_count"),
                "risk_score": d.get("risk_score"), "risk_label": d.get("risk_label"),
                "has_set": False,
            })
    if rescatados:
        print(f"[varianza] {len(rescatados)} informe(s) de runs no terminados "
              f"excluidos ({', '.join(rescatados[:3])}"
              f"{' …' if len(rescatados) > 3 else ''}). "
              f"Usa --incluir-rescatados para contarlos.", file=sys.stderr)
    return runs


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b) if (a | b) else 1.0


def analyze_group(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = [r["confirmed_count"] for r in runs if r["confirmed_count"] is not None]
    labels = [r["risk_label"] for r in runs if r["risk_label"]]
    sets = [r["confirmed_set"] for r in runs if r["has_set"] and r["confirmed_set"] is not None]

    res: Dict[str, Any] = {
        "n_runs": len(runs),
        "n_with_sets": len(sets),
        "count_mean": round(statistics.mean(counts), 2) if counts else None,
        "count_std": round(statistics.pstdev(counts), 2) if len(counts) > 1 else 0.0,
        "count_min": min(counts) if counts else None,
        "count_max": max(counts) if counts else None,
        "risk_labels": dict(Counter(labels)),
        "risk_label_mode": Counter(labels).most_common(1)[0][0] if labels else None,
    }
    if len(sets) >= 2:
        union: Set[str] = set().union(*sets)
        inter: Set[str] = set(sets[0]).intersection(*sets[1:])
        res["stability_index"] = round(len(inter) / len(union), 3) if union else 1.0
        pair = [_jaccard(a, b) for a, b in combinations(sets, 2)]
        res["mean_pairwise_jaccard"] = round(statistics.mean(pair), 3) if pair else 1.0
        res["stable_core"] = sorted(inter)
        res["union_size"] = len(union)

    # Dos causas distintas de un índice bajo, que el número agregado confunde.
    #
    # Un dispositivo puede salir con estabilidad 0.000 porque el agente encuentra
    # cosas DISTINTAS cada vez, o porque en la mayoría de ejecuciones no confirma
    # NADA —y entonces la intersección es vacía sin que haya discrepancia
    # ninguna—. Le pasa al televisor del banco de pruebas: 5 de 8 ejecuciones sin
    # un solo confirmado. Son diagnósticos opuestos (uno apunta a inconsistencia
    # del agente, el otro a un dispositivo sin superficie confirmable) y exigen
    # respuestas opuestas, así que se publican separados.
    # Volatilidad de la SUPERFICIE, que es una fuente de varianza distinta de la
    # del agente y hasta ahora quedaba mezclada con ella. Si los puertos abiertos
    # cambian entre réplicas, el objetivo no es el mismo de una a otra y parte de
    # la inestabilidad medida no es atribuible al agente; si son idénticos, lo
    # que varíe viene del agente o de lo que el servicio conteste. La distinción
    # importa porque los dos diagnósticos piden respuestas opuestas.
    superficies = [r["surface"] for r in runs if r.get("surface") is not None]
    if len(superficies) >= 2:
        u = set().union(*superficies)
        i = set(superficies[0]).intersection(*superficies[1:])
        res["surface_ports"] = len(u)
        res["surface_volatility"] = round(1 - len(i) / len(u), 3) if u else 0.0

    vacios = [s_ for s_ in sets if not s_]
    con_hallazgo = [s_ for s_ in sets if s_]
    res["n_empty"] = len(vacios)
    if len(con_hallazgo) >= 2:
        union2: Set[str] = set().union(*con_hallazgo)
        inter2: Set[str] = set(con_hallazgo[0]).intersection(*con_hallazgo[1:])
        res["stability_nonempty"] = round(len(inter2) / len(union2), 3) if union2 else 1.0
        pair2 = [_jaccard(a, b) for a, b in combinations(con_hallazgo, 2)]
        res["jaccard_nonempty"] = round(statistics.mean(pair2), 3) if pair2 else 1.0
    return res


def render_markdown(groups: Dict[str, Dict[str, Any]], labels: Dict[str, str],
                    min_runs: int) -> str:
    lines = ["# Varianza del agente entre ejecuciones",
             "",
             "Estabilidad de los hallazgos **confirmados** del agente, medida sobre los informes "
             "acumulados en `reports/`. Un confirmado = `vuln_found=True`, severidad ≠ INFO y "
             "evidencia acorde a la clase de impacto declarada. "
             "Agrupación por identidad de dispositivo (MAC, con respaldo a IP). "
             "El veredicto de riesgo se **recalcula uniformemente** con la fórmula final "
             "(Σ pesos de severidad de los confirmados / 0.4) para que ejecuciones de "
             "distintas fases del desarrollo sean comparables.",
             ""]
    qualifying = {k: v for k, v in groups.items() if v["n_runs"] >= min_runs}
    if not qualifying:
        lines.append(f"_No hay dispositivos con ≥ {min_runs} ejecuciones en `reports/`._")
        return "\n".join(lines)

    lines += ["| Dispositivo | Runs | Sin confirmar | Confirmados (media ± σ) | min–max | "
              "Riesgo (moda) | Estabilidad \\|∩\\|/\\|∪\\| | Jaccard medio | "
              "Estab. solo con hallazgo | Volatilidad de la superficie |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for k, v in sorted(qualifying.items(), key=lambda kv: -kv[1]["n_runs"]):
        mean = v["count_mean"]
        std = v["count_std"]
        cm = f"{mean} ± {std}" if mean is not None else "—"
        mm = f"{v['count_min']}–{v['count_max']}" if v["count_min"] is not None else "—"
        si = v.get("stability_index")
        si_s = f"**{si}**" if si is not None else "n/d (1 run con conjunto)"
        jac = v.get("mean_pairwise_jaccard")
        jac_s = str(jac) if jac is not None else "—"
        vac = v.get("n_empty")
        vac_s = f"{vac}/{v['n_with_sets']}" if vac is not None else "—"
        sne = v.get("stability_nonempty")
        sne_s = str(sne) if sne is not None else "—"
        vol = v.get("surface_volatility")
        vol_s = (f"{vol:.0%} ({v.get('surface_ports')} puertos TCP)"
                 if vol is not None else "—")
        lines.append(f"| {labels[k][:42]} | {v['n_runs']} | {vac_s} | {cm} | {mm} | "
                     f"{v['risk_label_mode'] or '—'} | {si_s} | {jac_s} | {sne_s} | {vol_s} |")

    lines += ["", "## Núcleo estable por dispositivo",
              "_(hallazgos confirmados presentes en TODAS las ejecuciones con conjunto)_", ""]
    for k, v in sorted(qualifying.items(), key=lambda kv: -kv[1]["n_runs"]):
        if v.get("stable_core") is not None:
            core = v["stable_core"]
            lines.append(f"- **{labels[k][:50]}** ({v['n_with_sets']} runs con conjunto, "
                         f"unión {v.get('union_size', 0)}): "
                         + (", ".join(f"`{c}`" for c in core) if core else "_∅_"))
    lines += ["",
              "## Interpretación",
              "El **índice de estabilidad** (|∩|/|∪|) y el **Jaccard medio por pares** miden cuánto "
              "coincide el conjunto de confirmados entre *runs* del mismo dispositivo: 1.0 = "
              "idénticos, 0 = disjuntos. El **núcleo estable** es lo que el agente confirma de forma "
              "reproducible; la diferencia respecto a la unión es la **variabilidad residual** del "
              "LLM, aceptable y documentada (OM1). La desviación típica del nº de confirmados "
              "acota esa variabilidad en una sola cifra."]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Cuantifica la varianza del agente entre runs.")
    ap.add_argument("--reports-dir", default="reports", help="Carpeta con los informes JSON.")
    ap.add_argument("--min-runs", type=int, default=2, help="Mínimo de runs por dispositivo.")
    ap.add_argument("--target", default=None, help="Filtra por IP objetivo.")
    ap.add_argument("--device", default=None, help="Filtra por subcadena de identidad (vendor/model/mac).")
    ap.add_argument("--out", default="reports_baseline/VARIANZA.md", help="Markdown de salida.")
    ap.add_argument("--incluir-rescatados", action="store_true",
                    help="Cuenta también los informes de runs que no llegaron a "
                         "done() (cancelados, timeout, error). Excluidos por "
                         "defecto: son un prefijo del pipeline, no una medición.")
    args = ap.parse_args()

    runs = load_runs(args.reports_dir, incluir_rescatados=args.incluir_rescatados)
    if args.target:
        runs = [r for r in runs if args.target in r["label"] or args.target in r["key"]]
    if args.device:
        runs = [r for r in runs if args.device.lower() in r["label"].lower()]

    groups: Dict[str, List[Dict[str, Any]]] = {}
    labels: Dict[str, str] = {}
    for r in runs:
        groups.setdefault(r["key"], []).append(r)
        labels[r["key"]] = r["label"]

    analyzed = {k: analyze_group(v) for k, v in groups.items()}
    md = render_markdown(analyzed, labels, args.min_runs)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(md + "\n")

    # Resumen en terminal
    print(f"[varianza] {len(runs)} runs en {len(groups)} dispositivos "
          f"(reports: {args.reports_dir})")
    for k, v in sorted(analyzed.items(), key=lambda kv: -kv[1]["n_runs"]):
        if v["n_runs"] >= args.min_runs:
            si = v.get("stability_index")
            print(f"  • {labels[k][:46]:46} | runs={v['n_runs']:2} | "
                  f"confirmados {v['count_mean']}±{v['count_std']} ({v['count_min']}–{v['count_max']}) | "
                  f"riesgo {v['risk_label_mode']} | estab={si if si is not None else 'n/d'}")
    print(f"[varianza] informe: {args.out}")


if __name__ == "__main__":
    main()
