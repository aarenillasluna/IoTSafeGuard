#!/usr/bin/env bash
#
# Preparar y cerrar una tanda de evaluación.
#
#   ./scripts/tanda.sh archivar                  guarda la tanda actual aparte
#   sudo ./scripts/tanda.sh baseline 192.168.1.1 escáner clásico para §5.9
#   ./scripts/tanda.sh varianza                  recalcula VARIANZA.md
#   ./scripts/tanda.sh estado                    qué hay ahora mismo
#
# Por qué existe: los tres pasos son fáciles de hacer en el orden equivocado.
# Archivar DESPUÉS de lanzar la tanda nueva mezcla dos épocas de código en la
# misma carpeta, y el arnés de varianza las promedia sin avisar: quince
# réplicas por aparato en vez de dos grupos de cinco comparables entre sí.

set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$RAIZ/venv/bin/python"
cd "$RAIZ"

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
gris()  { printf '\033[90m%s\033[0m\n' "$*"; }

# `sudo` deja los informes con propietario root, y las siguientes ejecuciones
# sin privilegios no pueden reescribirlos. Se devuelven a quien lanzó el script.
devolver_propiedad() {
  if [ -n "${SUDO_UID:-}" ]; then
    chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@" 2>/dev/null || true
  fi
}

# Sesiones de auditoría en reports/, una línea por marca de tiempo. Los
# sidecars `_risk` y `_telemetry` acompañan al informe, no son ejecuciones.
#
# El `|| true` no es decorativo: sin él, `grep` devuelve 1 cuando no hay nada
# que listar, `pipefail` lo propaga y `set -e` mata el script sin imprimir una
# sola línea. Es decir, «no hay informes» se comportaba como un fallo mudo.
sesiones() {
  ls reports/audit_report_*.json 2>/dev/null \
    | grep -vE '_risk|_telemetry' \
    | sed 's/.*report_//;s/\.json//' || true
}

cmd_estado() {
  local lista n
  lista=$(sesiones)
  n=$(printf '%s' "$lista" | grep -c . || true)
  echo "informes en reports/: $n"
  if [ "$n" -gt 0 ]; then
    gris "  del $(printf '%s\n' "$lista" | head -1)"
    gris "  al  $(printf '%s\n' "$lista" | tail -1)"
  fi

  # Recuento por aparato y por desenlace. Existe porque el 2026-08-09 una tanda
  # de quince quedó en doce sin que se notara hasta ir a calcular la varianza:
  # dos réplicas se perdieron (bucle y apagón) y una nunca llegó a lanzarse. Lo
  # que hace falta saber, y el script no decía, es CUÁNTAS FALTAN Y DE CUÁL.
  echo
  echo "réplicas por aparato:"
  "$PY" - <<'PY' 2>/dev/null || gris "  (sin informes legibles)"
import glob, json, os
from collections import Counter
completos, rescatados, etiquetas = Counter(), Counter(), {}
for p in sorted(glob.glob("reports/audit_report_*.json")):
    if p.endswith(("_risk.json", "_telemetry.json")):
        continue
    try:
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    for e in (d.get("findings") or []):
        if not (e.get("open_ports") or []):
            continue  # artefacto sin escaneo: no es una auditoría
        ident = e.get("device_identity") or {}
        # Agrupar por MAC, NUNCA por la etiqueta. La etiqueta incluye el modelo,
        # y el modelo cambia: al purgar de la KB un modelo envenenado
        # («CURVE25519», leído de una lista de cifrados SSH) a media jornada, el
        # mismo router apareció como dos aparatos distintos en este recuento, con
        # cuatro réplicas cada uno. El arnés de varianza agrupaba bien porque usa
        # la MAC; este script no, y decía que faltaban réplicas que ya existían.
        clave = ident.get("mac") or f"ip:{e.get('target_ip') or e.get('ip')}"
        etiqueta = " / ".join(x for x in (ident.get("vendor"), ident.get("model"),
                                          ident.get("mac") or e.get("ip")) if x)
        etiquetas[clave] = etiqueta or clave
        if (e.get("run_metadata") or {}).get("interrupted"):
            rescatados[clave] += 1
        else:
            completos[clave] += 1
if not completos and not rescatados:
    print("  (ninguna)")
for clave in sorted(set(completos) | set(rescatados), key=lambda k: etiquetas.get(k, k)):
    c, r = completos[clave], rescatados[clave]
    faltan = max(0, 5 - c)
    aviso = f"  ← faltan {faltan} para el umbral de varianza" if faltan else ""
    extra = f", {r} rescatada(s) sin contar" if r else ""
    print(f"  {etiquetas.get(clave, clave)[:52]:52} {c} completa(s){extra}{aviso}")
PY

  echo
  echo "tandas archivadas:"
  ls -1 ejecuciones_rendimiento/ 2>/dev/null | sed 's/^/  /' || echo "  (ninguna)"
}

cmd_archivar() {
  local n destino
  n=$(sesiones | grep -c . || true)
  if [ "$n" -eq 0 ]; then
    verde "reports/ ya está vacío — nada que archivar."
    return 0
  fi

  destino="ejecuciones_rendimiento/$(date +%Y-%m-%d)_$(git rev-parse --short HEAD)"
  echo "Se van a MOVER $n auditorías (más sus registros) a:"
  echo "    $destino"
  echo
  gris "La carpeta lleva el hash del commit para que se sepa con qué versión"
  gris "del código se produjeron. Es lo que hace citable la evidencia."
  echo
  read -r -p "¿Seguimos? [s/N] " respuesta
  [ "$respuesta" = "s" ] || [ "$respuesta" = "S" ] || { rojo "Cancelado."; return 1; }

  # Los informes van a `$destino/reports/`, NO sueltos en `$destino/`. La
  # primera tanda archivada usó esa disposición y las siguientes no, de modo que
  # el archivo quedó con dos formas distintas: cualquier herramienta que recorra
  # `ejecuciones_rendimiento/*/reports/*.json` —el patrón natural, y el que usan
  # los recuentos del Capítulo 5— veía la tanda vieja y se saltaba las nuevas en
  # silencio. Un archivo cuya estructura depende de cuándo se creó no es un
  # archivo consultable.
  mkdir -p "$destino/reports"
  mv reports/audit_report_* "$destino/reports/" 2>/dev/null || true
  mv reports/audit_run_*    "$destino/reports/" 2>/dev/null || true
  verde "Archivadas en $destino"
  echo
  gris "reports/ queda limpio. La tanda nueva ya no se mezcla con la vieja."

  # La base de conocimiento es la OTRA mitad del estado, y archivar informes sin
  # tocarla no produce una tanda «desde cero»: el agente arranca sabiendo qué
  # aparatos hay, qué sondas le funcionaron con cada fabricante y qué CVE ya
  # descartó. Eso es OM2 haciendo su trabajo —y lo que se quiere medir casi
  # siempre—, pero para una línea base limpia hay que apartarla, y conviene que
  # sea una decisión consciente y no un olvido.
  if [ -f data/kb.json ]; then
    echo
    "$PY" - <<'PY' 2>/dev/null || true
import json
kb = json.load(open("data/kb.json"))
dev = kb.get("devices_seen") or {}
perf = kb.get("vendor_profiles") or {}
print(f"La base de conocimiento sabe: {len(dev)} aparato(s), "
      f"{sum(len(v.get('useful_probes') or []) for v in perf.values())} sondas útiles "
      f"por fabricante, {len(kb.get('cve_validation_history') or {})} CVE con histórico.")
PY
    gris "  · conservarla  → el agente parte con ese aprendizaje (mide OM2)"
    gris "  · apartarla    → línea base desde cero, comparable con la primera tanda"
    echo
    read -r -p "¿Aparto también la base de conocimiento? [s/N] " kb_resp
    if [ "$kb_resp" = "s" ] || [ "$kb_resp" = "S" ]; then
      mv data/kb.json "$destino/" && verde "KB archivada en $destino/kb.json"
      gris "El caché de la NVD se queda: no es aprendizaje, solo evita volver a"
      gris "descargar lo mismo. Borrarlo haría la tanda más lenta, no más limpia."
    else
      gris "KB conservada. La tanda nueva parte del aprendizaje acumulado."
    fi
  fi
}

cmd_baseline() {
  local objetivo="${1:-}"
  [ -n "$objetivo" ] || { rojo "Falta el objetivo: sudo ./scripts/tanda.sh baseline 192.168.1.1"; return 1; }
  [ "$(id -u)" -eq 0 ] || { rojo "Necesita sudo (nmap con NSE)."; return 1; }

  mkdir -p reports_baseline
  echo "Escáner clásico contra $objetivo"
  gris "Solo scripts NSE 'vuln': no consultan Internet, así que la ejecución"
  gris "es reproducible con el mismo criterio que se le exige al agente."
  echo
  "$PY" scripts/baseline_scan.py \
      --target "$objetivo" \
      --scripts vuln \
      --report-dir reports_baseline \
      --label "Nmap+NSE vuln"
  devolver_propiedad reports_baseline
  echo
  verde "Listo. Salida en reports_baseline/"
  gris "Pásame el resumen y monto la tabla de COMPARATIVA.md."
}

cmd_varianza() {
  "$PY" scripts/variance_harness.py --min-runs 5 --out reports_baseline/VARIANZA.md
  devolver_propiedad reports_baseline
}

case "${1:-ayuda}" in
  archivar) cmd_archivar ;;
  baseline) shift; cmd_baseline "$@" ;;
  varianza) cmd_varianza ;;
  estado)   cmd_estado ;;
  *)
    sed -n '3,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
esac
