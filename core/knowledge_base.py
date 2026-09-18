"""
Knowledge Base persistente entre runs del agente.

Almacena:
  - devices_seen: targets auditados previamente con su fingerprint
  - vendor_profiles: perfiles agregados por vendor (puertos típicos, probes
    útiles, CVEs ya validados como patched)
  - cve_validation_history: histórico de cuántas veces se ha intentado un CVE
    y cuántas se confirmó vulnerable (útil para evitar re-probar lo conocido)
  - reflection_log: índice de reportes de reflexión generados

Persistencia: `data/kb.json` (configurable via KB_PATH env var).
Escritura atómica vía `tempfile + os.replace` para evitar corrupción si el
proceso muere a mitad de write.

Schema versionado — cargas que vean version desconocida abortan limpiamente.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from loguru import logger

from core.fsutil import publish_artifact, publish_dir
from core.severity import is_confirmed_vuln


_DEFAULT_KB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "kb.json",
)

KB_SCHEMA_VERSION = 1

# Intentos fallidos consecutivos, sin ninguna confirmación previa, tras los que
# un CVE se da por parcheado en ese fabricante. Una sola constante para las dos
# lecturas que dependen de ella: la que ESCRIBE `patched_cves`
# (`record_cve_test`) y la que PREGUNTA si ya está parcheado
# (`is_cve_consistently_patched`).
PATCHED_CVE_THRESHOLD = 3


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _run_id() -> str:
    """Identificador de la ejecución en curso, estable dentro del proceso.

    El PID basta y es lo único disponible sin acoplar la KB a la sesión del
    agente: lo que se necesita no es un nombre bonito, sino que dos guardados de
    la MISMA auditoría cuenten como uno y dos auditorías distintas como dos. Se
    le antepone la fecha para que dos runs con el mismo PID en días distintos
    —el sistema recicla PIDs— no se confundan.
    """
    return f"{time.strftime('%Y%m%d')}-{os.getpid()}"


def _looks_like_ipv4(s: Optional[str]) -> bool:
    """¿`s` es una IPv4 cruda (clave legada de devices_seen)?"""
    if not s or not isinstance(s, str):
        return False
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _merge_device_records(a: Dict[str, Any], b: Dict[str, Any],
                          *, counters: str = "sum") -> Dict[str, Any]:
    """Fusiona dos registros del mismo dispositivo: conserva el `first_seen` más
    antiguo, el `last_seen` más reciente y rellena campos vacíos.

    `counters` decide qué hacer con `audit_count`, y la distinción NO es un
    detalle: hay dos escenarios de fusión con aritmética opuesta.

      · `"sum"` — historiales DISJUNTOS. Dos claves distintas resultan ser el
        mismo aparato (migración IP→MAC, alias de interfaz). Ninguno de los dos
        contadores incluye las auditorías del otro, así que sumar es lo correcto.

      · `"max"` — historiales SOLAPADOS. El mismo aparato bajo la MISMA clave,
        en memoria y en disco (`_merge_from_disk`). El registro en memoria ya
        contiene el histórico del disco: se cargó al arrancar. Sumar aquí
        duplica el contador en CADA save, y como se guarda varias veces por
        auditoría el crecimiento es exponencial — en 15 ejecuciones reales dio
        `audit_count: 1.040.188.384` (≈2³⁰) para un televisor, cifra que además
        viajaba al prompt dentro de `kb_context.previous_audit`.

    Es el mismo criterio que `cve_validation_history` y `global_stats` ya
    aplicaban con `max()` en ese método; `audit_count` era la excepción que
    faltaba por alinear.
    """
    out = dict(a)
    for k, v in b.items():
        if v and not out.get(k):
            out[k] = v
    fs = [x for x in (a.get("first_seen"), b.get("first_seen")) if x]
    ls = [x for x in (a.get("last_seen"), b.get("last_seen")) if x]
    if fs:
        out["first_seen"] = min(fs)
    if ls:
        out["last_seen"] = max(ls)
        # los campos "frescos" provienen del registro con last_seen más reciente
        fresh = b if (b.get("last_seen") or "") >= (a.get("last_seen") or "") else a
        for k in ("vendor", "model", "firmware", "mac", "ip", "os_match",
                  "ports_last_seen", "findings_count_last", "confirmed_count_last"):
            if fresh.get(k):
                out[k] = fresh[k]
    # Conjunto de ejecuciones: la unión no necesita saber si los historiales
    # son disjuntos o solapados, porque unir es idempotente. Es lo que elimina
    # de raíz la distinción `sum`/`max` que este mismo módulo tuvo que aprender
    # a golpes; el parámetro `counters` se conserva solo para los registros
    # antiguos, que traen un número y no un conjunto.
    runs = sorted(set(a.get("audit_runs") or []) | set(b.get("audit_runs") or []))
    if runs:
        out["audit_runs"] = runs
        out["audit_count"] = len(runs)
    else:
        ca, cb = int(a.get("audit_count") or 0), int(b.get("audit_count") or 0)
        out["audit_count"] = max(ca, cb) if counters == "max" else ca + cb
    return out


_VENDOR_LIST_FIELDS = ("common_ports", "useful_probes",
                       "patched_cves", "fingerprint_markers")


def _known_probe_names() -> Set[str]:
    """Nombres `probe_*` que existen de verdad en el registro de herramientas.

    Import perezoso: `core.tools` importa este módulo (también en diferido), y
    hacerlo arriba cerraría el ciclo.
    """
    try:
        from core.tools import _REGISTRY
    except Exception:  # pragma: no cover - el registro siempre está en runtime
        return set()
    return {n for n in _REGISTRY if n.startswith("probe_")}


def _valid_probe_names(names: Optional[List[str]]) -> List[str]:
    """Filtra `useful_probes` dejando solo herramientas que existen.

    `vendor_profiles.useful_probes` alimenta el contexto del siguiente run
    («probes que históricamente funcionaron con este fabricante»), así que lo
    que se guarde aquí vuelve al prompt. Una de las dos fuentes es fiable —
    `session.executed_probes`, que son probes realmente ejecutadas— pero la otra
    es el JSON de reflexión del LLM, texto libre. En 15 ejecuciones reales, 29
    de 66 nombres aprendidos no existían:

        probe_alexa_api · probe_aws_greengrass · probe_dropbear_version_check
        "probe_ssh con credenciales_default_askey"
        "probe_upnp_igd especialmente relevante para CURVE25519"

    Frases en español guardadas como nombres de herramienta y devueltas al
    modelo en el turno 0 del run siguiente: la KB no aprendía, se contaminaba.
    El filtro va aquí, en el único punto por el que pasan ambas fuentes.
    """
    if not names:
        return []
    known = _known_probe_names()
    if not known:
        return [n for n in names if isinstance(n, str)]
    kept, dropped = [], []
    for n in names:
        (kept if isinstance(n, str) and n in known else dropped).append(n)
    if dropped:
        logger.info(
            f"[KB] {len(dropped)} probe(s) inexistentes descartadas: "
            f"{', '.join(str(d)[:40] for d in dropped[:5])}"
            f"{' …' if len(dropped) > 5 else ''}")
    return kept


def _merge_vendor_profiles(a: Dict[str, Any], b: Dict[str, Any],
                           *, counters: str = "sum") -> Dict[str, Any]:
    """Fusiona dos perfiles del mismo vendor conservando lo aprendido en ambos.

    Las listas se unen preservando el orden de descubrimiento, `first_seen` se
    queda con el más antiguo y `last_updated` con el más reciente. Lo usan tanto
    la migración de duplicados como el merge previo a guardar: antes había dos
    copias de esta lógica y solo una contemplaba todos los campos.

    `counters` gobierna `device_count` con el mismo criterio que
    `_merge_device_records`: perfiles disjuntos suman, perfiles solapados
    (memoria vs. disco, misma clave) toman el máximo.
    """
    out: Dict[str, Any] = {
        "first_seen": None, "last_updated": None, "device_count": 0,
    }
    for field_name in _VENDOR_LIST_FIELDS:
        out[field_name] = []
    for src in (a or {}, b or {}):
        if src.get("first_seen"):
            if out["first_seen"] is None or src["first_seen"] < out["first_seen"]:
                out["first_seen"] = src["first_seen"]
        if src.get("last_updated"):
            if out["last_updated"] is None or src["last_updated"] > out["last_updated"]:
                out["last_updated"] = src["last_updated"]
        dc = int(src.get("device_count", 0) or 0)
        out["device_count"] = (max(out["device_count"], dc) if counters == "max"
                               else out["device_count"] + dc)
        for field_name in _VENDOR_LIST_FIELDS:
            for item in (src.get(field_name) or []):
                if item not in out[field_name]:
                    out[field_name].append(item)
    return out


def _empty_kb() -> Dict[str, Any]:
    return {
        "version": KB_SCHEMA_VERSION,
        "created": _now_iso(),
        "last_updated": _now_iso(),
        "devices_seen": {},          # device_key → device record
        # MAC alternativa → clave del dispositivo al que pertenece. Un equipo
        # real tiene VARIAS interfaces (ethernet, wifi, P2P/Miracast) y anuncia
        # unas u otras según por dónde esté conectado: el televisor LG de la
        # tanda de campo declara tres MAC distintas, y `device_key` clava sobre
        # UNA. Conectado hoy por cable y mañana por wifi, el mismo aparato se
        # aprendía como dos dispositivos, partiendo su histórico y contando sus
        # réplicas por separado en el análisis de varianza. El propio mDNS
        # publica las otras MAC: hay señal para correlacionarlas.
        "mac_aliases": {},
        "vendor_profiles": {},       # vendor name → profile
        "cve_validation_history": {},  # cve_id → history
        "reflection_log": [],        # paths a reflection reports
        "global_stats": {
            "runs_total": 0,
            "findings_total": 0,
            "confirmed_total": 0,
        },
    }


@dataclass
class KnowledgeBase:
    """Knowledge base in-memory + disk persistence."""

    path: str = field(default_factory=lambda: os.getenv("KB_PATH") or _DEFAULT_KB_PATH)
    data: Dict[str, Any] = field(default_factory=_empty_kb)
    _loaded: bool = False

    # ---------------------------------------------------------------- load/save
    def load(self) -> None:
        """Carga el KB desde disco. Si no existe, mantiene `_empty_kb()`.
        Si existe pero schema mismatch, abortar limpio + warning.
        """
        if not os.path.isfile(self.path):
            self._loaded = True
            logger.debug(f"[KB] no existing file at {self.path} — starting fresh")
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[KB] failed to load {self.path}: {e}; using empty KB")
            self._loaded = True
            return

        loaded_version = loaded.get("version")
        if loaded_version != KB_SCHEMA_VERSION:
            logger.warning(
                f"[KB] schema mismatch (file v{loaded_version}, "
                f"code v{KB_SCHEMA_VERSION}); using empty KB"
            )
            self._loaded = True
            return

        # Backfill claves faltantes (forward-compatible para minor additions)
        defaults = _empty_kb()
        for k, v in defaults.items():
            loaded.setdefault(k, v)
        self.data = loaded

        # Migraciones lazy (vendors duplicados, devices_seen re-clavado por
        # identidad) y auto-reparación de contadores imposibles, probes
        # inexistentes y modelos envenenados. Todo idempotente, y todo en el
        # mismo sitio que usa el guardado: ver `_repair_invariants`.
        self._repair_invariants()

        self._loaded = True
        logger.info(
            f"[KB] loaded from {self.path}: "
            f"{len(self.data['devices_seen'])} devices, "
            f"{len(self.data['vendor_profiles'])} vendors, "
            f"{self.data['global_stats']['runs_total']} runs total"
        )

    def _migrate_vendor_duplicates(self) -> None:
        """Fusiona vendor_profiles cuyas keys diferentes mapean al mismo canónico.
        Ej: {'LG': {...}, 'LG Electronics.': {...}, 'LG Innotek': {...}} →
            {'LG': merged_profile}.
        Side effect: persiste si hubo cambios (atomic write).
        """
        from modules.fingerprint import canonicalize_vendor
        profiles = self.data.get("vendor_profiles") or {}
        if not profiles:
            return
        # Agrupar keys por canónico
        groups: Dict[str, List[str]] = {}
        for key in list(profiles.keys()):
            canon = canonicalize_vendor(key) or key
            groups.setdefault(canon, []).append(key)
        # Solo hay trabajo si algún grupo tiene >1 key o la canónica difiere
        needs_migration = any(
            len(keys) > 1 or keys[0] != canon for canon, keys in groups.items()
        )
        if not needs_migration:
            return
        merged: Dict[str, Dict[str, Any]] = {}
        for canon, keys in groups.items():
            if len(keys) == 1 and keys[0] == canon:
                merged[canon] = profiles[keys[0]]
                continue
            # Misma fusión que usa el merge previo a guardar: una sola
            # implementación, para que añadir un campo al perfil no obligue a
            # recordar que hay dos sitios donde fusionarlo.
            target: Dict[str, Any] = {}
            for k in keys:
                target = _merge_vendor_profiles(target, profiles[k] or {})
            merged[canon] = target
            logger.info(
                f"[KB] vendor merge: {keys} → '{canon}' "
                f"(devices={target['device_count']})"
            )
        self.data["vendor_profiles"] = merged

        # Canonicalizar también el field vendor en devices_seen para coherencia
        for ip, dev in (self.data.get("devices_seen") or {}).items():
            if not isinstance(dev, dict):
                continue
            v = dev.get("vendor")
            if v:
                canon = canonicalize_vendor(v, dev.get("mac")) or v
                if canon != v:
                    dev["vendor"] = canon

    def save(self) -> None:
        """Persistencia atómica y SERIALIZADA entre procesos.

        La escritura a temporal + `os.replace` evita la corrupción si el proceso
        muere a mitad, pero no resuelve el otro problema: cada auditoría carga
        la KB al arrancar y la guarda entera al terminar. El dashboard lanza
        auditorías CONCURRENTES (una por target, hasta 16), de modo que dos runs
        solapados leían el mismo estado inicial y el segundo en terminar
        sobrescribía lo aprendido por el primero. El aprendizaje entre
        auditorías (OM2) se perdía en silencio justo cuando más ejecuciones
        había —y era invisible, porque el fichero resultante siempre es válido—.

        Se arregla en dos pasos, ambos bajo un cerrojo de fichero (`flock`):
          1. **Releer** el estado en disco y fusionar lo aprendido en esta
             sesión sobre él, en lugar de pisarlo.
          2. Escribir el resultado de forma atómica.

        El cerrojo es de fichero, no de hilo, porque los runs son procesos
        distintos. Si `flock` no está disponible (p. ej. algunos sistemas de
        ficheros en red), se degrada a la escritura de siempre: es preferible
        guardar sin cerrojo a no guardar.
        """
        directory = os.path.dirname(self.path)
        os.makedirs(directory, exist_ok=True)
        publish_dir(directory)
        lock_path = self.path + ".lock"
        try:
            with open(lock_path, "a+", encoding="utf-8") as lock_file:
                try:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                except (ImportError, OSError) as e:
                    logger.debug(f"[KB] flock no disponible ({e}); guardo sin cerrojo")
                self._merge_from_disk()
                # La reparación va DESPUÉS del merge, no solo en `load()`.
                # Repararla solo al cargar no servía de nada: `_merge_from_disk`
                # vuelve a leer el fichero —todavía con la cifra imposible— y
                # toma el MÁXIMO entre disco y memoria, de modo que el valor
                # corrupto ganaba siempre y resucitaba en cada guardado. Un
                # `audit_count` de 1.040.188.384 sobrevivió así a la versión que
                # decía haberlo arreglado. El invariante pertenece al punto de
                # ESCRITURA; comprobarlo solo al leer es comprobarlo en el sitio
                # donde no puede tener efecto.
                self._repair_invariants()
                self._write_atomic(directory)
            publish_artifact(lock_path)
        except OSError as e:
            logger.warning(f"[KB] save failed: {e}")

    def _write_atomic(self, directory: str) -> None:
        """Vuelca `self.data` a disco sin dejar un fichero a medias."""
        self.data["last_updated"] = _now_iso()
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8",
            dir=directory,
            prefix=".kb_",
            suffix=".tmp",
            delete=False,
        ) as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False, default=str)
            tmp_path = f.name
        os.replace(tmp_path, self.path)
        # `tempfile` crea el temporal con modo 0600 y `os.replace` lo conserva:
        # sin esto la KB queda ilegible para el dashboard y para cualquier run
        # sin sudo, y el aprendizaje entre auditorías (OM2) se apaga en silencio.
        publish_artifact(self.path)
        logger.debug(f"[KB] saved to {self.path}")

    def _merge_from_disk(self) -> None:
        """Funde el estado en disco DEBAJO del que se tiene en memoria.

        «Debajo» es la palabra clave: lo aprendido en esta sesión gana en los
        campos escalares, y lo que otro proceso haya escrito entretanto se
        conserva en lugar de desaparecer. Se aplica por tipo de dato:

          · `devices_seen` / `vendor_profiles` — se fusionan por clave con los
            mismos helpers que ya usa la migración, así que un dispositivo visto
            por otro run no se pierde y uno visto por ambos suma su histórico.
          · `cve_validation_history` — los contadores son acumulativos: se toma
            el máximo de cada uno para no inventar intentos ni descartarlos.
          · `global_stats` — ídem, máximo por contador.

        Si el fichero no existe o no es legible, no hay nada que fusionar.
        """
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                disk = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[KB] merge omitido, disco ilegible: {e}")
            return
        if not isinstance(disk, dict) or disk.get("version") != KB_SCHEMA_VERSION:
            return

        for key in ("devices_seen", "vendor_profiles"):
            mine = self.data.setdefault(key, {})
            for k, rec in (disk.get(key) or {}).items():
                if not isinstance(rec, dict):
                    continue
                if k not in mine:
                    mine[k] = rec
                elif key == "devices_seen":
                    # counters="max": el registro en memoria YA incluye el
                    # histórico del disco (se cargó al arrancar). Ver
                    # `_merge_device_records`.
                    mine[k] = _merge_device_records(rec, mine[k], counters="max")
                else:
                    mine[k] = _merge_vendor_profiles(rec, mine[k], counters="max")

        mine_hist = self.data.setdefault("cve_validation_history", {})
        for cve_id, hist in (disk.get("cve_validation_history") or {}).items():
            if not isinstance(hist, dict):
                continue
            if cve_id not in mine_hist:
                mine_hist[cve_id] = hist
                continue
            merged = mine_hist[cve_id]
            for counter in ("tested_n_times", "confirmed_count"):
                merged[counter] = max(int(merged.get(counter, 0) or 0),
                                      int(hist.get(counter, 0) or 0))
            for vendor in hist.get("vendors_tested", []) or []:
                if vendor not in merged.setdefault("vendors_tested", []):
                    merged["vendors_tested"].append(vendor)

        stats = self.data.setdefault("global_stats", {})
        for counter, value in (disk.get("global_stats") or {}).items():
            if isinstance(value, int):
                stats[counter] = max(int(stats.get(counter, 0) or 0), value)

    def _migrate_devices_to_identity_keys(self) -> None:
        """Re-clava `devices_seen` de IP→identidad (`device_key`, anclado a MAC).

        Idempotente: re-ejecutar no cambia nada (las claves ya por identidad
        recomputan a sí mismas). Dos registros del mismo dispositivo (misma MAC,
        distinta IP) se fusionan. Los que no tienen MAC quedan bajo `ip:<ip>`.
        """
        from modules.fingerprint import device_key
        old = self.data.get("devices_seen") or {}
        if not old:
            return
        new: Dict[str, Any] = {}
        changed = False
        for k, rec in old.items():
            if not isinstance(rec, dict):
                continue
            rec_ip = rec.get("ip") or (k if _looks_like_ipv4(k) else None)
            if rec_ip and not rec.get("ip"):
                rec["ip"] = rec_ip
            nk = device_key(rec.get("mac"), rec.get("firmware"), rec_ip)
            if nk != k:
                changed = True
            new[nk] = _merge_device_records(new[nk], rec) if nk in new else rec
        if changed:
            self.data["devices_seen"] = new
            logger.info(
                f"[KB] devices_seen re-clavado por identidad (MAC, nunca IP): "
                f"{len(old)} → {len(new)} registros")

    # ------------------------------------------------------ alias de interfaz

    def link_device_macs(self, primary_key: str, macs) -> int:
        """Registra que `macs` pertenecen al dispositivo `primary_key`.

        Devuelve cuántos alias nuevos se registraron. Idempotente. Si una MAC ya
        tenía su propio registro en `devices_seen`, se FUSIONA con el principal
        en lugar de dejar dos históricos del mismo aparato.
        """
        from modules.fingerprint import normalize_mac
        aliases = self.data.setdefault("mac_aliases", {})
        devices = self.data.setdefault("devices_seen", {})
        added = 0
        for raw in macs or []:
            mac = normalize_mac(raw)
            if not mac or mac == primary_key or aliases.get(mac) == primary_key:
                continue
            aliases[mac] = primary_key
            added += 1
            # Si esa MAC ya se había aprendido como dispositivo aparte, se funde.
            stale = devices.pop(mac, None)
            if stale:
                devices[primary_key] = (
                    _merge_device_records(stale, devices[primary_key])
                    if primary_key in devices else stale)
                logger.info(
                    f"[KB] {mac} era un registro aparte del mismo equipo; "
                    f"fusionado en {primary_key}")
        if added:
            logger.info(f"[KB] {added} MAC alternativa(s) enlazadas a {primary_key}")
        return added

    def resolve_device_key(self, key: str) -> str:
        """Clave canónica de un dispositivo, siguiendo los alias de interfaz."""
        return (self.data.get("mac_aliases") or {}).get(key, key)

    # ---------------------------------------------------------------- queries
    def get_device_record(self, ip: Optional[str] = None, *,
                          mac: Optional[str] = None,
                          firmware: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Registro de un dispositivo previamente auditado, **identificado por
        MAC, nunca por IP** (las IPs se reutilizan). Se pasa la MAC del escaneo
        actual; `ip` solo se usa de último recurso si no hay MAC."""
        from modules.fingerprint import device_key
        key = self.resolve_device_key(device_key(mac, firmware, ip))
        return self.data["devices_seen"].get(key)

    def get_vendor_profile(self, vendor: str) -> Optional[Dict[str, Any]]:
        """Devuelve el perfil de un vendor, o None si no se ha visto.
        Canonicaliza la key para que 'LG Electronics.' encuentre el perfil
        guardado como 'LG'."""
        from modules.fingerprint import canonicalize_vendor
        canon = canonicalize_vendor(vendor) or vendor
        return self.data["vendor_profiles"].get(canon)

    def get_cve_history(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self.data["cve_validation_history"].get(cve_id)

    def is_cve_consistently_patched(self, cve_id: str, vendor: Optional[str] = None,
                                    threshold: int = PATCHED_CVE_THRESHOLD) -> bool:
        """True si el CVE ha sido tested ≥threshold veces y nunca confirmado.

        Útil para que recommend_probes/exploit phase eviten re-probar CVEs
        que ya consistentemente se vieron como patched en el mismo vendor.

        El umbral es el MISMO que usa `record_cve_test` para dar un CVE por
        parcheado (`PATCHED_CVE_THRESHOLD`). Estaban descuadrados —2 aquí, 3
        allí— y esa diferencia de uno abría una ventana en la que un CVE se
        consideraba «consistentemente parcheado» a efectos de no re-probarlo
        pero todavía no se anotaba como tal en el perfil del fabricante: dos
        respuestas distintas a la misma pregunta según a quién se le hiciera.
        """
        if vendor:
            profile = self.get_vendor_profile(vendor)
            if profile and cve_id in profile.get("patched_cves", []):
                return True
        history = self.get_cve_history(cve_id)
        if not history:
            return False
        return (
            history.get("tested_n_times", 0) >= threshold
            and history.get("confirmed_count", 0) == 0
        )

    # ---------------------------------------------------------------- updates
    def upsert_device(self, ip: str, scan_result: Dict[str, Any],
                      findings: List[Dict[str, Any]],
                      run_id: Optional[str] = None) -> None:
        """Actualiza/crea el registro de un device tras una auditoría.

        El registro se clava por **identidad (MAC), nunca por IP** (`device_key`):
        dos dispositivos en la misma IP (IP reutilizada) tienen claves distintas y
        no se pisan ni heredan identidad; el mismo dispositivo en distinta IP cae
        en la misma clave y acumula su histórico.

        `run_id` identifica la AUDITORÍA, no la llamada. Por omisión es la
        ejecución en curso, de modo que llamar dos veces dentro del mismo run
        —cosa que pasa— cuenta una sola auditoría. Se puede pasar explícito para
        reconstruir histórico o para simular ejecuciones distintas en pruebas:
        antes eso se hacía llamando al método varias veces, que es justo la
        suposición («una llamada = una auditoría») de la que salió un contador
        en el que no se podía confiar.
        """
        from modules.fingerprint import device_key
        key = self.resolve_device_key(
            device_key(scan_result.get("mac"), scan_result.get("firmware"), ip))
        # Otras interfaces del MISMO aparato, observadas en la evidencia (mDNS
        # publica la MAC de wifi aunque se le esté hablando por cable).
        self.link_device_macs(key, scan_result.get("also_macs") or [])
        existing = self.data["devices_seen"].get(key, {})
        runs_vistos = sorted(set(existing.get("audit_runs") or []) | {run_id or _run_id()})
        device = {
            "first_seen": existing.get("first_seen", _now_iso()),
            "last_seen": _now_iso(),
            # Auditorías de ESTE aparato, contadas por identidad de ejecución.
            #
            # Era un `+1` sobre lo que hubiera en disco, y esa aritmética no
            # sobrevive a la fusión entre procesos: el merge toma el máximo, y
            # la reparación topa a `runs_total`, de modo que el contador de cada
            # aparato acabó convergiendo al TOTAL de ejecuciones del sistema —los
            # tres dispositivos del banco marcaban 47 tras la jornada de campo,
            # que es el número de runs, no el de auditorías de cada uno—. Un
            # contador que vale lo mismo para todos no informa de nada, y ese
            # campo viaja al prompt de la ejecución siguiente dentro de
            # `kb_context`.
            #
            # Guardar los IDENTIFICADORES en vez de un número lo arregla en las
            # tres capas a la vez: la unión de dos conjuntos es idempotente
            # (fusionar dos veces no infla), es exacta (no hay cota que estimar)
            # y es auditable (se puede ver de qué ejecuciones habla).
            "audit_runs": runs_vistos,
            "audit_count": len(runs_vistos),
            "vendor": scan_result.get("vendor") or existing.get("vendor"),
            "model": scan_result.get("model") or existing.get("model"),
            "firmware": scan_result.get("firmware") or existing.get("firmware"),
            "mac": scan_result.get("mac") or existing.get("mac"),
            "ip": ip,  # última IP vista — informativo, NO es identidad
            "os_match": scan_result.get("os_match") or existing.get("os_match"),
            "ports_last_seen": scan_result.get("ports", []),
            "findings_count_last": len(findings),
            # Severidad EFECTIVA, no el campo crudo: un INFO verificado (p. ej.
            # «las credenciales por defecto NO funcionan») lleva confirmed=True
            # y NO es una vulnerabilidad. Contarlo aquí hacía que la KB
            # aprendiese una cifra distinta de la que publica el informe.
            "confirmed_count_last": sum(1 for f in findings if is_confirmed_vuln(f)),
        }
        self.data["devices_seen"][key] = device

        # Auto-crear vendor profile si el vendor es nuevo (sin datos extra).
        # Pasamos la MAC para que canonicalize_vendor pueda fusionar perfiles
        # heterogéneos (LG Electronics. / LG Innotek / LG → 'LG' via OUI).
        vendor = device.get("vendor")
        if vendor:
            from modules.fingerprint import canonicalize_vendor
            canonical = canonicalize_vendor(vendor, device.get("mac")) or vendor
            if canonical not in self.data["vendor_profiles"]:
                ports = [p["port"] for p in scan_result.get("ports", [])
                         if isinstance(p, dict) and p.get("port")]
                self.upsert_vendor_profile(canonical, ports_seen=ports or None,
                                           mac=device.get("mac"))
            # Persistir la forma canónica también en el device record
            device["vendor"] = canonical
            # `device_count` se refresca SIEMPRE, no solo al crear el perfil:
            # el segundo aparato de un fabricante ya conocido no pasa por
            # `upsert_vendor_profile` y su alta quedaría sin contar.
            profile = self.data["vendor_profiles"].get(canonical)
            if profile is not None:
                profile["device_count"] = self._count_devices_for_vendor(canonical) or 1

    def upsert_vendor_profile(self, vendor: str,
                              ports_seen: Optional[List[int]] = None,
                              useful_probes: Optional[List[str]] = None,
                              patched_cves: Optional[List[str]] = None,
                              fingerprint_markers: Optional[List[str]] = None,
                              mac: Optional[str] = None) -> None:
        """Merge incremental del perfil de un vendor.

        El vendor se canonicaliza antes de usarse como key, así
        'LG Electronics.', 'LG Electronics', 'LG Innotek' (con MAC LG) y 'LG'
        comparten un mismo perfil en lugar de crear duplicados.
        """
        if not vendor:
            return
        from modules.fingerprint import canonicalize_vendor
        vendor = canonicalize_vendor(vendor, mac) or vendor
        profile = self.data["vendor_profiles"].setdefault(vendor, {
            "first_seen": _now_iso(),
            "common_ports": [],
            "useful_probes": [],
            "patched_cves": [],
            "fingerprint_markers": [],
            "device_count": 0,
        })
        profile["last_updated"] = _now_iso()
        # `device_count` se DERIVA de devices_seen, no se incrementa. Incrementar
        # por llamada contaba auditorías, no dispositivos (30 runs sobre 3
        # aparatos → 30), y al sumarse además en cada merge disco/memoria acababa
        # en 3.556.776.512 para un único televisor.
        profile["device_count"] = self._count_devices_for_vendor(vendor) or 1

        # Merge sets (preservando orden de descubrimiento)
        def _merge_unique(base: list, new: Optional[list]) -> list:
            if not new:
                return base
            seen: Set[Any] = set(base)
            merged = list(base)
            for item in new:
                if item not in seen:
                    seen.add(item)
                    merged.append(item)
            return merged

        if ports_seen:
            profile["common_ports"] = _merge_unique(profile["common_ports"], ports_seen)
        if useful_probes:
            profile["useful_probes"] = _merge_unique(
                profile["useful_probes"], _valid_probe_names(useful_probes))
        if patched_cves:
            profile["patched_cves"] = _merge_unique(profile["patched_cves"], patched_cves)
        if fingerprint_markers:
            profile["fingerprint_markers"] = _merge_unique(
                profile["fingerprint_markers"], fingerprint_markers
            )

    def _count_devices_for_vendor(self, canonical_vendor: str) -> int:
        """Dispositivos distintos de ese fabricante en `devices_seen`."""
        from modules.fingerprint import canonicalize_vendor
        n = 0
        for dev in (self.data.get("devices_seen") or {}).values():
            if not isinstance(dev, dict):
                continue
            v = dev.get("vendor")
            if v and (canonicalize_vendor(v, dev.get("mac")) or v) == canonical_vendor:
                n += 1
        return n

    def _repair_invariants(self) -> None:
        """Restaura los invariantes de la KB. Idempotente; no escribe por sí.

        Se llama en DOS sitios —al cargar y justo antes de escribir— y esa
        duplicidad es deliberada: el guardado refunde el fichero de disco, así
        que un dato inválido escrito por otro proceso (o por una versión
        anterior) vuelve a entrar después de la carga.

        Las migraciones entran aquí por el mismo motivo, y no solo por simetría.
        Ninguna de las dos persiste por su cuenta: re-clavan y fusionan en
        memoria, y confían en el guardado posterior. Pero el guardado empieza
        releyendo el fichero SIN migrar, de modo que un registro bajo la clave
        vieja volvía a entrar y el dispositivo acababa duplicado —una entrada
        por `ip:…` y otra por MAC— justo después de haberlas unido. Es el mismo
        error que el de los contadores, en otro campo: comprobar el invariante
        solo al leer es comprobarlo donde no puede tener efecto.
        """
        self._migrate_vendor_duplicates()
        self._migrate_devices_to_identity_keys()
        self._repair_impossible_counters()
        self._repair_poisoned_model_names()

    def _repair_poisoned_model_names(self) -> None:
        """Borra los `model` que son nombres de algoritmo criptográfico.

        `_extract_model_from_text` ya no los produce, pero los que produjo
        siguen en la KB, y de ahí salen —vía el respaldo de identidad del
        informe— al CPE y a las búsquedas de CVE. El router Askey se publicaba
        como modelo «CURVE25519» en cinco informes de cinco; arreglar el
        extractor no tocó ni uno, porque el dato ya no venía del extractor.

        Se comparte el vocabulario con el extractor a propósito: si mañana se
        añade un algoritmo a `_CRYPTO_TOKENS`, la KB lo purga sin más cambios.
        """
        try:
            from modules.fingerprint import _CRYPTO_TOKENS
        except ImportError:  # pragma: no cover
            return
        limpiados = []
        for key, dev in (self.data.get("devices_seen") or {}).items():
            if not isinstance(dev, dict):
                continue
            model = (dev.get("model") or "").strip()
            if model and model.upper() in _CRYPTO_TOKENS:
                dev["model"] = None
                limpiados.append(f"{key}: '{model}' → None")
        if limpiados:
            logger.warning(
                f"[KB] {len(limpiados)} modelo(s) criptográficos purgados: "
                + "; ".join(limpiados[:4]))

    def _repair_impossible_counters(self) -> None:
        """Corrige contadores que la suma doble dejó fuera de rango.

        Auto-reparación en la carga, no migración de esquema: un fichero escrito
        por la versión con el fallo es válido y legible, solo tiene cifras
        imposibles. Los topes son los que la propia KB ya conoce:

          · `audit_count` de un aparato ≤ auditorías totales registradas.
          · `device_count` de un fabricante = dispositivos suyos en devices_seen.
          · `useful_probes` — se purgan los nombres que no existen.

        Idempotente: sobre una KB sana no cambia nada y no escribe.
        """
        runs_total = int((self.data.get("global_stats") or {}).get("runs_total", 0) or 0)
        repaired = []

        for key, dev in (self.data.get("devices_seen") or {}).items():
            if not isinstance(dev, dict):
                continue
            runs_dev = dev.get("audit_runs")
            if runs_dev:
                # Con conjunto no hay nada que estimar: el contador ES su
                # tamaño. La cota por `runs_total` solo aplica a los registros
                # antiguos, que solo tienen el número.
                if int(dev.get("audit_count") or 0) != len(set(runs_dev)):
                    dev["audit_count"] = len(set(runs_dev))
                    repaired.append(f"{key}.audit_count → {len(set(runs_dev))} (conjunto)")
                continue
            ac = int(dev.get("audit_count") or 0)
            # `runs_total` es una COTA SUPERIOR, no el valor real: la cifra
            # original es irrecuperable (la KB no guarda histórico por run).
            # Se prefiere una cota defendible a un número inventado.
            # Sin `runs_total` fiable no hay techo que aplicar; se deja estar.
            if runs_total and ac > runs_total:
                dev["audit_count"] = runs_total
                repaired.append(f"{key}.audit_count {ac}→{runs_total}")

        for vendor, profile in (self.data.get("vendor_profiles") or {}).items():
            if not isinstance(profile, dict):
                continue
            real = self._count_devices_for_vendor(vendor)
            dc = int(profile.get("device_count") or 0)
            if real and dc > real:
                profile["device_count"] = real
                repaired.append(f"{vendor}.device_count {dc}→{real}")
            probes = profile.get("useful_probes") or []
            clean = _valid_probe_names(probes)
            if len(clean) != len(probes):
                profile["useful_probes"] = clean
                repaired.append(f"{vendor}.useful_probes {len(probes)}→{len(clean)}")

        if repaired:
            logger.warning(
                f"[KB] {len(repaired)} contador(es)/lista(s) reparados: "
                + "; ".join(repaired[:6]) + (" …" if len(repaired) > 6 else ""))

    def _remove_from_patched_cves(self, vendor: str, cve_id: str) -> bool:
        """Elimina un CVE de vendor.patched_cves si está presente. Idempotente."""
        profile = self.data["vendor_profiles"].get(vendor)
        if not profile:
            return False
        patched = profile.get("patched_cves")
        if not patched or cve_id not in patched:
            return False
        patched.remove(cve_id)
        return True

    def record_cve_test(self, cve_id: str, confirmed: bool,
                        vendor: Optional[str] = None) -> None:
        """Registra un intento de validación de CVE.

        Side effects en vendor_profiles[vendor]:
          - confirmed=True  → si el CVE estaba en patched_cves, se elimina
                              (auto-corrección de falsos negativos previos).
          - confirmed=False → tras `PATCHED_CVE_THRESHOLD` tests fallidos sin
                              ningún confirmed previo, se añade a patched_cves.
        """
        history = self.data["cve_validation_history"].setdefault(cve_id, {
            "first_test": _now_iso(),
            "tested_n_times": 0,
            "confirmed_count": 0,
            "vendors_tested": [],
        })
        history["last_test"] = _now_iso()
        history["tested_n_times"] += 1
        if confirmed:
            history["confirmed_count"] += 1
        if vendor and vendor not in history["vendors_tested"]:
            history["vendors_tested"].append(vendor)

        if not vendor:
            return

        if confirmed:
            self._remove_from_patched_cves(vendor, cve_id)
        elif (history["tested_n_times"] >= PATCHED_CVE_THRESHOLD
                and history["confirmed_count"] == 0):
            self.upsert_vendor_profile(vendor, patched_cves=[cve_id])

    def add_reflection_path(self, path: str) -> None:
        """Añade el path de un reflection report al log (truncate a 100 más recientes)."""
        log = self.data.setdefault("reflection_log", [])
        log.append({"path": path, "timestamp": _now_iso()})
        if len(log) > 100:
            self.data["reflection_log"] = log[-100:]

    def increment_run_stats(self, findings: int, confirmed: int) -> None:
        stats = self.data["global_stats"]
        stats["runs_total"] += 1
        stats["findings_total"] += findings
        stats["confirmed_total"] += confirmed

    # ---------------------------------------------------------------- snapshots
    def snapshot(self) -> Dict[str, Any]:
        """Resumen estable del estado del KB para inyectar en system prompts."""
        return {
            "runs_total": self.data["global_stats"]["runs_total"],
            "devices_known": len(self.data["devices_seen"]),
            "vendors_known": list(self.data["vendor_profiles"].keys()),
            "cves_with_history": len(self.data["cve_validation_history"]),
        }


# ---------------------------------------------------------------- singleton
_KB_SINGLETON: Optional[KnowledgeBase] = None


def get_kb(path: Optional[str] = None, reload: bool = False) -> KnowledgeBase:
    """Singleton lazy. Auto-load la primera vez."""
    global _KB_SINGLETON
    if _KB_SINGLETON is None or reload:
        _KB_SINGLETON = KnowledgeBase(path=path or os.getenv("KB_PATH") or _DEFAULT_KB_PATH)
        _KB_SINGLETON.load()
    return _KB_SINGLETON


def reset_kb_singleton() -> None:
    """Útil en tests para forzar nuevo load."""
    global _KB_SINGLETON
    _KB_SINGLETON = None
