import json
import os
import random
import tempfile
import threading
import time
from typing import Optional

import requests
from colorama import Fore
from loguru import logger

from core.fsutil import publish_artifact, publish_dir


# ─────────────────────────────────────────────────────────────────────────────
# Cache NVD persistente en disco (L2)
# ─────────────────────────────────────────────────────────────────────────────
# El cache de proceso (`_RESULT_CACHE`) deduplica dentro de UN run, pero cada
# invocación del CLI es un proceso nuevo: sin persistencia, dos auditorías del
# mismo objetivo repiten todas las consultas a la NVD (lentas y limitadas por
# tasa, agravado por el atasco de enriquecimiento de 2024). Una cache en disco
# con TTL hace los runs más rápidos, con menos throttling 429 y, sobre todo,
# más reproducibles: la misma consulta devuelve lo mismo dentro de la ventana.
_DISK_CACHE_PATH = os.getenv(
    "NVD_CACHE_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "data", "nvd_cache.json"),
)
_DISK_CACHE_TTL = float(os.getenv("NVD_CACHE_TTL_SECONDS", str(24 * 3600)))  # 24 h
_DISK_CACHE_LOCK = threading.Lock()
_DISK_CACHE: Optional[dict] = None  # {key: {"ts": epoch, "result": [...]}}


def _disk_cache_load() -> dict:
    global _DISK_CACHE
    if _DISK_CACHE is not None:
        return _DISK_CACHE
    try:
        with open(_DISK_CACHE_PATH, encoding="utf-8") as fh:
            _DISK_CACHE = json.load(fh)
            if not isinstance(_DISK_CACHE, dict):
                _DISK_CACHE = {}
    except (OSError, ValueError):
        _DISK_CACHE = {}
    return _DISK_CACHE


def _disk_cache_get(key: str):
    """Devuelve el resultado cacheado si existe y no ha expirado; si no, None."""
    with _DISK_CACHE_LOCK:
        entry = _disk_cache_load().get(key)
    if not entry:
        return None
    if (time.time() - entry.get("ts", 0)) > _DISK_CACHE_TTL:
        return None  # expirado → se recomputará y sobrescribirá
    return entry.get("result")


def _disk_cache_put(key: str, result: list) -> None:
    """Escritura atómica (tempfile + os.replace) para no corromper ante kill -9."""
    with _DISK_CACHE_LOCK:
        cache = _disk_cache_load()
        now = time.time()
        # Poda las entradas expiradas al escribir: sin esto el fichero solo
        # crece (las claves viejas nunca se re-consultan ni se sobreescriben).
        for stale in [k for k, v in cache.items()
                      if not isinstance(v, dict)
                      or (now - v.get("ts", 0)) > _DISK_CACHE_TTL]:
            del cache[stale]
        cache[key] = {"ts": now, "result": result}
        try:
            d = os.path.dirname(_DISK_CACHE_PATH)
            if d:
                os.makedirs(d, exist_ok=True)
            if d:
                publish_dir(d)
            fd, tmp = tempfile.mkstemp(dir=d or ".", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(cache, fh)
            os.replace(tmp, _DISK_CACHE_PATH)
            # `mkstemp` crea con modo 0600 y `os.replace` lo conserva: sin esto la
            # caché escrita por un run con sudo es ilegible para los demás, y cada
            # ejecución vuelve a golpear la NVD como si no hubiera caché.
            publish_artifact(_DISK_CACHE_PATH)
        except OSError as e:
            logger.debug(f"[NVD] cache en disco no escribible ({e}); solo memoria")


class NVDCVEClient:
    """
    Cliente NVD Profesional (National Vulnerability Database).
    Thread-safe: rate limits y cachés protegidos con locks para uso con ThreadPoolExecutor.
    """

    def __init__(self, api_key=None):
        self.base_url_cve = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.base_url_cpe = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.api_key = api_key

        # Rate Limit: 0.6s con API Key, 6.0s sin ella (NIST specs).
        self.delay = 0.6 if api_key else 6.0
        self.last_request_time = 0.0

        # Cachés thread-safe
        self._cve_cache: dict = {}
        self._cpe_cache: dict = {}
        self._rate_lock = threading.Lock()
        self._cache_lock = threading.Lock()

    def _sleep_rate_limit(self):
        """
        Garantiza que se respete el tiempo de espera entre peticiones.
        Thread-safe: usa un lock para serializar el acceso con ThreadPoolExecutor.
        """
        with self._rate_lock:
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < self.delay:
                sleep_time = self.delay - elapsed
                time.sleep(sleep_time)
            self.last_request_time = time.time()

    # Retry configuration: exponential backoff with jitter, respects Retry-After.
    _MAX_RETRIES = 4
    _BASE_BACKOFF = 1.0   # seconds, doubled each attempt + jitter
    _MAX_BACKOFF = 30.0

    def _compute_backoff(self, attempt: int, retry_after: Optional[float]) -> float:
        """Retry-After header wins; otherwise exponential 2^n with +/-25% jitter."""
        if retry_after is not None and retry_after > 0:
            return min(retry_after, self._MAX_BACKOFF)
        exp = self._BASE_BACKOFF * (2 ** attempt)
        jitter = random.uniform(-0.25, 0.25) * exp
        return max(0.1, min(self._MAX_BACKOFF, exp + jitter))

    def _make_request(self, url, params):
        """HTTP request with exponential-backoff retries and Retry-After honoring."""
        headers = {'apiKey': self.api_key} if self.api_key else {}

        for attempt in range(self._MAX_RETRIES + 1):
            self._sleep_rate_limit()
            try:
                response = requests.get(url, params=params, headers=headers, timeout=20)
            except requests.exceptions.RequestException as exc:
                if attempt == self._MAX_RETRIES:
                    logger.warning(f"[NVD] Request failed after {attempt+1} attempts: {exc}")
                    return None
                wait = self._compute_backoff(attempt, None)
                logger.debug(f"[NVD] Transport error '{exc}'; retry in {wait:.1f}s (attempt {attempt+1})")
                time.sleep(wait)
                continue

            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    logger.warning("[NVD] 200 OK but body is not valid JSON")
                    return None

            # Retryable: 429, 503, 5xx network blips
            if response.status_code in (429, 503) or 500 <= response.status_code < 600:
                if attempt == self._MAX_RETRIES:
                    logger.warning(f"[NVD] HTTP {response.status_code} after {attempt+1} attempts")
                    return None
                retry_after = None
                ra_hdr = response.headers.get("Retry-After")
                if ra_hdr:
                    try:
                        retry_after = float(ra_hdr)
                    except ValueError:
                        retry_after = None
                wait = self._compute_backoff(attempt, retry_after)
                logger.debug(
                    f"[NVD] HTTP {response.status_code}; retry in {wait:.1f}s (attempt {attempt+1})"
                )
                time.sleep(wait)
                continue

            # Non-retryable (4xx other than 429)
            if response.status_code == 404:
                # 404 = NVD no tiene ese cpeName EXACTO en su diccionario (típico con
                # versión wildcard). Es esperado y lo maneja el fallback → solo debug.
                logger.debug(f"[NVD] HTTP 404 — cpeName no en diccionario NVD (fallback activo)")
            else:
                logger.warning(f"[NVD] HTTP {response.status_code} (non-retryable)")
            return None

        return None

    def _extract_brand_clean(self, product_raw):
        """Normaliza el término para NVD: lowercase + trim. Sin heurísticas:
        la selección del keyword distintivo ocurre aguas arriba (LLM)."""
        if not product_raw:
            return ""
        return str(product_raw).lower().strip()

    @staticmethod
    def _to_cpe23_match(raw_cpe, version=None):
        """Normaliza un CPE (2.2 URI `cpe:/a:...` o 2.3 `cpe:2.3:a:...`) a un
        string apto para `virtualMatchString`: `cpe:2.3:<part>:<vendor>:<product>`
        + `:<version>` si hay versión concreta. Devuelve None si falta vendor/producto.

        Por qué virtualMatchString y no cpeName: NVD devuelve 404 a un `cpeName`
        con versión wildcard (`...:*:...`) porque no es una entrada EXACTA de su
        diccionario. `virtualMatchString` hace match por prefijo/rango → 200 +
        todos los CVEs del producto. Determinista (mismo CPE → mismo resultado)."""
        if not raw_cpe:
            return None
        s = str(raw_cpe).strip()
        if s.startswith("cpe:2.3:"):
            parts = s.split(":")[2:]          # tras 'cpe:2.3:'  → [part, vendor, product, version, ...]
        elif s.startswith("cpe:/"):
            parts = s[len("cpe:/"):].split(":")  # 2.2 URI → [part, vendor, product, version, ...]
        else:
            return None
        if len(parts) < 3 or not parts[1] or not parts[2]:
            return None
        part, vendor, product = parts[0], parts[1], parts[2]
        base = f"cpe:2.3:{part}:{vendor}:{product}"
        ver = version or (parts[3] if len(parts) > 3 else "")
        if ver and ver not in ("*", "-", ""):
            base += f":{ver}"
        return base

    def _cves_by_virtual_match(self, cpe23_match):
        """Consulta CVEs por virtualMatchString (prefijo CPE, sin riesgo de 404).
        Devuelve lista parseada o []."""
        if not cpe23_match:
            return []
        params = {"virtualMatchString": cpe23_match, "resultsPerPage": 100}
        data = self._make_request(self.base_url_cve, params)
        if data and data.get("totalResults", 0) > 0:
            return self._parse_nvd_response(data)
        return []

    def resolve_cpe(self, product, version):
        """
        Intenta encontrar el CPE 2.3 oficial en el diccionario de la NVD.
        """
        clean_prod = self._extract_brand_clean(product)
        if len(clean_prod) < 3: return None
        
        cache_key = f"{clean_prod}:{version}"
        with self._cache_lock:
            if cache_key in self._cpe_cache:
                return self._cpe_cache[cache_key]

        params = {
            'keywordSearch': f"{clean_prod} {version}",
            'resultsPerPage': 1
        }
        
        data = self._make_request(self.base_url_cpe, params)
        
        cpe_found = None
        if data and data.get('products'):
            cpe_item = data['products'][0]['cpe']
            cpe_found = cpe_item['cpeName']
        else:
            # Reintento solo con la marca si falla la búsqueda precisa
            params['keywordSearch'] = clean_prod
            data = self._make_request(self.base_url_cpe, params)
            if data and data.get('products'):
                base_cpe = data['products'][0]['cpe']['cpeName']
                parts = base_cpe.split(":")
                if len(parts) > 5:
                    # Reconstruimos el CPE inyectando la versión detectada
                    # Se usa 'or' para asegurar que la versión no sea None
                    parts[5] = version or '*'
                    cpe_found = ":".join(parts)
        with self._cache_lock:
            self._cpe_cache[cache_key] = cpe_found
        return cpe_found

    # Cache de proceso (nivel CLASE): tools.py instancia un cliente nuevo por cada
    # cve_search, así que un cache de instancia no persistiría. Deduplica búsquedas
    # repetidas (mismo producto/versión/CPE) entre llamadas y entre runs del proceso
    # — incluye resultados vacíos, para no repetir 40s en un término que no aporta.
    _RESULT_CACHE: dict = {}

    def get_cves_for_product(self, product, version, nmap_cpe=None, allow_broad_keyword=True):
        """Wrapper con cache de proceso sobre `_get_cves_uncached`.

        `allow_broad_keyword`: si False, NO se hace la búsqueda por keyword amplio
        versionless (p. ej. solo "nginx"), que matchea cualquier CVE que mencione el
        término y genera ruido de ecosistema (Authelia, Roxy-wi…). El barrido
        determinista `cve_scan_recon` lo desactiva para quedarse solo con matches por
        CPE o por producto+versión concretos.
        """
        key = f"{(product or '').lower().strip()}|{version or ''}|{nmap_cpe or ''}|{int(allow_broad_keyword)}"
        # L1: cache de proceso (mismo run).
        if key in self._RESULT_CACHE:
            logger.debug(f"[NVD] cache hit (memoria): {key}")
            return list(self._RESULT_CACHE[key])
        # L2: cache en disco (entre runs, con TTL).
        disk = _disk_cache_get(key)
        if disk is not None:
            logger.debug(f"[NVD] cache hit (disco): {key}")
            self._RESULT_CACHE[key] = list(disk)
            return list(disk)
        result = self._get_cves_uncached(product, version, nmap_cpe, allow_broad_keyword) or []
        self._RESULT_CACHE[key] = list(result)
        _disk_cache_put(key, list(result))
        return result

    def _get_cves_uncached(self, product, version, nmap_cpe=None, allow_broad_keyword=True):
        """
        Método Maestro para obtener vulnerabilidades usando múltiples estrategias.
        """
        cves_found = []

        # --- ESTRATEGIA 1: CPE NATIVO (NMAP) — vía virtualMatchString ---
        # nmap da CPE 2.2 (`cpe:/a:...`) y a menudo sin versión. Lo normalizamos a
        # match 2.3 y usamos virtualMatchString (evita el 404 del cpeName exacto).
        if nmap_cpe and len(nmap_cpe) > 5:
            cves_found = self._cves_by_virtual_match(self._to_cpe23_match(nmap_cpe, version))
            if cves_found:
                return self._rank_locally(cves_found, version)

        # --- ESTRATEGIA 2: CPE INFERIDO (API) — vía virtualMatchString ---
        inferred_cpe = self.resolve_cpe(product, version)
        if inferred_cpe:
            cves_found = self._cves_by_virtual_match(self._to_cpe23_match(inferred_cpe, version))
            if cves_found:
                return self._rank_locally(cves_found, version)

        # --- ESTRATEGIA 3: PALABRAS CLAVE (FALLBACK) ---
        clean_prod = self._extract_brand_clean(product)
        search_candidates = []

        # Prioridad 1: Producto + Versión exacta
        if clean_prod and version:
            search_candidates.append(f"{clean_prod} {version}")

        # Prioridad 2: Producto + Versión Major.Minor (si aplica)
        if version and "." in version:
            parts = version.split('.')
            if len(parts) > 1:
                short_ver = f"{parts[0]}.{parts[1]}"
                if clean_prod:
                    search_candidates.append(f"{clean_prod} {short_ver}")

        # Prioridad 3: Producto completo sin versión (solo si >=4 chars para evitar
        # términos demasiado genéricos como "lg", "hp" que generan ruido masivo).
        # Se omite si allow_broad_keyword=False (barrido determinista): el keyword
        # versionless es justo lo que mete ruido de ecosistema (nginx → Authelia…).
        if allow_broad_keyword and len(clean_prod) >= 4:
            search_candidates.append(clean_prod)

        # Eliminar duplicados manteniendo orden
        unique_candidates = []
        for x in search_candidates:
            if x not in unique_candidates:
                unique_candidates.append(x)

        print(f"    {Fore.MAGENTA}[NVD STRATEGY] Fallback a keywords: {unique_candidates}{Fore.RESET}")

        for term in unique_candidates:
            is_broad_search = (term == clean_prod)

            params = {
                'keywordSearch': term,
                'resultsPerPage': 50 if is_broad_search else 100
            }

            data = None
            if is_broad_search:
                print(f"    {Fore.YELLOW} -> Búsqueda amplia '{term}': Buscando CRITICAL...{Fore.RESET}")
                params['cvssV3Severity'] = 'CRITICAL'
                data = self._make_request(self.base_url_cve, params)

                if not data or data.get('totalResults', 0) == 0:
                    print(f"    {Fore.YELLOW} -> No se encontraron CRITICAL. Buscando HIGH...{Fore.RESET}")
                    params['cvssV3Severity'] = 'HIGH'
                    data = self._make_request(self.base_url_cve, params)
            else:
                data = self._make_request(self.base_url_cve, params)

            if data and data.get('totalResults', 0) > 0:
                cves_found = self._parse_nvd_response(data)
                break

        return self._rank_locally(cves_found, version)

    def _rank_locally(self, cves, version):
        """
        Reordena los CVEs encontrados basándose en la coincidencia de versión
        en la descripción, para reducir falsos positivos.
        """
        ranked_cves = []
        version_str = str(version).lower().strip() if version else ""
        
        for cve in cves:
            relevance = cve['score']
            desc = cve['description'].lower()
            
            # Lógica de coincidencia mejorada
            if version_str and version_str in desc: 
                relevance += 20 # Gran boost si coincide exacto
            elif version_str and "." in version_str and version_str.split(".")[0] in desc: 
                relevance += 5  # Boost medio si coincide versión mayor
            
            # Penalización por versión incorrecta (heurística simple)
            # Si la descripción dice explícitamente "before 2.0" y tenemos "3.0"
            # (Esta lógica se podría ampliar con regex para ser más precisa)
                
            cve['inference_score'] = relevance
            ranked_cves.append(cve)
        
        # Ordenar descendente por score de inferencia
        ranked_cves.sort(key=lambda x: x.get('inference_score', 0), reverse=True)
        
        # Si la versión estaba definida, cortamos los que tienen bajo score
        if version_str and len(version_str) > 1:
            return ranked_cves[:15] # Top 15 más relevantes
        
        # Para búsquedas amplias sin versión, limitar a 20 para evitar explosión
        return ranked_cves[:20]

    def _parse_nvd_response(self, data):
        """Convierte la respuesta JSON cruda de NVD a un formato simplificado."""
        vulnerabilities = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id')
            
            descriptions = cve.get('descriptions', [])
            desc = "Sin descripción"
            for d in descriptions:
                if d.get('lang') == 'en': 
                    desc = d.get('value')
                    break
            
            metrics = cve.get('metrics', {})
            score = 0.0
            severity = "UNKNOWN"
            
            # Prioridad de métricas: V3.1 > V3.0 > V2
            # `.get(...)` (truthy) en vez de `in`: la clave puede existir con lista
            # vacía y `[0]` reventaría con IndexError.
            if metrics.get('cvssMetricV31'):
                m = metrics['cvssMetricV31'][0]['cvssData']
                score = m['baseScore']
                severity = m['baseSeverity']
            elif metrics.get('cvssMetricV30'):
                m = metrics['cvssMetricV30'][0]['cvssData']
                score = m['baseScore']
                severity = m['baseSeverity']
            elif metrics.get('cvssMetricV2'):
                m = metrics['cvssMetricV2'][0]['cvssData']
                score = m['baseScore']
                if score >= 7.0: severity = "HIGH"
                elif score >= 4.0: severity = "MEDIUM"
                else: severity = "LOW"

            vulnerabilities.append({
                "id": cve_id,
                "description": desc,
                "severity": severity,
                "score": score,
                "verification_cmd": "Consultar NVD"
            })
        
        return vulnerabilities