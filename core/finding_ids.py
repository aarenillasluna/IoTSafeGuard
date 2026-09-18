"""Identificadores canónicos de hallazgo.

El problema que resuelve, medido sobre 26 informes de campo del 2026-08-09:
cuando el identificador lo emite una **sonda**, es estable —`SOCKS5-NOAUTH`
aparece 10 veces de 10, `SSH-DROPBEAR-OLD` 9—; cuando lo inventa el **modelo**,
no se repite jamás. El televisor LG acumuló cinco hallazgos confirmados en ocho
ejecuciones con **cinco identificadores distintos**:

    UPNP-DESCRIPTOR-EXPOSURE
    UPnP-DEVICE-DISCLOSURE              ← el mismo hecho
    UPNP-DEVICE-DESCRIPTOR-EXPOSURE     ← el mismo hecho
    CHROMECAST-EUREKA-INFO-DISCLOSURE
    CHROMECAST-EUREKA-INFO-EXPOSURE     ← el mismo hecho

y el router registró `WEB-UNAUTH-ACCESS` y `WEB-UNAUTHENTICATED-ACCESS` en
ejecuciones distintas.

La consecuencia no es cosmética. El índice de estabilidad de §5.10.2 se calcula
como |∩|/|∪| sobre los conjuntos de confirmados: si el mismo hecho lleva un
nombre distinto cada vez, la intersección es vacía **por construcción**, y la
métrica publica 0.000 para un agente que en realidad encontró lo mismo. Es
decir: la cifra estaba midiendo la libertad léxica del modelo, no su
consistencia.

La normalización actúa en dos dimensiones y solo en dos, para no fusionar cosas
que sí son distintas:

  · **sinónimos** — DISCLOSURE / EXPOSED / LEAK dicen lo mismo que EXPOSURE;
    UNAUTHENTICATED lo mismo que UNAUTH;
  · **relleno** — DEVICE, INFO, SERVICE no distinguen nada.

Lo demás se conserva, de modo que `SOCKS5-NOAUTH` y `SOCKS5-OPEN-RELAY` siguen
siendo hallazgos diferentes: se diferencian en un token con contenido, no en
adorno. Y los CVE reales no se tocan: ya son un identificador canónico, y
reescribirlos rompería el emparejamiento con la NVD.

Sobre el vocabulario: cuando la forma normalizada coincide con la de un
identificador que ya emite una sonda, se devuelve **la grafía de la sonda**. Así
el modelo y las sondas convergen en el mismo nombre en vez de mantener dos
dialectos para el mismo hecho.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, Iterable, Optional, Tuple

# Tokens que significan lo mismo. El destino es el que ya usan las sondas.
_SINONIMOS: Dict[str, str] = {
    "DISCLOSURE": "EXPOSURE",
    "DISCLOSED": "EXPOSURE",
    "EXPOSED": "EXPOSURE",
    "EXPOSING": "EXPOSURE",
    "LEAK": "EXPOSURE",
    "LEAKED": "EXPOSURE",
    "LEAKAGE": "EXPOSURE",
    "UNAUTHENTICATED": "UNAUTH",
    "NOAUTH": "NOAUTH",
    "NO": "NO",
    # «Está ahí y responde» tiene muchos nombres, y el modelo los usa todos.
    # En una tanda de campo escribió `HTTPS-ACCESSIBLE` para decir exactamente lo
    # que la tabla de puertos abiertos ya decía; sin esta equivalencia, cada
    # sinónimo nuevo es un hallazgo confirmado nuevo.
    "ACCESSIBLE": "EXPOSURE",
    "REACHABLE": "EXPOSURE",
    "AVAILABLE": "EXPOSURE",
    "PRESENT": "EXPOSURE",
    "DETECTED": "EXPOSURE",
    "RESPONDING": "EXPOSURE",
    "LISTENING": "EXPOSURE",
    "OPEN": "EXPOSURE",
    # `ACCESSIBLE` y `ACCESS` NO son lo mismo y no deben colapsar: el primero
    # dice que el servicio responde, el segundo que se entró en él. Son tokens
    # distintos, así que la tabla los mantiene separados sin esfuerzo.
    #
    # La familia web se nombra de tres maneras —WEB, HTTP y HTTPS— para el mismo
    # plano. El destino es HTTP y no WEB a propósito: los identificadores que las
    # sondas construyen con el puerto dentro (`HTTP-4070-EXPOSED`) dependen de
    # conservar ese prefijo para reconocerse como superficie.
    "WEB": "HTTP",
    "HTTPS": "HTTP",
    "ANONYMOUS": "ANON",
    "CREDENTIALS": "CRED",
    "CREDS": "CRED",
    "CREDENTIAL": "CRED",
    "DEFAULTS": "DEFAULT",
    "OUTDATED": "OLD",
    "OBSOLETE": "OLD",
    "VULNERABLE": "VULN",
}

# Tokens que no distinguen un hallazgo de otro. Quitarlos es lo que hace que
# `UPNP-DEVICE-DESCRIPTOR-EXPOSURE` y `UPNP-DESCRIPTOR-EXPOSURE` sean uno solo.
# OJO con lo que se declara relleno. `INFO` estuvo aquí y fusionaba
# `CHROMECAST-EXPOSED` (puerto alcanzable, clase EXPOSURE) con
# `CHROMECAST-INFO-DISCLOSURE` (datos legibles, clase DISCLOSURE): dos hallazgos
# distintos, con topes distintos, colapsados en uno. Un token es relleno solo si
# no distingue NINGÚN par del vocabulario, y de eso se encarga una prueba.
_RELLENO = frozenset({
    "DEVICE", "SERVICE", "SERVER", "THE", "A", "AN",
    "OF", "ON", "IN", "AND", "GENERIC", "ISSUE", "FINDING", "DETECTED",
})

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
# Una frase, no un identificador: `Puerto 4070 - Servicio HTTP sin
# identificación` llegó así a un informe de campo.
_PARECE_FRASE_RE = re.compile(r"[a-z]{2,}\s+[a-z]{2,}")


def _sin_acentos(texto: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", texto)
                   if not unicodedata.combining(c))


def _tokens(raw: str) -> Tuple[str, ...]:
    """Descompone un identificador en tokens normalizados y sin relleno."""
    limpio = _sin_acentos(raw).upper()
    crudos = [t for t in re.split(r"[^A-Z0-9]+", limpio) if t]
    salida = []
    for t in crudos:
        t = _SINONIMOS.get(t, t)
        if t in _RELLENO:
            continue
        # Sin duplicados consecutivos: `EXPOSED-DISCLOSURE` colapsa a uno.
        if salida and salida[-1] == t:
            continue
        salida.append(t)
    return tuple(salida)


def _clave(raw: str) -> Tuple[str, ...]:
    """Clave de comparación: tokens normalizados, sin orden.

    Sin orden a propósito: `UPNP-EXPOSURE-DESCRIPTOR` y
    `UPNP-DESCRIPTOR-EXPOSURE` son el mismo hallazgo escrito por dos réplicas.
    """
    tokens = set(_tokens(raw))

    # Credenciales por defecto sobre HTTP: el sistema tiene UN identificador
    # para este hecho, `WEAK-CREDENTIALS`, que es el que emite `web_login` y al
    # que ya apunta el mapeo de títulos. Pero el modelo escribe además
    # `HTTP-DEFAULT-CRED` y `WEB-DEFAULT-CRED`, y en campo llegó a registrar
    # las dos formas en la MISMA tanda: cuatro réplicas de cinco confirmaron el
    # acceso con admin:password y la métrica las contó como dos hallazgos
    # distintos de 3/5 y 1/5. El servicio se descarta solo cuando es HTTP,
    # porque el identificador desnudo ya significa HTTP en este vocabulario;
    # `TELNET-DEFAULT-CRED` y `SSH-DEFAULT-CREDS` llevan su servicio y siguen
    # siendo hallazgos distintos, con remediación distinta.
    if "CRED" in tokens and tokens & {"WEAK", "DEFAULT"}:
        if "HTTP" in tokens:
            tokens.discard("HTTP")
        tokens.discard("DEFAULT")
        tokens.add("WEAK")

    return tuple(sorted(tokens))


def _vocabulario() -> Dict[Tuple[str, ...], str]:
    """Identificadores que ya emiten las sondas, indexados por su clave.

    Se lee del registro de severidad en lugar de duplicarlo: añadir una sonda
    con un identificador nuevo lo incorpora al vocabulario sin tocar este
    módulo. La importación es perezosa para no crear un ciclo con `severity`.
    """
    global _VOCAB_CACHE
    if _VOCAB_CACHE is not None:
        return _VOCAB_CACHE
    conocidos: Iterable[str] = ()
    try:
        from core.severity import (
            _CONFIRMED_NEGATIVE_IDS,
            _PROBE_IMPACT_CLASS,
            _CANONICAL_SEVERITY,
        )
        conocidos = (list(_PROBE_IMPACT_CLASS)
                     + list(_CONFIRMED_NEGATIVE_IDS)
                     + list(_CANONICAL_SEVERITY))
    except ImportError:  # pragma: no cover
        pass
    vocab: Dict[Tuple[str, ...], str] = {}
    for cid in conocidos:
        vocab.setdefault(_clave(cid), cid)
    _VOCAB_CACHE = vocab
    return vocab


_VOCAB_CACHE: Optional[Dict[Tuple[str, ...], str]] = None


def canonicalize_finding_id(raw: Optional[str]) -> str:
    """Identificador canónico de un hallazgo. Idempotente.

    Devuelve la cadena vacía si no hay nada que canonizar, para que quien llama
    decida (el registro de hallazgos exige identificador; el arnés de varianza
    lo ignora).
    """
    if not raw or not str(raw).strip():
        return ""
    raw = str(raw).strip()
    if _CVE_RE.match(raw):
        return raw.upper()

    tokens = _tokens(raw)
    if not tokens:
        return ""

    conocido = _vocabulario().get(_clave(raw))
    if conocido:
        return conocido

    # Desconocido: se devuelve la forma normalizada en el ORDEN en que venía.
    # Dos réplicas que escriben los mismos tokens en el mismo orden convergen;
    # la clave sin orden solo se usa para reconocer el vocabulario, porque
    # reordenar alfabéticamente produciría nombres ilegibles en el informe.
    return "-".join(tokens)[:64]


def looks_like_free_text(raw: Optional[str]) -> bool:
    """¿El «identificador» es en realidad una frase?

    Caso de campo: `Puerto 4070 - Servicio HTTP sin identificación`. Se
    canoniza igual —perder el hallazgo sería peor— pero quien llama puede
    avisar al modelo del formato que se espera.
    """
    if not raw:
        return False
    return bool(_PARECE_FRASE_RE.search(str(raw)))
