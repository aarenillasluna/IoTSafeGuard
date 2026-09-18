"""
Guards del agent loop: detector de repetición + hints de validación.

Inspirado en pentagi/repeatingDetector y fixToolCallArgs:
- RepetitionDetector: bloquea/avisa cuando el modelo llama la misma tool
  con los mismos args N veces consecutivas (síntoma de loop).
- build_validation_hint: cuando dispatch devuelve error de validación,
  envuelve la respuesta con un mensaje explícito guiando al modelo
  para que corrija los args en el siguiente turno.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def _hash_call(name: str, args: Dict[str, Any]) -> str:
    """Hash estable de (tool, args) para detectar repeticiones."""
    payload = json.dumps(
        {"name": name, "args": args or {}},
        sort_keys=True,
        default=str,
        ensure_ascii=False,
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


@dataclass
class RepetitionDetector:
    """
    Detector de bucles. Cubre las DOS formas en que un agente se queda atascado:

    1. **Repetición inmediata** (A-A-A): la misma llamada con los mismos
       argumentos, seguidas.
    2. **Ciclo** (A-B-A-B-A-B, A-B-C-A-B-C): el agente alterna entre dos o más
       llamadas sin avanzar. Es la patología MÁS común de las dos —el modelo
       "prueba otra cosa" y vuelve— y era invisible: se guardaba `history` pero
       no se miraba, de modo que un agente podía alternar dos herramientas hasta
       agotar el presupuesto sin que ninguna guarda dijera nada.

    Uso:
        det = RepetitionDetector(threshold=3)
        if det.observe("nmap_scan", {"ip": "1.2.3.4"}):
            # bucle detectado (repetición o ciclo) -> intervenir
    """

    threshold: int = 3
    last_hash: Optional[str] = None
    consecutive: int = 0
    history: list = field(default_factory=list)
    # Longitud máxima de ciclo que se busca. Con 4, se detectan alternancias de
    # hasta cuatro llamadas (A-B-C-D-A-B-C-D); más allá, la "repetición" empieza
    # a ser indistinguible de un barrido legítimo de sondas.
    max_cycle_length: int = 4
    # Motivo de la última detección, para construir el aviso al modelo.
    last_reason: Optional[str] = None
    cycle_length: int = 0

    def observe(self, name: str, args: Dict[str, Any]) -> bool:
        """
        Registra una llamada. Devuelve True si el agente está atascado, sea por
        repetición inmediata o por ciclo.
        """
        h = _hash_call(name, args)
        if h == self.last_hash:
            self.consecutive += 1
        else:
            self.last_hash = h
            self.consecutive = 1
        self.history.append((name, h))
        if len(self.history) > 50:
            self.history = self.history[-50:]

        if self.consecutive >= self.threshold:
            self.last_reason = "repetition"
            self.cycle_length = 1
            return True

        cycle = self._detect_cycle()
        if cycle:
            self.last_reason = "cycle"
            self.cycle_length = cycle
            return True

        self.last_reason = None
        self.cycle_length = 0
        return False

    def _detect_cycle(self) -> int:
        """Longitud del ciclo que se está repitiendo, o 0 si no hay ninguno.

        Busca el patrón más CORTO que se repita `threshold` veces al final del
        historial: A-B-A-B-A-B con threshold=3 devuelve 2. Se exige el mismo
        número de repeticiones que para la repetición inmediata, de modo que un
        único ida y vuelta (algo perfectamente normal: sondear, registrar,
        volver a sondear otro puerto) no dispare la guarda.
        """
        hashes = [h for _, h in self.history]
        for length in range(2, self.max_cycle_length + 1):
            needed = length * self.threshold
            if len(hashes) < needed:
                continue
            window = hashes[-needed:]
            pattern = window[:length]
            # Un "ciclo" cuyos elementos son todos iguales ya lo cubre la
            # repetición inmediata; aquí solo interesa la alternancia real.
            if len(set(pattern)) == 1:
                continue
            if all(window[i] == pattern[i % length] for i in range(needed)):
                return length
        return 0

    def reset(self) -> None:
        self.last_hash = None
        self.consecutive = 0
        self.last_reason = None
        self.cycle_length = 0
        # El historial también se limpia: tras un cambio de fase, el catálogo de
        # herramientas es otro y las llamadas previas ya no forman un ciclo con
        # las nuevas. Conservarlo producía avisos de bucle inexistentes.
        self.history = []


def _is_sterile(result: Dict[str, Any]) -> bool:
    """El resultado no aporta información nueva sobre el objetivo.

    No es lo mismo que «error»: un 404 se ejecuta perfectamente, devuelve
    `ok=True`, y dice exactamente lo mismo que los 233 anteriores.
    """
    if not isinstance(result, dict) or result.get("_finish"):
        return False
    if (result.get("error_type") or "").upper() in (
            "FAIL", "TIMEOUT", "CONN_REFUSED", "VALIDATION", "POLICY"):
        return True
    if result.get("ok") is False:
        return True
    output = result.get("output")
    return isinstance(output, str) and not output.strip()


@dataclass
class SterileStreakDetector:
    """Tercera forma de atasco: llamadas TODAS DISTINTAS que no informan.

    `RepetitionDetector` cubre repetir (A-A-A) y alternar (A-B-A-B). Le queda
    fuera la patología que más caro salió en campo: **enumerar**. En la tanda
    del 2026-08-09, una réplica contra el router encadenó 234 turnos, uno por
    `curl`, contra rutas inventadas (`te_zoom.asp`, `te_yes.asp`, `te_404.asp`…)
    generalizadas de dos nombres reales que sí había leído del *frameset*. Las
    234 devolvieron el mismo 404 y ninguna cambió su conducta.

    Ninguna capa podía pararlo, y no por descuido: cada una mide otra cosa.
    El detector de repetición compara (herramienta, argumentos), y **las 238
    llamadas eran distintas**. El `SafetyMonitor` acota el RITMO —iban a 9
    req/min contra un presupuesto de 60— no el volumen. Y el presupuesto de
    turnos era infinito. Faltaba la única pregunta que sí lo delata: *¿qué está
    devolviendo el objetivo?* Esta guarda es la primera que mira el RESULTADO en
    vez de la petición.

    Dos umbrales, porque las dos salidas son distintas:
      · `threshold` → aviso. El modelo puede rectificar solo, y a veces lo hace.
      · `hard_limit` → corte. Ya se le avisó y siguió; el bucle termina y el
        informe se rescata con lo que hubiera.

    Y una señal aparte, la **revisita**: repetir una llamada que YA salió
    estéril. Aquella réplica pidió `te_block.asp` en el turno 175 y otra vez en
    el 274 —había recorrido su lista de palabras entera y volvía a empezar—. Es
    invisible para el detector de ciclos, que solo mira los últimos 50 y ciclos
    de hasta 4.
    """

    threshold: int = 10
    hard_limit: int = 25
    # Racha mínima para que una revisita cuente como síntoma. Repetir algo ya
    # descartado es normal si el agente está avanzando; solo delata cuando
    # además lleva rato sin obtener nada.
    revisit_after: int = 4
    streak: int = 0
    total: int = 0
    sterile_hashes: set = field(default_factory=set)
    last_reason: Optional[str] = None

    def observe(self, name: str, args: Dict[str, Any],
                result: Dict[str, Any], gained_finding: bool) -> Optional[str]:
        """Devuelve `None`, `"warn"` o `"stop"`.

        `gained_finding` rompe la racha aunque el resultado sea estéril: si el
        agente registró un hallazgo a partir de esa llamada, la llamada informó
        —de eso trata la guarda— por mucho que el comando «fallara». Registrar
        un negativo confirmado es un resultado, no un turno perdido.
        """
        if gained_finding or not _is_sterile(result):
            self.streak = 0
            self.last_reason = None
            return None

        self.streak += 1
        self.total += 1

        h = _hash_call(name, args)
        # La revisita solo cuenta si el agente YA está en racha. Sin esa
        # condición saltaba en campo al re-sondear `probe_tcp(80)` tras cambiar
        # de fase —una acción legítima: en exploit hay rutas que en recon no
        # existían— y le decía «estás dando vueltas» a un agente que avanzaba.
        # Volver sobre algo ya descartado solo es síntoma cuando forma parte de
        # una tanda improductiva; aislado, es trabajo normal.
        if h in self.sterile_hashes and self.streak >= self.revisit_after:
            self.last_reason = "revisit"
            return "warn"
        self.sterile_hashes.add(h)

        if self.streak >= self.hard_limit:
            self.last_reason = "sterile_enumeration"
            return "stop"
        if self.streak == self.threshold:
            self.last_reason = "sterile_streak"
            return "warn"
        return None

    def reset(self) -> None:
        """Al cambiar de fase la racha se olvida, igual que en el detector de
        repetición: el catálogo de herramientas es otro. El conjunto de llamadas
        ya estériles NO se olvida — que una ruta diera 404 en recon sigue siendo
        cierto en exploit."""
        self.streak = 0
        self.last_reason = None


def build_sterile_warning(name: str, streak: int, reason: str) -> str:
    """Aviso al modelo. En inglés, como el resto de su superficie (§4.4)."""
    if reason == "revisit":
        return (
            f"⚠️  You already ran this exact `{name}` call earlier in this run and "
            f"it returned nothing. You are cycling back through paths you have "
            f"already ruled out. Stop enumerating and use what you learned: call "
            f"`audit_status` to see what is still pending, then either probe a "
            f"different service/port or finish with save_report + done."
        )
    return (
        f"⚠️  The last {streak} calls to `{name}` returned NO new information "
        f"(empty bodies, 404s or failures) and produced no finding. Guessing "
        f"endpoint names one per turn is not reconnaissance — the target has "
        f"already told you they do not exist. Change the CLASS of action: a "
        f"different port, a different protocol, an actual probe tool, or close "
        f"the audit with save_report + done. Do NOT continue the list."
    )


# =====================================================================
# Validation hint injection
# =====================================================================

def looks_like_validation_error(result: Dict[str, Any]) -> bool:
    """
    Heurística: el dispatch devolvió un fallo recuperable por el modelo.
    """
    if not isinstance(result, dict):
        return False
    if result.get("ok") is True:
        return False
    err = (result.get("error") or "").lower()
    err_type = (result.get("error_type") or "").lower()
    if "unknown tool" in err:
        return True
    if err_type in ("validation", "missing_arg", "bad_args", "schema"):
        return True
    if "missing" in err or "required" in err or "invalid" in err:
        return True
    return False


def build_validation_hint(name: str, args: Dict[str, Any], result: Dict[str, Any]) -> str:
    """
    Construye un mensaje corto explicando qué argumentos arreglar.
    Se inyecta en el campo `_hint` de la function_response.

    En inglés, como el resto de la superficie que ve el modelo (§4.4): estos
    textos se inyectan en su contexto junto al system prompt y al catálogo de
    herramientas, así que forman parte de las instrucciones, no del informe.
    """
    err = result.get("error") or result.get("error_type") or "validation_error"
    return (
        f"The call to `{name}` failed with invalid arguments: {err}. "
        f"Arguments sent: {list((args or {}).keys())}. "
        f"Review the tool schema and retry with the correct fields. "
        f"Do NOT repeat the exact same call."
    )


# =====================================================================
# Repetition feedback
# =====================================================================

def build_repetition_warning(name: str, args: Dict[str, Any], count: int,
                             reason: str = "repetition",
                             cycle_length: int = 1) -> str:
    """
    Mensaje a inyectar cuando RepetitionDetector dispara.

    El texto distingue repetición de ciclo porque la salida es distinta: ante
    una repetición basta con dejar de reintentar, mientras que en un ciclo el
    agente CREE que está cambiando de estrategia —por eso alterna— y hay que
    señalarle que el conjunto de llamadas, no cada una, es lo que se repite.

    Redactado en inglés por el mismo motivo que `build_validation_hint`: se
    inyecta en el contexto del modelo, no en el informe.
    """
    if reason == "cycle":
        return (
            f"⚠️  You are in a LOOP: you keep alternating the same {cycle_length} "
            f"calls over and over (the latest one, `{name}`) without gaining new "
            f"information. Alternating between two tools is NOT changing strategy. "
            f"Call `audit_status` to see what is actually still pending, and pick "
            f"an action you have not tried yet: another port, another endpoint, "
            f"another class of probe, or move to the next phase."
        )
    return (
        f"⚠️  You have called `{name}` with the same arguments {count} times in a row. "
        f"Change strategy: try another endpoint, another tool, or move to the next phase. "
        f"If the tool returns no useful data, do NOT retry it — record the result and move on."
    )
