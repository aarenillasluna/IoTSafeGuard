"""Lecciones de las quince ejecuciones secuenciales del 2026-08-09.

Tres aparatos (altavoz Amazon, televisor LG, router Askey) por cinco réplicas.
Cada prueba de aquí fija un comportamiento que en esa tanda salió mal.
"""
import pytest

from core.policy_engine import PolicyEngine, PolicyViolation
from core.tools import (AgentSession, _reject_os_range_kernel_search,
                        _render_binary_output, bind_session)


@pytest.fixture
def sesion():
    s = AgentSession(target_ip="192.168.1.1")
    bind_session(s)
    return s


# ── El rango de fingerprint no es una versión ──────────────────────────────

class TestBarridoDeKernel:
    """nmap devuelve `Linux 2.6.31 - 2.6.35`: un intervalo, no una versión.

    Tomar un extremo y barrer el kernel produjo entre 15 y 23 CVEs de 2009
    probados de uno en uno, cero confirmados en 38 intentos. El coste real no
    fue el acierto sino la consistencia: solo se dispara en algunas réplicas, y
    es el causante principal de la varianza medida (mismo router: 4, 4, 8, 8 y
    23 hallazgos; mismo televisor: 6 y 34).
    """

    def test_se_rechaza_la_version_sacada_del_rango(self, sesion):
        sesion.scan_cache = {"os_match": "Linux 2.6.31 - 2.6.35"}
        r = _reject_os_range_kernel_search("Linux kernel 2.6", "2.6.31", None)
        assert r and r["error"] == "os_fingerprint_range_is_not_a_version"

    def test_tambien_el_otro_extremo(self, sesion):
        sesion.scan_cache = {"os_match": "Linux 3.2 - 4.9"}
        assert _reject_os_range_kernel_search("Linux kernel", "4.9", None)

    def test_un_kernel_de_verdad_si_pasa(self, sesion):
        """Si una sonda leyó la versión (sysDescr, banner), es evidencia."""
        sesion.scan_cache = {"os_match": "Linux 3.2 - 4.9"}
        assert _reject_os_range_kernel_search("Linux kernel", "4.19.100", None) is None

    def test_sin_rango_no_hay_motivo_para_rechazar(self, sesion):
        sesion.scan_cache = {"os_match": "Linux 4.19.5"}
        assert _reject_os_range_kernel_search("Linux kernel", "4.19.5", None) is None

    def test_no_estorba_a_los_productos_normales(self, sesion):
        sesion.scan_cache = {"os_match": "Linux 2.6.31 - 2.6.35"}
        assert _reject_os_range_kernel_search("Dropbear SSH", "2019.78", None) is None


# ── Ver los bytes sin pelearse con la política ─────────────────────────────

class TestSalidaBinaria:
    """El modelo pedía `| xxd` y `| od -A x -t x1z` para leer respuestas
    binarias: nueve intentos bloqueados en quince ejecuciones, por querer
    *mirar* unos bytes que sí se le permite enviar."""

    def test_una_salida_de_texto_sale_intacta(self):
        texto, hexa = _render_binary_output("HTTP/1.1 200 OK\r\nServer: boa\r\n")
        assert texto == "HTTP/1.1 200 OK\r\nServer: boa\r\n"
        assert hexa is None

    def test_los_bytes_crudos_se_rinden_en_hex(self):
        texto, hexa = _render_binary_output("\x05\x00 respuesta")
        assert hexa and hexa.startswith("0500")
        assert "\x05" not in texto, "el texto entregado ya no lleva control"

    def test_la_salida_binaria_no_corrompe_el_log(self):
        """Mismo fallo que el banner SSH: unos NUL bastan para que `file`
        clasifique el `.log` como `data`."""
        texto, _ = _render_binary_output("dropbear\x00\x00\x01t")
        assert "\x00" not in texto

    def test_vacio_no_revienta(self):
        assert _render_binary_output("") == ("", None)


# ── Un rechazo que no enseña se convierte en reintentos ────────────────────

class TestLosRechazosEnsenan:
    """En la tanda, el modelo repitió `tftp` cuatro veces y
    `$(printf 'A%.0s' {1..2000})` cinco: el mensaje decía qué estaba prohibido,
    nunca qué usar en su lugar."""

    @pytest.fixture
    def politica(self):
        return PolicyEngine()

    @pytest.mark.parametrize("comando,esperado", [
        ("tftp 192.168.1.37 -c get /etc/passwd", "probe_tftp"),
        ("curl -x socks5://192.168.1.37:1080 http://192.168.1.1", "probe_socks5"),
        ("printf 'x' | nc -x 192.168.1.37:1080 192.168.1.1 80", "probe_socks5"),
        ("curl -sk \"http://192.168.1.1/$(printf 'A%.0s' {1..2000})\"", "payload_hex"),
        ("printf 'HELP' | nc 192.168.1.37 8888 | xxd", "output_hex"),
    ])
    def test_cada_rechazo_nombra_la_alternativa(self, politica, comando, esperado):
        with pytest.raises(PolicyViolation, match=esperado):
            politica.validate_and_parse(comando)

    def test_la_plantilla_sin_sustituir_se_explica(self, politica):
        """`curl -v telnet://<TARGET_IP>:1080` llegó literal, y el rechazo
        hablaba de redirección de entrada — que no era el problema."""
        with pytest.raises(PolicyViolation, match="TARGET_IP"):
            politica.validate_and_parse("curl -v telnet://<TARGET_IP>:1080")

    def test_un_comando_valido_sigue_pasando(self, politica):
        tool, _, _ = politica.validate_and_parse("curl -sk http://192.168.1.1/")
        assert tool == "curl"


# ── El estrangulamiento del proveedor se mide ──────────────────────────────

class TestRetrocesoAnte429:
    """Era fijo en 10s y la racha se reinicia con cada éxito, así que nunca
    crecía: quince 429 seguidos a 10s son 150 s de una auditoría de 13 minutos,
    sin que el ritmo bajase ni una vez."""

    def test_el_retroceso_crece_con_la_racha(self):
        from core.base_agent import BaseReActAgent as B
        esperas = [B._backoff_seconds(n) for n in range(1, 6)]
        assert esperas == sorted(esperas) and esperas[0] < esperas[-1]

    def test_esta_acotado(self):
        from core.base_agent import BaseReActAgent as B
        assert B._backoff_seconds(20) == 60

    def test_la_pista_del_proveedor_manda_si_es_mayor(self):
        from core.base_agent import BaseReActAgent as B
        assert B._backoff_seconds(1, provider_hint=25.0) == 26

    def test_el_total_del_run_llega_al_informe(self, sesion):
        from core.base_agent import BaseReActAgent

        class _Agente(BaseReActAgent):
            def __init__(self):
                pass

        a = _Agente()
        assert a._record_rate_limit_hit() == 1
        assert a._record_rate_limit_hit() == 2
        assert sesion.provider_rate_limit_hits == 2
