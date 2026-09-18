"""PolicyEngine: allowlist, pipes, subshells y rechazos.

Consolidado en tablas parametrizadas: cada fila es el mismo caso que antes era una
función propia, pero el motivo de cada una queda como comentario junto al dato en
lugar de diluido en un nombre de test. Menos código que mantener, idéntico número
de casos, y añadir un caso nuevo es añadir una fila.
"""
import os
import sys

import pytest

# Asegurar que el proyecto esté en el path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.policy_engine import PolicyEngine, PolicyViolation


@pytest.fixture
def engine():
    return PolicyEngine()


# --------------------------------------------------------- comandos permitidos

@pytest.mark.parametrize("cmd,expected_tool", [
    ("curl -k -s http://192.168.1.1:8080/info", "curl"),
    ("nmap -sV -p 80,443 192.168.1.1", "nmap"),
    ("ping -c 3 192.168.1.1", "ping"),
    ("echo 'hello world'", "echo"),
    ("socat - TCP:192.168.1.1:23", "socat"),
    ("nc -u -w1 192.168.1.1 1900", "nc"),
    # User-Agent como vector: el bypass de autenticación de D-Link va en la cabecera
    ("curl -A 'xmlset_roodkcableoj28840ybtide' -d 'data=test' http://192.168.1.1/cgi", "curl"),
    # Rutas absolutas: se normaliza el ejecutable antes de comparar con la allowlist
    ("/usr/bin/curl -k http://192.168.1.1", "curl"),
])
def test_allowed_commands_parse_to_their_tool(engine, cmd, expected_tool):
    tool, _args, _ = engine.validate_and_parse(cmd)
    assert tool == expected_tool


def test_flags_survive_the_parsing(engine):
    """No basta con identificar la herramienta: los flags llegan al ejecutor."""
    _tool, args, _ = engine.validate_and_parse("curl -k -s http://192.168.1.1:8080/info")
    assert "-k" in args and "-s" in args
    _tool, args, _ = engine.validate_and_parse("nc -u -w1 192.168.1.1 1900")
    assert "-u" in args


def test_xml_payload_in_curl_d_is_not_input_redirection(engine):
    """El `<` de un cuerpo SOAP es un dato para el dispositivo, no una redirección
    del shell local (vector HNAP/TR-069)."""
    cmd = ("""curl -k -X POST -d "<?xml version='1.0'?><soap:Envelope>"""
           """<soap:Body></soap:Body></soap:Envelope>" http://192.168.1.1/HNAP1/""")
    tool, _args, _ = engine.validate_and_parse(cmd)
    assert tool == "curl"


# ------------------------------------------------------------------- pipes

@pytest.mark.parametrize("cmd,expected_kind,left,right", [
    # WebSocket con payload JSON: el vector de los Smart TV
    ("""echo '{"type":"request"}' | websocat -k wss://192.168.1.1:3001""",
     "pipe_pair", "echo", "websocat"),
    # M-SEARCH SSDP por UDP con socat
    ("echo -e 'M-SEARCH * HTTP/1.1' | socat - UDP-DATAGRAM:192.168.1.1:1900",
     "pipe_pair", "echo", "socat"),
    # Rutas absolutas en ambos lados de la tubería
    ("""/usr/bin/echo '{"x":1}' | /usr/bin/websocat -k wss://192.168.1.1:3001""",
     "pipe_pair", "echo", "websocat"),
    # printf: obligatorio porque el shell del dispositivo suele ser dash
    ("printf 'root\\nroot\\nid\\nexit\\n' | nc 192.168.1.1 23",
     "pipe_pair", "printf", "nc"),
])
def test_valid_pipes(engine, cmd, expected_kind, left, right):
    tool, parts, _ = engine.validate_and_parse(cmd)
    assert tool == expected_kind
    left_parts, right_parts = parts
    assert left_parts[0] == left
    assert right_parts[0] == right


@pytest.mark.parametrize("cmd,echoes,sleeps", [
    # Dos payloads seguidos hacia el mismo WebSocket
    ("""(echo '{"type":"register"}'; echo '{"type":"request"}') """
     """| websocat -k --no-close wss://192.168.1.1:3001""", 2, 0),
    # `sleep` en el subshell: el login telnet necesita que el servidor procese
    # cada línea antes de la siguiente, así que las esperas son parte del vector
    ("(sleep 1; echo 'Alphanetworks'; sleep 1; echo 'id') | nc 192.168.1.1 23", 2, 2),
    ("(sleep 1; echo 'admin'; sleep 1; echo 'password') | netcat 192.168.1.1 23", 2, 2),
    # SSAP de webOS: el prompt de pairing aparece entre el register y el subscribe
    ("""(echo '{"type":"register"}'; sleep 2; echo '{"type":"subscribe"}') """
     """| wscat -c ws://192.168.1.40:3000""", 2, 1),
])
def test_subshell_pipes_preserve_payloads_and_their_timing(engine, cmd, echoes, sleeps):
    """Ni un payload se pierde ni una espera se descarta: el orden y las pausas SON
    el vector en los logins telnet y en el pairing de webOS."""
    tool, parts, _ = engine.validate_and_parse(cmd)
    assert tool == "multi_echo_pipe"
    actions, _right = parts
    assert sum(1 for kind, _v in actions if kind == "echo") == echoes
    assert sum(1 for kind, _v in actions if kind == "sleep") == sleeps


# -------------------------------------------------------------- rechazos

@pytest.mark.parametrize("cmd,match", [
    ("rm -rf /", "not allowed"),                          # binario destructivo
    ("curl `whoami`", "Forbidden pattern"),                        # backticks
    ("curl $(cat /etc/passwd)", "Forbidden pattern"),              # sustitución de comandos
    ("echo 'payload' | bash", "Forbidden pattern"),                # tubería a shell
    ("echo 'payload' | sh", "Forbidden pattern"),
    ("eval curl http://evil.com", "Forbidden pattern"),
    ("exec curl http://evil.com", "Forbidden pattern"),
    ("curl http://x > /etc/passwd", "Forbidden pattern"),          # redirección a fichero
    ("curl http://x | grep token", "Forbidden pattern"),           # filtrado local del output
    ("curl http://x | awk '{print $1}'", "Forbidden pattern"),
    ("(cat /etc/passwd) | websocat wss://x", "echo"),      # subshell: solo echo/sleep
    ("echo 'a' | echo 'b' | websocat wss://x", "2-segment"),  # tuberías de 3 tramos
])
def test_rejected_commands(engine, cmd, match):
    with pytest.raises(PolicyViolation, match=match):
        engine.validate_and_parse(cmd)


def test_empty_command_is_rejected(engine):
    with pytest.raises(PolicyViolation):
        engine.validate_and_parse("")
