"""La allowlist acotaba los flags, pero no sus valores.

La comprobación final de `_validate_args` solo levantaba `PolicyViolation` si el
argumento empezaba por `-`:

    if not matched and arg.startswith("-"):
        raise PolicyViolation(...)

es decir, **cualquier operando pasaba sin mirar**. La política declaraba
controlar lo que el agente puede ejecutar y en realidad controlaba solo la mitad
de cada comando.

Ahora los operandos también se validan, con la misma distinción que ya hacía
`_check_forbidden`: lo que viaja al DISPOSITIVO (cuerpos, cabeceras, cargas de
`echo`/`printf`) es dato y se deja pasar; lo que se queda en el plano local no
puede llevar metacaracteres de shell.
"""
import pytest

from core.policy_engine import PolicyEngine, PolicyViolation


@pytest.fixture
def policy():
    return PolicyEngine()


# ── Operandos locales: acotados ────────────────────────────────────────────

@pytest.mark.parametrize("cmd", [
    "nmap -sV 192.168.1.1;whoami",
    "nmap --script /tmp/x.nse`id`",
    "curl -s http://192.168.1.1/$(whoami)",
    "nc -z 192.168.1.1|sh",
])
def test_operands_with_shell_metacharacters_are_rejected(policy, cmd):
    with pytest.raises(PolicyViolation):
        policy.validate_and_parse(cmd)


# ── Operandos legítimos: siguen pasando ────────────────────────────────────

@pytest.mark.parametrize("cmd", [
    "curl -sk http://192.168.1.1/config.cfg",
    "nmap -sV -p 80,443 192.168.1.1",
    "nc -zv 192.168.1.1 23",
    "snmpwalk -v 2c -c public 192.168.1.1",
    "ping -c 2 192.168.1.1",
])
def test_ordinary_audit_commands_are_untouched(policy, cmd):
    tool, _, _ = policy.validate_and_parse(cmd)
    assert tool


# ── Cargas destinadas al dispositivo: son datos, no instrucciones ──────────

def test_soap_body_with_angle_brackets_is_data(policy):
    """Un cuerpo SOAP lleva `<` y `>` y va al dispositivo, no al shell local."""
    cmd = ("curl -s -X POST -d '<soap:Envelope><Body/></soap:Envelope>' "
           "http://192.168.1.1/HNAP1/")
    tool, _, _ = policy.validate_and_parse(cmd)
    assert tool == "curl"


def test_header_with_semicolon_is_data(policy):
    cmd = "curl -sk -H 'Cookie: uid=1; sid=abc' http://192.168.1.1/admin"
    tool, _, _ = policy.validate_and_parse(cmd)
    assert tool == "curl"


def test_printf_enumeration_payload_reaches_the_device(policy):
    """El patrón que los propios prompts instruyen tras obtener shell: el `;` y
    el `2>/dev/null` van al shell DEL DISPOSITIVO."""
    cmd = ("printf 'id; cat /etc/*release 2>/dev/null\\nexit\\n' "
           "| nc 192.168.1.50 23")
    tool, _, _ = policy.validate_and_parse(cmd)
    assert tool in ("pipe_pair", "multi_echo_pipe")


def test_a_real_local_redirection_is_still_blocked(policy):
    """La excepción cubre lo entrecomillado, no una redirección de verdad."""
    with pytest.raises(PolicyViolation):
        policy.validate_and_parse("printf 'x' > /tmp/robado")
