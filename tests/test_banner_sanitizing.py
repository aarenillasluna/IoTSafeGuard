"""Un banner es texto de una línea, no el volcado del socket.

Contra un router Askey con Dropbear, el ident SSH y el paquete KEXINIT llegan
en el MISMO segmento TCP. Cortar por `\\n` no basta —la línea de identificación
termina en CRLF (RFC 4253 §4.2) y detrás vienen los bytes del intercambio de
claves— y `bytes.decode(errors="ignore")` no elimina los bytes de control,
porque son codepoints Unicode válidos. Resultado en campo, cinco veces de cinco:

  · cinco NUL por fichero de log → `file` lo clasificaba como `data`, y
    `grep`/`tail` lo trataban como binario (el dashboard lo transmite línea a
    línea);
  · el extractor de modelo leía `curve25519-sha256` de la lista de algoritmos y
    publicaba el aparato como modelo **CURVE25519**, que se propagaba a la KB,
    al CPE y a las búsquedas de CVE («ASKEY CURVE25519» → 0 resultados).
"""
from modules.fingerprint import _extract_model_from_text
from modules.interrogator import _clean_banner

# Lo que Dropbear devolvió de verdad en 192.168.1.1:22.
BANNER_DROPBEAR_REAL = (
    b"SSH-2.0-dropbear_2019.78 \r\n"
    b"\x00\x00\x01t\x05\x14.C\x02l\x08mc\x2e\xcc\xa1\x00\x00\x00"
    b"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,"
    b"ecdh-sha2-nistp384,diffie-hellman-group14-sha256"
)


class TestLimpiezaDeBanner:

    def test_ssh_se_corta_en_la_linea_de_identificacion(self):
        assert _clean_banner(BANNER_DROPBEAR_REAL, 22) == "SSH-2.0-dropbear_2019.78"

    def test_no_quedan_bytes_de_control(self):
        limpio = _clean_banner(BANNER_DROPBEAR_REAL, 22)
        assert not any(ord(c) < 0x20 or 0x7f <= ord(c) <= 0x9f for c in limpio)

    def test_un_puerto_no_ssh_conserva_su_contenido(self):
        """El corte por línea es específico de SSH; FTP o RTSP no lo llevan."""
        crudo = b"220 Welcome to VulnRouter FTP\r\n220 ProFTPD 1.3.5\r\n"
        limpio = _clean_banner(crudo, 21)
        assert "VulnRouter" in limpio and "ProFTPD 1.3.5" in limpio

    def test_los_controles_se_limpian_aunque_no_sea_ssh(self):
        assert _clean_banner(b"REDIS\x00\x01 v6.0", 6379) == "REDIS v6.0"

    def test_se_respeta_el_tope_de_longitud(self):
        assert len(_clean_banner(b"A" * 5000, 21)) == 400


class TestModeloNoEsUnAlgoritmo:

    def test_curve25519_no_es_un_modelo(self):
        assert _extract_model_from_text(
            "SSH-2.0-dropbear_2019.78 curve25519-sha256,ecdh-sha2-nistp521") is None

    def test_el_banner_real_completo_no_produce_modelo(self):
        sucio = BANNER_DROPBEAR_REAL.decode(errors="ignore")
        assert _extract_model_from_text(sucio) is None

    def test_otros_algoritmos_tampoco(self):
        for texto in ("aes128-ctr,aes256-gcm@openssh.com",
                      "ecdh-sha2-nistp384", "hmac-sha2-512", "x25519:secp256r1"):
            assert _extract_model_from_text(texto) is None, texto

    def test_un_modelo_real_junto_a_criptografia_se_sigue_extrayendo(self):
        """Descartar un candidato no puede abortar la búsqueda entera.

        Un banner puede traer ruido criptográfico ANTES del modelo; rendirse en
        el primer descarte perdería la identidad igualmente.
        """
        assert _extract_model_from_text(
            "Dropbear curve25519-sha256 on DIR-825 router") == "DIR-825"

    def test_no_se_rompen_los_modelos_de_siempre(self):
        assert _extract_model_from_text("D-Link DIR-815 rev B") == "DIR-815"
        assert _extract_model_from_text("Local time is now 07:35") is None
