"""
MQTT Probing Module: Detección y análisis de brokers MQTT en dispositivos IoT.
Intenta conexión anónima, suscripción wildcard, y publicación de prueba.
"""
import socket
import struct
import time
from typing import Dict, List, Any
from loguru import logger


# Puertos MQTT estándar
MQTT_PORTS = [1883, 8883]

# MQTT CONNECT packet mínimo (protocolo 3.1.1, sin auth)
_PROTOCOL_NAME = b"\x00\x04MQTT"
_PROTOCOL_LEVEL = b"\x04"  # 3.1.1
_CONNECT_FLAGS = b"\x02"  # Clean Session
_KEEP_ALIVE = b"\x00\x3c"  # 60 seconds


def _build_connect_packet(client_id: str = "iot-pentest-probe") -> bytes:
    """Construye un paquete MQTT CONNECT mínimo (sin auth)."""
    client_id_bytes = client_id.encode("utf-8")
    client_id_field = struct.pack("!H", len(client_id_bytes)) + client_id_bytes

    variable_header = _PROTOCOL_NAME + _PROTOCOL_LEVEL + _CONNECT_FLAGS + _KEEP_ALIVE
    payload = client_id_field

    remaining = variable_header + payload
    remaining_length = _encode_remaining_length(len(remaining))

    # Fixed header: CONNECT (0x10)
    return b"\x10" + remaining_length + remaining


def _build_subscribe_packet(topic: str = "#", packet_id: int = 1) -> bytes:
    """Construye un paquete MQTT SUBSCRIBE."""
    topic_bytes = topic.encode("utf-8")
    topic_field = struct.pack("!H", len(topic_bytes)) + topic_bytes + b"\x00"  # QoS 0

    variable_header = struct.pack("!H", packet_id)
    payload = topic_field

    remaining = variable_header + payload
    remaining_length = _encode_remaining_length(len(remaining))

    # Fixed header: SUBSCRIBE (0x82)
    return b"\x82" + remaining_length + remaining


def _build_publish_packet(topic: str, message: str) -> bytes:
    """Construye un paquete MQTT PUBLISH (QoS 0, no retain)."""
    topic_bytes = topic.encode("utf-8")
    topic_field = struct.pack("!H", len(topic_bytes)) + topic_bytes
    payload = message.encode("utf-8")

    remaining = topic_field + payload
    remaining_length = _encode_remaining_length(len(remaining))

    # Fixed header: PUBLISH (0x30) - QoS 0, no retain
    return b"\x30" + remaining_length + remaining


def _encode_remaining_length(length: int) -> bytes:
    """Codifica el campo Remaining Length de MQTT (variable byte encoding)."""
    result = bytearray()
    while True:
        byte = length % 128
        length = length // 128
        if length > 0:
            byte = byte | 0x80
        result.append(byte)
        if length == 0:
            break
    return bytes(result)


def _parse_connack(data: bytes) -> Dict[str, Any]:
    """Parsea un paquete CONNACK."""
    if len(data) < 4:
        return {"connected": False, "reason": "Response too short"}

    packet_type = (data[0] & 0xF0) >> 4
    if packet_type != 2:  # CONNACK = 2
        return {"connected": False, "reason": f"Unexpected packet type: {packet_type}"}

    return_code = data[3]
    codes = {
        0: "Connection Accepted",
        1: "Unacceptable Protocol Version",
        2: "Identifier Rejected",
        3: "Server Unavailable",
        4: "Bad Username or Password",
        5: "Not Authorized",
    }
    return {
        "connected": return_code == 0,
        "return_code": return_code,
        "reason": codes.get(return_code, f"Unknown code: {return_code}"),
    }


class MQTTProber:
    """
    Sonda MQTT para análisis de seguridad de brokers IoT.
    Opera a nivel de socket sin dependencia de paho-mqtt.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def detect_mqtt_ports(self, ip: str, ports: List[Dict]) -> List[int]:
        """Detecta puertos MQTT entre los puertos abiertos escaneados."""
        mqtt_ports = []
        for port_info in ports:
            port = port_info.get("port", 0)
            service = (port_info.get("service_name") or "").lower()
            product = (port_info.get("product") or "").lower()

            if port in MQTT_PORTS:
                mqtt_ports.append(port)
            elif "mqtt" in service or "mosquitto" in product:
                mqtt_ports.append(port)

        return mqtt_ports

    def probe_broker(self, ip: str, port: int = 1883) -> Dict[str, Any]:
        """
        Prueba completa de un broker MQTT:
        1. Conexión anónima
        2. Suscripción wildcard (#)
        3. Publicación de prueba

        Retorna resumen de hallazgos.
        """
        results: Dict[str, Any] = {
            "ip": ip,
            "port": port,
            "anonymous_access": False,
            "wildcard_subscribe": False,
            "publish_allowed": False,
            "messages_intercepted": [],
            "vulnerabilities": [],
            "error": None,
        }

        sock = None
        try:
            # --- 1. Conexión anónima ---
            sock = socket.create_connection((ip, port), timeout=self.timeout)
            sock.settimeout(self.timeout)

            connect_packet = _build_connect_packet()
            sock.sendall(connect_packet)

            response = sock.recv(1024)
            connack = _parse_connack(response)

            if not connack["connected"]:
                results["error"] = f"CONNACK rejected: {connack['reason']}"
                logger.info(f"[MQTT] {ip}:{port} — conexión rechazada: {connack['reason']}")
                if connack.get("return_code") == 5:
                    results["vulnerabilities"].append({
                        "id": "MQTT-AUTH-REQUIRED",
                        "description": "Broker requiere autenticación (seguro)",
                        "severity": "INFO",
                        "score": 0.0,
                    })
                return results

            # ¡Conexión anónima exitosa!
            results["anonymous_access"] = True
            results["vulnerabilities"].append({
                "id": "MQTT-ANON-ACCESS",
                "description": f"Broker MQTT en {ip}:{port} permite conexión anónima sin credenciales",
                "severity": "HIGH",
                "score": 8.5,
                "source": "mqtt_probe",
                "verification_cmd": f"mosquitto_sub -h {ip} -p {port} -t '#' -v -C 5",
            })
            logger.warning(f"[MQTT] {ip}:{port} — ⚠️ CONEXIÓN ANÓNIMA PERMITIDA")

            # --- 2. Suscripción wildcard ---
            subscribe_packet = _build_subscribe_packet("#")
            sock.sendall(subscribe_packet)

            try:
                sub_response = sock.recv(1024)
                if len(sub_response) >= 4:
                    suback_type = (sub_response[0] & 0xF0) >> 4
                    if suback_type == 9:  # SUBACK
                        return_code = sub_response[-1]
                        if return_code in (0, 1, 2):  # QoS 0/1/2 granted
                            results["wildcard_subscribe"] = True
                            results["vulnerabilities"].append({
                                "id": "MQTT-WILDCARD-SUB",
                                "description": "Suscripción wildcard '#' permitida. "
                                               "Un atacante puede interceptar TODOS los mensajes del broker.",
                                "severity": "CRITICAL",
                                "score": 9.5,
                                "source": "mqtt_probe",
                                "verification_cmd": f"mosquitto_sub -h {ip} -p {port} -t '#' -v -C 10",
                            })
                            logger.warning(f"[MQTT] {ip}:{port} — ⚠️ SUSCRIPCIÓN WILDCARD PERMITIDA")
            except socket.timeout:
                logger.debug(f"[MQTT] {ip}:{port} — timeout en SUBACK (posible restricción)")

            # Intentar capturar mensajes por 2 segundos
            if results["wildcard_subscribe"]:
                sock.settimeout(2.0)
                try:
                    while True:
                        msg_data = sock.recv(4096)
                        if not msg_data:
                            break
                        # Parseo básico de PUBLISH
                        if (msg_data[0] & 0xF0) >> 4 == 3:  # PUBLISH
                            topic_len = struct.unpack("!H", msg_data[2:4])[0]
                            topic = msg_data[4:4 + topic_len].decode("utf-8", errors="replace")
                            payload_start = 4 + topic_len
                            payload = msg_data[payload_start:].decode("utf-8", errors="replace")
                            results["messages_intercepted"].append({
                                "topic": topic,
                                "payload_preview": payload[:200],
                            })
                            if len(results["messages_intercepted"]) >= 5:
                                break
                except socket.timeout:
                    pass

            # --- 3. Publicación de prueba ---
            test_topic = "iot_pentest/probe"
            test_message = "IoTSafeGuard-Agent security probe"
            publish_packet = _build_publish_packet(test_topic, test_message)
            try:
                sock.sendall(publish_packet)
                results["publish_allowed"] = True
                results["vulnerabilities"].append({
                    "id": "MQTT-PUB-ALLOWED",
                    "description": f"Publicación anónima permitida en topic '{test_topic}'. "
                                   "Un atacante podría inyectar comandos en dispositivos IoT.",
                    "severity": "HIGH",
                    "score": 8.0,
                    "source": "mqtt_probe",
                    "verification_cmd": f"mosquitto_pub -h {ip} -p {port} -t '{test_topic}' -m 'test'",
                })
                logger.warning(f"[MQTT] {ip}:{port} — ⚠️ PUBLICACIÓN ANÓNIMA PERMITIDA")
            except (socket.error, BrokenPipeError):
                logger.debug(f"[MQTT] {ip}:{port} — publicación rechazada")

            # Desconexión limpia
            try:
                sock.sendall(b"\xe0\x00")  # DISCONNECT
            except (socket.error, BrokenPipeError):
                pass

        except socket.timeout:
            results["error"] = "Connection timeout"
            logger.debug(f"[MQTT] {ip}:{port} — timeout de conexión")
        except ConnectionRefusedError:
            results["error"] = "Connection refused"
            logger.debug(f"[MQTT] {ip}:{port} — conexión rechazada")
        except Exception as e:
            results["error"] = str(e)
            logger.warning(f"[MQTT] {ip}:{port} — error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

        return results

    def probe_all(self, ip: str, ports: List[Dict]) -> List[Dict[str, Any]]:
        """Prueba todos los puertos MQTT detectados."""
        mqtt_ports = self.detect_mqtt_ports(ip, ports)
        if not mqtt_ports:
            logger.debug(f"[MQTT] No se detectaron puertos MQTT en {ip}")
            return []

        results = []
        for port in mqtt_ports:
            logger.info(f"[MQTT] Probando broker en {ip}:{port}...")
            result = self.probe_broker(ip, port)
            results.append(result)
            time.sleep(0.5)  # Cortesía entre pruebas

        return results
