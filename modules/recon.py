import os
import nmap
from colorama import Fore
from loguru import logger

class ReconScanner:
    IOT_EXTENDED_PORTS = [
        # Web & Admin
        80, 443, 8080, 8443, 8888, 3000, 5000,
        # Control & Discovery
        1900, 5353, 161, 1625, 8008,
        # IoT Protocols
        1883, 8883, 5683, 502, 47808,
        # Vendor-local control (ESP8266/ESP32 baratos: Tuya, ESPHome, Shelly)
        6668, 6053,
        # Streaming & Shells
        22, 23, 554, 8554, 111, 2049, 32400
    ]

    # UDP ports cruciales para IoT discovery — nmap -sU pase aparte
    # 54321 = Xiaomi miIO (protocolo nativo; rara vez "open" en UDP scan, pero
    # se incluye por si el dispositivo responde al pase -sU).
    IOT_UDP_PORTS = [161, 1900, 5353, 5683, 69, 123, 137, 138, 1701, 500, 4500, 54321]

    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            logger.info("[RECON] Scanner inicializado")
        except nmap.PortScannerError as e:
            logger.error(f"[RECON] Nmap no instalado: {e}")
            print(f"{Fore.RED}[ERROR] Nmap no instalado en el sistema.{Fore.RESET}")
            raise

    def scan_device(self, ip, ports=None, gentle=False):
        """
        Escaneo profundo:
          - Pase 1: TCP top-10000 puertos nmap (--top-ports 10000) con -sV/-O.
          - Pase 2: IOT_EXTENDED_PORTS que no estén ya cubiertos (por si alguno
                    esotérico como BACnet 47808 no entra en el top-10k).
          - Pase 3: UDP IoT (solo root).
        Si ports= explícito → se usa ese rango directo (un solo pase).

        gentle=True activa un **perfil suave** para dispositivos frágiles (p. ej.
        ESP8266/lwIP, con ~5 sockets TCP): limita el ritmo de paquetes
        (`--max-rate`), baja el paralelismo y los reintentos, acota la duración
        (`--host-timeout`) y aligera la detección de versión. Evita saturar el
        stack del objetivo (que se cuelga y devuelve 0 puertos falsos), en línea
        con la filosofía del SafetyMonitor de proteger al dispositivo auditado.
        """
        # Seleccionar argumentos según privilegios del sistema
        is_root = os.geteuid() == 0
        if gentle:
            # Perfil suave: ritmo limitado, sin --version-all, con timeout de host.
            if is_root:
                scan_args = ('-sS -sV --version-intensity 2 -O --osscan-guess '
                             '-T2 --max-retries 1 --max-rate 100 --host-timeout 180s -Pn -n')
            else:
                scan_args = ('-sT -sV --version-intensity 2 '
                             '-T2 --max-retries 1 --max-rate 100 --host-timeout 180s -Pn -n')
            logger.info("[RECON] Perfil SUAVE (objetivo frágil): ritmo limitado "
                        "(--max-rate 100, -T2), sin --version-all, host-timeout 180s")
        elif is_root:
            scan_args = '-sS -sV --version-intensity 7 --version-all -O --osscan-guess -T4 -Pn -n'
        else:
            scan_args = '-sT -sV --version-intensity 5 -T3 -Pn -n'
            logger.warning("[RECON] Sin root: usando TCP connect scan (sin OS/MAC detection)")

        fallback_args = '-sT -sV -T3 -Pn -n' + (' --max-rate 100 --host-timeout 180s' if gentle else '')

        # ---------------- Pase 1: TCP principal ----------------
        if ports is None:
            primary_args = scan_args + ' --top-ports 10000'
            primary_ports = None  # nmap decide (top-10000)
            scan_label = "TOP-10000 TCP + IOT EXTENDED"
        else:
            primary_args = scan_args
            primary_ports = ports
            scan_label = f"RANGO {ports}"

        logger.info(f"[RECON] Escaneando {ip} ({scan_label})")
        print(f"{Fore.BLUE}[RECON] Fingerprinting ({scan_label}) en {ip}...{Fore.RESET}")

        try:
            self.nm.scan(ip, ports=primary_ports, arguments=primary_args)
            logger.debug(f"[RECON] Escaneo primario exitoso para {ip}")
        except Exception as e:
            logger.warning(f"[RECON] Escaneo primario falló, intentando fallback: {e}")
            try:
                fb_args = fallback_args + (' --top-ports 10000' if ports is None else '')
                self.nm.scan(ip, ports=primary_ports, arguments=fb_args)
            except Exception as e2:
                logger.error(f"[RECON] Error en escaneo: {e2}", exc_info=True)
                return None

        # El pase primario puede "tener éxito" para python-nmap (sin excepción)
        # y aun así NO encontrar el host: ocurre cuando `-sS` no logra abrir el
        # device de red (host con varios bridges Docker → "dnet: Failed to open
        # device br-..."). En ese caso nmap devuelve vacío en vez de lanzar. Como
        # el `except` de arriba no se dispara, hay que reintentar aquí con
        # connect-scan `-sT`, que NO usa raw sockets y sobrevive a ese fallo.
        if ip not in self.nm.all_hosts() and '-sT' not in primary_args:
            fb_args = fallback_args + (' --top-ports 10000' if ports is None else '')
            logger.warning(
                f"[RECON] pase primario sin host {ip} (posible fallo de raw-socket "
                f"en -sS); reintento con connect-scan -sT")
            try:
                self.nm.scan(ip, ports=primary_ports, arguments=fb_args)
            except Exception as e:
                logger.error(f"[RECON] fallback -sT falló: {e}", exc_info=True)

        # --- Procesamiento de resultados (Tu lógica original optimizada) ---
        if ip not in self.nm.all_hosts(): return None
        raw_data = self.nm[ip]

        # Extraer MAC y OS de forma segura
        mac_address = raw_data.get('addresses', {}).get('mac')
        os_match = "Unknown"
        os_cpe = None
        if raw_data.get('osmatch'):
            os_match = raw_data['osmatch'][0].get('name', 'Unknown')
            # `or [...]` cubre tanto la clave ausente como la lista vacía:
            # dispositivos IoT (p. ej. Espressif/ESP) hacen OS-match sin CPE
            # (`'cpe': []`), y `.get('cpe', [None])[0]` reventaba con IndexError.
            os_class = (raw_data['osmatch'][0].get('osclass') or [{}])[0]
            os_cpe = (os_class.get('cpe') or [None])[0]

        results = {
            'ip': ip,
            'mac': mac_address,
            'status': raw_data.state(),
            'os_match': os_match,
            'os_cpe': os_cpe,
            'ports': [] 
        }

        for proto in self.nm[ip].all_protocols():
            for port, service in raw_data[proto].items():
                if service.get('state') != 'open': continue

                results['ports'].append({
                    'port': port,
                    'protocol': proto,
                    'service_name': service.get('name', 'unknown'),
                    'product': service.get('product', ''),
                    'version': service.get('version', ''),
                    'cpe': (service.get('cpe') or [None])[0] if isinstance(service.get('cpe'), list) else service.get('cpe', ''),
                    'script_output': service.get('script', {})
                })

        # --- Pase 2: IoT extras no cubiertos por el top-10000 ---
        if ports is None:
            seen_tcp = {p['port'] for p in results['ports'] if p['protocol'] == 'tcp'}
            extras = [pt for pt in self.IOT_EXTENDED_PORTS if pt not in seen_tcp]
            if extras:
                extras_str = ",".join(map(str, extras))
                extras_args = scan_args  # sin --top-ports, con -sV/-O
                logger.info(f"[RECON] Pase extras IoT TCP {ip} puertos={extras_str}")
                try:
                    self.nm.scan(ip, ports=extras_str, arguments=extras_args)
                    if ip in self.nm.all_hosts():
                        extras_raw = self.nm[ip]
                        for port, svc in extras_raw.get('tcp', {}).items():
                            if svc.get('state') != 'open':
                                continue
                            if any(p['port'] == port and p['protocol'] == 'tcp' for p in results['ports']):
                                continue
                            results['ports'].append({
                                'port': port,
                                'protocol': 'tcp',
                                'service_name': svc.get('name', 'unknown'),
                                'product': svc.get('product', ''),
                                'version': svc.get('version', ''),
                                'cpe': (svc.get('cpe') or [None])[0] if isinstance(svc.get('cpe'), list) else svc.get('cpe', ''),
                                'script_output': svc.get('script', {}),
                            })
                except Exception as e:
                    logger.debug(f"[RECON] Pase extras IoT omitido: {e}")

        # --- Pase UDP (solo root). open|filtered cuenta como "posible abierto" ---
        if is_root:
            try:
                udp_ports_str = ",".join(map(str, self.IOT_UDP_PORTS))
                udp_args = '-sU --version-intensity 3 -T4 -Pn -n --max-retries 1 --host-timeout 45s'
                logger.info(f"[RECON] Escaneo UDP {ip} puertos={udp_ports_str}")
                self.nm.scan(ip, ports=f"U:{udp_ports_str}", arguments=udp_args)
                if ip in self.nm.all_hosts():
                    udp_raw = self.nm[ip]
                    for port, svc in udp_raw.get('udp', {}).items():
                        state = svc.get('state', '')
                        if state not in ('open', 'open|filtered'):
                            continue
                        # Evitar duplicados si ya estaba en TCP
                        if any(p['port'] == port and p['protocol'] == 'udp' for p in results['ports']):
                            continue
                        results['ports'].append({
                            'port': port,
                            'protocol': 'udp',
                            'service_name': svc.get('name', 'unknown'),
                            'product': svc.get('product', ''),
                            'version': svc.get('version', ''),
                            'cpe': (svc.get('cpe') or [None])[0] if isinstance(svc.get('cpe'), list) else svc.get('cpe', ''),
                            'script_output': svc.get('script', {}),
                            'state_confidence': state,  # open vs open|filtered
                        })
            except Exception as e:
                logger.debug(f"[RECON] UDP pass omitido: {e}")
        else:
            logger.debug("[RECON] Skip UDP scan — requiere root")

        n_open = len(results['ports'])
        if n_open:
            detail = ", ".join(
                f"{p['port']}/{p['protocol']}"
                + (f" ({p['service_name']})" if p.get('service_name') and p['service_name'] != 'unknown' else "")
                for p in sorted(results['ports'], key=lambda x: (x['protocol'], x['port']))
            )
            logger.success(f"[RECON] Escaneo completado: {n_open} puertos abiertos → {detail}")
        else:
            logger.success(f"[RECON] Escaneo completado: 0 puertos abiertos")
        return results