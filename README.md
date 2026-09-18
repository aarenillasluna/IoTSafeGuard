# IoTSafeGuard-Agent

Agente autónomo de pentesting para dispositivos IoT. Un LLM (Claude, directo o
vía Amazon Bedrock) conduce el ciclo completo de auditoría —reconocimiento,
fingerprinting, búsqueda de CVEs, verificación y reporte— sobre un catálogo de
herramientas deterministas, con el bucle estándar de *tool use*.

**Instalación desde cero: [`INSTALL.md`](INSTALL.md).**

> Ejecuta reconocimiento activo y comandos ofensivos contra el objetivo que se
> le indique. Úsalo solo contra dispositivos propios o con autorización
> escrita. El laboratorio Docker incluido existe para poder probarlo todo sin
> salir de tu máquina.

---

## Arranque rápido

```bash
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp .env.example .env                        # rellena ANTHROPIC_API_KEY
docker compose -f docker-compose.iot-lab.yml up -d
./venv/bin/python run.py --target 172.30.0.10 --auto --no-safety
```

Los informes salen en `reports/`, en cuatro formatos más un `*_pocs.sh` con los
comandos reproducibles.

Dashboard web (opcional):

```bash
npm run install:all && npm run dev          # UI en :5173, API en :8000
```

---

## Qué hace

- **Catálogo de 45 herramientas** deterministas: escaneo, interrogación HTTP,
  sondas raw-socket para Modbus, RTSP, BACnet, CWMP, Telnet, UPnP, OPC-UA,
  TFTP, MQTT, mDNS, CoAP, SSH, FTP, SMB, DNS, LG WebOS, DIAL, Chromecast,
  SOCKS5 y miio.
- **Fases** — el agente alterna `recon` y `exploit` con `transition_phase`;
  cada fase carga su prompt y su subconjunto de tools.
- **PolicyEngine** activo por defecto: allowlist por binario, validación de
  flags *y de operandos*, sin `shell=True`. `--no-policy` lo desactiva (modo
  investigación) y lo anuncia en la primera línea del log.
- **SafetyMonitor** — presupuesto de peticiones/minuto, sonda de salud
  (ICMP con fallback TCP) y kill-switch por degradación o incomunicación.
- **Gobernanza de severidad determinista** — techo canónico por tipo de
  hallazgo, tope por clase de impacto declarada y cap de alcanzabilidad.
  Reafirmar que un servicio está expuesto no cuenta como vulnerabilidad
  confirmada: eso ya lo dice la tabla de puertos abiertos.
- **Identificadores canónicos de hallazgo** — el mismo hecho recibe el mismo id
  en cada ejecución, que es lo que permite correlacionar entre auditorías.
- **El informe se guarda pase lo que pase** — `done()` es una de las once
  formas de terminar el bucle; en las otras diez (presupuesto, reloj, 429,
  `Ctrl+C`, `SIGTERM`, apagón) el artefacto se rescata igual y declara su
  desenlace, para que un run interrumpido no se confunda con uno completo.
- **Knowledge Base persistente** (`data/kb.json`) — qué sondas son útiles por
  fabricante, qué CVEs salen consistentemente parcheados, qué aparatos ya se
  auditaron. La identidad es `vendor + modelo + MAC`, nunca la IP.
- **Reflexión post-run** y **observabilidad Langfuse** opcional.

---

## Estructura

```
run.py                        CLI: valida el modelo e instancia el agente
core/                         Plano de razonamiento y gobernanza
  claude_agent.py             Bucle de tool use (Anthropic / Bedrock)
  base_agent.py               Contrato BaseReActAgent + rescate del informe
  tools.py                    Registro y despacho del catálogo de tools
  policy_engine.py            Allowlist de binarios, flags y operandos
  safety_monitor.py           Presupuesto, sonda de salud y kill-switch
  severity.py                 Gobernanza de severidad
  finding_ids.py              Canonización de identificadores de hallazgo
  knowledge_base.py           Memoria entre auditorías
  agent_guards.py             Detectores de repetición, ciclo y esterilidad
  observability.py            Instrumentación Langfuse (no-op sin claves)
  reflection.py               Análisis post-run y propagación a la KB
  telemetry.py  mitre_attack.py  prompts.py  fsutil.py
modules/                      Sondas y reporte
  recon.py  discovery.py  interrogator.py  fingerprint.py
  iot_probes.py  packet_probes.py  mqtt_probes.py  snmp_probe.py  hnap.py
  cve_api.py  cve_pocs.py  searcher.py  exploiter.py  remediation_kb.py
  reporter.py                 JSON · Markdown · HTML · SARIF · bash de PoCs
api/                          Backend FastAPI del dashboard
frontend/                     UI React + Vite
lab/                          Configs del lab Docker + ground_truth.yml
prompts/                      Prompts de planner, recon y exploit
scripts/                      Arneses de evaluación y utilidades de entorno
tests/                        Suite (1269 pruebas)
```

---

## Comandos habituales

| Qué | Comando |
|---|---|
| Auditar un objetivo | `sudo ./venv/bin/python run.py --target <ip>` |
| Auditar el lab | `./venv/bin/python run.py --target 172.30.0.10 --auto --no-safety` |
| Suite de pruebas | `./venv/bin/python -m pytest -q` |
| Levantar el lab | `docker compose -f docker-compose.iot-lab.yml up -d` |
| Dashboard | `npm run dev` |
| Langfuse arriba/abajo | `npm run langfuse:up` · `npm run langfuse:down` |
| P/R/F1 contra el lab | `./venv/bin/python scripts/lab_scoring.py reports/<informe>.json` |
| Varianza entre réplicas | `./venv/bin/python scripts/variance_harness.py --min-runs 5` |
| Línea base con nmap+NSE | `sudo ./scripts/tanda.sh baseline <ip>` |
| Estado de la tanda actual | `./scripts/tanda.sh estado` |

`sudo` hace falta en las auditorías reales porque nmap necesita privilegios
para leer la MAC, y la MAC es lo que sostiene la identidad del dispositivo.
Contra el lab Docker no hace falta.

---

## Configuración

Todo vive en `.env` (copia de `.env.example`, que documenta **todas** las
variables que el código lee de verdad). Lo mínimo es una clave de modelo:
`ANTHROPIC_API_KEY`, o `AWS_BEARER_TOKEN_BEDROCK` + `AWS_DEFAULT_REGION` para
la vía Bedrock. `NVD_API_KEY` es opcional pero muy recomendable.

Para Langfuse self-host, `.env.langfuse` (copia de `.env.langfuse.example`).
Detalles en [`INSTALL.md`](INSTALL.md) §3 y §5.
