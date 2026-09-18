"""IoTSafeGuard dashboard backend (FastAPI).

Lee la KB y los reportes existentes del agente y expone una API HTTP/WS
que el frontend (React + Vite) consume. Diseñado para correr como root
junto al agente (mismo trust boundary que `sudo run.py`).
"""
