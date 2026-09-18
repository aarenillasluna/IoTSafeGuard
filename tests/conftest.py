"""Configuración común de la suite.

La regla que impone este fichero: **ninguna prueba escribe en los directorios
de evidencia del proyecto**. `reports/` no es una carpeta de trabajo, es el
material del que salen las cifras del Capítulo 5, y `data/kb.json` es la
memoria entre auditorías.
"""
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _no_escribir_en_reports(tmp_path, monkeypatch):
    """Redirige el destino por defecto de `save_report` a un temporal.

    `_save_report` toma `out_dir` de sus argumentos y cae en `"reports"` si no
    se lo dan. Casi todas las pruebas pasan `out_dir`, pero no hace falta que
    falle una: basta con ejercitar una rama del agente que llame a la
    herramienta sin argumentos. Eso es exactamente lo que hacía la prueba del
    bloqueo por SAFETY del agente, y cada pasada de la suite dejaba dos informes
    de mentira —`10.0.0.1` y `127.0.0.1`, cero puertos, un hallazgo— en la
    carpeta de evidencias.

    No era ruido inofensivo. El arnés de varianza lee esa carpeta, y con 24
    artefactos acumulados informaba de «53 ejecuciones en 5 dispositivos»
    cuando las reales eran 30 en 3: dos dispositivos inventados, con sus
    desviaciones típicas, listos para acabar en una tabla de la memoria.

    El parche va en el valor por defecto, no en la prueba concreta: quien
    escriba mañana otra rama que llame a `save_report` sin `out_dir` no tiene
    por qué acordarse de esto.
    """
    # Nombre deliberadamente raro: `tmp_path/"reports"` es el que varias
    # pruebas crean por su cuenta, y un fixture automático no puede pelearse
    # con ellas por el mismo directorio.
    destino = tmp_path / "_reports_aislados"
    destino.mkdir(exist_ok=True)
    try:
        from core import tools as toolbox
    except ImportError:  # pragma: no cover
        return
    original = toolbox._save_report

    def _save_report_aislado(args):
        args = dict(args or {})
        args.setdefault("out_dir", str(destino))
        return original(args)

    monkeypatch.setattr(toolbox, "_save_report", _save_report_aislado)
    tool = toolbox._REGISTRY.get("save_report")
    if tool is not None:
        monkeypatch.setattr(tool, "impl", _save_report_aislado)
