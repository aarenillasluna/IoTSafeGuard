"""
Limpieza puntual de la KB: elimina clasificaciones de vendor que fueron
introducidas por la heurística buggy anterior (substring matching sin word
boundaries — `LG` matcheaba dentro de `algoritmo`, etc.).

Uso (desde la raíz del repo, KB pertenece a root tras runs con sudo):
    sudo ./venv/bin/python scripts/clean_kb_stale_vendor.py --ip 192.168.1.1

Sin --ip lista los devices y vendors actuales para revisión manual.
Con --ip <ip> borra el campo `vendor` del device y opcionalmente, con
--purge-vendor-profile <name>, elimina el vendor_profile entero.

El script no escribe nada en modo `--dry-run` (default true salvo
`--apply`).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

DEFAULT_KB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "kb.json",
)


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_atomic(path: str, data: dict) -> None:
    dirname = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=dirname,
        prefix=".kb_", suffix=".tmp", delete=False,
    ) as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        tmp = f.name
    os.replace(tmp, path)


def _summary(kb: dict) -> None:
    devs = kb.get("devices_seen", {})
    profs = kb.get("vendor_profiles", {})
    print(f"Devices ({len(devs)}):")
    for ip, dev in devs.items():
        print(f"  {ip:15}  vendor={dev.get('vendor')!r:15}  "
              f"model={dev.get('model')!r}  firmware={dev.get('firmware')!r}")
    print(f"\nVendor profiles ({len(profs)}):")
    for v, prof in profs.items():
        print(f"  {v:15}  devices={prof.get('device_count', 0)}  "
              f"patched_cves={len(prof.get('patched_cves', []))}  "
              f"useful_probes={len(prof.get('useful_probes', []))}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--kb", default=DEFAULT_KB, help="Ruta del kb.json")
    p.add_argument("--ip", help="IP cuyo campo vendor borrar")
    p.add_argument("--purge-vendor-profile", metavar="NAME",
                   help="Borra el vendor_profile entero (e.g. 'TP-Link')")
    p.add_argument("--apply", action="store_true",
                   help="Aplica los cambios; sin esto es dry-run.")
    args = p.parse_args()

    if not os.path.exists(args.kb):
        print(f"[ERROR] no existe {args.kb}", file=sys.stderr)
        return 1

    kb = _load(args.kb)

    if not args.ip and not args.purge_vendor_profile:
        _summary(kb)
        return 0

    changed = False
    if args.ip:
        dev = kb.get("devices_seen", {}).get(args.ip)
        if dev and dev.get("vendor"):
            old = dev["vendor"]
            print(f"[device] {args.ip}: vendor {old!r} → None")
            if args.apply:
                dev["vendor"] = None
            changed = True
        elif dev:
            print(f"[device] {args.ip}: ya no tiene vendor — no-op")
        else:
            print(f"[device] {args.ip}: no encontrado en KB")

    if args.purge_vendor_profile:
        name = args.purge_vendor_profile
        if name in kb.get("vendor_profiles", {}):
            prof = kb["vendor_profiles"][name]
            print(f"[vendor_profile] borrando '{name}' "
                  f"(device_count={prof.get('device_count', 0)}, "
                  f"patched_cves={len(prof.get('patched_cves', []))})")
            if args.apply:
                del kb["vendor_profiles"][name]
            changed = True
        else:
            print(f"[vendor_profile] '{name}' no existe en KB")

    if not changed:
        print("Sin cambios.")
        return 0

    if not args.apply:
        print("\nDRY-RUN. Re-ejecuta con --apply para escribir.")
        return 0

    _save_atomic(args.kb, kb)
    print(f"\n✓ Guardado {args.kb}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
