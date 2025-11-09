#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Escáner de manifests de Odoo Enterprise.
- Recorre un árbol (por defecto ./addons/enterprise)
- Extrae metadatos de __manifest__.py usando ast.literal_eval de forma segura
- Emite:
  * reports/enterprise_catalog.json
  * reports/enterprise_catalog.csv
  * reports/enterprise_dependencies.dot (grafo de dependencias)
Uso:
  python3 tools/scan_enterprise.py --root . --enterprise addons/enterprise --out reports
"""
import argparse
import ast
import csv
import json
import os
from pathlib import Path


def find_manifest_paths(base: Path):
    for root, dirs, files in os.walk(base):
        if '__manifest__.py' in files:
            yield Path(root) / '__manifest__.py'


def parse_manifest(manifest_path: Path):
    text = manifest_path.read_text(encoding='utf-8')
    # Intento robusto: localizar el primer '{' y el último '}'
    start = text.find('{')
    end = text.rfind('}')
    if start == -1 or end == -1:
        raise ValueError(f"No se encontró un dict literal en {manifest_path}")
    payload = text[start:end+1]
    try:
        data = ast.literal_eval(payload)
    except Exception as e:
        raise ValueError(f"Error al parsear {manifest_path}: {e}")
    if not isinstance(data, dict):
        raise ValueError(f"El manifest no es un dict en {manifest_path}")
    return data


def to_row(module_name: str, rel_dir: str, m: dict):
    return {
        'module': module_name,
        'path': rel_dir,
        'name': m.get('name'),
        'summary': m.get('summary'),
        'version': m.get('version'),
        'category': m.get('category'),
        'depends': ','.join(m.get('depends', []) or []),
        'auto_install': m.get('auto_install'),
        'application': m.get('application'),
        'license': m.get('license'),
        'has_qweb': bool(m.get('qweb')),
        'has_data': bool(m.get('data')),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.', help='Directorio raíz del workspace')
    ap.add_argument('--enterprise', default='addons/enterprise', help='Ruta relativa a la carpeta enterprise')
    ap.add_argument('--out', default='reports', help='Directorio de salida para los reportes')
    args = ap.parse_args()

    root = Path(args.root).resolve()
    ent = (root / args.enterprise).resolve()
    out = (root / args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    manifests = list(find_manifest_paths(ent))
    catalog = []
    deps_edges = []  # (from, to)

    for mp in sorted(manifests):
        rel_dir = str(mp.parent.relative_to(root))
        module_name = mp.parent.name
        try:
            m = parse_manifest(mp)
        except Exception as e:
            # Registrar error como fila con nota
            catalog.append({
                'module': module_name,
                'path': rel_dir,
                'name': None,
                'summary': f'ERROR: {e}',
                'version': None,
                'category': None,
                'depends': None,
                'auto_install': None,
                'application': None,
                'license': None,
                'has_qweb': None,
                'has_data': None,
            })
            continue

        row = to_row(module_name, rel_dir, m)
        catalog.append(row)

        depends = m.get('depends', []) or []
        for dep in depends:
            deps_edges.append((module_name, dep))

    # Salidas
    json_path = out / 'enterprise_catalog.json'
    csv_path = out / 'enterprise_catalog.csv'
    dot_path = out / 'enterprise_dependencies.dot'

    with json_path.open('w', encoding='utf-8') as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)

    with csv_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(catalog[0].keys()) if catalog else [])
        writer.writeheader()
        for row in catalog:
            writer.writerow(row)

    # Grafo DOT (dirigido)
    with dot_path.open('w', encoding='utf-8') as f:
        f.write('digraph enterprise_deps {\n')
        f.write('  rankdir=LR;\n')
        # Nodos (módulos enterprise)
        for row in catalog:
            mod = row['module']
            label = row['module']
            f.write(f'  "{mod}" [shape=box,label="{label}"];\n')
        # Aristas de dependencia
        for a, b in deps_edges:
            f.write(f'  "{a}" -> "{b}";\n')
        f.write('}\n')

    print(f"OK: {len(catalog)} módulos inventariados.\n- {json_path}\n- {csv_path}\n- {dot_path}")


if __name__ == '__main__':
    main()
