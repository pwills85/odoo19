#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE_PATH="$ROOT_DIR/addons/localization/l10n_cl_financial_reports"

if [[ ! -d "$MODULE_PATH" ]]; then
    echo "[ERROR] No se encontró el módulo en $MODULE_PATH" >&2
    exit 1
fi

printf '\n[1/3] Revisando sintaxis Python...\n'
MODULE_DIR="$MODULE_PATH" python <<'PY'
import pathlib
import sys

module_dir = pathlib.Path(__import__('os').environ['MODULE_DIR'])
errors = []
for py_file in module_dir.rglob('*.py'):
    try:
        compile(py_file.read_text(), str(py_file), 'exec')
    except SyntaxError as exc:
        errors.append(f"{py_file}:{exc.lineno} {exc.msg}")

if errors:
    for err in errors:
        print(f"[syntax] {err}", file=sys.stderr)
    sys.exit(1)
PY

status=0
INIT_FILE="$MODULE_PATH/models/__init__.py"
if ! grep -q "from \\. import core" "$INIT_FILE"; then
    echo "[P0] Falta importar el paquete core en models/__init__.py" >&2
    status=1
fi
if ! grep -q "from \\. import services" "$INIT_FILE"; then
    echo "[P0] Falta importar el paquete services en models/__init__.py" >&2
    status=1
fi

printf '\n[2/3] Validando campos y métodos críticos de F29...\n'
F29_PATH="$MODULE_PATH/models/l10n_cl_f29.py" python <<'PY'
import ast
import pathlib
import sys

path = pathlib.Path(__import__('os').environ['F29_PATH'])
module = ast.parse(path.read_text())
klass = None
for node in module.body:
    if isinstance(node, ast.ClassDef) and node.name == 'L10nClF29':
        klass = node
        break

if not klass:
    print('[P0] No se encontró la clase L10nClF29 en', path, file=sys.stderr)
    sys.exit(1)

fields = set()
methods = set()
for item in klass.body:
    if isinstance(item, ast.Assign):
        for target in item.targets:
            if isinstance(target, ast.Name):
                fields.add(target.id)
    elif isinstance(item, ast.FunctionDef):
        methods.add(item.name)

required_fields = {
    'period_string', 'ventas_gravadas', 'ventas_exentas', 'ventas_total',
    'iva_debito', 'compras_gravadas', 'compras_exentas', 'compras_total',
    'iva_credito', 'move_ids', 'provision_move_id'
}
required_methods = {
    'action_send_sii', 'action_check_status', 'action_replace', 'create_monthly_f29'
}

missing_fields = sorted(required_fields - fields)
missing_methods = sorted(required_methods - methods)

ok = True
if missing_fields:
    print('[P0] Campos faltantes en l10n_cl.f29:', ', '.join(missing_fields), file=sys.stderr)
    ok = False
if missing_methods:
    print('[P0] Métodos faltantes en l10n_cl.f29:', ', '.join(missing_methods), file=sys.stderr)
    ok = False

if not ok:
    sys.exit(1)
PY
if [[ $? -ne 0 ]]; then
    status=1
fi

printf '\n[3/3] Revisando cron F29/F22...\n'
if ! grep -q "create_monthly_f29" "$MODULE_PATH/models/l10n_cl_f29.py"; then
    echo "[P0] create_monthly_f29 no está implementado" >&2
    status=1
fi

if [[ $status -ne 0 ]]; then
    echo -e '\nValidación terminada con errores (ver mensajes anteriores).' >&2
    exit $status
fi

echo -e '\nValidación rápida completada sin errores críticos.'
