#!/bin/bash
###############################################################################
#
# 🔧 SCRIPT DE CORRECCIÓN: Python 3.9+ Opcodes para Odoo 12
#
# Propósito: Agregar opcodes de Python 3.9+ a safe_eval.py de Odoo 12
# Problema:  Python 3.9.2 usa CONTAINS_OP y LIST_EXTEND que Odoo 12 bloquea
# Solución:  Parchear safe_eval.py para permitir estos opcodes
#
# Autor: Ingeniero Senior Odoo
# Fecha: 3 de noviembre de 2025
#
###############################################################################

set -e

CONTAINER_NAME="prod_odoo-12-GR_web"
SAFE_EVAL_PATH="/usr/lib/python3/dist-packages/odoo/tools/safe_eval.py"
BACKUP_PATH="/tmp/safe_eval.py.backup_$(date +%Y%m%d_%H%M%S)"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔧 CORRECCIÓN: Python 3.9+ Opcodes para Odoo 12"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Verificar que el contenedor esté corriendo
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ Error: El contenedor $CONTAINER_NAME no está corriendo"
    exit 1
fi

echo "✅ Contenedor encontrado: $CONTAINER_NAME"
echo ""

# 1. Crear backup del archivo original
echo "📦 Creando backup de safe_eval.py..."
docker exec "$CONTAINER_NAME" cp "$SAFE_EVAL_PATH" "$BACKUP_PATH"
echo "   Backup guardado en: $BACKUP_PATH"
echo ""

# 2. Verificar si ya está parcheado
echo "🔍 Verificando si ya está parcheado..."
if docker exec "$CONTAINER_NAME" grep -q "CONTAINS_OP" "$SAFE_EVAL_PATH"; then
    echo "⚠️  El archivo ya contiene CONTAINS_OP, posiblemente ya está parcheado"
    read -p "¿Desea continuar de todas formas? (s/N): " continuar
    if [[ ! "$continuar" =~ ^[sS]$ ]]; then
        echo "❌ Operación cancelada"
        exit 0
    fi
fi

# 3. Aplicar el parche
echo "🔧 Aplicando parche para Python 3.9+ opcodes..."
echo ""

docker exec "$CONTAINER_NAME" python3 << 'PYTHON_SCRIPT'
import re

safe_eval_path = "/usr/lib/python3/dist-packages/odoo/tools/safe_eval.py"

# Leer el archivo
with open(safe_eval_path, 'r') as f:
    content = f.read()

# Buscar la sección _SAFE_OPCODES
# Patrón para encontrar la lista de opcodes seguros
pattern = r"(_SAFE_OPCODES\s*=\s*opcodes\([^\)]+)\)"

def add_opcodes(match):
    opcodes_section = match.group(1)
    
    # Verificar si ya están agregados
    if 'CONTAINS_OP' in opcodes_section or 'LIST_EXTEND' in opcodes_section:
        print("⚠️  Los opcodes ya están presentes en el archivo")
        return match.group(0)
    
    # Agregar los nuevos opcodes antes del cierre
    new_opcodes = """
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔧 PARCHE: Python 3.9+ Opcodes (agregados para compatibilidad)
    # Fecha: 3 de noviembre de 2025
    # Razón: Odoo 12 corriendo en Python 3.9.2
    # Impacto: Permite operaciones 'in' y list extend en QWeb templates
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    'CONTAINS_OP',      # Python 3.9+: operador 'in' (ej: 'x' in obj)
    'LIST_EXTEND',      # Python 3.9+: extend de listas
    'LIST_TO_TUPLE',    # Python 3.9+: conversión list a tuple
    'IS_OP',            # Python 3.9+: operador 'is'
    'DICT_MERGE',       # Python 3.9+: merge de diccionarios
    'DICT_UPDATE',      # Python 3.9+: update de diccionarios
"""
    
    return opcodes_section + new_opcodes + "\n)"

# Aplicar el reemplazo
new_content = re.sub(pattern, add_opcodes, content, count=1)

if new_content == content:
    print("❌ No se pudo encontrar la sección _SAFE_OPCODES")
    print("   El archivo puede tener un formato diferente")
    exit(1)

# Escribir el archivo modificado
with open(safe_eval_path, 'w') as f:
    f.write(new_content)

print("✅ Parche aplicado correctamente")
print("")
print("Opcodes agregados:")
print("  • CONTAINS_OP     → Permite 'x' in objeto")
print("  • LIST_EXTEND     → Permite list.extend()")
print("  • LIST_TO_TUPLE   → Permite tuple(list)")
print("  • IS_OP           → Permite operador 'is'")
print("  • DICT_MERGE      → Permite dict | dict")
print("  • DICT_UPDATE     → Permite dict.update()")

PYTHON_SCRIPT

if [ $? -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ✅ PARCHE APLICADO EXITOSAMENTE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "📋 PRÓXIMOS PASOS:"
    echo ""
    echo "1. Reiniciar el contenedor Odoo:"
    echo "   docker restart $CONTAINER_NAME"
    echo ""
    echo "2. Verificar los logs:"
    echo "   docker logs -f $CONTAINER_NAME"
    echo ""
    echo "3. Probar el acceso web:"
    echo "   http://localhost:8269"
    echo ""
    echo "💾 Backup guardado en:"
    echo "   $BACKUP_PATH"
    echo ""
    echo "🔄 Para revertir (si es necesario):"
    echo "   docker exec $CONTAINER_NAME cp $BACKUP_PATH $SAFE_EVAL_PATH"
    echo "   docker restart $CONTAINER_NAME"
    echo ""
else
    echo ""
    echo "❌ Error al aplicar el parche"
    echo ""
    echo "🔄 Restaurando backup..."
    docker exec "$CONTAINER_NAME" cp "$BACKUP_PATH" "$SAFE_EVAL_PATH"
    echo "✅ Backup restaurado"
    exit 1
fi
