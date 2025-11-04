#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Análisis de Contactos Problemáticos en CSV
==========================================
"""

import csv
import re

print("=" * 100)
print("  🔍 ANÁLISIS DE CONTACTOS PROBLEMÁTICOS EN CSV")
print("=" * 100)

# Leer CSV
stats = {
    'total': 0,
    'with_parent': 0,
    'invalid_name': 0,
    'not_customer_supplier': 0,
    'only_symbol': 0,
    'only_number': 0,
    'empty_name': 0,
    'valid': 0,
}

invalid_examples = []

with open('/tmp/partners_full_export_20251025_014753.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)

    for row in reader:
        stats['total'] += 1
        name = row.get('name', '').strip()
        parent_id = row.get('parent_id', '').strip()
        is_customer = row.get('customer', '') == 't'
        is_supplier = row.get('supplier', '') == 't'

        is_invalid = False

        # Check parent_id (child contacts)
        if parent_id:
            stats['with_parent'] += 1
            is_invalid = True
            if len(invalid_examples) < 5:
                invalid_examples.append(('CHILD_CONTACT', name, parent_id, row.get('id')))

        # Check invalid names
        if name in ['@', '.', '-', '']:
            stats['only_symbol'] += 1
            is_invalid = True
            if len(invalid_examples) < 10:
                invalid_examples.append(('SYMBOL_NAME', name or '(vacío)', '', row.get('id')))

        # Check if name is only a number
        if name.replace('+', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', '').isdigit():
            stats['only_number'] += 1
            is_invalid = True
            if len(invalid_examples) < 15:
                invalid_examples.append(('NUMBER_NAME', name, '', row.get('id')))

        # Check if empty name
        if not name:
            stats['empty_name'] += 1
            is_invalid = True

        # Check if not customer and not supplier
        if not is_customer and not is_supplier:
            stats['not_customer_supplier'] += 1

        if is_invalid:
            stats['invalid_name'] += 1
        else:
            stats['valid'] += 1

print(f"\n📊 ESTADÍSTICAS DEL CSV")
print("─" * 100)
print(f"  Total registros:                    {stats['total']:,}")
print(f"  Registros válidos para importar:    {stats['valid']:,} ({stats['valid']*100//stats['total']}%)")
print(f"  Registros INVÁLIDOS:                {stats['invalid_name']:,} ({stats['invalid_name']*100//stats['total']}%)")
print()
print(f"  Problemas detectados:")
print(f"  ├─ Child contacts (parent_id):      {stats['with_parent']:,}")
print(f"  ├─ Nombre solo símbolo (@, ., -):   {stats['only_symbol']:,}")
print(f"  ├─ Nombre solo número/teléfono:     {stats['only_number']:,}")
print(f"  ├─ Nombre vacío:                    {stats['empty_name']:,}")
print(f"  └─ Ni cliente ni proveedor:         {stats['not_customer_supplier']:,}")

print(f"\n📋 EJEMPLOS DE CONTACTOS INVÁLIDOS (primeros 15)")
print("─" * 100)
print(f"  {'Tipo':<20} {'Nombre':<40} {'Parent ID':<12} {'ID Odoo 11':<12}")
print("  " + "─" * 96)

for tipo, nombre, parent, id_odoo in invalid_examples:
    print(f"  {tipo:<20} {nombre[:38]:<40} {parent:<12} {id_odoo:<12}")

print("\n" + "=" * 100)
