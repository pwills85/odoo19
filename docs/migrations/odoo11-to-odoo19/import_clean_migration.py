#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Importación LIMPIA de Contactos desde CSV (Odoo 11 → Odoo 19)
==============================================================

VERSION MEJORADA con filtros para excluir contactos basura:
- Child contacts (parent_id != NULL)
- Nombres inválidos (@, ., números, vacíos)
- Solo importa clientes O proveedores

Ejecutar:
    docker-compose exec odoo odoo shell -d TEST --no-http < addons/localization/l10n_cl_dte/scripts/import_clean_migration.py
"""

import csv
import re
from datetime import datetime

print("=" * 100)
print("  MIGRACIÓN LIMPIA: Contactos Odoo 11 CE → Odoo 19 CE (FILTRADA)")
print("=" * 100)
print(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 100)

# Mapeo Provincia → Región (completo)
PROVINCIA_TO_REGION = {
    1: 1, 2: 1,  # XV
    3: 2, 4: 2,  # I
    5: 3, 6: 3, 7: 3,  # II
    8: 4, 9: 4, 10: 4,  # III
    11: 5, 12: 5, 13: 5,  # IV
    14: 6, 15: 6, 16: 6, 17: 6, 18: 6, 19: 6, 20: 6, 21: 6,  # V
    22: 7, 23: 7, 24: 7, 25: 7, 26: 7, 27: 7,  # XIII
    28: 8, 29: 8, 30: 8,  # VI
    31: 9, 32: 9, 33: 9, 34: 9,  # VII
    35: 16, 36: 16, 37: 16,  # XVI
    38: 10, 39: 10, 40: 10,  # VIII
    41: 11, 42: 11,  # IX
    43: 12, 44: 12,  # XIV
    45: 13, 46: 13, 47: 13, 48: 13,  # X
    49: 14, 50: 14, 51: 14, 52: 14,  # XI
    53: 15, 54: 15, 55: 15, 56: 15,  # XII
}

def format_rut(document_number):
    """Formatea RUT chileno"""
    if not document_number:
        return None

    rut = str(document_number).upper().replace('CL', '').replace('.', '').replace(' ', '').strip()

    if '-' not in rut and len(rut) >= 2:
        rut = rut[:-1] + '-' + rut[-1]

    if not re.match(r'^\d{7,8}-[\dK]$', rut):
        return None

    return rut

def validate_rut_modulo11(rut):
    """Valida RUT chileno"""
    if not rut or '-' not in rut:
        return False

    try:
        numero, dv = rut.split('-')
        numero = int(numero)

        suma = 0
        multiplo = 2

        for digit in reversed(str(numero)):
            suma += int(digit) * multiplo
            multiplo = multiplo + 1 if multiplo < 7 else 2

        resto = suma % 11
        dv_calculado = 11 - resto

        if dv_calculado == 11:
            dv_esperado = '0'
        elif dv_calculado == 10:
            dv_esperado = 'K'
        else:
            dv_esperado = str(dv_calculado)

        return dv.upper() == dv_esperado
    except:
        return False

def is_valid_name(name):
    """Valida que el nombre sea válido"""
    if not name or not name.strip():
        return False

    name = name.strip()

    # Rechazar nombres que son solo símbolos
    if name in ['@', '.', '-', '_', '*', '#']:
        return False

    # Rechazar nombres que son solo números (probablemente teléfonos)
    cleaned = name.replace('+', '').replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
    if cleaned.isdigit() and len(cleaned) > 6:
        return False

    # Rechazar nombres muy cortos sin sentido
    if len(name) < 2:
        return False

    return True

# Leer CSV
Partner = env['res.partner']

stats = {
    'total_csv': 0,
    'filtered_parent': 0,
    'filtered_invalid_name': 0,
    'filtered_not_customer_supplier': 0,
    'attempted_import': 0,
    'inserted': 0,
    'duplicates': 0,
    'errors': 0,
    'rut_valid': 0,
    'rut_invalid': 0,
    'rut_missing': 0,
    'customers': 0,
    'suppliers': 0,
    'mipymes': 0,
}

print("\n📥 Importando partners desde CSV con FILTROS...")
print("  Filtros activos:")
print("    ✓ Excluir child contacts (parent_id != NULL)")
print("    ✓ Excluir nombres inválidos (@, ., números, etc.)")
print("    ✓ Solo importar si es cliente O proveedor")

with open('/tmp/partners_full_migration.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)

    for row in reader:
        stats['total_csv'] += 1

        # FILTRO 1: Excluir child contacts (tienen parent_id)
        if row.get('parent_id') and row['parent_id'].strip():
            stats['filtered_parent'] += 1
            continue

        # FILTRO 2: Excluir nombres inválidos
        name = row.get('name', '').strip()
        if not is_valid_name(name):
            stats['filtered_invalid_name'] += 1
            if stats['filtered_invalid_name'] <= 5:
                print(f"  ⚠️  Nombre inválido filtrado: '{name}'")
            continue

        # FILTRO 3: Solo importar si es cliente O proveedor
        is_customer = row.get('customer', '') == 't'
        is_supplier = row.get('supplier', '') == 't'

        if not is_customer and not is_supplier:
            stats['filtered_not_customer_supplier'] += 1
            continue

        # Si pasó todos los filtros, intentar importar
        stats['attempted_import'] += 1

        try:
            vals = {
                'name': name,
                'active': True,
            }

            # Campos opcionales
            if row.get('ref') and row['ref'].strip():
                vals['ref'] = row['ref']
            if row.get('email') and row['email'].strip() and '@' in row['email']:
                vals['email'] = row['email']

            # CRÍTICO: mobile → phone
            if row.get('mobile') and row['mobile'].strip():
                vals['phone'] = row['mobile']
            elif row.get('phone') and row['phone'].strip():
                vals['phone'] = row['phone']

            if row.get('website') and row['website'].strip():
                vals['website'] = row['website']
            if row.get('street') and row['street'].strip():
                vals['street'] = row['street']
            if row.get('street2') and row['street2'].strip():
                vals['street2'] = row['street2']
            if row.get('zip') and row['zip'].strip():
                vals['zip'] = row['zip']
            if row.get('city') and row['city'].strip():
                vals['city'] = row['city']
            if row.get('function') and row['function'].strip():
                vals['function'] = row['function']
            if row.get('comment') and row['comment'].strip():
                vals['comment'] = row['comment']
            if row.get('lang') and row['lang'].strip():
                vals['lang'] = row['lang']
            if row.get('tz') and row['tz'].strip():
                vals['tz'] = row['tz']

            # Boolean
            vals['is_company'] = row.get('is_company', '') == 't'

            # RUT
            if row.get('document_number'):
                rut = format_rut(row['document_number'])
                if rut:
                    # Verificar duplicados
                    existing = Partner.search([('vat', '=', rut)], limit=1)
                    if existing:
                        stats['duplicates'] += 1
                        if stats['duplicates'] <= 5:
                            print(f"  ⚠️  Duplicado: {name} (RUT: {rut})")
                        continue

                    if validate_rut_modulo11(rut):
                        vals['vat'] = rut
                        stats['rut_valid'] += 1
                    else:
                        # NO importar RUTs inválidos - skip este contacto
                        stats['rut_invalid'] += 1
                        if stats['rut_invalid'] <= 5:
                            print(f"  ⚠️  RUT inválido, contacto omitido: {name} (RUT: {rut})")
                        continue
            else:
                stats['rut_missing'] += 1

            # Customer/Supplier rank
            vals['customer_rank'] = 1 if is_customer else 0
            vals['supplier_rank'] = 1 if is_supplier else 0

            if is_customer:
                stats['customers'] += 1
            if is_supplier:
                stats['suppliers'] += 1

            # State (Provincia → Región)
            if row.get('state_id') and row['state_id'].isdigit():
                old_state = int(row['state_id'])
                vals['state_id'] = PROVINCIA_TO_REGION.get(old_state, 7)

            # Country (Chile)
            if row.get('country_id') and row['country_id'] == '46':
                vals['country_id'] = env.ref('base.cl').id

            # DTE email
            if row.get('dte_email') and row['dte_email'].strip() and '@' in row['dte_email']:
                vals['dte_email'] = row['dte_email']

            # MIPYME
            vals['es_mipyme'] = row.get('es_mipyme', '') == 't'
            if row.get('es_mipyme', '') == 't':
                stats['mipymes'] += 1

            # Crear partner
            partner = Partner.create(vals)
            stats['inserted'] += 1

            # Log cada 100
            if stats['inserted'] % 100 == 0:
                pct = stats['inserted'] * 100 // stats['attempted_import'] if stats['attempted_import'] > 0 else 0
                print(f"  ✓ {stats['inserted']} / {stats['attempted_import']} importados ({pct}%)...")
                env.cr.commit()

        except Exception as e:
            stats['errors'] += 1
            if stats['errors'] <= 5:
                print(f"  ❌ Error con '{name}': {e}")
            env.cr.rollback()
            continue

# Commit final
env.cr.commit()

# Resumen
print("\n" + "=" * 100)
print("  ✅ MIGRACIÓN LIMPIA COMPLETADA")
print("=" * 100)
print(f"  Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()
print(f"  📊 ESTADÍSTICAS CSV:")
print(f"  • Total registros en CSV:             {stats['total_csv']:,}")
print(f"  • Filtrados (child contacts):         {stats['filtered_parent']:,}")
print(f"  • Filtrados (nombre inválido):        {stats['filtered_invalid_name']:,}")
print(f"  • Filtrados (no cliente/proveedor):   {stats['filtered_not_customer_supplier']:,}")
print(f"  • Intentados importar:                {stats['attempted_import']:,}")
print()
print(f"  📥 RESULTADOS IMPORTACIÓN:")
print(f"  • Importados exitosamente:            {stats['inserted']:,}")
print(f"  • Duplicados omitidos:                {stats['duplicates']:,}")
print(f"  • Errores:                            {stats['errors']:,}")
print()
print(f"  📋 DATOS IMPORTADOS:")
print(f"  • RUT válidos:                        {stats['rut_valid']:,}")
print(f"  • RUT inválidos (omitidos):           {stats['rut_invalid']:,}")
print(f"  • Sin RUT:                            {stats['rut_missing']:,}")
print(f"  • Customers:                          {stats['customers']:,}")
print(f"  • Suppliers:                          {stats['suppliers']:,}")
print(f"  • MIPYMEs:                            {stats['mipymes']:,}")
print("=" * 100)

# Verificación final
print("\n" + "=" * 100)
print("  VERIFICACIÓN FINAL")
print("=" * 100)

total_partners = Partner.search_count([])
with_rut = Partner.search_count([('vat', '!=', False)])
with_dte_email = Partner.search_count([('dte_email', '!=', False)])
mipymes_count = Partner.search_count([('es_mipyme', '=', True)])

print(f"  • Total partners en Odoo 19:          {total_partners:,}")
print(f"  • Partners con RUT:                   {with_rut:,} ({with_rut*100//total_partners if total_partners > 0 else 0}%)")
print(f"  • Partners con DTE Email:             {with_dte_email:,} ({with_dte_email*100//total_partners if total_partners > 0 else 0}%)")
print(f"  • Partners MIPYME:                    {mipymes_count:,}")
print("=" * 100)
