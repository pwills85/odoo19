#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Importación COMPLETA de Contactos desde CSV (Odoo 11 → Odoo 19)
===============================================================

Migración completa de 3,922 partners desde Odoo 11 CE a Odoo 19 CE

Ejecutar:
    docker cp /tmp/partners_full_migration.csv odoo19_app:/tmp/
    docker-compose exec odoo odoo shell -d TEST --no-http < addons/localization/l10n_cl_dte/scripts/import_full_migration.py
"""

import csv
import re
from datetime import datetime

print("=" * 80)
print("  MIGRACIÓN COMPLETA: Contactos Odoo 11 CE → Odoo 19 CE")
print("=" * 80)
print(f"  Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 80)

# Mapeo Provincia → Región
PROVINCIA_TO_REGION = {
    # Región de Arica y Parinacota (XV)
    1: 1, 2: 1,
    # Región de Tarapacá (I)
    3: 2, 4: 2,
    # Región de Antofagasta (II)
    5: 3, 6: 3, 7: 3,
    # Región de Atacama (III)
    8: 4, 9: 4, 10: 4,
    # Región de Coquimbo (IV)
    11: 5, 12: 5, 13: 5,
    # Región de Valparaíso (V)
    14: 6, 15: 6, 16: 6, 17: 6, 18: 6, 19: 6, 20: 6, 21: 6,
    # Región Metropolitana (XIII)
    22: 7, 23: 7, 24: 7, 25: 7, 26: 7, 27: 7,
    # Región del Libertador (VI)
    28: 8, 29: 8, 30: 8,
    # Región del Maule (VII)
    31: 9, 32: 9, 33: 9, 34: 9,
    # Región de Ñuble (XVI)
    35: 16, 36: 16, 37: 16,
    # Región del Biobío (VIII)
    38: 10, 39: 10, 40: 10,
    # Región de La Araucanía (IX)
    41: 11, 42: 11,
    # Región de Los Ríos (XIV)
    43: 12, 44: 12,
    # Región de Los Lagos (X)
    45: 13, 46: 13, 47: 13, 48: 13,
    # Región Aysén (XI)
    49: 14, 50: 14, 51: 14, 52: 14,
    # Región de Magallanes (XII)
    53: 15, 54: 15, 55: 15, 56: 15,
}

def format_rut(document_number):
    """Formatea RUT chileno"""
    if not document_number:
        return None

    rut = str(document_number).replace('.', '').replace(' ', '').strip()

    if '-' not in rut and len(rut) >= 2:
        rut = rut[:-1] + '-' + rut[-1]

    if not re.match(r'^\d{7,8}-[\dK]$', rut):
        return None

    return rut.upper()

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

# Leer CSV
Partner = env['res.partner']

stats = {
    'total': 0,
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

print("\n📥 Importando partners desde CSV completo...")

with open('/tmp/partners_full_migration.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)

    for row in reader:
        stats['total'] += 1

        try:
            vals = {
                'name': row['name'],
                'active': True,
            }

            # Campos opcionales (solo asignar si NO están vacíos)
            if row.get('ref') and row['ref'].strip():
                vals['ref'] = row['ref']
            if row.get('email') and row['email'].strip():
                vals['email'] = row['email']

            # CRÍTICO: En Odoo 19, 'mobile' NO EXISTE, solo 'phone'
            # Priorizar mobile si existe, sino phone
            if row.get('mobile') and row['mobile'].strip():
                vals['phone'] = row['mobile']  # Mapear mobile → phone
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
                        if stats['duplicates'] <= 10:
                            print(f"  ⚠️  Duplicado: {row['name']} (RUT: {rut})")
                        continue

                    if validate_rut_modulo11(rut):
                        vals['vat'] = rut
                        stats['rut_valid'] += 1
                    else:
                        vals['vat'] = rut
                        stats['rut_invalid'] += 1
                        if stats['rut_invalid'] <= 10:
                            print(f"  ⚠️  RUT inválido: {row['name']} (RUT: {rut})")
            else:
                stats['rut_missing'] += 1

            # Customer/Supplier rank
            vals['customer_rank'] = 1 if row.get('customer', '') == 't' else 0
            vals['supplier_rank'] = 1 if row.get('supplier', '') == 't' else 0

            if row.get('customer', '') == 't':
                stats['customers'] += 1
            if row.get('supplier', '') == 't':
                stats['suppliers'] += 1

            # State (Provincia → Región)
            if row.get('state_id') and row['state_id'].isdigit():
                old_state = int(row['state_id'])
                vals['state_id'] = PROVINCIA_TO_REGION.get(old_state, 7)  # Default: RM

            # Country (Chile)
            if row.get('country_id') and row['country_id'] == '46':
                vals['country_id'] = env.ref('base.cl').id

            # DTE email
            if row.get('dte_email') and row['dte_email'].strip():
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
                print(f"  ✓ {stats['inserted']} / {stats['total']} partners importados... ({stats['inserted']*100//stats['total']}%)")
                env.cr.commit()

        except Exception as e:
            stats['errors'] += 1
            if stats['errors'] <= 10:
                print(f"  ❌ Error con '{row.get('name')}': {e}")
            env.cr.rollback()
            continue

# Commit final
env.cr.commit()

# Resumen
print("\n" + "=" * 80)
print("  ✅ MIGRACIÓN COMPLETA FINALIZADA")
print("=" * 80)
print(f"  Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  • Total en CSV: {stats['total']}")
print(f"  • Importados: {stats['inserted']}")
print(f"  • Duplicados omitidos: {stats['duplicates']}")
print(f"  • Errores: {stats['errors']}")
print(f"  • RUT válidos: {stats['rut_valid']}")
print(f"  • RUT inválidos: {stats['rut_invalid']}")
print(f"  • RUT faltantes: {stats['rut_missing']}")
print(f"  • Customers: {stats['customers']}")
print(f"  • Suppliers: {stats['suppliers']}")
print(f"  • MIPYMEs: {stats['mipymes']}")
print("=" * 80)

# Verificación final
print("\n" + "=" * 80)
print("  VERIFICACIÓN FINAL")
print("=" * 80)

total_partners = Partner.search_count([])
with_rut = Partner.search_count([('vat', '!=', False)])
with_dte_email = Partner.search_count([('dte_email', '!=', False)])
mipymes_count = Partner.search_count([('es_mipyme', '=', True)])

print(f"  • Total partners en Odoo 19: {total_partners}")
print(f"  • Partners con RUT: {with_rut} ({with_rut*100//total_partners}%)")
print(f"  • Partners con DTE Email: {with_dte_email} ({with_dte_email*100//total_partners}%)")
print(f"  • Partners MIPYME: {mipymes_count}")
print("=" * 80)
