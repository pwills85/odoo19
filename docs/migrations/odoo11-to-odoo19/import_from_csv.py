#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Importación de Contactos desde CSV (Odoo 11 → Odoo 19)
=====================================================

Ejecutar:
    docker cp /tmp/partners_from_odoo11.csv odoo19_app:/tmp/
    docker-compose exec odoo odoo shell -d TEST --no-http < addons/localization/l10n_cl_dte/scripts/import_from_csv.py
"""

import csv
import re

print("=" * 80)
print("  IMPORTACIÓN CONTACTOS desde CSV (Odoo 11 → Odoo 19)")
print("=" * 80)

# Mapeo Provincia → Región
PROVINCIA_TO_REGION = {
    708: 11,  # CAUTIN → IX Región (La Araucanía)
    # Agregar más según sea necesario
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
}

print("\n📥 Importando partners desde CSV...")

with open('/tmp/partners_from_odoo11.csv', 'r', encoding='utf-8') as f:
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
            # En Odoo 19, 'mobile' NO EXISTE, solo 'phone'
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
            vals['is_company'] = row['is_company'] == 't'

            # RUT
            if row.get('document_number'):
                rut = format_rut(row['document_number'])
                if rut:
                    # Verificar duplicados
                    existing = Partner.search([('vat', '=', rut)], limit=1)
                    if existing:
                        print(f"  ⚠️  Duplicado: {row['name']} (RUT: {rut})")
                        stats['duplicates'] += 1
                        continue

                    if validate_rut_modulo11(rut):
                        vals['vat'] = rut
                        stats['rut_valid'] += 1
                    else:
                        vals['vat'] = rut
                        stats['rut_invalid'] += 1

            # Customer/Supplier rank
            vals['customer_rank'] = 1 if row['customer'] == 't' else 0
            vals['supplier_rank'] = 1 if row['supplier'] == 't' else 0

            # State (Provincia → Región)
            if row.get('state_id') and row['state_id'].isdigit():
                old_state = int(row['state_id'])
                vals['state_id'] = PROVINCIA_TO_REGION.get(old_state, 7)  # Default: RM

            # Country (Chile)
            if row.get('country_id') and row['country_id'] == '46':
                vals['country_id'] = env.ref('base.cl').id

            # DTE email
            if row.get('dte_email'):
                vals['dte_email'] = row['dte_email']

            # MIPYME
            vals['es_mipyme'] = row.get('es_mipyme') == 't'

            # Crear partner
            partner = Partner.create(vals)
            stats['inserted'] += 1

            if stats['inserted'] % 10 == 0:
                print(f"  ✓ {stats['inserted']} partners importados...")
                env.cr.commit()

        except Exception as e:
            stats['errors'] += 1
            print(f"  ❌ Error con '{row.get('name')}': {e}")
            env.cr.rollback()
            continue

# Commit final
env.cr.commit()

# Resumen
print("\n" + "=" * 80)
print("  ✅ IMPORTACIÓN COMPLETADA")
print("=" * 80)
print(f"  • Total en CSV: {stats['total']}")
print(f"  • Importados: {stats['inserted']}")
print(f"  • Duplicados omitidos: {stats['duplicates']}")
print(f"  • Errores: {stats['errors']}")
print(f"  • RUT válidos: {stats['rut_valid']}")
print(f"  • RUT inválidos: {stats['rut_invalid']}")
print("=" * 80)
