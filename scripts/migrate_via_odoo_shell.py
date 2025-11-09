#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ETL via Odoo Shell: Migración de Contactos Odoo 11 → Odoo 19
============================================================

Este script se ejecuta DENTRO de Odoo shell para aprovechar el ORM.
Uso:
    docker-compose exec odoo odoo shell -d TEST --no-http < scripts/migrate_via_odoo_shell.py
"""

import re
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════════

# Mapeo Provincia (Odoo 11) → Región (Odoo 19)
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

DRY_RUN = False  # Cambiar a True para testing
LIMIT = None  # None = todos, o número para limitar (ej: 100)

print("=" * 80)
print("  ETL: MIGRACIÓN CONTACTOS ODOO 11 CE → ODOO 19 CE (via ORM)")
print("=" * 80)
print(f"  Database: {env.cr.dbname}")
print(f"  Dry-run: {DRY_RUN}")
print(f"  Limit: {LIMIT if LIMIT else 'None (todos)'}")
print("=" * 80)

# ═══════════════════════════════════════════════════════════════════════
# UTILIDADES
# ═══════════════════════════════════════════════════════════════════════

def format_rut(document_number):
    """Formatea RUT chileno al formato estándar XXXXXXXX-X"""
    if not document_number:
        return None

    rut = str(document_number).upper().replace('CL', '').replace('.', '').replace(' ', '').strip()

    if '-' not in rut and len(rut) >= 2:
        rut = rut[:-1] + '-' + rut[-1]

    if not re.match(r'^\d{7,8}-[\dK]$', rut):
        return None

    return rut

def validate_rut_modulo11(rut):
    """Valida RUT chileno usando algoritmo Módulo 11"""
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

    except (ValueError, AttributeError):
        return False

# ═══════════════════════════════════════════════════════════════════════
# EXTRACCIÓN (vía SQL directo a Odoo 11)
# ═══════════════════════════════════════════════════════════════════════

print("\n📤 FASE 1: EXTRACCIÓN desde Odoo 11...")

# Conectar a DB Odoo 11 via psycopg2
import psycopg2

conn_o11 = psycopg2.connect(
    host='prod_odoo-11_eergygroup_db',
    port=5432,
    database='EERGYGROUP',
    user='odoo',
    password='l&UKgl^9046hPo7K!AowqV&g'
)

cursor_o11 = conn_o11.cursor()

query = """
    SELECT
        id, name, ref, document_number, email, phone, mobile, website,
        street, street2, zip, city, state_id, country_id, function,
        is_company, customer, supplier, active, comment,
        activity_description, dte_email, es_mipyme, parent_id,
        lang, tz, title, type, company_id, user_id
    FROM res_partner
    WHERE active = true
    ORDER BY id
"""

if LIMIT:
    query += f" LIMIT {LIMIT}"

cursor_o11.execute(query)
partners_o11 = cursor_o11.fetchall()
columns = [desc[0] for desc in cursor_o11.description]

print(f"✅ Extraídos {len(partners_o11)} partners desde Odoo 11")

# ═══════════════════════════════════════════════════════════════════════
# TRANSFORMACIÓN Y CARGA
# ═══════════════════════════════════════════════════════════════════════

print("\n🔄 FASE 2: TRANSFORMACIÓN Y CARGA en Odoo 19...")

Partner = env['res.partner']

stats = {
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

for row in partners_o11:
    partner_o11 = dict(zip(columns, row))

    try:
        # Transformar partner
        vals = {
            'name': partner_o11['name'],
            'active': partner_o11.get('active', True),
        }

        # Campos opcionales
        for field in ['ref', 'email', 'phone', 'mobile', 'website', 'street',
                      'street2', 'zip', 'city', 'function', 'comment',
                      'parent_id', 'lang', 'tz', 'title', 'type',
                      'company_id', 'user_id', 'country_id']:
            if partner_o11.get(field):
                vals[field] = partner_o11[field]

        # is_company
        vals['is_company'] = partner_o11.get('is_company', False)

        # VAT (RUT)
        if partner_o11.get('document_number'):
            rut = format_rut(partner_o11['document_number'])
            if rut and validate_rut_modulo11(rut):
                # Verificar si ya existe
                existing = Partner.search([('vat', '=', rut)], limit=1)
                if existing:
                    stats['duplicates'] += 1
                    continue

                vals['vat'] = rut
                stats['rut_valid'] += 1
            elif rut:
                vals['vat'] = rut  # Guardar igual para revisión manual
                stats['rut_invalid'] += 1
        else:
            stats['rut_missing'] += 1

        # Customer/Supplier rank
        vals['customer_rank'] = 1 if partner_o11.get('customer') else 0
        vals['supplier_rank'] = 1 if partner_o11.get('supplier') else 0

        if partner_o11.get('customer'):
            stats['customers'] += 1
        if partner_o11.get('supplier'):
            stats['suppliers'] += 1

        # State (Provincia → Región)
        if partner_o11.get('state_id'):
            old_state_id = partner_o11['state_id']
            new_state_id = PROVINCIA_TO_REGION.get(old_state_id, 7)  # Default: RM
            vals['state_id'] = new_state_id

        # DTE email
        if partner_o11.get('dte_email'):
            vals['dte_email'] = partner_o11['dte_email']

        # MIPYME
        vals['es_mipyme'] = partner_o11.get('es_mipyme', False)
        if partner_o11.get('es_mipyme'):
            stats['mipymes'] += 1

        # Crear partner
        if not DRY_RUN:
            new_partner = Partner.create(vals)
            stats['inserted'] += 1
        else:
            stats['inserted'] += 1

        # Log cada 100
        if stats['inserted'] % 100 == 0:
            print(f"  ✓ {stats['inserted']} partners procesados...")
            if not DRY_RUN:
                env.cr.commit()

    except Exception as e:
        stats['errors'] += 1
        print(f"  ❌ Error con partner '{partner_o11.get('name')}': {e}")
        if not DRY_RUN:
            env.cr.rollback()
        continue

# Commit final
if not DRY_RUN:
    env.cr.commit()

# Cerrar conexión Odoo 11
cursor_o11.close()
conn_o11.close()

# ═══════════════════════════════════════════════════════════════════════
# RESUMEN
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("  ✅ MIGRACIÓN COMPLETADA")
print("=" * 80)
print(f"  • Partners extraídos: {len(partners_o11)}")
print(f"  • Partners insertados: {stats['inserted']}")
print(f"  • Duplicados omitidos: {stats['duplicates']}")
print(f"  • Errores: {stats['errors']}")
print(f"  • RUT válidos: {stats['rut_valid']}")
print(f"  • RUT inválidos: {stats['rut_invalid']}")
print(f"  • RUT faltantes: {stats['rut_missing']}")
print(f"  • Customers: {stats['customers']}")
print(f"  • Suppliers: {stats['suppliers']}")
print(f"  • MIPYMEs: {stats['mipymes']}")

if DRY_RUN:
    print("\n⚠️  DRY-RUN: No se realizaron cambios permanentes")
else:
    print("\n✅ Cambios confirmados en base de datos TEST")

print("=" * 80)
