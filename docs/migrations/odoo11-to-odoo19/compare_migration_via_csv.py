#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validación de Integridad de Migración (vía CSV)
===============================================

Compara datos del CSV exportado de Odoo 11 con los datos en Odoo 19
para validar que la migración preservó correctamente la información.
"""

import csv
import random
import re

print("=" * 120)
print("  🔍 VALIDACIÓN DE INTEGRIDAD - MIGRACIÓN ODOO 11 → ODOO 19 (vía CSV)")
print("=" * 120)

Partner = env['res.partner']

def format_rut(rut):
    """Normaliza RUT para comparación"""
    if not rut:
        return None
    rut = str(rut).upper().replace('CL', '').replace('.', '').replace(' ', '').strip()
    if '-' not in rut and len(rut) >= 2:
        rut = rut[:-1] + '-' + rut[-1]
    return rut

def normalize_phone(phone):
    """Normaliza teléfono para comparación"""
    if not phone:
        return None
    return re.sub(r'[\s\(\)\-\+]', '', str(phone))

# Estadísticas
stats = {
    'total_in_csv': 0,
    'total_checked': 0,
    'found_in_o19': 0,
    'not_found_in_o19': 0,
    'perfect_match': 0,
    'partial_match': 0,
    'field_mismatches': {
        'name': 0,
        'rut': 0,
        'email': 0,
        'phone': 0,
        'street': 0,
        'city': 0,
        'customer': 0,
        'supplier': 0,
        'dte_email': 0,
        'es_mipyme': 0,
        'is_company': 0,
    }
}

# Leer CSV de Odoo 11
print("\n📄 Leyendo CSV exportado de Odoo 11...")
csv_data = []
with open('/tmp/partners_full_migration.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        stats['total_in_csv'] += 1
        # Solo incluir registros que deberían haberse migrado
        # (no child contacts, es cliente o proveedor)
        if row.get('parent_id'):
            continue
        if row.get('customer') != 't' and row.get('supplier') != 't':
            continue
        csv_data.append(row)

print(f"  • Total registros en CSV: {stats['total_in_csv']:,}")
print(f"  • Registros válidos para migración: {len(csv_data):,}")

# Seleccionar muestra aleatoria
sample_size = min(50, len(csv_data))
sample_data = random.sample(csv_data, sample_size)

print(f"  • Muestra seleccionada: {sample_size}")

print("\n" + "─" * 120)
print("  COMPARACIÓN DETALLADA")
print("─" * 120)

for idx, row in enumerate(sample_data, 1):
    stats['total_checked'] += 1

    o11_name = row.get('name', '')
    o11_rut = format_rut(row.get('document_number', ''))

    print(f"\n  [{idx}/{sample_size}] {o11_name}")
    print(f"  {'─' * 116}")

    # Buscar en Odoo 19
    partner_o19 = None

    # Primero por RUT
    if o11_rut:
        partner_o19 = Partner.search([('vat', '=', o11_rut)], limit=1)

    # Si no se encontró, buscar por nombre exacto
    if not partner_o19 and o11_name:
        partner_o19 = Partner.search([('name', '=', o11_name)], limit=1)

    if not partner_o19:
        stats['not_found_in_o19'] += 1
        print(f"  ⚠️  NO ENCONTRADO en Odoo 19")
        print(f"      RUT: {o11_rut if o11_rut else 'Sin RUT'}")
        print(f"      Nombre: {o11_name}")
        # Podría ser que fue filtrado por RUT inválido o nombre inválido
        continue

    stats['found_in_o19'] += 1

    # Comparar campos
    mismatches = []

    # 1. Nombre
    if partner_o19.name != o11_name:
        mismatches.append(('name', o11_name, partner_o19.name))
        stats['field_mismatches']['name'] += 1

    # 2. RUT
    o19_rut = format_rut(partner_o19.vat)
    if o11_rut != o19_rut:
        mismatches.append(('rut', o11_rut, o19_rut))
        stats['field_mismatches']['rut'] += 1

    # 3. Email
    o11_email = row.get('email', '') or ''
    o19_email = partner_o19.email or ''
    if o11_email.strip() != o19_email.strip():
        mismatches.append(('email', o11_email, o19_email))
        stats['field_mismatches']['email'] += 1

    # 4. Teléfono (mobile → phone en Odoo 19)
    o11_mobile = row.get('mobile', '') or ''
    o11_phone = row.get('phone', '') or ''
    o11_phone_value = o11_mobile if o11_mobile else o11_phone
    o19_phone = partner_o19.phone or ''

    o11_phone_norm = normalize_phone(o11_phone_value)
    o19_phone_norm = normalize_phone(o19_phone)

    if o11_phone_norm != o19_phone_norm:
        mismatches.append(('phone', o11_phone_value, o19_phone))
        stats['field_mismatches']['phone'] += 1

    # 5. Dirección
    o11_street = row.get('street', '') or ''
    o19_street = partner_o19.street or ''
    if o11_street.strip() != o19_street.strip():
        mismatches.append(('street', o11_street[:50], o19_street[:50]))
        stats['field_mismatches']['street'] += 1

    # 6. Ciudad
    o11_city = row.get('city', '') or ''
    o19_city = partner_o19.city or ''
    if o11_city.strip() != o19_city.strip():
        mismatches.append(('city', o11_city, o19_city))
        stats['field_mismatches']['city'] += 1

    # 7. Customer
    o11_is_customer = row.get('customer', '') == 't'
    o19_is_customer = partner_o19.customer_rank > 0
    if o11_is_customer != o19_is_customer:
        mismatches.append(('customer', o11_is_customer, o19_is_customer))
        stats['field_mismatches']['customer'] += 1

    # 8. Supplier
    o11_is_supplier = row.get('supplier', '') == 't'
    o19_is_supplier = partner_o19.supplier_rank > 0
    if o11_is_supplier != o19_is_supplier:
        mismatches.append(('supplier', o11_is_supplier, o19_is_supplier))
        stats['field_mismatches']['supplier'] += 1

    # 9. DTE Email
    o11_dte_email = row.get('dte_email', '') or ''
    o19_dte_email = partner_o19.dte_email or ''
    if o11_dte_email.strip() != o19_dte_email.strip():
        mismatches.append(('dte_email', o11_dte_email, o19_dte_email))
        stats['field_mismatches']['dte_email'] += 1

    # 10. MIPYME
    o11_es_mipyme = row.get('es_mipyme', '') == 't'
    o19_es_mipyme = partner_o19.es_mipyme or False
    if o11_es_mipyme != o19_es_mipyme:
        mismatches.append(('es_mipyme', o11_es_mipyme, o19_es_mipyme))
        stats['field_mismatches']['es_mipyme'] += 1

    # 11. is_company
    o11_is_company = row.get('is_company', '') == 't'
    o19_is_company = partner_o19.is_company or False
    if o11_is_company != o19_is_company:
        mismatches.append(('is_company', o11_is_company, o19_is_company))
        stats['field_mismatches']['is_company'] += 1

    # Resultado
    if not mismatches:
        stats['perfect_match'] += 1
        print(f"  ✅ MATCH PERFECTO (Odoo 11 ID: {row.get('id')})")
    else:
        stats['partial_match'] += 1
        print(f"  ⚠️  DIFERENCIAS ENCONTRADAS (Odoo 11 ID: {row.get('id')}, Odoo 19 ID: {partner_o19.id}):")
        for field, o11_val, o19_val in mismatches:
            o11_display = str(o11_val)[:50] if o11_val else '(vacío)'
            o19_display = str(o19_val)[:50] if o19_val else '(vacío)'
            print(f"      • {field:12} | Odoo 11: {o11_display:50} | Odoo 19: {o19_display:50}")

# Resumen
print("\n" + "=" * 120)
print("  📊 RESUMEN DE VALIDACIÓN")
print("=" * 120)

print(f"\n  MUESTRA ANALIZADA:")
print(f"  • Total partners verificados:        {stats['total_checked']}")
print(f"  • Encontrados en Odoo 19:            {stats['found_in_o19']} ({stats['found_in_o19']*100//stats['total_checked'] if stats['total_checked'] > 0 else 0}%)")
print(f"  • No encontrados en Odoo 19:         {stats['not_found_in_o19']} ({stats['not_found_in_o19']*100//stats['total_checked'] if stats['total_checked'] > 0 else 0}%)")

if stats['found_in_o19'] > 0:
    print(f"\n  CALIDAD DE MIGRACIÓN:")
    perfect_pct = stats['perfect_match'] * 100 // stats['found_in_o19']
    partial_pct = stats['partial_match'] * 100 // stats['found_in_o19']
    print(f"  • Match perfecto:                    {stats['perfect_match']} ({perfect_pct}%)")
    print(f"  • Match con diferencias:             {stats['partial_match']} ({partial_pct}%)")

    print(f"\n  DIFERENCIAS POR CAMPO:")
    for field, count in sorted(stats['field_mismatches'].items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            pct = count * 100 // stats['found_in_o19']
            print(f"  • {field:15} {count:3} diferencias ({pct}%)")

    # Evaluación final
    print(f"\n  {'─' * 116}")
    print(f"  EVALUACIÓN FINAL:")
    if perfect_pct >= 90:
        print(f"  ✅ MIGRACIÓN EXCELENTE - {perfect_pct}% de matches perfectos")
    elif perfect_pct >= 75:
        print(f"  ✅ MIGRACIÓN BUENA - {perfect_pct}% de matches perfectos")
    elif perfect_pct >= 50:
        print(f"  ⚠️  MIGRACIÓN ACEPTABLE - {perfect_pct}% de matches perfectos (revisar diferencias)")
    else:
        print(f"  ❌ MIGRACIÓN CON PROBLEMAS - Solo {perfect_pct}% de matches perfectos")

print("=" * 120)
