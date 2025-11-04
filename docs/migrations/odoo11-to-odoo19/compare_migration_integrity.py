#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validación de Integridad de Migración
=====================================

Compara datos entre Odoo 11 CE y Odoo 19 CE para validar que la migración
preservó correctamente toda la información.

Ejecutar:
    docker-compose exec odoo odoo shell -d TEST --no-http < addons/localization/l10n_cl_dte/scripts/compare_migration_integrity.py
"""

import psycopg2
import random
import re

print("=" * 120)
print("  🔍 VALIDACIÓN DE INTEGRIDAD - MIGRACIÓN ODOO 11 → ODOO 19")
print("=" * 120)

# Conectar a Odoo 11
print("\n📡 Conectando a Odoo 11...")
try:
    conn_o11 = psycopg2.connect(
        host='prod_odoo-11_eergygroup_db',
        port=5432,
        database='EERGYGROUP',
        user='odoo',
        password='l&UKgl^9046hPo7K!AowqV&g'
    )
    cursor_o11 = conn_o11.cursor()
    print("  ✅ Conectado a Odoo 11")
except Exception as e:
    print(f"  ❌ Error conectando a Odoo 11: {e}")
    exit(1)

# Odoo 19
Partner = env['res.partner']
print("  ✅ Conectado a Odoo 19")

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
    # Eliminar espacios, paréntesis, guiones
    return re.sub(r'[\s\(\)\-\+]', '', str(phone))

# Estadísticas
stats = {
    'total_checked': 0,
    'found_in_o11': 0,
    'not_found_in_o11': 0,
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
    }
}

# Seleccionar muestra aleatoria de Odoo 19
print("\n📊 Seleccionando muestra aleatoria de partners migrados...")
all_partners_o19 = Partner.search([('id', '>', 5)])  # Excluir sistema
total_o19 = len(all_partners_o19)
sample_size = min(50, total_o19)
sample_partners = random.sample(all_partners_o19.ids, sample_size)

print(f"  • Total partners en Odoo 19: {total_o19}")
print(f"  • Muestra seleccionada: {sample_size} partners")

print("\n" + "─" * 120)
print("  COMPARACIÓN DETALLADA")
print("─" * 120)

for idx, partner_id in enumerate(sample_partners, 1):
    partner_o19 = Partner.browse(partner_id)
    stats['total_checked'] += 1

    print(f"\n  [{idx}/{sample_size}] {partner_o19.name}")
    print(f"  {'─' * 116}")

    # Buscar en Odoo 11
    # Primero por RUT, luego por nombre
    partner_o11_data = None

    if partner_o19.vat:
        rut_search = format_rut(partner_o19.vat)
        cursor_o11.execute("""
            SELECT id, name, document_number, email, phone, mobile, street, city,
                   customer, supplier, dte_email, es_mipyme, is_company
            FROM res_partner
            WHERE document_number = %s AND active = true
            LIMIT 1
        """, (rut_search,))
        partner_o11_data = cursor_o11.fetchone()

    if not partner_o11_data and partner_o19.name:
        cursor_o11.execute("""
            SELECT id, name, document_number, email, phone, mobile, street, city,
                   customer, supplier, dte_email, es_mipyme, is_company
            FROM res_partner
            WHERE name = %s AND active = true
            LIMIT 1
        """, (partner_o19.name,))
        partner_o11_data = cursor_o11.fetchone()

    if not partner_o11_data:
        stats['not_found_in_o11'] += 1
        print(f"  ⚠️  NO ENCONTRADO en Odoo 11")
        print(f"      RUT buscado: {partner_o19.vat if partner_o19.vat else 'Sin RUT'}")
        print(f"      Nombre: {partner_o19.name}")
        continue

    stats['found_in_o11'] += 1

    # Extraer datos de Odoo 11
    (o11_id, o11_name, o11_document_number, o11_email, o11_phone, o11_mobile,
     o11_street, o11_city, o11_customer, o11_supplier, o11_dte_email,
     o11_es_mipyme, o11_is_company) = partner_o11_data

    # Comparar campos
    mismatches = []

    # 1. Nombre
    if partner_o19.name != o11_name:
        mismatches.append(('name', o11_name, partner_o19.name))
        stats['field_mismatches']['name'] += 1

    # 2. RUT (document_number → vat)
    o11_rut = format_rut(o11_document_number)
    o19_rut = format_rut(partner_o19.vat)
    if o11_rut != o19_rut:
        mismatches.append(('rut', o11_rut, o19_rut))
        stats['field_mismatches']['rut'] += 1

    # 3. Email
    if (partner_o19.email or '') != (o11_email or ''):
        mismatches.append(('email', o11_email, partner_o19.email))
        stats['field_mismatches']['email'] += 1

    # 4. Teléfono (mobile → phone)
    # En Odoo 19, mobile se migró a phone
    o11_phone_norm = normalize_phone(o11_mobile or o11_phone)
    o19_phone_norm = normalize_phone(partner_o19.phone)
    if o11_phone_norm != o19_phone_norm:
        mismatches.append(('phone', f"{o11_mobile or o11_phone}", partner_o19.phone))
        stats['field_mismatches']['phone'] += 1

    # 5. Dirección
    if (partner_o19.street or '') != (o11_street or ''):
        mismatches.append(('street', o11_street, partner_o19.street))
        stats['field_mismatches']['street'] += 1

    # 6. Ciudad
    if (partner_o19.city or '') != (o11_city or ''):
        mismatches.append(('city', o11_city, partner_o19.city))
        stats['field_mismatches']['city'] += 1

    # 7. Customer (boolean → rank)
    o19_is_customer = partner_o19.customer_rank > 0
    if o19_is_customer != o11_customer:
        mismatches.append(('customer', o11_customer, o19_is_customer))
        stats['field_mismatches']['customer'] += 1

    # 8. Supplier (boolean → rank)
    o19_is_supplier = partner_o19.supplier_rank > 0
    if o19_is_supplier != o11_supplier:
        mismatches.append(('supplier', o11_supplier, o19_is_supplier))
        stats['field_mismatches']['supplier'] += 1

    # 9. DTE Email
    if (partner_o19.dte_email or '') != (o11_dte_email or ''):
        mismatches.append(('dte_email', o11_dte_email, partner_o19.dte_email))
        stats['field_mismatches']['dte_email'] += 1

    # 10. MIPYME
    if partner_o19.es_mipyme != (o11_es_mipyme or False):
        mismatches.append(('es_mipyme', o11_es_mipyme, partner_o19.es_mipyme))
        stats['field_mismatches']['es_mipyme'] += 1

    # Resultado
    if not mismatches:
        stats['perfect_match'] += 1
        print(f"  ✅ MATCH PERFECTO (Odoo 11 ID: {o11_id})")
    else:
        stats['partial_match'] += 1
        print(f"  ⚠️  DIFERENCIAS ENCONTRADAS (Odoo 11 ID: {o11_id}):")
        for field, o11_val, o19_val in mismatches:
            o11_display = str(o11_val)[:50] if o11_val else '(vacío)'
            o19_display = str(o19_val)[:50] if o19_val else '(vacío)'
            print(f"      • {field:12} | Odoo 11: {o11_display:50} | Odoo 19: {o19_display:50}")

# Cerrar conexión Odoo 11
cursor_o11.close()
conn_o11.close()

# Resumen
print("\n" + "=" * 120)
print("  📊 RESUMEN DE VALIDACIÓN")
print("=" * 120)

print(f"\n  MUESTRA ANALIZADA:")
print(f"  • Total partners verificados:        {stats['total_checked']}")
print(f"  • Encontrados en Odoo 11:            {stats['found_in_o11']} ({stats['found_in_o11']*100//stats['total_checked']}%)")
print(f"  • No encontrados en Odoo 11:         {stats['not_found_in_o11']} ({stats['not_found_in_o11']*100//stats['total_checked'] if stats['total_checked'] > 0 else 0}%)")

print(f"\n  CALIDAD DE MIGRACIÓN:")
perfect_pct = stats['perfect_match'] * 100 // stats['found_in_o11'] if stats['found_in_o11'] > 0 else 0
partial_pct = stats['partial_match'] * 100 // stats['found_in_o11'] if stats['found_in_o11'] > 0 else 0
print(f"  • Match perfecto:                    {stats['perfect_match']} ({perfect_pct}%)")
print(f"  • Match con diferencias:             {stats['partial_match']} ({partial_pct}%)")

print(f"\n  DIFERENCIAS POR CAMPO:")
total_mismatches = sum(stats['field_mismatches'].values())
for field, count in sorted(stats['field_mismatches'].items(), key=lambda x: x[1], reverse=True):
    if count > 0:
        pct = count * 100 // stats['found_in_o11'] if stats['found_in_o11'] > 0 else 0
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
