#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verificación Detallada de Migración Completa
============================================

Valida los datos migrados desde Odoo 11 CE a Odoo 19 CE
"""

import re

print("=" * 80)
print("  VERIFICACIÓN DETALLADA - MIGRACIÓN COMPLETA")
print("=" * 80)

Partner = env['res.partner']

# Estadísticas generales
total = Partner.search_count([])
with_rut = Partner.search_count([('vat', '!=', False)])
with_dte_email = Partner.search_count([('dte_email', '!=', False)])
mipymes = Partner.search_count([('es_mipyme', '=', True)])
customers = Partner.search_count([('customer_rank', '>', 0)])
suppliers = Partner.search_count([('supplier_rank', '>', 0)])

print(f"\n📊 ESTADÍSTICAS GENERALES")
print(f"  • Total partners: {total}")
print(f"  • Partners con RUT: {with_rut} ({with_rut*100//total if total > 0 else 0}%)")
print(f"  • Partners con DTE Email: {with_dte_email} ({with_dte_email*100//total if total > 0 else 0}%)")
print(f"  • Partners MIPYME: {mipymes}")
print(f"  • Customers: {customers}")
print(f"  • Suppliers: {suppliers}")

# Validar formato RUTs
print(f"\n🔍 VALIDACIÓN FORMATO RUTs")
partners_with_rut = Partner.search([('vat', '!=', False)])
rut_pattern = re.compile(r'^\d{7,8}-[\dK]$')
valid_format = 0
invalid_format = 0
invalid_ruts = []

for partner in partners_with_rut:
    if rut_pattern.match(partner.vat):
        valid_format += 1
    else:
        invalid_format += 1
        if len(invalid_ruts) < 10:
            invalid_ruts.append(f"{partner.name} ({partner.vat})")

print(f"  • RUTs con formato válido: {valid_format}/{with_rut}")
print(f"  • RUTs con formato inválido: {invalid_format}")

if invalid_ruts:
    print(f"\n  Ejemplos de RUTs inválidos:")
    for rut in invalid_ruts:
        print(f"    - {rut}")

# Distribución por región
print(f"\n🗺️  DISTRIBUCIÓN POR REGIÓN")
regions = env['res.country.state'].search([('country_id', '=', env.ref('base.cl').id)])
for region in regions[:5]:  # Top 5 regiones
    count = Partner.search_count([('state_id', '=', region.id)])
    if count > 0:
        print(f"  • {region.name}: {count} partners")

# Distribución customer/supplier
print(f"\n👥 DISTRIBUCIÓN CUSTOMER/SUPPLIER")
only_customers = Partner.search_count([('customer_rank', '>', 0), ('supplier_rank', '=', 0)])
only_suppliers = Partner.search_count([('supplier_rank', '>', 0), ('customer_rank', '=', 0)])
both = Partner.search_count([('customer_rank', '>', 0), ('supplier_rank', '>', 0)])
neither = Partner.search_count([('customer_rank', '=', 0), ('supplier_rank', '=', 0)])

print(f"  • Solo clientes: {only_customers}")
print(f"  • Solo proveedores: {only_suppliers}")
print(f"  • Ambos: {both}")
print(f"  • Ninguno: {neither}")

# Partners sin datos críticos
print(f"\n⚠️  PARTNERS SIN DATOS CRÍTICOS")
no_rut = Partner.search_count([('vat', '=', False)])
no_email = Partner.search_count([('email', '=', False)])
no_phone = Partner.search_count([('phone', '=', False)])

print(f"  • Sin RUT: {no_rut} ({no_rut*100//total if total > 0 else 0}%)")
print(f"  • Sin email: {no_email} ({no_email*100//total if total > 0 else 0}%)")
print(f"  • Sin teléfono: {no_phone} ({no_phone*100//total if total > 0 else 0}%)")

# Últimos 10 partners importados
print(f"\n📋 ÚLTIMOS 10 PARTNERS IMPORTADOS")
last_10 = Partner.search([], order='id desc', limit=10)
for p in reversed(last_10):
    rut_display = p.vat if p.vat else "Sin RUT"
    dte_display = "✉️ DTE" if p.dte_email else ""
    mipyme_display = "🏢 MIPYME" if p.es_mipyme else ""
    customer_display = "👤C" if p.customer_rank > 0 else ""
    supplier_display = "🏭S" if p.supplier_rank > 0 else ""
    print(f"  • ID {p.id}: {p.name[:40]:40} | {rut_display:15} {dte_display} {mipyme_display} {customer_display} {supplier_display}")

print("\n" + "=" * 80)
print("  ✅ VERIFICACIÓN COMPLETADA")
print("=" * 80)
