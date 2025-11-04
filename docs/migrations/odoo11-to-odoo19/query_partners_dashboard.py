#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dashboard de Consultas - Partners Odoo 19 CE
============================================

Consultas detalladas para visualizar estado de contactos migrados
"""

print("=" * 100)
print("  📊 DASHBOARD DE CONTACTOS - ODOO 19 CE")
print("=" * 100)

Partner = env['res.partner']

# ═══════════════════════════════════════════════════════════════════════
# 1. ESTADÍSTICAS GENERALES
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  1️⃣  ESTADÍSTICAS GENERALES")
print("─" * 100)

total = Partner.search_count([])
active = Partner.search_count([('active', '=', True)])
inactive = Partner.search_count([('active', '=', False)])
companies = Partner.search_count([('is_company', '=', True)])
individuals = Partner.search_count([('is_company', '=', False)])

print(f"\n  Total Partners:        {total:,}")
print(f"  ├─ Activos:            {active:,} ({active*100//total}%)")
print(f"  └─ Inactivos:          {inactive:,} ({inactive*100//total}%)")
print(f"\n  Por Tipo:")
print(f"  ├─ Empresas:           {companies:,} ({companies*100//total}%)")
print(f"  └─ Personas:           {individuals:,} ({individuals*100//total}%)")

# ═══════════════════════════════════════════════════════════════════════
# 2. DISTRIBUCIÓN CUSTOMER / SUPPLIER
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  2️⃣  DISTRIBUCIÓN CUSTOMER / SUPPLIER")
print("─" * 100)

customers = Partner.search_count([('customer_rank', '>', 0)])
suppliers = Partner.search_count([('supplier_rank', '>', 0)])
both = Partner.search_count([('customer_rank', '>', 0), ('supplier_rank', '>', 0)])
only_customers = customers - both
only_suppliers = suppliers - both
neither = total - customers - suppliers + both

print(f"\n  Clientes:              {customers:,} ({customers*100//total}%)")
print(f"  ├─ Solo clientes:      {only_customers:,}")
print(f"  └─ Cliente + Prov:     {both:,}")
print(f"\n  Proveedores:           {suppliers:,} ({suppliers*100//total}%)")
print(f"  ├─ Solo proveedores:   {only_suppliers:,}")
print(f"  └─ Cliente + Prov:     {both:,}")
print(f"\n  Sin clasificación:     {neither:,} ({neither*100//total}%)")

# ═══════════════════════════════════════════════════════════════════════
# 3. DATOS DE CONTACTO (RUT, EMAIL, TELÉFONO)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  3️⃣  COMPLETITUD DE DATOS DE CONTACTO")
print("─" * 100)

with_rut = Partner.search_count([('vat', '!=', False)])
with_email = Partner.search_count([('email', '!=', False)])
with_phone = Partner.search_count([('phone', '!=', False)])
with_dte_email = Partner.search_count([('dte_email', '!=', False)])
with_address = Partner.search_count([('street', '!=', False)])

print(f"\n  RUT:                   {with_rut:,} / {total:,} ({with_rut*100//total}%)")
print(f"  Email:                 {with_email:,} / {total:,} ({with_email*100//total}%)")
print(f"  Teléfono:              {with_phone:,} / {total:,} ({with_phone*100//total}%)")
print(f"  Email DTE:             {with_dte_email:,} / {total:,} ({with_dte_email*100//total}%)")
print(f"  Dirección:             {with_address:,} / {total:,} ({with_address*100//total}%)")

# Datos críticos para clientes
customers_with_rut = Partner.search_count([('customer_rank', '>', 0), ('vat', '!=', False)])
customers_with_email = Partner.search_count([('customer_rank', '>', 0), ('email', '!=', False)])
print(f"\n  Clientes con RUT:      {customers_with_rut:,} / {customers:,} ({customers_with_rut*100//customers if customers > 0 else 0}%)")
print(f"  Clientes con Email:    {customers_with_email:,} / {customers:,} ({customers_with_email*100//customers if customers > 0 else 0}%)")

# Datos críticos para proveedores
suppliers_with_rut = Partner.search_count([('supplier_rank', '>', 0), ('vat', '!=', False)])
suppliers_with_email = Partner.search_count([('supplier_rank', '>', 0), ('email', '!=', False)])
print(f"  Proveedores con RUT:   {suppliers_with_rut:,} / {suppliers:,} ({suppliers_with_rut*100//suppliers if suppliers > 0 else 0}%)")
print(f"  Proveedores con Email: {suppliers_with_email:,} / {suppliers:,} ({suppliers_with_email*100//suppliers if suppliers > 0 else 0}%)")

# ═══════════════════════════════════════════════════════════════════════
# 4. CLASIFICACIÓN MIPYME Y PAÍS
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  4️⃣  CLASIFICACIÓN MIPYME Y PAÍS")
print("─" * 100)

mipymes = Partner.search_count([('es_mipyme', '=', True)])
chile = Partner.search_count([('country_id.code', '=', 'CL')])
other_countries = Partner.search_count([('country_id', '!=', False), ('country_id.code', '!=', 'CL')])
no_country = Partner.search_count([('country_id', '=', False)])

print(f"\n  MIPYME:                {mipymes:,} ({mipymes*100//total}%)")
print(f"\n  Por País:")
print(f"  ├─ Chile:              {chile:,} ({chile*100//total}%)")
print(f"  ├─ Otros países:       {other_countries:,} ({other_countries*100//total}%)")
print(f"  └─ Sin país:           {no_country:,} ({no_country*100//total}%)")

# ═══════════════════════════════════════════════════════════════════════
# 5. TOP 20 CLIENTES (POR CUSTOMER_RANK)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  5️⃣  TOP 20 CLIENTES")
print("─" * 100)

top_customers = Partner.search([('customer_rank', '>', 0)], order='customer_rank desc', limit=20)

print(f"\n  {'#':<4} {'RUT':<16} {'Nombre':<50} {'Email DTE':<8}")
print("  " + "─" * 94)

for idx, p in enumerate(top_customers, 1):
    rut = p.vat if p.vat else "Sin RUT"
    name = p.name[:48] if len(p.name) > 48 else p.name
    dte = "✅" if p.dte_email else "❌"
    print(f"  {idx:<4} {rut:<16} {name:<50} {dte:<8}")

# ═══════════════════════════════════════════════════════════════════════
# 6. TOP 20 PROVEEDORES (POR SUPPLIER_RANK)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  6️⃣  TOP 20 PROVEEDORES")
print("─" * 100)

top_suppliers = Partner.search([('supplier_rank', '>', 0)], order='supplier_rank desc', limit=20)

print(f"\n  {'#':<4} {'RUT':<16} {'Nombre':<50} {'Email DTE':<8}")
print("  " + "─" * 94)

for idx, p in enumerate(top_suppliers, 1):
    rut = p.vat if p.vat else "Sin RUT"
    name = p.name[:48] if len(p.name) > 48 else p.name
    dte = "✅" if p.dte_email else "❌"
    print(f"  {idx:<4} {rut:<16} {name:<50} {dte:<8}")

# ═══════════════════════════════════════════════════════════════════════
# 7. DISTRIBUCIÓN POR REGIÓN (CHILE)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  7️⃣  DISTRIBUCIÓN POR REGIÓN (TOP 10)")
print("─" * 100)

State = env['res.country.state']
chile_country = env.ref('base.cl')
regions = State.search([('country_id', '=', chile_country.id)])

region_data = []
for region in regions:
    count = Partner.search_count([('state_id', '=', region.id)])
    if count > 0:
        region_data.append((region.name, count))

region_data.sort(key=lambda x: x[1], reverse=True)

print(f"\n  {'Región':<50} {'Partners':<10}")
print("  " + "─" * 60)

for region_name, count in region_data[:10]:
    print(f"  {region_name:<50} {count:>10,}")

# ═══════════════════════════════════════════════════════════════════════
# 8. PARTNERS RECIÉN CREADOS (ÚLTIMOS 30)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  8️⃣  PARTNERS RECIÉN CREADOS (ÚLTIMOS 30)")
print("─" * 100)

recent = Partner.search([], order='id desc', limit=30)

print(f"\n  {'ID':<6} {'RUT':<16} {'Nombre':<40} {'Tipo':<12} {'Email':<6}")
print("  " + "─" * 94)

for p in recent:
    rut = p.vat[:14] if p.vat else "Sin RUT"
    name = p.name[:38] if len(p.name) > 38 else p.name

    tipo = []
    if p.customer_rank > 0:
        tipo.append("Cliente")
    if p.supplier_rank > 0:
        tipo.append("Proveedor")
    if p.is_company:
        tipo.append("Empresa")
    tipo_str = (", ".join(tipo)[:10]) if tipo else "Sin tipo"

    email_icon = "✅" if p.email or p.dte_email else "❌"

    print(f"  {p.id:<6} {rut:<16} {name:<40} {tipo_str:<12} {email_icon:<6}")

# ═══════════════════════════════════════════════════════════════════════
# 9. VALIDACIÓN DE RUTs (MUESTRA ALEATORIA)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  9️⃣  VALIDACIÓN DE RUTs (MUESTRA 20 ALEATORIOS)")
print("─" * 100)

import re
rut_pattern = re.compile(r'^\d{7,8}-[\dK]$')

partners_with_rut = Partner.search([('vat', '!=', False)], limit=20)

valid_count = 0
invalid_count = 0

print(f"\n  {'RUT':<16} {'Formato':<10} {'Nombre':<60}")
print("  " + "─" * 94)

for p in partners_with_rut:
    is_valid = bool(rut_pattern.match(p.vat))
    status = "✅ Válido" if is_valid else "❌ Inválido"
    name = p.name[:58] if len(p.name) > 58 else p.name

    if is_valid:
        valid_count += 1
    else:
        invalid_count += 1

    print(f"  {p.vat:<16} {status:<10} {name:<60}")

print(f"\n  Válidos: {valid_count}/20 | Inválidos: {invalid_count}/20")

# ═══════════════════════════════════════════════════════════════════════
# 10. PARTNERS SIN DATOS CRÍTICOS (ALERTA)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  🔟 PARTNERS SIN DATOS CRÍTICOS (REQUIEREN ATENCIÓN)")
print("─" * 100)

# Clientes sin RUT
customers_no_rut = Partner.search([('customer_rank', '>', 0), ('vat', '=', False)], limit=10)
print(f"\n  ⚠️  CLIENTES SIN RUT (primeros 10 de {Partner.search_count([('customer_rank', '>', 0), ('vat', '=', False)])})")
print("  " + "─" * 94)
for p in customers_no_rut:
    print(f"  • {p.name[:90]}")

# Proveedores sin RUT
suppliers_no_rut = Partner.search([('supplier_rank', '>', 0), ('vat', '=', False)], limit=10)
print(f"\n  ⚠️  PROVEEDORES SIN RUT (primeros 10 de {Partner.search_count([('supplier_rank', '>', 0), ('vat', '=', False)])})")
print("  " + "─" * 94)
for p in suppliers_no_rut:
    print(f"  • {p.name[:90]}")

# Partners con RUT pero sin email DTE
no_dte_email = Partner.search([
    ('vat', '!=', False),
    ('dte_email', '=', False),
    ('email', '=', False),
    '|', ('customer_rank', '>', 0), ('supplier_rank', '>', 0)
], limit=10)
print(f"\n  ⚠️  CLIENTES/PROVEEDORES CON RUT PERO SIN EMAIL (primeros 10 de {Partner.search_count([('vat', '!=', False), ('dte_email', '=', False), ('email', '=', False), '|', ('customer_rank', '>', 0), ('supplier_rank', '>', 0)])})")
print("  " + "─" * 94)
for p in no_dte_email:
    print(f"  • {p.vat:<16} {p.name[:70]}")

# ═══════════════════════════════════════════════════════════════════════
# 11. BÚSQUEDA POR NOMBRE (EJEMPLOS)
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "─" * 100)
print("  1️⃣1️⃣  BÚSQUEDAS POR NOMBRE (EJEMPLOS)")
print("─" * 100)

# Buscar "EERGY"
eergy_partners = Partner.search([('name', 'ilike', 'eergy')])
print(f"\n  🔍 Búsqueda 'EERGY': {len(eergy_partners)} resultados")
print("  " + "─" * 94)
for p in eergy_partners[:5]:
    print(f"  • ID {p.id}: {p.name} | RUT: {p.vat if p.vat else 'Sin RUT'}")

# Buscar "SPA"
spa_partners = Partner.search([('name', 'ilike', 'SPA')], limit=5)
print(f"\n  🔍 Búsqueda 'SPA': {Partner.search_count([('name', 'ilike', 'SPA')])} resultados (mostrando 5)")
print("  " + "─" * 94)
for p in spa_partners:
    print(f"  • ID {p.id}: {p.name[:80]} | RUT: {p.vat if p.vat else 'Sin RUT'}")

# Buscar "LTDA"
ltda_partners = Partner.search([('name', 'ilike', 'LTDA')], limit=5)
print(f"\n  🔍 Búsqueda 'LTDA': {Partner.search_count([('name', 'ilike', 'LTDA')])} resultados (mostrando 5)")
print("  " + "─" * 94)
for p in ltda_partners:
    print(f"  • ID {p.id}: {p.name[:80]} | RUT: {p.vat if p.vat else 'Sin RUT'}")

# ═══════════════════════════════════════════════════════════════════════
# 12. RESUMEN FINAL
# ═══════════════════════════════════════════════════════════════════════

print("\n" + "=" * 100)
print("  📊 RESUMEN EJECUTIVO")
print("=" * 100)

print(f"""
  TOTALES:
  • Total Partners:              {total:,}
  • Activos:                     {active:,} ({active*100//total}%)
  • Empresas:                    {companies:,} ({companies*100//total}%)

  CLASIFICACIÓN:
  • Clientes:                    {customers:,} ({customers*100//total}%)
  • Proveedores:                 {suppliers:,} ({suppliers*100//total}%)
  • Ambos:                       {both:,} ({both*100//total}%)

  CALIDAD DE DATOS:
  • Con RUT:                     {with_rut:,} ({with_rut*100//total}%)
  • Con Email:                   {with_email:,} ({with_email*100//total}%)
  • Con Email DTE:               {with_dte_email:,} ({with_dte_email*100//total}%)
  • Con Teléfono:                {with_phone:,} ({with_phone*100//total}%)
  • MIPYME:                      {mipymes:,} ({mipymes*100//total}%)

  COBERTURA CHILE:
  • Partners en Chile:           {chile:,} ({chile*100//total}%)

  CALIDAD CLIENTES/PROVEEDORES:
  • Clientes con RUT:            {customers_with_rut:,} / {customers:,} ({customers_with_rut*100//customers if customers > 0 else 0}%)
  • Proveedores con RUT:         {suppliers_with_rut:,} / {suppliers:,} ({suppliers_with_rut*100//suppliers if suppliers > 0 else 0}%)
""")

print("=" * 100)
print("  ✅ DASHBOARD COMPLETADO")
print("=" * 100)
