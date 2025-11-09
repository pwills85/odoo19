#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Consulta de RUTs Problemáticos
==============================

Identifica y analiza los 7 contactos que no se pudieron importar
debido a problemas de validación de RUT
"""

import re

print("=" * 100)
print("  🔍 ANÁLISIS DE RUTs PROBLEMÁTICOS - MIGRACIÓN ODOO 11 → ODOO 19")
print("=" * 100)

# RUTs problemáticos identificados durante la migración
PROBLEMATIC_RUTS = [
    ('16184842-6', 'RICHARD VIDAL TORO'),
    ('75758502-0', 'CROX CO SPA'),
    ('25493249-6', 'DANIEL ROSAS HUEQUELEF'),
    ('19974357-4', 'DIEGO ARMANDO PARDO MUÑOZ'),
    ('1905885-0', 'FRANCO NICOLAS GONZALEZ CARRASCO'),
    ('19944587-7', 'Rodrigo Andrés Sandoval Gatica'),
    ('18051684-5', 'Guillermo Andrés Mella Arias'),
]

def validate_rut_modulo11(rut):
    """Valida RUT chileno usando algoritmo Módulo 11"""
    if not rut or '-' not in rut:
        return False, "Formato inválido (sin guión)"

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

        if dv.upper() == dv_esperado:
            return True, "Válido"
        else:
            return False, f"DV incorrecto (esperado: {dv_esperado}, encontrado: {dv})"

    except (ValueError, AttributeError) as e:
        return False, f"Error de formato: {str(e)}"

def calculate_correct_rut(rut_number):
    """Calcula el dígito verificador correcto para un número de RUT"""
    try:
        numero = int(rut_number.replace('-', '').replace('.', '').strip())

        suma = 0
        multiplo = 2

        for digit in reversed(str(numero)):
            suma += int(digit) * multiplo
            multiplo = multiplo + 1 if multiplo < 7 else 2

        resto = suma % 11
        dv_calculado = 11 - resto

        if dv_calculado == 11:
            dv = '0'
        elif dv_calculado == 10:
            dv = 'K'
        else:
            dv = str(dv_calculado)

        return f"{numero}-{dv}"
    except Exception as e:
        return f"Error: {str(e)}"

print("\n" + "─" * 100)
print("  📋 CONTACTOS NO IMPORTADOS POR PROBLEMAS DE RUT")
print("─" * 100)

print(f"\n  {'#':<4} {'RUT Incorrecto':<20} {'Nombre':<40} {'RUT Correcto':<20}")
print("  " + "─" * 96)

for idx, (rut, nombre) in enumerate(PROBLEMATIC_RUTS, 1):
    is_valid, reason = validate_rut_modulo11(rut)

    # Extraer número sin DV
    rut_number = rut.split('-')[0] if '-' in rut else rut
    rut_correcto = calculate_correct_rut(rut_number)

    print(f"  {idx:<4} {rut:<20} {nombre[:38]:<40} {rut_correcto:<20}")

print("\n" + "─" * 100)
print("  🔬 ANÁLISIS DETALLADO DE CADA RUT")
print("─" * 100)

for idx, (rut, nombre) in enumerate(PROBLEMATIC_RUTS, 1):
    print(f"\n  {idx}. {nombre}")
    print(f"  {'─' * 96}")

    is_valid, reason = validate_rut_modulo11(rut)
    rut_number = rut.split('-')[0] if '-' in rut else rut
    rut_correcto = calculate_correct_rut(rut_number)

    print(f"  RUT Ingresado:         {rut}")
    print(f"  Estado:                ❌ {reason}")
    print(f"  RUT Correcto:          ✅ {rut_correcto}")
    print(f"  Acción Requerida:      Actualizar en Odoo 11 con RUT {rut_correcto}")

# Verificar si alguno de estos contactos está en Odoo 19 (no deberían estar)
print("\n" + "─" * 100)
print("  🔍 VERIFICACIÓN EN BASE DE DATOS ODOO 19")
print("─" * 100)

Partner = env['res.partner']

print(f"\n  Buscando contactos con RUTs problemáticos en Odoo 19...")
print("  " + "─" * 96)

found_count = 0
for rut, nombre in PROBLEMATIC_RUTS:
    # Buscar por nombre (ya que el RUT no se importó)
    partner = Partner.search([('name', 'ilike', nombre)], limit=1)

    if partner:
        found_count += 1
        print(f"  ⚠️  ENCONTRADO: {nombre}")
        print(f"      ID: {partner.id}")
        print(f"      RUT en DB: {partner.vat if partner.vat else 'Sin RUT'}")
        print(f"      Email: {partner.email if partner.email else 'Sin email'}")
        print(f"      Customer: {'Sí' if partner.customer_rank > 0 else 'No'}")
        print(f"      Supplier: {'Sí' if partner.supplier_rank > 0 else 'No'}")
    else:
        print(f"  ✅ NO ENCONTRADO (correcto): {nombre}")

print(f"\n  Total contactos encontrados: {found_count}/7")

if found_count == 0:
    print("  ✅ Ningún contacto con RUT inválido se importó (comportamiento correcto)")

# Buscar en Odoo 11 CSV para más información
print("\n" + "─" * 100)
print("  📄 DATOS COMPLETOS DESDE ODOO 11 (CSV)")
print("─" * 100)

import csv

try:
    with open('/tmp/partners_full_migration.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        print(f"\n  Buscando en CSV exportado desde Odoo 11...")
        print("  " + "─" * 96)

        for row in reader:
            if row.get('document_number'):
                # Formatear RUT para comparación
                rut_csv = row['document_number'].replace('.', '').replace(' ', '').strip()
                if '-' not in rut_csv and len(rut_csv) >= 2:
                    rut_csv = rut_csv[:-1] + '-' + rut_csv[-1]
                rut_csv = rut_csv.upper()

                # Verificar si está en la lista de problemáticos
                for prob_rut, prob_nombre in PROBLEMATIC_RUTS:
                    if rut_csv == prob_rut or row['name'].upper() == prob_nombre.upper():
                        print(f"\n  📋 {row['name']}")
                        print(f"  {'─' * 96}")
                        print(f"      RUT Original:      {row.get('document_number', 'N/A')}")
                        print(f"      Email:             {row.get('email', 'N/A')}")
                        print(f"      Teléfono:          {row.get('phone', 'N/A')}")
                        print(f"      Móvil:             {row.get('mobile', 'N/A')}")
                        print(f"      Dirección:         {row.get('street', 'N/A')}")
                        print(f"      Ciudad:            {row.get('city', 'N/A')}")
                        print(f"      Es Cliente:        {'Sí' if row.get('customer') == 't' else 'No'}")
                        print(f"      Es Proveedor:      {'Sí' if row.get('supplier') == 't' else 'No'}")
                        print(f"      ID Odoo 11:        {row.get('id', 'N/A')}")
                        break
except FileNotFoundError:
    print("  ⚠️  Archivo CSV no encontrado en /tmp/partners_full_migration.csv")

# Generar script SQL para corregir en Odoo 11
print("\n" + "─" * 100)
print("  🔧 SCRIPT SQL PARA CORREGIR EN ODOO 11")
print("─" * 100)

print("""
  Ejecutar en base de datos EERGYGROUP (Odoo 11):
  """)

for rut, nombre in PROBLEMATIC_RUTS:
    rut_number = rut.split('-')[0]
    rut_correcto = calculate_correct_rut(rut_number)

    print(f"""  -- {nombre}
  UPDATE res_partner
  SET document_number = '{rut_correcto}'
  WHERE name = '{nombre}' AND document_number = '{rut}';
""")

# Recomendaciones
print("\n" + "─" * 100)
print("  📝 RECOMENDACIONES Y PASOS A SEGUIR")
print("─" * 100)

print("""
  1. VALIDACIÓN CON CLIENTES/PROVEEDORES
     • Contactar a cada persona/empresa para validar su RUT real
     • Solicitar copia de cédula de identidad o RUT empresarial
     • Verificar en sitio SII: https://www.sii.cl/servicios_online/1039-1208.html

  2. CORRECCIÓN EN ODOO 11
     • Ejecutar scripts SQL arriba en base de datos EERGYGROUP
     • Verificar que los RUTs se hayan actualizado correctamente
     • Crear backup antes de ejecutar UPDATE

  3. RE-EXPORTAR E IMPORTAR
     • Exportar nuevamente solo estos 7 contactos desde Odoo 11
     • Importar en Odoo 19 usando script de migración
     • Verificar que se importen sin errores

  4. IMPORTANCIA POR TIPO DE CONTACTO
""")

for rut, nombre in PROBLEMATIC_RUTS:
    print(f"     • {nombre}: Verificar si es cliente/proveedor activo")

print("\n  5. ALTERNATIVA: IMPORTACIÓN MANUAL")
print("     Si son pocos contactos activos, considerar:")
print("     • Crear manualmente en Odoo 19 con RUT correcto")
print("     • Validar RUT en tiempo real durante creación")
print("     • Odoo 19 no permitirá guardar con RUT inválido")

print("\n" + "=" * 100)
print("  ✅ ANÁLISIS COMPLETADO")
print("=" * 100)
