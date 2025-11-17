# Script para actualizar regla AFC directamente
# docker-compose run --rm odoo odoo shell -d odoo19 < fix_afc_rule.py

print("=== ACTUALIZANDO REGLA AFC ===")

# Buscar regla AFC
afc_rule = env['hr.salary.rule'].search([('code', '=', 'AFC')], limit=1)

if not afc_rule:
    print("ERROR: No se encontró regla AFC")
else:
    print(f"Regla AFC encontrada: {afc_rule.id} - {afc_rule.name}")
    print(f"Código Python actual:")
    print(afc_rule.amount_python_compute)
    print("\n" + "="*70 + "\n")

    # Nuevo código Python
    new_code = """# AFC Trabajador = 0.6% sobre TOTAL_IMPONIBLE (tope 131.9 UF - Actualizado 2025)
# Normativa: AFC tiene tope diferente al AFP (131.9 UF vs 87.8 UF)
# Ref: Superintendencia de Pensiones - Límite máximo mensual AFC 2025
# FIX: Usar TOTAL_IMPONIBLE directamente, NO BASE_TRIBUTABLE (que tiene tope AFP 87.8 UF)

# Obtener tope AFC (131.9 UF)
tope_afc_uf = 131.9
tope_afc = payslip.indicadores_id.uf * tope_afc_uf

# Aplicar tope AFC sobre TOTAL_IMPONIBLE (no BASE_TRIBUTABLE)
base = min(categories.TOTAL_IMPONIBLE, tope_afc)

# Calcular AFC
tasa_afc = 0.006  # 0.6%
result = -(base * tasa_afc)"""

    # Actualizar regla
    afc_rule.write({
        'amount_python_compute': new_code
    })

    print("Código Python actualizado:")
    print(afc_rule.amount_python_compute)
    print("\n✅ Regla AFC actualizada correctamente")

env.cr.commit()
print("\n✅ Cambios guardados en BD")
