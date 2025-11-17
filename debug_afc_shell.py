# Script para ejecutar en shell de Odoo
# docker-compose run --rm odoo odoo shell -d odoo19 < debug_afc_shell.py

from datetime import date

print("=== CREANDO TEST DATA ===")

# Crear indicadores
indicators = env['hr.economic.indicators'].create({
    'period': date(2025, 10, 1),
    'uf': 39383.07,
    'utm': 68647,
    'uta': 823764.00,
    'minimum_wage': 500000.00,
    'afp_limit': 87.8,
})
print(f"Indicadores: {indicators.id}")

# Crear AFP
afp = env['hr.afp'].create({
    'name': 'Capital Debug',
    'code': 'CAP_DBG',
    'rate': 11.44,
})
print(f"AFP: {afp.id}")

# Crear empleado
employee = env['hr.employee'].create({
    'name': 'Test AFC Employee',
    'identification_id': '22222222-2',
})
print(f"Empleado: {employee.id}")

# Crear contrato con sueldo alto
contract = env['hr.contract'].create({
    'name': 'Test AFC Contract',
    'employee_id': employee.id,
    'wage': 5000000,  # $5M
    'afp_id': afp.id,
    'afp_rate': 11.44,
    'health_system': 'fonasa',
    'weekly_hours': 45,
    'state': 'open',
    'date_start': date(2025, 1, 1),
})
print(f"Contrato: {contract.id}, wage={contract.wage}")

# Crear liquidación
struct = env.ref('l10n_cl_hr_payroll.structure_base_cl')
payslip = env['hr.payslip'].create({
    'name': 'Test AFC Payslip',
    'employee_id': employee.id,
    'contract_id': contract.id,
    'date_from': date(2025, 10, 1),
    'date_to': date(2025, 10, 31),
    'indicadores_id': indicators.id,
    'struct_id': struct.id,
})
print(f"Payslip: {payslip.id}")

print("\n=== CALCULANDO ===")
payslip.action_compute_sheet()

print("\n=== TOTALES PAYSLIP ===")
print(f"Total Imponible: ${payslip.total_imponible:,.2f}")
print(f"Total Tributable: ${payslip.total_tributable:,.2f}")
print(f"Total Descuentos: ${payslip.total_descuentos:,.2f}")
print(f"Total Líquido: ${payslip.total_liquido:,.2f}")

print("\n=== TODAS LAS LÍNEAS ===")
for line in payslip.line_ids.sorted(key=lambda l: l.sequence):
    cat_code = line.category_id.code if line.category_id else 'N/A'
    cat_imponible = '✓' if line.category_id and line.category_id.imponible else ''
    print(f"{line.code:25s} | {line.total:>15,.2f} | {cat_code:20s} | {cat_imponible}")

print("\n=== ANÁLISIS AFC ===")
afc_line = payslip.line_ids.filtered(lambda l: l.code == 'AFC')
if afc_line:
    print(f"AFC Total: ${abs(afc_line.total):,.2f}")
    base_usada = abs(afc_line.total) / 0.006
    print(f"Base usada: ${base_usada:,.2f}")

    tope_afc = indicators.uf * 131.9
    print(f"Tope AFC: ${tope_afc:,.2f}")
    print(f"AFC esperado: ${tope_afc * 0.006:,.2f}")

    print(f"\nDiferencia base: ${payslip.total_imponible - base_usada:,.2f}")

print("\n=== LÍNEAS IMPONIBLES ===")
total_imponible_manual = 0
for line in payslip.line_ids:
    if line.category_id and line.category_id.imponible and line.total > 0:
        print(f"{line.code:25s} | ${line.total:>15,.2f} | {line.category_id.code}")
        total_imponible_manual += line.total

print(f"\nTotal imponible (manual): ${total_imponible_manual:,.2f}")
print(f"Total imponible (campo):  ${payslip.total_imponible:,.2f}")
print(f"Diferencia: ${payslip.total_imponible - total_imponible_manual:,.2f}")

print("\n=== LIMPIEZA ===")
payslip.unlink()
contract.unlink()
employee.unlink()
afp.unlink()
indicators.unlink()
print("✓ Test data eliminado")

env.cr.commit()
