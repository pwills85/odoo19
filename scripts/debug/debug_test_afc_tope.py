#!/usr/bin/env python3
"""Script para depurar test_afc_tope"""

import xmlrpc.client
from datetime import date

# Conexión
url = 'http://localhost:8069'
db = 'odoo19'
username = 'admin'
password = 'admin'

common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common')
uid = common.authenticate(db, username, password, {})

models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object')

print("=== CREANDO TEST DATA ===")

# Crear indicadores
indicators_id = models.execute_kw(db, uid, password, 'hr.economic.indicators', 'create', [{
    'period': '2025-10-01',
    'uf': 39383.07,
    'utm': 68647,
    'uta': 823764.00,
    'minimum_wage': 500000.00,
    'afp_limit': 87.8,
}])
print(f"Indicadores creados: {indicators_id}")

# Crear AFP
afp_id = models.execute_kw(db, uid, password, 'hr.afp', 'create', [{
    'name': 'Capital Debug',
    'code': 'CAP_DEBUG',
    'rate': 11.44,
}])
print(f"AFP creada: {afp_id}")

# Crear empleado
employee_id = models.execute_kw(db, uid, password, 'hr.employee', 'create', [{
    'name': 'Test AFC Employee',
    'identification_id': '11111111-1',
}])
print(f"Empleado creado: {employee_id}")

# Crear contrato con sueldo alto
contract_id = models.execute_kw(db, uid, password, 'hr.contract', 'create', [{
    'name': 'Test AFC Contract',
    'employee_id': employee_id,
    'wage': 5000000,  # $5M
    'afp_id': afp_id,
    'afp_rate': 11.44,
    'health_system': 'fonasa',
    'weekly_hours': 45,
    'state': 'open',
    'date_start': '2025-01-01',
}])
print(f"Contrato creado: {contract_id} con wage=5000000")

# Crear liquidación
struct_id = models.execute_kw(db, uid, password, 'hr.payroll.structure', 'search', [[['name', '=', 'Chile Base']]], {'limit': 1})
if not struct_id:
    print("ERROR: No se encontró estructura Chile Base")
    exit(1)

payslip_id = models.execute_kw(db, uid, password, 'hr.payslip', 'create', [{
    'name': 'Test AFC Payslip',
    'employee_id': employee_id,
    'contract_id': contract_id,
    'date_from': '2025-10-01',
    'date_to': '2025-10-31',
    'indicadores_id': indicators_id,
    'struct_id': struct_id[0],
}])
print(f"Payslip creado: {payslip_id}")

print("\n=== CALCULANDO LIQUIDACIÓN ===")
models.execute_kw(db, uid, password, 'hr.payslip', 'action_compute_sheet', [[payslip_id]])
print("Liquidación calculada")

print("\n=== LEYENDO PAYSLIP ===")
payslip = models.execute_kw(db, uid, password, 'hr.payslip', 'read', [[payslip_id]], {
    'fields': ['total_imponible', 'total_tributable', 'total_descuentos', 'total_liquido']
})[0]

print(f"Total Imponible: {payslip['total_imponible']:,.2f}")
print(f"Total Tributable: {payslip['total_tributable']:,.2f}")
print(f"Total Descuentos: {payslip['total_descuentos']:,.2f}")
print(f"Total Líquido: {payslip['total_liquido']:,.2f}")

print("\n=== TODAS LAS LÍNEAS ===")
line_ids = models.execute_kw(db, uid, password, 'hr.payslip.line', 'search', [[['slip_id', '=', payslip_id]]])
lines = models.execute_kw(db, uid, password, 'hr.payslip.line', 'read', [line_ids], {
    'fields': ['code', 'name', 'total', 'category_id']
})

for line in sorted(lines, key=lambda x: x['id']):
    category_name = line['category_id'][1] if line['category_id'] else 'Sin categoría'
    print(f"{line['code']:20s} | {line['total']:>15,.2f} | {category_name}")

# Buscar línea AFC
print("\n=== LÍNEA AFC ===")
afc_line = [l for l in lines if l['code'] == 'AFC']
if afc_line:
    print(f"AFC Total: {afc_line[0]['total']:,.2f}")
    print(f"AFC Esperado: {5194620 * 0.006:,.2f}")  # tope * tasa

    # Calcular base usada
    base_usada = abs(afc_line[0]['total']) / 0.006
    print(f"Base usada: {base_usada:,.2f}")
    print(f"Tope AFC: {39383.07 * 131.9:,.2f}")
else:
    print("ERROR: No se encontró línea AFC")

print("\n=== LÍNEAS CON CATEGORÍA IMPONIBLE ===")
for line in lines:
    if line['category_id']:
        category_id = line['category_id'][0]
        category = models.execute_kw(db, uid, password, 'hr.salary.rule.category', 'read', [[category_id]], {
            'fields': ['code', 'imponible']
        })[0]
        if category.get('imponible'):
            print(f"{line['code']:20s} | {line['total']:>15,.2f} | {category['code']}")

print("\n=== LIMPIEZA ===")
models.execute_kw(db, uid, password, 'hr.payslip', 'unlink', [[payslip_id]])
models.execute_kw(db, uid, password, 'hr.contract', 'unlink', [[contract_id]])
models.execute_kw(db, uid, password, 'hr.employee', 'unlink', [[employee_id]])
models.execute_kw(db, uid, password, 'hr.afp', 'unlink', [[afp_id]])
models.execute_kw(db, uid, password, 'hr.economic.indicators', 'unlink', [[indicators_id]])
print("Test data eliminado")
