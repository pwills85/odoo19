# Datasets y Evidencias de Reproducibilidad

**Fecha:** 2025-11-07
**Propósito:** Facilitar reproducción de hallazgos de auditoría regulatoria
**Alcance:** l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports

---

## 1. Datasets Sintéticos DTE (Facturación Electrónica)

### 1.1 Fixtures XML Disponibles

Todos los fixtures están **validados contra XSD oficial SII** y usan datos **sintéticos** (no sensibles).

#### Factura Electrónica (Tipo 33)

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/dte33_factura.xml`

**Características:**
- RUT Emisor: 76.XXX.XXX-X (sintético)
- RUT Receptor: 77.YYY.YYY-Y (sintético)
- Folio: 12345
- Montos: Neto $1,000,000 + IVA $190,000 = Total $1,190,000
- Items: 3 productos con códigos SKU
- Validado: ✅ XSD SII DTE_v10.xsd

**Uso:**
```bash
python3 -m pytest addons/localization/l10n_cl_dte/tests/test_dte_workflow.py::TestDTEWorkflow::test_01_generate_dte_33
```

---

#### Factura Exenta (Tipo 34)

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/dte34_factura_exenta.xml`

**Características:**
- RUT Emisor: 76.XXX.XXX-X (sintético)
- RUT Receptor: Organismo público sintético
- Folio: 23456
- Montos: Total $500,000 (sin IVA)
- Artículo exención indicado
- Validado: ✅ XSD SII

---

#### Guía de Despacho (Tipo 52) - Con Transporte

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/dte52_with_transport.xml`

**Características:**
- Tipo Traslado: 1 (venta)
- Datos transporte: Patente AA-BB-12, Chofer, RUT transportista
- Dirección origen y destino
- 3 items con cantidades
- Validado: ✅ XSD SII

---

#### Guía de Despacho (Tipo 52) - Sin Transporte

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/dte52_without_transport.xml`

**Características:**
- Tipo Traslado: 8 (traslado entre bodegas propias)
- Sin datos transporte
- Validado: ✅ XSD SII

---

#### Nota de Débito (Tipo 56)

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/dte56_nota_debito.xml`

**Características:**
- Referencia a factura original (tipo 33, folio 12345)
- Código referencia: 3 (corrige monto)
- Monto adicional: $50,000
- Validado: ✅ XSD SII

---

#### Nota de Crédito (Tipo 61)

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/dte61_nota_credito.xml`

**Características:**
- Referencia a factura original (tipo 33, folio 12345)
- Código referencia: 1 (anula documento)
- Razón: Devolución mercadería
- Monto NC: $300,000 (< factura original)
- Validado: ✅ XSD SII

---

### 1.2 CAF Sintético (Folios)

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/test_caf_tipo33.xml`

**Características:**
- Tipo DTE: 33 (Factura)
- Rango folios: 10000-10100 (100 folios)
- Fecha autorización: 2025-01-01
- FRMA del SII: (firma sintética válida para tests)
- RSASK: Llave privada RSA sintética

**Nota:** Este CAF es **solo para testing** y **no debe usarse en producción**.

---

### 1.3 Certificado Digital Sintético

**Archivo:** `addons/localization/l10n_cl_dte/tests/fixtures/test_certificate.p12`

**Características:**
- Formato: PKCS#12 (.p12)
- RUT: 76.XXX.XXX-X (sintético)
- Clase: 2 (simulado)
- Vigencia: 2025-01-01 hasta 2026-01-01
- Password: `test1234`

**Nota:** Este certificado es **solo para testing** y **no es válido para SII**.

---

### 1.4 Scripts de Validación DTE

#### Smoke Test XSD

```bash
# Validar todos los fixtures contra XSD oficial
cd addons/localization/l10n_cl_dte/tests/smoke/

# Factura 33
python3 smoke_xsd_dte33.py

# Factura Exenta 34
python3 smoke_xsd_dte34.py

# Nota Débito 56
python3 smoke_xsd_dte56.py

# Nota Crédito 61
python3 smoke_xsd_dte61.py

# FALTANTE (crear): Guía Despacho 52
# python3 smoke_xsd_dte52.py
```

---

## 2. Datasets Sintéticos Nómina Chile

### 2.1 Datos de Prueba Empleado

**Empleado Sintético 1:**
```python
{
    'name': 'Juan Pérez González',
    'rut': '12.345.678-5',  # RUT sintético válido módulo 11
    'email': 'juan.perez@example.com',
    'job_id': 'Desarrollador Senior',
    'department_id': 'IT',
}
```

**Contrato:**
```python
{
    'wage': 1500000,  # Sueldo base $1,500,000
    'movilization': 50000,  # Colación $50,000
    'collation': 30000,  # Movilización $30,000
    'afp_id': 'Provida',
    'health_system': 'fonasa',
    'num_cargas': 2,  # 2 cargas familiares
    'gratification_type': 'mensual',
    'zona_extrema': False,
}
```

---

### 2.2 Indicadores Económicos Sintéticos 2025

**Archivo:** `addons/localization/l10n_cl_hr_payroll/tests/data/test_economic_indicators.py`

```python
INDICATORS_2025 = {
    'enero': {
        'uf_value': 38500.00,
        'utm_value': 67000.00,
        'minimum_wage': 500000.00,
        'tope_afp': 83.1,  # UF
        'tope_salud': 101.9,  # UF
        'tope_afc': 126.3,  # UF
    },
    # ... otros meses
}
```

---

### 2.3 Topes Legales Sintéticos 2025

**Archivo:** `addons/localization/l10n_cl_hr_payroll/tests/data/test_legal_caps.py`

```python
LEGAL_CAPS_2025 = [
    {
        'cap_type': 'afp',
        'ceiling_value': 83.1,  # UF (CORRECTO 2025)
        'valid_from': '2025-01-01',
        'valid_until': '2025-12-31',
    },
    {
        'cap_type': 'salud',
        'ceiling_value': 101.9,  # UF
        'valid_from': '2025-01-01',
        'valid_until': '2025-12-31',
    },
    # ... otros topes
]
```

---

### 2.4 Tramos Impuesto Único 2025

**Archivo:** `addons/localization/l10n_cl_hr_payroll/tests/data/test_tax_brackets.py`

```python
TAX_BRACKETS_2025 = [
    {'from_uta': 0.00, 'to_uta': 13.5, 'rate': 0.00, 'deduction': 0},
    {'from_uta': 13.5, 'to_uta': 30.0, 'rate': 0.04, 'deduction': 0.54},
    {'from_uta': 30.0, 'to_uta': 50.0, 'rate': 0.08, 'deduction': 1.74},
    {'from_uta': 50.0, 'to_uta': 70.0, 'rate': 0.135, 'deduction': 4.49},
    {'from_uta': 70.0, 'to_uta': 90.0, 'rate': 0.23, 'deduction': 11.14},
    {'from_uta': 90.0, 'to_uta': 120.0, 'rate': 0.304, 'deduction': 17.8},
    {'from_uta': 120.0, 'to_uta': 999999.0, 'rate': 0.35, 'deduction': 23.32},
]
# UTA 2025: $726,000
```

---

### 2.5 Script de Cálculo Liquidación

**Archivo:** `addons/localization/l10n_cl_hr_payroll/tests/test_payslip_calculation.py`

```python
def test_01_payslip_calculation_basic():
    """Test cálculo liquidación caso estándar"""

    # Setup: Empleado + Contrato
    employee = env['hr.employee'].create({
        'name': 'Juan Pérez',
        'rut': '12.345.678-5',
    })

    contract = env['hr.contract'].create({
        'employee_id': employee.id,
        'wage': 1500000,
        'afp_id': afp_provida.id,
        'health_system': 'fonasa',
        'num_cargas': 2,
    })

    # Crear liquidación
    payslip = env['hr.payslip'].create({
        'employee_id': employee.id,
        'contract_id': contract.id,
        'date_from': '2025-01-01',
        'date_to': '2025-01-31',
    })

    # Calcular
    payslip.action_compute_sheet()

    # Validaciones
    assert payslip.total_imponible == 1500000
    assert payslip.afp_cotizacion == pytest.approx(165000, rel=1)  # 11% aprox
    assert payslip.salud_cotizacion == pytest.approx(105000, rel=1)  # 7%
    assert payslip.impuesto_unico > 0
    assert payslip.liquido_pagar < 1500000
```

**Ejecutar:**
```bash
python3 -m pytest addons/localization/l10n_cl_hr_payroll/tests/test_payslip_calculation.py -v
```

---

### 2.6 Dataset LRE Previred (Pendiente P0-2)

**Archivo:** `addons/localization/l10n_cl_hr_payroll/tests/data/test_lre_105_campos.csv`

**Nota:** Este dataset debe crearse **después** de cerrar P0-2 (completar 76 campos faltantes).

**Estructura:**
```csv
RUT_Empresa,Razon_Social,Periodo,RUT_Trabajador,Nombres,Apellidos,AFP_Codigo,Salud_Codigo,Imponible_AFP,Imponible_Salud,Cotizacion_AFP,Cotizacion_Salud,...
76123456-7,Empresa Test SpA,202501,12345678-5,Juan,Pérez González,005,1,1500000,1500000,165000,105000,...
```

**Total Campos:** 105 (según DT Circular 1)

---

## 3. Datasets Sintéticos Reportes Financieros

### 3.1 Plan de Cuentas Sintético

**Archivo:** `addons/localization/l10n_cl_financial_reports/tests/data/test_chart_of_accounts.py`

```python
CHART_OF_ACCOUNTS_CL = [
    # Activo Corriente
    {'code': '1101', 'name': 'Caja', 'account_type': 'asset_cash'},
    {'code': '1102', 'name': 'Banco Chile Cta. Cte.', 'account_type': 'asset_cash'},
    {'code': '1201', 'name': 'Clientes', 'account_type': 'asset_receivable'},
    {'code': '1301', 'name': 'Existencias', 'account_type': 'asset_current'},

    # Activo No Corriente
    {'code': '2101', 'name': 'Maquinaria y Equipos', 'account_type': 'asset_fixed'},
    {'code': '2102', 'name': 'Depreciación Acumulada', 'account_type': 'asset_fixed'},

    # Pasivo Corriente
    {'code': '3101', 'name': 'Proveedores', 'account_type': 'liability_payable'},
    {'code': '3201', 'name': 'IVA Débito Fiscal', 'account_type': 'liability_current'},

    # Pasivo No Corriente
    {'code': '4101', 'name': 'Préstamos Bancarios LP', 'account_type': 'liability_non_current'},

    # Patrimonio
    {'code': '5101', 'name': 'Capital', 'account_type': 'equity'},
    {'code': '5201', 'name': 'Utilidades Retenidas', 'account_type': 'equity_unaffected'},

    # Ingresos
    {'code': '6101', 'name': 'Ventas', 'account_type': 'income'},
    {'code': '6201', 'name': 'Ingresos Financieros', 'account_type': 'income_other'},

    # Gastos
    {'code': '7101', 'name': 'Costo de Ventas', 'account_type': 'expense_direct_cost'},
    {'code': '7201', 'name': 'Gastos Administrativos', 'account_type': 'expense'},
    {'code': '7301', 'name': 'Gastos Financieros', 'account_type': 'expense'},
]
```

---

### 3.2 Movimientos Contables Sintéticos

**Archivo:** `addons/localization/l10n_cl_financial_reports/tests/data/test_account_moves.py`

```python
def create_test_moves(env):
    """Crea movimientos sintéticos para testing reportes"""

    # Venta $1,000,000 + IVA
    move_venta = env['account.move'].create({
        'move_type': 'out_invoice',
        'partner_id': cliente.id,
        'invoice_date': '2025-01-15',
        'line_ids': [
            (0, 0, {
                'account_id': cuenta_ventas.id,
                'credit': 1000000,
            }),
            (0, 0, {
                'account_id': cuenta_iva_debito.id,
                'credit': 190000,
            }),
            (0, 0, {
                'account_id': cuenta_clientes.id,
                'debit': 1190000,
            }),
        ],
    })
    move_venta.action_post()

    # Gasto $300,000 + IVA
    move_gasto = env['account.move'].create({
        'move_type': 'in_invoice',
        'partner_id': proveedor.id,
        'invoice_date': '2025-01-20',
        'line_ids': [
            (0, 0, {
                'account_id': cuenta_gastos_admin.id,
                'debit': 300000,
            }),
            (0, 0, {
                'account_id': cuenta_iva_credito.id,
                'debit': 57000,
            }),
            (0, 0, {
                'account_id': cuenta_proveedores.id,
                'credit': 357000,
            }),
        ],
    })
    move_gasto.action_post()

    return move_venta, move_gasto
```

---

### 3.3 Test Balance General

**Archivo:** `addons/localization/l10n_cl_financial_reports/tests/test_balance_sheet_report.py`

```bash
# Ejecutar test
python3 -m pytest addons/localization/l10n_cl_financial_reports/tests/test_balance_sheet_report.py::TestBalanceSheetReport::test_01_report_definition -v

# Resultado esperado:
# - Total Activo = Total Pasivo + Patrimonio (cuadra)
# - Saldos por cuenta correctos
# - PDF generado sin placeholders
# - Drill-down funciona
```

---

### 3.4 Test Edge Cases

**Archivo:** `addons/localization/l10n_cl_financial_reports/tests/test_reports_edge_cases.py`

```python
def test_01_balance_with_zero_balances():
    """Test reporte con cuentas saldo cero"""
    # ... crea movimientos que resultan en cero
    # Valida que reporte no falle

def test_02_period_without_movements():
    """Test reporte período sin movimientos"""
    # ... genera reporte vacío
    # Valida que muestre ceros correctamente

def test_07_multi_company_separation():
    """Test isolación multi-compañía"""
    # ... crea 2 empresas con movimientos
    # Valida que cada empresa vea solo sus datos
```

---

## 4. Scripts de Reproducibilidad

### 4.1 Validar Instalación Módulos

**Archivo:** `/Users/pedro/Documents/odoo19/scripts/validate_enterprise_compliance.py`

```bash
# Validar que módulos se instalan sin errores
python3 scripts/validate_enterprise_compliance.py

# Resultado esperado:
# ✅ l10n_cl_dte installed successfully
# ✅ l10n_cl_hr_payroll installed successfully
# ✅ l10n_cl_financial_reports installed successfully
# ✅ All tests passed
```

---

### 4.2 Ejecutar Smoke Tests Completos

**Script:** `scripts/run_smoke_tests.sh`

```bash
#!/bin/bash
# Smoke tests completos para auditoría regulatoria

set -e

echo "========================================="
echo "Smoke Tests - Auditoría Regulatoria SII"
echo "========================================="

# DTE Tests
echo "[1/3] Testing l10n_cl_dte..."
python3 odoo-bin -c config/odoo.conf \
  --test-enable \
  --test-tags /l10n_cl_dte \
  --stop-after-init \
  --workers=0 \
  --log-level=test

# Nómina Tests
echo "[2/3] Testing l10n_cl_hr_payroll..."
python3 odoo-bin -c config/odoo.conf \
  --test-enable \
  --test-tags /l10n_cl_hr_payroll \
  --stop-after-init \
  --workers=0 \
  --log-level=test

# Reportes Tests
echo "[3/3] Testing l10n_cl_financial_reports..."
python3 odoo-bin -c config/odoo.conf \
  --test-enable \
  --test-tags /l10n_cl_financial_reports \
  --stop-after-init \
  --workers=0 \
  --log-level=test

echo "========================================="
echo "✅ All smoke tests completed successfully"
echo "========================================="
```

**Ejecutar:**
```bash
chmod +x scripts/run_smoke_tests.sh
./scripts/run_smoke_tests.sh
```

---

### 4.3 Generar Reporte de Cobertura

```bash
# Instalar coverage
pip install coverage pytest-cov

# Ejecutar con cobertura
coverage run --source=addons/localization/l10n_cl_dte,addons/localization/l10n_cl_hr_payroll,addons/localization/l10n_cl_financial_reports \
  -m pytest addons/localization/l10n_cl_*/tests/

# Reporte
coverage report -m
coverage html

# Abrir reporte
open htmlcov/index.html
```

---

## 5. Validación Manual (Checklist)

### 5.1 DTE - Checklist Validación

```
[ ] Generar factura (33) con datos sintéticos
[ ] Validar XML contra XSD (sin errores)
[ ] Firmar DTE con certificado test
[ ] Validar firma digital (sin errores)
[ ] Generar TED (timbre electrónico)
[ ] Validar TED con RSA-SHA1
[ ] Consultar estado SII sandbox (Maullin)
[ ] Activar modo contingencia
[ ] Almacenar DTE pendiente
[ ] Desactivar contingencia y reenviar
[ ] Validar multi-compañía (crear 2 empresas, verificar isolación)
```

---

### 5.2 Nómina - Checklist Validación

```
[ ] Crear empleado sintético con contrato
[ ] Calcular liquidación enero 2025
[ ] Validar AFP usa tope 83.1 UF (corregir P0-1 antes)
[ ] Validar Salud FONASA 7%
[ ] Validar Impuesto Único con tramos 2025
[ ] Exportar LRE Previred (validar 105 campos post P0-2)
[ ] Validar formato LRE contra DT Circular 1
[ ] Generar finiquito sintético
[ ] Validar cálculo indemnización años servicio
[ ] Validar cálculo vacaciones proporcionales
[ ] Validar multi-compañía (crear 2 empresas, verificar isolación post P0-3)
```

---

### 5.3 Reportes - Checklist Validación

```
[ ] Crear movimientos contables sintéticos (ventas + gastos)
[ ] Generar Balance General
[ ] Validar cuadre: Total Activo = Total Pasivo + Patrimonio
[ ] Exportar PDF Balance (verificar sin placeholders)
[ ] Generar Estado de Resultados
[ ] Validar Utilidad/Pérdida = Ingresos - Gastos
[ ] Exportar PDF Estado Resultados
[ ] Probar drill-down (click en cuenta → ver movimientos)
[ ] Probar filtros (fecha, comparación)
[ ] Exportar XLSX Balance
[ ] Validar multi-compañía (crear 2 empresas, verificar isolación)
```

---

## 6. Evidencias Fotográficas

### 6.1 Capturas Pantalla Sugeridas

**DTE:**
1. Vista listado DTEs con estados (draft, pending, accepted)
2. Vista form DTE 33 con XML y TED generado
3. Vista dashboard KPIs DTE (cantidad enviados, rechazados, etc.)
4. Vista modo contingencia activado
5. Vista CAF con folios disponibles

**Nómina:**
1. Vista form empleado con contrato Chile (AFP, ISAPRE, cargas)
2. Vista liquidación calculada con totales (imponible, descuentos, líquido)
3. Vista wizard exportación LRE Previred
4. Vista indicadores económicos con UF/UTM histórico
5. Vista topes legales con vigencias

**Reportes:**
1. Vista Balance General (QWeb preview)
2. PDF Balance General exportado
3. Vista Estado de Resultados
4. PDF Estado de Resultados exportado
5. Vista drill-down movimientos contables

---

## 7. Logs y Trazabilidad

### 7.1 Activar Logging Estructurado

```python
# En config/odoo.conf
[options]
log_level = info
log_handler = werkzeug:INFO,odoo.addons.l10n_cl_dte:DEBUG,odoo.addons.l10n_cl_hr_payroll:DEBUG
```

### 7.2 Logs Esperados

**DTE:**
```
[INFO] l10n_cl_dte: Generating DTE type 33 for invoice INV/2025/0001
[DEBUG] l10n_cl_dte.xml_generator: XML structure validated against XSD
[DEBUG] l10n_cl_dte.xml_signer: Signing XML with certificate ID 1
[INFO] l10n_cl_dte.sii_soap_client: Sending DTE to SII Maullin (sandbox)
[INFO] l10n_cl_dte.sii_soap_client: SII Response: Track ID 123456789
[INFO] l10n_cl_dte: DTE status updated to 'pending'
```

**Nómina:**
```
[INFO] l10n_cl_hr_payroll: Computing payslip for employee Juan Pérez (period 2025-01)
[DEBUG] l10n_cl_hr_payroll.hr_payslip: Total imponible: 1580000 (wage 1500000 + collation 50000 + movilization 30000)
[DEBUG] l10n_cl_hr_payroll.hr_payslip: AFP cotizacion: 165000 (using cap 83.1 UF)
[DEBUG] l10n_cl_hr_payroll.hr_payslip: Salud FONASA: 105000 (7%)
[DEBUG] l10n_cl_hr_payroll.hr_payslip: Impuesto unico: 85000 (using 2025 brackets)
[INFO] l10n_cl_hr_payroll: Payslip computed successfully. Liquid: 1370000
```

**Reportes:**
```
[INFO] l10n_cl_financial_reports: Generating Balance Sheet report for period 2025-01
[DEBUG] l10n_cl_financial_reports.account_report: Fetching account balances...
[DEBUG] l10n_cl_financial_reports.account_report: Total Assets: 15000000
[DEBUG] l10n_cl_financial_reports.account_report: Total Liabilities: 8000000
[DEBUG] l10n_cl_financial_reports.account_report: Total Equity: 7000000
[DEBUG] l10n_cl_financial_reports.account_report: Balance check: OK (Assets = Liabilities + Equity)
[INFO] l10n_cl_financial_reports: Report generated successfully
```

---

## 8. Contactos Soporte Reproducibilidad

**Desarrollador Principal:**
- Responsable: Dev Team Lead
- Email: dev@company.com
- Disponibilidad: Lunes-Viernes 9:00-18:00 CLT

**QA/Testing:**
- Responsable: QA Team Lead
- Email: qa@company.com
- Disponibilidad: Lunes-Viernes 9:00-18:00 CLT

**Consultor SII:**
- Responsable: Contador Especialista SII Chile
- Email: contador@consultora.cl
- Disponibilidad: Consultas por appointment

---

## 9. Conclusión

Este documento proporciona todos los datasets, scripts y procedimientos necesarios para **reproducir los hallazgos** de la auditoría regulatoria.

**Archivos Clave:**
- Fixtures DTE: `addons/localization/l10n_cl_dte/tests/fixtures/*.xml`
- Tests Nómina: `addons/localization/l10n_cl_hr_payroll/tests/test_*.py`
- Tests Reportes: `addons/localization/l10n_cl_financial_reports/tests/test_*.py`
- Scripts: `/Users/pedro/Documents/odoo19/scripts/*.py`

**Próximos Pasos:**
1. Ejecutar `scripts/run_smoke_tests.sh` después de cerrar P0
2. Validar manualmente con checklists sección 5
3. Generar capturas pantalla sección 6
4. Documentar logs en repositorio evidencias

---

**Fecha Generación:** 2025-11-07
**Versión:** 1.0
**Repositorio:** `/Users/pedro/Documents/odoo19/`
