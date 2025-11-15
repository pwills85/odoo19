# Plan de Verificación Compliance Integral - Stack Completo
**Fecha:** 2025-11-14
**Scope:** Análisis exhaustivo funcional, legal y técnico
**Objetivo:** Identificar errores, deficiencias, mejoras y optimizaciones

---

## 🤔 PARTE 1: ANÁLISIS PROFUNDO - PREGUNTAS RETÓRICAS

### 1. l10n_cl_dte - Documentos Tributarios Electrónicos

#### Función Core
- ¿El módulo genera, valida, firma y envía DTEs al SII según especificaciones técnicas Nov 2025?
- ¿Soporta TODOS los tipos de DTE mandatorios (33, 34, 39, 41, 43, 46, 52, 56, 61)?
- ¿Implementa correctamente el ciclo completo: CAF → Generación → Firma → Envío → Tracking?

#### Features Mandatorias
- ¿Genera XML según schema XSD v1.0 SII (última versión)?
- ¿Firma con certificado digital válido (formato .pfx/.p12)?
- ¿Consume folios de CAF correctamente sin saltos ni duplicados?
- ¿Envía a ambiente certificación vs producción según configuración?
- ¿Recibe y procesa respuestas del SII (ACK, aceptación, rechazo, reparos)?
- ¿Genera set de pruebas (setDTE) correctamente?
- ¿Implementa Cesión de Créditos (Factoring)?
- ¿Implementa Libros Electrónicos (CV, IECV)?

#### Integración Odoo 19 CE
- ¿Se integra con módulo account (Facturas de Cliente/Proveedor)?
- ¿Se integra con stock (Guías de Despacho, Traslados)?
- ¿Se integra con sale (Cotizaciones → Factura)?
- ¿Se integra con purchase (Facturas de compra)?
- ¿Hereda campos fiscales (RUT, Giro, dirección fiscal)?
- ¿Usa secuencias de Odoo para numeración interna?

#### Integración Stack AI
- ¿Usa AI Service para validación semántica de DTEs?
- ¿AI Service valida coherencia de montos, fechas, RUTs?
- ¿AI Service detecta errores antes de envío al SII?
- ¿Hay cache Redis para validaciones repetidas?
- ¿Usa RabbitMQ para procesamiento asíncrono de envíos masivos?

#### Cumplimiento Legal (Nov 2025)
- ¿Cumple Resolución Exenta SII N°11 (2024) - Factura Electrónica?
- ¿Cumple Resolución Exenta SII N°45 (2003) - DTEs?
- ¿Cumple Circular N°55 (2020) - Certificación Digital?
- ¿Cumple Ley 19.983 - Firma Electrónica?
- ¿Cumple Código Tributario Art. 59 - Contabilidad Electrónica?
- ¿Implementa validaciones F29/F50 según circulares vigentes?
- ¿Contempla tasas de IVA actuales (19%)?
- ¿Contempla exenciones/no afectos según ley?

#### Cálculos Mandatorios
- IVA: Neto * 0.19 → redondeo según norma
- Descuentos: Globales vs por línea
- Recargos: Por mora, intereses
- Retenciones: ¿Implementa retenciones de IVA (Art. 3°)?
- Créditos: ¿Implementa crédito especial empresas constructoras?

---

### 2. l10n_cl_hr_payroll - Nómina y Remuneraciones

#### Función Core
- ¿Calcula liquidaciones de sueldo según Código del Trabajo?
- ¿Genera archivo LRE (Libro Remuneraciones Electrónico) para Previred?
- ¿Calcula AFP, Salud, Cesantía, SIS según tasas vigentes?
- ¿Calcula Impuesto Único según tramos 2025?
- ¿Gestiona Gratificaciones Legal/Convencional?
- ¿Calcula Asignación Familiar según cargas y tramos?

#### Features Mandatorias
- ¿Importa indicadores Previred mensualmente (UF, UTM, UTA)?
- ¿Calcula PPM (Pago Provisional Mensual) correctamente?
- ¿Aplica topes de cotización (AFP 81.6 UF, Salud sin tope)?
- ¿Calcula Horas Extra (50%, 100%) según jornada?
- ¿Maneja diferentes tipos de contrato (Indefinido, Plazo Fijo, Honorarios)?
- ¿Genera Certificados (Renta, Cotizaciones, Finiquito)?
- ¿Procesa Licencias Médicas (subsidios)?
- ¿Calcula Finiquitos con años de servicio?

#### Integración Odoo 19 CE
- ¿Se integra con hr (Empleados, Contratos)?
- ¿Se integra con hr_attendance (Control de asistencia)?
- ¿Se integra con account (Asientos contables de nómina)?
- ¿Genera journal entries automáticas para provisiones?
- ¿Se integra con expenses (Reembolsos)?

#### Integración Stack AI
- ¿AI Service valida liquidaciones contra normativa?
- ¿AI Service calcula Impuesto Único con tabla vigente?
- ¿AI Service detecta inconsistencias en contratos?
- ¿Cache Redis almacena tasas/indicadores del mes?
- ¿RabbitMQ procesa cálculos masivos de lotes?

#### Cumplimiento Legal (Nov 2025)
- ¿Cumple Código del Trabajo (Ley 16.744, 19.010, etc)?
- ¿Cumple DFL N°1 (1994) - Código del Trabajo actualizado?
- ¿Cumple Ley 20.255 - Reforma Previsional?
- ¿Cumple Ley 21.133 - Sala Cuna Universal?
- ¿Cumple Circular Previred N°2024-XX (última vigente)?
- ¿Cumple tasas AFP/Salud/Cesantía vigentes Nov 2025?
- ¿Cumple tramos Impuesto Único 2025 (actualizado anualmente)?
- ¿Cumple Sueldo Mínimo vigente ($460.000 aprox)?
- ¿Cumple Asignación Familiar tramos 2025?

#### Cálculos Mandatorios
```python
# AFP (10% empleado + X% comisión según AFP)
afp_empleado = min(sueldo_base, tope_afp_uf * uf) * tasa_afp

# Salud (7% mínimo legal)
salud = sueldo_base * 0.07  # + plan complementario

# Cesantía
cesantia_empleador = sueldo_base * 0.024  # (2.4%)
cesantia_trabajador = sueldo_base * 0.006  # (0.6%)

# SIS (Seguro Invalidez y Sobrevivencia)
sis = sueldo_base * tasa_sis_afp  # Variable por AFP

# Impuesto Único (tramos progresivos)
renta_imponible = sueldo_bruto - afp - salud - ...
impuesto = calcular_por_tramos(renta_imponible, tabla_2025)

# Gratificación Legal (25% utilidades, tope 4.75 IML)
gratificacion_legal = min(utilidades * 0.25, 4.75 * sueldo_minimo)

# Asignación Familiar
asig_familiar = num_cargas * monto_segun_tramo(sueldo)
```

---

### 3. l10n_cl_financial_reports - Reportes Financieros y Tributarios

#### Función Core
- ¿Genera F29 (Declaración Mensual de IVA)?
- ¿Genera F50 (Declaración Jurada Anual Renta)?
- ¿Genera Balance Tributario según normas SII?
- ¿Genera Libro Compra/Venta según formato oficial?
- ¿Calcula PPM (Provisional Mensual) correctamente?
- ¿Genera reportes de análisis financiero (liquidez, rentabilidad)?

#### Features Mandatorias
- ¿Cruza DTEs emitidos con Libro Ventas?
- ¿Cruza DTEs recibidos con Libro Compras?
- ¿Calcula débito fiscal (IVA ventas)?
- ¿Calcula crédito fiscal (IVA compras) con restricciones?
- ¿Calcula IVA a pagar/recuperar?
- ¿Detecta diferencias vs declaraciones SII?
- ¿Genera análisis de flujo de caja?
- ¿Genera KPIs financieros (EBITDA, ROE, etc)?

#### Integración Odoo 19 CE
- ¿Se integra con account (Contabilidad general)?
- ¿Usa account.move.line para análisis?
- ¿Se integra con l10n_cl_dte para validar DTEs?
- ¿Genera reportes desde SQL optimizado (performance)?

#### Integración Stack AI
- ¿AI Service genera insights de F29?
- ¿AI Service detecta anomalías tributarias?
- ¿AI Service sugiere optimizaciones fiscales?
- ¿Cache Redis almacena reportes pre-calculados?

#### Cumplimiento Legal (Nov 2025)
- ¿Cumple formato F29 según Resolución SII vigente?
- ¿Cumple requisitos F50 (DJ Anual)?
- ¿Cumple Circular N°33 (2018) - Libros Electrónicos?
- ¿Cumple Art. 14 Ley Renta - Cálculo de Renta Líquida?
- ¿Cumple restricciones de crédito fiscal (proporción)?
- ¿Contempla 31 de Diciembre como cierre contable?

#### Cálculos Mandatorios
```python
# F29 - IVA
debito_fiscal = sum(iva_ventas)  # Codigos 10-49
credito_fiscal = sum(iva_compras)  # Codigos 50-69
iva_a_pagar = debito_fiscal - credito_fiscal  # Codigo 89

# PPM (Primera Categoría)
renta_liquida_imponible = ingresos - gastos_aceptados
ppm = renta_liquida_imponible * tasa_ppm  # Variable según actividad

# Proporción Crédito Fiscal (ventas afectas/exentas)
proporcion = ventas_afectas / (ventas_afectas + ventas_exentas)
credito_proporcional = credito_fiscal * proporcion
```

---

## 📋 PARTE 2: PLAN DE VERIFICACIÓN ESTRUCTURADO

### Metodología

**Niveles de Verificación:**
1. **L1 - Smoke Test:** ¿Módulo se instala y activa sin errores?
2. **L2 - Unit Test:** ¿Funciones core ejecutan correctamente?
3. **L3 - Integration Test:** ¿Módulos se comunican correctamente?
4. **L4 - Compliance Test:** ¿Cumple normativa legal vigente?
5. **L5 - Performance Test:** ¿Soporta volumen de producción?
6. **L6 - Security Test:** ¿Protege datos sensibles adecuadamente?

---

### 🔍 PLAN A: l10n_cl_dte

#### A.1. Verificación Funcional Core

**A.1.1. Generación de XML**
```bash
# Test: Generar Factura Electrónica (Tipo 33)
- Crear factura de venta en Odoo
- Trigger: Botón "Generar DTE"
- Verificar: XML generado cumple XSD v1.0 SII
- Validar: Estructura, campos obligatorios, formato de fecha
- Resultado esperado: XML válido sin errores de esquema
```

**A.1.2. Firma Digital**
```bash
# Test: Firmar DTE con certificado
- Cargar certificado .pfx válido
- Configurar: Clave, ambiente (certificación)
- Firmar: XML generado
- Verificar: Tag <Signature> presente y válido
- Validar: Certificado no expirado, cadena de confianza
- Resultado esperado: DTE firmado correctamente
```

**A.1.3. Consumo de Folios (CAF)**
```bash
# Test: Asignación secuencial de folios
- Cargar archivo CAF con rango 1-100
- Generar 5 facturas consecutivas
- Verificar: Folios 1,2,3,4,5 asignados sin saltos
- Validar: No reutilización, no duplicados
- Alertar: Cuando quedan <20% folios
- Resultado esperado: Folios secuenciales correctos
```

**A.1.4. Envío al SII**
```bash
# Test: Enviar DTE a certificación SII
- Configurar: URL certificación maullin.sii.cl
- Enviar: setDTE con 1 factura firmada
- Recibir: Track ID del SII
- Verificar: ACK recibido (código 0 = OK)
- Polling: Estado cada 5 min hasta aceptado/rechazado
- Resultado esperado: Aceptado por SII
```

**A.1.5. Procesamiento de Respuestas SII**
```bash
# Test: Interpretar respuestas SII
- Caso 1: Aceptado (RPT) - Actualizar estado DTE
- Caso 2: Rechazado (RCT) - Mostrar errores específicos
- Caso 3: Reparos (RPA) - Alertar pero continuar
- Verificar: Estado en Odoo refleja respuesta SII
- Resultado esperado: Estados sincronizados
```

#### A.2. Verificación de Tipos de DTE

| Tipo | Nombre | ¿Implementado? | Test |
|------|--------|----------------|------|
| 33 | Factura Electrónica | ¿? | Generar desde sale.order |
| 34 | Factura Exenta | ¿? | Con productos exentos IVA |
| 39 | Boleta Electrónica | ¿? | POS / Venta al detalle |
| 41 | Boleta Exenta | ¿? | Productos exentos |
| 43 | Liquidación-Factura | ¿? | Compras sector primario |
| 46 | Factura Compra | ¿? | Compras con IVA |
| 52 | Guía Despacho | ¿? | Desde stock.picking |
| 56 | Nota Débito | ¿? | Aumentar factura |
| 61 | Nota Crédito | ¿? | Anular/reducir factura |

**Test para cada tipo:**
```python
def test_dte_type_XX():
    # Crear documento origen
    doc = crear_documento_odoo(tipo=XX)

    # Generar DTE
    dte = doc.action_create_dte()

    # Validaciones
    assert dte.tipo_dte == XX
    assert dte.folio > 0
    assert dte.xml_generado is not None
    assert validar_xsd(dte.xml_generado)

    # Firmar y enviar
    dte.action_sign()
    dte.action_send_sii()

    # Verificar estado
    time.sleep(60)  # Esperar procesamiento SII
    assert dte.estado_sii in ['Aceptado', 'Aceptado con Reparos']
```

#### A.3. Verificación Integración Odoo

**A.3.1. Integración con account.move**
```python
# Test: Factura de Cliente genera DTE
def test_invoice_to_dte():
    partner = create_partner(country='CL', vat='76XXX-K')
    invoice = create_invoice(partner, products=[...])
    invoice.action_post()  # Validar factura

    # ¿Botón "Generar DTE" disponible?
    assert invoice.can_generate_dte()

    # Generar DTE
    dte = invoice.action_create_dte()

    # Verificar vinculación
    assert dte.invoice_id == invoice
    assert invoice.dte_id == dte
    assert invoice.numero_dte == dte.folio
```

**A.3.2. Integración con stock.picking**
```python
# Test: Orden de Entrega genera Guía Despacho
def test_picking_to_guia():
    picking = create_delivery_order(products=[...])
    picking.action_confirm()
    picking.action_assign()
    picking.button_validate()

    # ¿Genera Guía automáticamente o manual?
    assert hasattr(picking, 'dte_guia_id')

    guia = picking.action_create_guia_despacho()
    assert guia.tipo_dte == 52
    assert guia.picking_id == picking
```

#### A.4. Verificación Compliance Legal

**A.4.1. Validación contra XSD Oficial SII**
```bash
# Test: XML cumple esquema oficial
wget http://www.sii.cl/factura_electronica/schema/DTE_v10.xsd
xmllint --schema DTE_v10.xsd dte_generado.xml --noout
# Resultado esperado: validates
```

**A.4.2. Validación Campos Obligatorios**
```python
# Test: Campos mandatorios según SII
campos_obligatorios = {
    'RUTEmisor': 'RUT empresa formato 11111111-1',
    'RUTReceptor': 'RUT cliente',
    'FchEmis': 'Fecha emisión YYYY-MM-DD',
    'MntTotal': 'Monto total > 0',
    'IVA': 'IVA calculado (si aplica)',
    'FmaPago': 'Forma pago (1=Contado, 2=Crédito)',
}

for campo, validacion in campos_obligatorios.items():
    assert campo in xml_dte
    # Validar formato específico
```

**A.4.3. Validación Cálculo IVA**
```python
# Test: IVA calculado correctamente
def test_iva_calculation():
    neto = 1000
    iva = round(neto * 0.19, 0)  # Redondeo según norma
    total = neto + iva

    factura = create_factura(neto=neto)
    assert factura.amount_untaxed == neto
    assert factura.amount_tax == iva  # 190
    assert factura.amount_total == total  # 1190
```

#### A.5. Verificación Integración Stack AI

**A.5.1. Validación Semántica Pre-Envío**
```python
# Test: AI Service valida DTE antes de enviar SII
def test_ai_validation():
    dte = create_dte_with_errors()  # RUT inválido, fecha futura, etc

    # Enviar a AI Service para validación
    response = ai_service.validate_dte(dte.to_dict())

    # Verificar respuesta
    assert response['valid'] == False
    assert len(response['errors']) > 0
    assert 'RUT' in response['errors'][0]
```

**A.5.2. Cache Redis de Validaciones**
```python
# Test: Validaciones repetidas usan cache
def test_redis_cache():
    dte_dict = {...}

    # Primera validación (sin cache)
    t1 = time.time()
    result1 = ai_service.validate_dte(dte_dict)
    duration1 = time.time() - t1

    # Segunda validación (con cache)
    t2 = time.time()
    result2 = ai_service.validate_dte(dte_dict)
    duration2 = time.time() - t2

    assert result1 == result2
    assert duration2 < duration1 * 0.5  # >50% más rápido
```

**A.5.3. RabbitMQ Procesamiento Asíncrono**
```python
# Test: Envío masivo de DTEs por cola
def test_rabbitmq_batch():
    dtes = [create_dte() for _ in range(100)]

    # Enviar a cola
    for dte in dtes:
        rabbitmq.publish('dte.send', dte.to_dict())

    # Verificar procesamiento
    time.sleep(30)  # Esperar workers

    processed = DTE.search([('id', 'in', [d.id for d in dtes])])
    assert all(d.estado_sii != 'pending' for d in processed)
```

---

### 🔍 PLAN B: l10n_cl_hr_payroll

#### B.1. Verificación Cálculo de Liquidaciones

**B.1.1. Cálculo AFP**
```python
# Test: AFP calculada correctamente
def test_afp_calculation():
    # Parámetros vigentes Nov 2025
    sueldo_base = 1_000_000
    tope_afp_uf = 81.6
    uf_nov_2025 = 37_500  # Aproximado
    tope_afp_pesos = tope_afp_uf * uf_nov_2025

    # AFP Capital (ejemplo)
    tasa_afp = 0.1144  # 10% empleado + 1.44% comisión

    base_imponible = min(sueldo_base, tope_afp_pesos)
    afp_esperada = round(base_imponible * tasa_afp, 0)

    # Crear liquidación
    liquidacion = crear_liquidacion(sueldo=sueldo_base, afp='Capital')

    assert liquidacion.afp == afp_esperada
```

**B.1.2. Cálculo Impuesto Único**
```python
# Test: Impuesto Único tramos 2025
def test_impuesto_unico():
    # Tramos vigentes (actualizar con ley 2025)
    TRAMOS_2025 = [
        {'desde': 0, 'hasta': 13.5 * UF, 'tasa': 0.0, 'rebaja': 0},
        {'desde': 13.5 * UF, 'hasta': 30 * UF, 'tasa': 0.04, 'rebaja': 0.54 * UF},
        {'desde': 30 * UF, 'hasta': 50 * UF, 'tasa': 0.08, 'rebaja': 1.74 * UF},
        # ... más tramos
    ]

    renta_imponible = 1_500_000  # Después de deducciones
    impuesto_esperado = calcular_por_tramos(renta_imponible, TRAMOS_2025)

    liquidacion = crear_liquidacion(renta_imponible=renta_imponible)

    assert abs(liquidacion.impuesto_unico - impuesto_esperado) < 10  # Tolerancia redondeo
```

**B.1.3. Cálculo Gratificación Legal**
```python
# Test: Gratificación Legal (25% utilidades, tope 4.75 IML)
def test_gratificacion_legal():
    utilidades_empresa = 100_000_000
    empleados = 50
    sueldo_minimo = 460_000  # Nov 2025 aprox
    tope = 4.75 * sueldo_minimo

    gratificacion_proporcional = utilidades_empresa * 0.25 / empleados
    gratificacion_final = min(gratificacion_proporcional, tope)

    liquidacion = crear_liquidacion(tipo_gratificacion='legal')

    assert liquidacion.gratificacion == gratificacion_final
```

#### B.2. Verificación Generación LRE Previred

**B.2.1. Formato Archivo LRE**
```python
# Test: Archivo LRE cumple especificación Previred
def test_lre_format():
    liquidaciones = [crear_liquidacion() for _ in range(10)]

    # Generar LRE
    lre_file = generate_lre(liquidaciones, periodo='2025-11')

    # Validaciones formato
    lines = lre_file.split('\n')

    # Header
    assert lines[0].startswith('01')  # Tipo registro header
    assert '76XXXXXX' in lines[0]  # RUT empresa

    # Detalle empleados
    for i, liq in enumerate(liquidaciones):
        line = lines[i+1]
        assert line.startswith('02')  # Tipo registro detalle
        assert liq.employee_id.rut in line
        assert str(liq.sueldo_base) in line
```

**B.2.2. Validación Montos LRE**
```python
# Test: Montos LRE coinciden con liquidaciones
def test_lre_amounts():
    liquidaciones = crear_liquidaciones_mes(periodo='2025-11')
    lre = generate_lre(liquidaciones)

    # Parsear LRE
    totales_lre = parse_lre_totals(lre)

    # Calcular desde liquidaciones
    totales_calculados = {
        'remuneracion_imponible': sum(l.sueldo_imponible for l in liquidaciones),
        'total_afp': sum(l.afp for l in liquidaciones),
        'total_salud': sum(l.salud for l in liquidaciones),
        'total_cesantia': sum(l.cesantia for l in liquidaciones),
    }

    for key, value in totales_calculados.items():
        assert abs(totales_lre[key] - value) < 100  # Tolerancia redondeo
```

#### B.3. Verificación Integración Odoo

**B.3.1. Integración con hr.contract**
```python
# Test: Contrato define parámetros de liquidación
def test_contract_to_payslip():
    contract = create_contract(
        wage=1_000_000,
        afp='Capital',
        isapre='Banmédica',
        gratification_type='legal'
    )

    payslip = create_payslip(contract)
    payslip.compute_sheet()

    assert payslip.sueldo_base == contract.wage
    assert payslip.afp_id == contract.afp_id
```

**B.3.2. Integración con account (Asientos Contables)**
```python
# Test: Liquidación genera asientos contables
def test_payslip_journal_entry():
    payslip = create_payslip()
    payslip.action_payslip_done()

    # Verificar asiento creado
    assert payslip.move_id is not None

    move = payslip.move_id

    # Verificar cuentas débito/crédito
    debit_lines = move.line_ids.filtered(lambda l: l.debit > 0)
    credit_lines = move.line_ids.filtered(lambda l: l.credit > 0)

    # Gasto sueldos (débito)
    assert any('6210' in l.account_id.code for l in debit_lines)

    # Provisión AFP (crédito)
    assert any('2110' in l.account_id.code for l in credit_lines)

    # Balance cuadrado
    assert sum(l.debit for l in move.line_ids) == sum(l.credit for l in move.line_ids)
```

#### B.4. Verificación Compliance Legal

**B.4.1. Validación Tasas Vigentes**
```python
# Test: Tasas AFP/Salud/Cesantía vigentes Nov 2025
def test_tasas_vigentes():
    # Obtener desde AI Service (fuente: Previred)
    tasas = ai_service.get_tasas_previred(periodo='2025-11')

    # Validar tasas esperadas
    assert tasas['afp_capital']['empleado'] == 0.10
    assert tasas['afp_capital']['comision'] >= 0.0077  # Variable
    assert tasas['salud_legal'] == 0.07
    assert tasas['cesantia_empleador'] == 0.024
    assert tasas['cesantia_trabajador'] == 0.006
```

**B.4.2. Validación Indicadores Económicos**
```python
# Test: UF, UTM, UTA actualizadas
def test_indicadores_economicos():
    indicadores = get_indicadores(periodo='2025-11')

    # Validar presencia
    assert 'uf' in indicadores
    assert 'utm' in indicadores
    assert 'uta' in indicadores

    # Validar rangos razonables (Nov 2025)
    assert 37_000 < indicadores['uf'] < 40_000
    assert 65_000 < indicadores['utm'] < 70_000
    assert 800_000 < indicadores['uta'] < 900_000
```

---

### 🔍 PLAN C: l10n_cl_financial_reports

#### C.1. Verificación Generación F29

**C.1.1. Cálculo Débito Fiscal**
```python
# Test: Débito Fiscal = IVA Ventas
def test_debito_fiscal_f29():
    # Crear facturas de venta
    facturas_venta = [
        create_invoice(amount_untaxed=1000) for _ in range(10)
    ]

    # IVA esperado
    debito_fiscal_esperado = sum(f.amount_tax for f in facturas_venta)

    # Generar F29
    f29 = generate_f29(periodo='2025-11')

    # Verificar código 10 (Ventas Netas)
    assert f29.codigo_10 == sum(f.amount_untaxed for f in facturas_venta)

    # Verificar código 20 (Débito Fiscal)
    assert f29.codigo_20 == debito_fiscal_esperado
```

**C.1.2. Cálculo Crédito Fiscal**
```python
# Test: Crédito Fiscal = IVA Compras (con restricciones)
def test_credito_fiscal_f29():
    # Crear facturas de compra
    facturas_compra = [
        create_vendor_bill(amount_untaxed=500) for _ in range(5)
    ]

    credito_fiscal_esperado = sum(f.amount_tax for f in facturas_compra)

    # Generar F29
    f29 = generate_f29(periodo='2025-11')

    # Verificar código 50 (Compras Netas)
    assert f29.codigo_50 == sum(f.amount_untaxed for f in facturas_compra)

    # Verificar código 69 (Crédito Fiscal)
    assert f29.codigo_69 == credito_fiscal_esperado
```

**C.1.3. Cálculo IVA a Pagar**
```python
# Test: IVA a Pagar = Débito - Crédito
def test_iva_a_pagar_f29():
    debito = 1_000_000
    credito = 700_000
    iva_a_pagar_esperado = debito - credito  # 300,000

    f29 = generate_f29()

    assert f29.codigo_89 == iva_a_pagar_esperado  # IVA determinado
```

#### C.2. Verificación Libros Electrónicos

**C.2.1. Libro de Compras**
```python
# Test: Libro Compras incluye todas las facturas
def test_libro_compras():
    # Crear facturas de compra con DTE
    bills = [create_vendor_bill_with_dte() for _ in range(20)]

    # Generar Libro Compras
    libro = generate_libro_compras(periodo='2025-11')

    # Verificar cada factura está en el libro
    for bill in bills:
        assert any(
            entry['folio'] == bill.dte_id.folio and
            entry['rut_proveedor'] == bill.partner_id.vat
            for entry in libro.entries
        )
```

**C.2.2. Libro de Ventas**
```python
# Test: Libro Ventas coincide con DTEs emitidos
def test_libro_ventas():
    # Crear facturas de venta con DTE
    invoices = [create_invoice_with_dte() for _ in range(30)]

    # Generar Libro Ventas
    libro = generate_libro_ventas(periodo='2025-11')

    # Verificar totales
    total_neto_libro = sum(e['monto_neto'] for e in libro.entries)
    total_neto_facturas = sum(inv.amount_untaxed for inv in invoices)

    assert abs(total_neto_libro - total_neto_facturas) < 100
```

#### C.3. Verificación Reportes Financieros

**C.3.1. Balance General**
```python
# Test: Balance cuadra Activo = Pasivo + Patrimonio
def test_balance_general():
    balance = generate_balance_general(fecha='2025-11-30')

    activo_total = balance['activo_corriente'] + balance['activo_no_corriente']
    pasivo_patrimonio = balance['pasivo_total'] + balance['patrimonio_total']

    assert abs(activo_total - pasivo_patrimonio) < 10  # Tolerancia centavos
```

**C.3.2. Estado de Resultados**
```python
# Test: Estado Resultados = Ingresos - Gastos
def test_estado_resultados():
    estado = generate_estado_resultados(periodo='2025-11')

    utilidad_calculada = estado['ingresos_operacionales'] - estado['costos_operacionales'] - estado['gastos_administracion']

    assert abs(utilidad_calculada - estado['utilidad_operacional']) < 10
```

#### C.4. Verificación Integración Stack AI

**C.4.1. Insights de F29**
```python
# Test: AI Service genera insights de F29
def test_f29_insights():
    f29_data = {
        'debito_fiscal': 10_000_000,
        'credito_fiscal': 7_000_000,
        'iva_a_pagar': 3_000_000,
    }

    insights = ai_service.analyze_f29(f29_data)

    # Verificar insights generados
    assert 'credito_fiscal_ratio' in insights
    assert insights['credito_fiscal_ratio'] == 0.7  # 70%

    # Alertas
    if insights['credito_fiscal_ratio'] > 0.8:
        assert 'warning' in insights['alerts']
```

**C.4.2. Detección de Anomalías**
```python
# Test: AI detecta anomalías tributarias
def test_anomaly_detection():
    # F29 con anomalías
    f29_anomalo = {
        'debito_fiscal': 1_000_000,
        'credito_fiscal': 2_000_000,  # Crédito > Débito (posible)
        'ventas_netas': 100_000,      # Bajo vs IVA (anomalía)
    }

    analysis = ai_service.detect_anomalies(f29_anomalo)

    assert analysis['has_anomalies'] == True
    assert any('ventas_netas' in a['field'] for a in analysis['anomalies'])
```

---

## 📊 PARTE 3: CRITERIOS DE ÉXITO

### Nivel P0 - CRÍTICO (Must Pass)
- ✅ Todos los módulos se instalan sin errores
- ✅ DTEs generados validan contra XSD oficial SII
- ✅ Liquidaciones calculan AFP/Salud/Impuesto correctamente
- ✅ F29 calcula IVA a pagar correctamente
- ✅ Sin errores de seguridad (OWASP Top 10)
- ✅ Stack completo (Odoo + AI Service + Redis + RabbitMQ) funcional

### Nivel P1 - ALTO (Should Pass)
- ✅ DTEs se envían y aceptan en SII Certificación
- ✅ LRE Previred genera archivo válido
- ✅ Libros Electrónicos coinciden con DTEs
- ✅ Integración AI Service funcional (validación, insights)
- ✅ Cache Redis mejora performance >50%
- ✅ Tests unitarios >80% cobertura

### Nivel P2 - MEDIO (Nice to Have)
- ⏳ DTEs se envían y aceptan en SII Producción
- ⏳ Reportes financieros optimizados (<5 seg)
- ⏳ AI Service genera insights avanzados
- ⏳ RabbitMQ procesa 1000+ DTEs en <10 min
- ⏳ Documentación completa para usuarios

### Nivel P3 - BAJO (Future Enhancement)
- ⏳ Migración automática desde Odoo 18
- ⏳ Dashboard ejecutivo con BI
- ⏳ Mobile app para consultas
- ⏳ Integración con bancos (pagos)

---

## 🚀 PARTE 4: METODOLOGÍA DE EJECUCIÓN

### Fase 1: Preparación (1 día)
1. Crear base de datos limpia
2. Instalar los 3 módulos
3. Configurar datos maestros (empresa, certificado, CAF)
4. Cargar datos de prueba (partners, products)

### Fase 2: Tests Automatizados (3 días)
1. Ejecutar suite de tests unitarios
2. Ejecutar tests de integración
3. Ejecutar tests de compliance
4. Generar reporte de cobertura

### Fase 3: Tests Manuales (2 días)
1. Flujo completo: Venta → Factura → DTE → SII
2. Flujo completo: Contrato → Liquidación → LRE
3. Flujo completo: Mes contable → F29 → Libros
4. Validar UI/UX (usabilidad)

### Fase 4: Tests de Carga (1 día)
1. Generar 1000 DTEs en 1 hora
2. Calcular 100 liquidaciones en 5 minutos
3. Generar F29 de 1000 facturas en 30 segundos
4. Validar: Sin timeouts, sin memory leaks

### Fase 5: Documentación (1 día)
1. Documentar hallazgos (errores, deficiencias)
2. Priorizar fixes (P0, P1, P2, P3)
3. Estimar esfuerzo de corrección
4. Generar plan de acción

---

## 📝 PARTE 5: PLANTILLA DE REPORTE

### Por cada test ejecutado:

```markdown
### Test: [ID] - [Nombre]
**Módulo:** [l10n_cl_dte / l10n_cl_hr_payroll / l10n_cl_financial_reports]
**Categoría:** [Funcional / Integración / Compliance / Performance / Security]
**Prioridad:** [P0 / P1 / P2 / P3]

**Objetivo:**
Verificar que [descripción objetivo]

**Precondiciones:**
- [Condición 1]
- [Condición 2]

**Pasos:**
1. [Paso 1]
2. [Paso 2]
3. [Paso 3]

**Resultado Esperado:**
[Descripción resultado esperado]

**Resultado Obtenido:**
[Descripción resultado real]

**Estado:** [PASS / FAIL / BLOCKED / SKIP]

**Evidencia:**
- Screenshot: [ruta]
- Log: [ruta]
- Código: [archivo:línea]

**Deficiencias Encontradas:**
1. [Deficiencia 1 - Descripción detallada]
   - Severidad: [Crítica / Alta / Media / Baja]
   - Impacto: [Descripción impacto]
   - Sugerencia: [Cómo corregir]

**Mejoras Sugeridas:**
1. [Mejora 1 - Descripción]
   - Beneficio: [Descripción beneficio]
   - Esfuerzo: [Bajo / Medio / Alto]
```

---

## 🎯 PRÓXIMOS PASOS

1. **Revisión del Plan:** ¿Están de acuerdo con el alcance?
2. **Priorización:** ¿Qué verificar primero?
3. **Ejecución:** Comenzar con tests automatizados
4. **Iteración:** Corregir → Re-test → Validar

---

**Generado:** 2025-11-14
**Por:** Claude Code - Análisis de Ingeniero Senior
**Propósito:** Verificación integral pre-producción

