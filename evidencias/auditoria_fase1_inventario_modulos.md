# AUDITORÍA FUNCIONAL ODOO 11 - FASE 1: INVENTARIO DE MÓDULOS

**Fecha:** 2025-11-09
**Fase:** 1 de 10
**Duración estimada:** 30 minutos
**Estado:** ✅ Completado

---

## Resumen Ejecutivo

Se identificaron **8 módulos principales** de localización chilena en producción (Odoo 11), distribuidos en dos categorías funcionales:

- **7 módulos** de facturación electrónica y contabilidad
- **1 módulo** de nóminas y recursos humanos

Todos los módulos están activos y operacionales en el ambiente de producción ubicado en:
```
/Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons
```

---

## Inventario Completo de Módulos

### CATEGORÍA 1: FACTURACIÓN ELECTRÓNICA Y CONTABILIDAD

#### 1.1 l10n_cl_fe - Facturación Electrónica para Chile

**Información General:**
- **Versión:** 0.27.2
- **Categoría:** Localization/Chile
- **Autor:** Daniel Santibáñez Polanco, Cooperativa OdooCoop
- **Licencia:** AGPL-3
- **Website:** https://globalresponse.cl
- **Nivel de Complejidad:** ⭐⭐⭐⭐⭐ (Muy Alto)

**Propósito Funcional:**
Módulo principal de facturación electrónica para Chile. Gestiona todo el ciclo de vida de los documentos tributarios electrónicos (DTE) según normativa SII.

**Dependencias:**
- base
- base_address_city
- account
- purchase
- sale_management
- l10n_cl_chart_of_account
- report_xlsx
- contacts
- portal

**Dependencias Externas Python:**
- facturacion_electronica
- base64, hashlib
- suds (SOAP client)
- num2words
- xlsxwriter
- PIL (Pillow - procesamiento de imágenes)
- urllib3
- fitz (PyMUPDF - procesamiento de PDFs)

**Features Funcionales Identificadas:**

1. **Gestión de Folios (CAF):**
   - Administración de archivos CAF
   - Consumo de folios
   - Control de numeración

2. **Documentos Tributarios Electrónicos (DTE):**
   - Facturas electrónicas
   - Boletas electrónicas
   - Notas de crédito
   - Notas de débito
   - Guías de despacho (integración)
   - Facturas de exportación
   - Facturas de compra

3. **Comunicación con SII:**
   - Envío masivo de DTE
   - Validación de documentos
   - Cola de envío automática
   - Procesamiento de respuestas SII
   - Aceptación/rechazo de DTE recibidos

4. **Libros Contables:**
   - Libro de compras
   - Libro de ventas
   - Libro de honorarios

5. **Configuración y Maestros:**
   - Tipos de documentos SII
   - Clases de documentos
   - Letras de documentos
   - Conceptos y tipos opcionales
   - Actividades económicas
   - Oficinas regionales SII
   - Firmas electrónicas
   - Sucursales
   - Responsabilidades tributarias

6. **Gestión de Partners:**
   - Actividades económicas de partners
   - Responsabilidades tributarias
   - Giros comerciales
   - Comunas y regiones chilenas

7. **Tributación:**
   - Impuestos (IVA, exentos, etc.)
   - Impuesto MEPCO
   - Descuentos y recargos globales

8. **Exportaciones e Importaciones:**
   - Upload de XML
   - Exportación de libros
   - Importación de documentos

9. **Portal Cliente:**
   - Portal de boletas para clientes
   - Visualización de DTE

10. **Honorarios:**
    - Gestión de boletas de honorarios
    - Libro de honorarios

11. **Integraciones:**
    - Órdenes de venta
    - Facturas de compra
    - Journal entries
    - Líneas de movimiento contable

**Vistas Identificadas (42 archivos XML):**
- Wizards: apicaf, masive_send_dte, masive_dte_process, masive_dte_accept, notas, upload_xml, validar, journal_config_wizard
- Views: account_tax_mepco, account_tax, account_invoice, consumo_folios, caf, export, layout, libro_compra_venta, libro_honorarios, mail_dte, partner_activities, payment_t, res_company, res_partner, res_state, res_city, sii_activity_description, sii_cola_envio, sii_regional_offices, sii_firma, account_journal_sii_document_class, account_move_line, account_move, country, currency, honorarios, journal, report_invoice, sii_concept_type, sii_document_class, sii_document_letter, sii_document_type, sii_optional_type, sii_responsability, sii_respuesta_cliente, sii_sucursal, sii_xml_envio, global_descuento_recargo, res_config_settings, portal_boleta_layout, sale_order

**Datos Maestros Incluidos:**
- Responsabilidades tributarias
- Comunas (counties_data)
- País (Chile)
- Cron jobs (automatizaciones)
- Tipos de documentos SII
- Actividades económicas (CSV)
- Partners base
- Productos base
- Secuencias
- Conceptos SII (CSV)
- Letras de documentos (CSV)
- Clases de documentos (CSV)
- Oficinas regionales SII (CSV)
- Decimal precision
- Monedas (CSV)

**Seguridad:**
- State manager (gestión de estados)
- Control de accesos (ir.model.access.csv)

---

#### 1.2 l10n_cl_dte_factoring - Cesión de Créditos Electrónica para Chile

**Información General:**
- **Versión:** 0.20.0
- **Categoría:** Localization/Chile
- **Autor:** Daniel Santibáñez Polanco, Cooperativa OdooCoop
- **Licencia:** AGPL-3
- **Website:** https://globalresponse.cl
- **Nivel de Complejidad:** ⭐⭐⭐ (Medio)

**Propósito Funcional:**
Gestión de cesión de documentos tributarios electrónicos (factoring). Permite ceder facturas y otros documentos tributarios a terceros (empresas de factoring).

**Dependencias:**
- l10n_cl_fe (depende del módulo principal de facturación electrónica)

**Features Funcionales Identificadas:**
1. Cesión de documentos tributarios
2. Gestión de cesionarios
3. Notificación de cesión al SII

**Vistas Identificadas:**
- invoice_view.xml (extensión de vista de facturas)

**Seguridad:**
- Control de accesos (ir.model.access.csv)

---

#### 1.3 l10n_cl_balance - Balance de 8 Columnas para Chile

**Información General:**
- **Versión:** 0.1.1
- **Categoría:** Localization/Chile
- **Autor:** Konos
- **Licencia:** AGPL-3
- **Website:** http://konos.cl
- **Nivel de Complejidad:** ⭐⭐ (Bajo)

**Propósito Funcional:**
Formato de balance contable de 8 columnas específico para Chile. Reporte contable estándar usado en Chile para presentación de estados financieros.

**Dependencias:**
- account

**Features Funcionales Identificadas:**
1. Reporte de balance de 8 columnas
2. Layout específico chileno

**Datos Incluidos:**
- Formato de papel para reportes
- Layout de vista

---

#### 1.4 l10n_cl_financial_indicators - Indicadores Financieros Chilenos

**Información General:**
- **Versión:** 11.0.1.0.0
- **Categoría:** Tools
- **Autor:** Blanco Martin & Asociados
- **Licencia:** AGPL-3
- **Website:** http://blancomartin.cl
- **Nivel de Complejidad:** ⭐⭐⭐ (Medio)

**Propósito Funcional:**
Actualización automática diaria de UF, UTM y valor del Dólar oficial usando webservices de SBIF (Superintendencia de Bancos e Instituciones Financieras).

**Dependencias:**
- decimal_precision
- webservices_generic

**Features Funcionales Identificadas:**
1. **Indicadores Actualizados:**
   - UF (Unidad de Fomento)
   - UTM (Unidad Tributaria Mensual)
   - Dólar Observado (valor oficial)

2. **Actualización Automática:**
   - Cron job diario
   - Conexión a webservices SBIF
   - Botón de actualización manual

**Vistas Identificadas:**
- Botón de actualización manual (update_button.xml)

**Datos Incluidos:**
- Cron job (ir_cron.xml)
- Monedas (res.currency.csv)
- Configuración de webservices (webservices.server.csv)
- Precisión decimal

---

#### 1.5 l10n_cl_chart_of_account - Plan de Cuentas SII Chile

**Información General:**
- **Versión:** 1.10.0
- **Categoría:** Localization/Chile
- **Autor:** Konos
- **Licencia:** AGPL-3
- **Website:** http://www.konos.cl
- **Nivel de Complejidad:** ⭐⭐⭐⭐ (Alto)

**Propósito Funcional:**
Plan contable chileno e impuestos de acuerdo a disposiciones vigentes del SII (Servicio de Impuestos Internos). Base contable para toda la localización chilena.

**Dependencias:**
- account

**Features Funcionales Identificadas:**
1. **Plan de Cuentas:**
   - Cuentas contables según SII
   - Jerarquía de cuentas
   - Plantilla de plan contable

2. **Impuestos:**
   - IVA (19%)
   - Impuestos específicos
   - Configuración de impuestos

3. **Configuración:**
   - Unidades de medida chilenas
   - Diarios contables
   - Template de plan contable

**Datos Incluidos:**
- Vista de impuestos (account_tax.xml)
- Unidades de medida (product_uom.xml)
- Datos de plan de cuentas (l10n_cl_chart_of_account_data.xml)
- Datos de impuestos (account_tax_data.xml)
- Template de plan contable (account_chart_template_data.yml)
- Diarios contables (account_journal.xml)

---

#### 1.6 l10n_cl_banks_sbif - Bancos Chilenos con Códigos SBIF

**Información General:**
- **Versión:** 11.0.1.0.1
- **Categoría:** Localization/Banks
- **Autor:** Blanco Martin & Asociados
- **Licencia:** AGPL-3
- **Website:** http://blancomartin.cl
- **Nivel de Complejidad:** ⭐ (Muy Bajo)

**Propósito Funcional:**
Actualización de bancos chilenos con códigos oficiales de SBIF (Superintendencia de Bancos e Instituciones Financieras). Necesario para conciliaciones bancarias y exportaciones.

**Dependencias:**
- account

**Features Funcionales Identificadas:**
1. Listado de bancos chilenos
2. Códigos oficiales SBIF
3. Información de bancos

**Datos Incluidos:**
- Bancos chilenos (res.bank.csv)
- Vista de bancos SBIF (res_bank_sbif.xml)

---

#### 1.7 l10n_cl_stock_picking - Guías de Despacho Electrónica para Chile

**Información General:**
- **Versión:** 0.23.0
- **Categoría:** Stock/picking
- **Autor:** Daniel Santibáñez Polanco, Cooperativa OdooCoop
- **Licencia:** AGPL-3
- **Website:** http://globalresponse.cl
- **Nivel de Complejidad:** ⭐⭐⭐⭐ (Alto)

**Propósito Funcional:**
Gestión de guías de despacho electrónicas para Chile. Permite emitir guías de despacho como documentos tributarios electrónicos (DTE).

**Dependencias:**
- stock
- fleet (gestión de flota)
- delivery (entrega)
- sale_stock
- l10n_cl_fe

**Features Funcionales Identificadas:**
1. **Guías de Despacho Electrónicas:**
   - Generación de guías desde stock picking
   - Envío a SII
   - Validación SII

2. **Libros:**
   - Libro de guías de despacho

3. **Configuración:**
   - Talonarios de guías
   - Numeración automática

4. **Integración:**
   - Integración con facturas
   - Integración con órdenes de venta
   - Integración con entregas

**Vistas Identificadas:**
- stock_picking.xml
- stock_location.xml
- dte.xml
- layout.xml
- libro_guias.xml
- account_invoice.xml
- Wizard: masive_send_dte.xml

**Seguridad:**
- Control de accesos (ir.model.access.csv)

---

### CATEGORÍA 2: NÓMINAS Y RECURSOS HUMANOS

#### 2.1 l10n_cl_hr - Chilean Payroll & Human Resources

**Información General:**
- **Versión:** 11.0.1.5.0
- **Categoría:** Localization
- **Autor:** Konos
- **Licencia:** AGPL-3
- **Website:** http://konos.cl
- **Nivel de Complejidad:** ⭐⭐⭐⭐⭐ (Muy Alto)

**Propósito Funcional:**
Configuración completa de nóminas para localización chilena. Incluye todas las reglas de contribuciones chilenas (AFP, Salud, AFC, Impuesto Único, etc.), cálculo de liquidaciones, y exportación a Previred.

**Dependencias:**
- hr_payroll
- hr_payroll_account

**Dependencias Externas Python:**
- num2words (conversión de números a palabras)

**Contributors:**
- Nelson Ramirez (Konos)
- Daniel Blanco Martin
- Carlos Lopez Mite
- Daniel Santibáñez Polanco
- Francisco Lorca

**Features Funcionales Identificadas:**

1. **Información de Empleados:**
   - Información básica de empleados
   - Contratos de empleados
   - Tipos de empleado

2. **Asistencia y Ausencias:**
   - Asistencia
   - Vacaciones
   - Licencias médicas

3. **Cálculo de Nóminas:**
   - Liquidaciones de sueldo (payslips)
   - Reglas salariales chilenas
   - Categorías de reglas salariales

4. **Asignaciones y Deducciones:**
   - Asignaciones (bonos, colación, movilización, etc.)
   - Deducciones (préstamos, anticipos, etc.)
   - Aportes de empresa

5. **Horas Extras:**
   - Cálculo de horas extras
   - Diferentes tipos de horas extras

6. **Previsión:**
   - AFP (Administradoras de Fondos de Pensiones)
   - Salud (FONASA/ISAPRE)
   - AFC (Aporte de Cesantía)
   - APV (Ahorro Previsional Voluntario)
   - Mutual (Seguro de Accidentes)
   - CCAF (Cajas de Compensación)

7. **Impuestos:**
   - Impuesto Único de Segunda Categoría (7 tramos)
   - Cálculo progresivo de impuestos

8. **Gratificación Legal:**
   - Cálculo de gratificación legal
   - Mensualización de gratificación

9. **Indicadores Previsionales:**
   - UF, UTM, Tope Imponible
   - Tasas de AFP, Salud, AFC
   - Tramos de Impuesto Único
   - Sueldo Mínimo

10. **Libros de Remuneraciones:**
    - Libro de remuneraciones
    - Reportes de nóminas

11. **Exportación Previred:**
    - Exportación a texto plano Previred
    - Wizard de exportación CSV

12. **Reportes:**
    - Reporte de liquidación de sueldo
    - Reporte de salarios por mes
    - Libros de remuneraciones

13. **Centros de Costo:**
    - Asignación de centros de costo
    - Distribución de costos

14. **Integración Contable:**
    - Diarios contables para nóminas
    - Asientos contables automáticos

**Vistas Identificadas:**
- hr_indicadores_previsionales_view.xml
- hr_salary_rule_view.xml
- hr_contract_view.xml
- hr_employee.xml
- hr_payslip_view.xml
- hr_afp_view.xml
- hr_payslip_run_view.xml
- report_payslip.xml
- report_hrsalarybymonth.xml
- hr_salary_books.xml
- hr_holiday_views.xml
- wizard_export_csv_previred_view.xml

**Datos Maestros Incluidos:**
- Categorías de reglas salariales (hr_salary_rule_category.xml)
- Centros de costos (hr_centros_costos.xml)
- Indicadores previsionales (l10n_cl_hr_indicadores.xml)
- ISAPREs (l10n_cl_hr_isapre.xml)
- AFPs (l10n_cl_hr_afp.xml)
- Mutuales (l10n_cl_hr_mutual.xml)
- APV (l10n_cl_hr_apv.xml)
- Tipos de empleado (hr_type_employee.xml)
- Calendarios de recursos (resource_calendar_attendance.xml)
- Estados de vacaciones (hr_holidays_status.xml)
- Tipos de contrato (hr_contract_type.xml)
- CCAF (l10n_cl_hr_ccaf.xml)
- Diarios contables (account_journal.xml)
- Partners (partner.xml)
- Datos de nómina (l10n_cl_hr_payroll_data.xml)
- Cron jobs (cron.xml)

**Seguridad:**
- Control de accesos (ir.model.access.csv)

**Demo Data:**
- Datos de demostración (l10n_cl_hr_payroll_demo.xml)

---

## Análisis de Dependencias

### Dependencias Entre Módulos Chilenos

```
l10n_cl_chart_of_account (base contable)
    ↓
l10n_cl_fe (facturación electrónica)
    ↓
l10n_cl_dte_factoring (factoring)
l10n_cl_stock_picking (guías de despacho)

l10n_cl_financial_indicators (independiente, usa webservices_generic)

l10n_cl_balance (independiente, solo reportes)

l10n_cl_banks_sbif (independiente, datos maestros)

hr_payroll + hr_payroll_account (Odoo estándar)
    ↓
l10n_cl_hr (nóminas chilenas)
```

### Módulos Externos Requeridos

**Para Facturación (l10n_cl_fe):**
- webservices_generic (comunicación con SII)
- report_xlsx (exportaciones Excel)
- base_address_city (ciudades y comunas)

**Para Indicadores (l10n_cl_financial_indicators):**
- webservices_generic (comunicación con SBIF)
- decimal_precision

---

## Nivel de Complejidad por Módulo

| Módulo | Complejidad | Archivos Vista | Datos Maestros | Models Estimados |
|--------|-------------|----------------|----------------|------------------|
| l10n_cl_fe | ⭐⭐⭐⭐⭐ | 42+ | 15+ | 30+ |
| l10n_cl_hr | ⭐⭐⭐⭐⭐ | 12+ | 13+ | 20+ |
| l10n_cl_stock_picking | ⭐⭐⭐⭐ | 7 | 0 | 5+ |
| l10n_cl_chart_of_account | ⭐⭐⭐⭐ | 6 | 6 | 10+ |
| l10n_cl_financial_indicators | ⭐⭐⭐ | 1 | 4 | 3+ |
| l10n_cl_dte_factoring | ⭐⭐⭐ | 1 | 0 | 3+ |
| l10n_cl_balance | ⭐⭐ | 1 | 1 | 1+ |
| l10n_cl_banks_sbif | ⭐ | 1 | 1 | 1+ |

---

## Conclusiones de Fase 1

### Hallazgos Principales

1. **Ecosistema Completo:** Se identificó un ecosistema completo de localización chilena con 8 módulos interrelacionados.

2. **Alta Complejidad:** Los módulos principales (l10n_cl_fe y l10n_cl_hr) son de muy alta complejidad funcional, con múltiples features y datos maestros.

3. **Integración Profunda:** Existe una integración profunda entre módulos, especialmente en facturación electrónica.

4. **Datos Maestros Extensos:** Se incluyen datos maestros extensos (AFPs, ISAPREs, bancos, comunas, actividades económicas, etc.).

5. **Automatizaciones:** Se identificaron cron jobs para automatización de actualización de indicadores y envío de DTE.

6. **Webservices:** Integración con webservices externos (SII, SBIF).

### Módulos Críticos a Analizar

**Prioridad 1 (Críticos):**
1. **l10n_cl_fe** - Facturación electrónica (funcionalidad core del negocio)
2. **l10n_cl_hr** - Nóminas (funcionalidad core del negocio)

**Prioridad 2 (Importantes):**
3. **l10n_cl_stock_picking** - Guías de despacho (operaciones diarias)
4. **l10n_cl_chart_of_account** - Plan de cuentas (base contable)

**Prioridad 3 (Complementarios):**
5. **l10n_cl_financial_indicators** - Indicadores financieros (automatización)
6. **l10n_cl_dte_factoring** - Factoring (funcionalidad específica)
7. **l10n_cl_balance** - Reportes contables
8. **l10n_cl_banks_sbif** - Datos maestros de bancos

### Estimación de Esfuerzo por Fase

| Fase | Módulo | Esfuerzo Estimado |
|------|--------|-------------------|
| 2.1 | Modelos Facturación | 2-3 horas |
| 2.2 | Modelos Nóminas | 2-3 horas |
| 3.1 | Cálculos Facturación | 2-3 horas |
| 3.2 | Cálculos Nóminas | 2-3 horas |
| 4.1 | Vistas Facturación | 1-2 horas |
| 4.2 | Vistas Nóminas | 1-2 horas |
| **Total estimado** | | **12-18 horas** |

### Próximos Pasos

1. **Fase 2.1:** Analizar modelos de datos de facturación (l10n_cl_fe, l10n_cl_dte_factoring, l10n_cl_stock_picking)
2. **Fase 2.2:** Analizar modelos de datos de nóminas (l10n_cl_hr)
3. **Documentar:** Estructura de datos, campos, relaciones, métodos de negocio

---

## Archivos de Evidencia Generados

- ✅ `evidencias/auditoria_fase1_inventario_modulos.md` (este archivo)

---

## Metadata de Auditoría

- **Ruta de producción auditada:** `/Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons`
- **Fecha de última modificación de módulos:** Octubre 2023 - Mayo 2024
- **Versión Odoo:** 11
- **Total de módulos identificados:** 38 (8 de localización chilena)
- **Módulos analizados en detalle:** 8
- **Archivos manifest leídos:** 8

---

**FIN DE FASE 1**
