# WEEK 2 - FRONTEND DEVELOPMENT
## Professional Plan - l10n_cl_dte_enhanced & eergygroup_branding

**Fecha Inicio:** 2025-11-04
**Ingeniero:** Ing. Pedro Troncoso Willz - EERGYGROUP
**Principio:** SIN IMPROVISAR, SIN PARCHES - ENTERPRISE QUALITY ONLY

---

## 📋 ANÁLISIS DE ARQUITECTURA ACTUAL

### Estado del Módulo Base (l10n_cl_dte)

**Archivos Existentes:**
```
l10n_cl_dte/
├── models/
│   └── account_move_dte.py (81KB)
│       ├── ✅ Campos DTE (dte_status, dte_code, dte_folio, dte_timestamp)
│       ├── ✅ Método generate_ted() - Delega a TEDGenerator
│       └── ❌ NO tiene métodos para reportes PDF
├── libs/
│   ├── ✅ ted_generator.py - Generación de TED XML
│   ├── ✅ xml_generator.py - Generación de DTE XML
│   ├── ✅ xml_signer.py - Firma digital
│   └── ✅ xsd_validator.py - Validación esquemas
└── report/
    └── report_invoice_dte_document.xml
        ├── ⚠️  Template QWeb INCOMPLETO
        ├── ❌ Referencias a funciones NO EXISTENTES:
        │   - get_ted_pdf417(o)
        │   - get_ted_qrcode(o)
        │   - get_dte_type_name(o.dte_code)
        │   - get_payment_term_lines(o)
        │   - format_vat(vat)
        └── ✅ Layout profesional SII-compliant
```

### Brechas Identificadas

| # | Brecha | Impacto | Prioridad |
|---|--------|---------|-----------|
| **1** | Métodos helper para reportes NO EXISTEN | 🔴 CRÍTICO | P0 |
| **2** | Generación PDF417 NO IMPLEMENTADA | 🔴 CRÍTICO | P0 |
| **3** | Reportes PDF no muestran TED (timbre) | 🔴 CRÍTICO | P0 |
| **4** | Sin branding EERGYGROUP en reportes | 🟡 ALTO | P1 |
| **5** | Sin dashboard analítico DTE | 🟢 MEDIO | P2 |
| **6** | UX mejorable en vistas | 🟢 MEDIO | P2 |

---

## 🎯 OBJETIVOS WEEK 2

### Objetivo General
Completar el frontend de l10n_cl_dte_enhanced con:
1. ✅ Reportes PDF DTE profesionales con PDF417
2. ✅ Branding EERGYGROUP completo
3. ✅ Dashboard analítico funcional
4. ✅ UX enterprise-grade

### Objetivos Específicos

**FASE 1: Report Helpers & PDF417** (P0 - CRÍTICO)
- [ ] Crear clase ReportHelper profesional
- [ ] Implementar generación PDF417 con librería pdf417
- [ ] Implementar helpers: get_dte_type_name, format_vat, etc.
- [ ] Tests unitarios (>90% coverage)

**FASE 2: QWeb Templates Branded** (P1 - ALTO)
- [ ] Heredar template base l10n_cl_dte
- [ ] Aplicar branding EERGYGROUP (colores, logos)
- [ ] Integrar campos enhanced (contact_id, forma_pago, cedible, references)
- [ ] Layout responsive y profesional

**FASE 3: Dashboard Analítico** (P2 - MEDIO)
- [ ] Vista Kanban para DTEs
- [ ] Gráficos estadísticos (Chart.js)
- [ ] Filtros avanzados
- [ ] Exportación a Excel

**FASE 4: UX Enhancements** (P2 - MEDIO)
- [ ] Smart buttons en facturas
- [ ] Wizards para procesos comunes
- [ ] Tooltips informativos
- [ ] Mensajes de ayuda contextual

---

## 🏗️ ARQUITECTURA TÉCNICA

### Principios de Diseño

```
┌─────────────────────────────────────────────────────────────┐
│  SEPARACIÓN DE RESPONSABILIDADES                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  l10n_cl_dte (BASE)          l10n_cl_dte_enhanced (ENHANCED)│
│  ==================          =============================   │
│                                                              │
│  • Campos DTE básicos         • Campos UX (contact_id, etc)│
│  • Generación XML/TED         • Referencias SII            │
│  • Envío SII                  • Report Helpers             │
│  • CAF management             • PDF417 generation          │
│  • Template básico            • Template extensions        │
│                                                              │
│                          eergygroup_branding (BRANDING)     │
│                          ===============================    │
│                                                              │
│                          • Colores EERGYGROUP               │
│                          • Logos y assets                   │
│                          • CSS customization                │
│                          • Footer branding                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Stack Tecnológico

**Backend:**
- Python 3.11+
- Odoo 19 CE Framework
- lxml (XML processing)
- Pillow (Image processing)
- pdf417 library (Barcode generation)

**Frontend:**
- QWeb Templates (Odoo templating engine)
- Bootstrap 5 (Layout)
- Font Awesome 6 (Icons)
- Chart.js 4 (Gráficos)
- Owl Framework (Componentes interactivos)

**Testing:**
- pytest (Unit tests)
- Odoo Test Framework (Integration tests)
- Selenium (E2E tests opcionales)

---

## 📦 ESTRUCTURA DE ARCHIVOS

### l10n_cl_dte_enhanced/

```
l10n_cl_dte_enhanced/
├── models/
│   ├── account_move.py (existente - extender)
│   ├── account_move_reference.py (existente)
│   ├── res_company.py (existente - extender)
│   └── report_helper.py ✨ NUEVO
│       └── Métodos helper para reportes PDF
│
├── libs/ ✨ NUEVO
│   └── pdf417_generator.py
│       └── Generación profesional PDF417
│
├── report/ ✨ NUEVO
│   ├── report_invoice_dte_enhanced.xml
│   │   └── Template heredado con branding
│   └── report_dashboard_dte.xml
│       └── Dashboard analítico
│
├── views/
│   ├── account_move_views.xml (existente - extender)
│   ├── account_move_reference_views.xml (existente)
│   ├── res_company_views.xml (existente)
│   └── dashboard_dte_views.xml ✨ NUEVO
│       └── Vistas dashboard analítico
│
├── static/
│   ├── src/
│   │   ├── css/
│   │   │   └── report_dte.css ✨ NUEVO
│   │   ├── js/
│   │   │   ├── dashboard_dte.js ✨ NUEVO
│   │   │   └── charts_config.js ✨ NUEVO
│   │   └── img/
│   │       └── (logos, iconos)
│   └── description/
│       └── icon.png
│
├── tests/
│   ├── test_report_helper.py ✨ NUEVO
│   ├── test_pdf417_generator.py ✨ NUEVO
│   └── test_dashboard.py ✨ NUEVO
│
└── wizards/ (opcional - Week 3)
    └── dte_batch_report_wizard.py
```

### eergygroup_branding/

```
eergygroup_branding/
├── report/ ✨ NUEVO
│   └── report_invoice_eergygroup.xml
│       └── Override con branding EERGYGROUP
│
├── static/
│   ├── src/
│   │   ├── css/
│   │   │   └── eergygroup_branding.css (existente - extender)
│   │   └── img/
│   │       ├── eergygroup_logo.png ✨ NUEVO
│   │       ├── eergymas_logo.png ✨ NUEVO
│   │       └── eergyhaus_logo.png ✨ NUEVO
│   └── description/
│       └── icon.png
│
└── data/
    └── eergygroup_branding_defaults.xml (existente)
```

---

## 🔨 IMPLEMENTACIÓN DETALLADA

### FASE 1: Report Helpers & PDF417

#### 1.1 Crear pdf417_generator.py

**Archivo:** `l10n_cl_dte_enhanced/libs/pdf417_generator.py`

**Requisitos Técnicos:**
- Librería: `pdf417` (instalar via pip)
- Output: PNG base64-encoded
- Dimensiones: 400px width, auto height
- Encoding: UTF-8
- Error correction: Level 5 (SII requirement)

**Métodos Públicos:**
```python
class PDF417Generator:
    """
    Professional PDF417 barcode generator for Chilean DTE.

    SII Requirements:
    - Error correction level: 5
    - Max width: 400px
    - Encoding: UTF-8
    - Format: PNG base64

    Usage:
        generator = PDF417Generator()
        barcode_b64 = generator.generate_pdf417(ted_xml_string)
    """

    def generate_pdf417(self, ted_xml: str) -> str:
        """Generate PDF417 barcode from TED XML."""
        pass

    def validate_ted_xml(self, ted_xml: str) -> bool:
        """Validate TED XML before encoding."""
        pass

    def get_barcode_dimensions(self) -> tuple:
        """Return (width, height) in pixels."""
        pass
```

**Tests Requeridos:**
- test_generate_valid_pdf417()
- test_generate_with_invalid_ted()
- test_dimensions()
- test_encoding_utf8()
- test_base64_output()

#### 1.2 Crear report_helper.py

**Archivo:** `l10n_cl_dte_enhanced/models/report_helper.py`

**Métodos Públicos:**
```python
class AccountMove(models.Model):
    _inherit = 'account.move'

    def get_ted_pdf417(self):
        """
        Generate PDF417 barcode for TED (Timbre Electrónico).

        Returns:
            str: Base64-encoded PNG image or False

        SII Compliance:
        - Uses TED XML from dte_ted_xml field
        - Error correction level 5
        - Max width 400px
        """
        pass

    def get_ted_qrcode(self):
        """Fallback: Generate QR code if PDF417 fails."""
        pass

    def get_dte_type_name(self):
        """
        Get human-readable DTE type name.

        Returns:
            str: e.g., "Factura Electrónica" for code 33
        """
        pass

    def get_payment_term_lines(self):
        """
        Get payment term schedule.

        Returns:
            list: [{'date': date, 'amount': Decimal}, ...]
        """
        pass

    @api.model
    def format_vat(self, vat):
        """
        Format Chilean RUT with proper formatting.

        Args:
            vat (str): Raw RUT (e.g., "762012345")

        Returns:
            str: Formatted RUT (e.g., "76.201.234-5")
        """
        pass
```

**Tests Requeridos:**
- test_get_ted_pdf417_success()
- test_get_ted_pdf417_no_ted_xml()
- test_get_dte_type_name_all_types()
- test_get_payment_term_lines()
- test_format_vat_valid()
- test_format_vat_invalid()

### FASE 2: QWeb Templates Branded

#### 2.1 Heredar Template Base

**Archivo:** `l10n_cl_dte_enhanced/report/report_invoice_dte_enhanced.xml`

**Estrategia de Herencia:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <!-- Inherit base DTE template -->
    <template id="report_invoice_dte_document"
              inherit_id="l10n_cl_dte.report_invoice_dte_document">

        <!-- Override: Add PDF417 generation -->
        <xpath expr="//t[@t-set='ted_barcode']" position="replace">
            <t t-set="ted_barcode" t-value="o.get_ted_pdf417()"/>
        </xpath>

        <!-- Override: Add contact person field -->
        <xpath expr="//div[@class='row mb-4'][2]" position="inside">
            <div class="col-12" t-if="o.contact_id">
                <p class="mb-1">
                    <strong>Persona de Contacto:</strong>
                    <t t-out="o.contact_id.name"/>
                </p>
            </div>
        </xpath>

        <!-- Override: Add custom payment terms -->
        <xpath expr="//tr[td[contains(text(), 'Condición de Pago')]]" position="replace">
            <tr t-if="o.forma_pago or o.invoice_payment_term_id">
                <td><strong>Condición de Pago:</strong></td>
                <td>
                    <t t-if="o.forma_pago" t-out="o.forma_pago"/>
                    <t t-else="" t-out="o.invoice_payment_term_id.name"/>
                </td>
            </tr>
        </xpath>

        <!-- Override: Add CEDIBLE indicator -->
        <xpath expr="//div[contains(@class, 'border-dark p-3')]" position="inside">
            <p class="mb-0 small text-danger" t-if="o.cedible">
                <strong>✓ CEDIBLE ELECTRÓNICAMENTE</strong>
            </p>
        </xpath>

        <!-- Override: Add SII References section -->
        <xpath expr="//div[@class='row mt-3'][@t-if='o.narration']" position="after">
            <div class="row mt-3" t-if="o.reference_ids">
                <div class="col-12">
                    <p class="mb-1"><strong>Referencias SII:</strong></p>
                    <table class="table table-sm table-bordered">
                        <thead>
                            <tr>
                                <th>Tipo Doc.</th>
                                <th>Folio</th>
                                <th>Fecha</th>
                                <th>Código</th>
                                <th>Razón</th>
                            </tr>
                        </thead>
                        <tbody>
                            <t t-foreach="o.reference_ids" t-as="ref">
                                <tr>
                                    <td><t t-out="ref.document_type_id.name"/></td>
                                    <td><t t-out="ref.folio"/></td>
                                    <td><t t-out="ref.date" t-options='{"widget": "date"}'/></td>
                                    <td><t t-out="ref.code"/></td>
                                    <td><t t-out="ref.reason"/></td>
                                </tr>
                            </t>
                        </tbody>
                    </table>
                </div>
            </div>
        </xpath>

    </template>
</odoo>
```

#### 2.2 Branding EERGYGROUP

**Archivo:** `eergygroup_branding/report/report_invoice_eergygroup.xml`

**Customizaciones:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <!-- EERGYGROUP Branded Template -->
    <template id="report_invoice_dte_document_eergygroup"
              inherit_id="l10n_cl_dte_enhanced.report_invoice_dte_document">

        <!-- Override: EERGYGROUP Header Colors -->
        <xpath expr="//div[@class='border border-dark p-3 d-inline-block text-center']" position="attributes">
            <attribute name="style">min-width: 250px; background-color: #E97300; color: white; border-color: #E97300 !important;</attribute>
        </xpath>

        <!-- Override: EERGYGROUP Logo -->
        <xpath expr="//img[@alt='Company Logo']" position="attributes">
            <attribute name="style">max-height: 100px; max-width: 250px;</attribute>
        </xpath>

        <!-- Add: EERGYGROUP Footer -->
        <xpath expr="//div[@class='row mt-3'][last()]" position="after">
            <div class="row mt-5 border-top pt-3" style="background-color: #FFF5E6;">
                <div class="col-12 text-center">
                    <p class="mb-1" style="color: #E97300; font-weight: bold; font-size: 14pt;">
                        Gracias por Preferirnos
                    </p>
                    <p class="mb-0 small" style="color: #1A1A1A;">
                        <a href="https://www.eergymas.cl" style="color: #E97300; text-decoration: none;">www.eergymas.cl</a> |
                        <a href="https://www.eergyhaus.cl" style="color: #E97300; text-decoration: none;">www.eergyhaus.cl</a> |
                        <a href="https://www.eergygroup.cl" style="color: #E97300; text-decoration: none;">www.eergygroup.cl</a>
                    </p>
                </div>
            </div>
        </xpath>

    </template>

    <!-- Report Action -->
    <record id="action_report_invoice_dte_eergygroup" model="ir.actions.report">
        <field name="name">DTE - Factura EERGYGROUP</field>
        <field name="model">account.move</field>
        <field name="report_type">qweb-pdf</field>
        <field name="report_name">eergygroup_branding.report_invoice_dte_document_eergygroup</field>
        <field name="report_file">eergygroup_branding.report_invoice_dte_document_eergygroup</field>
        <field name="print_report_name">'DTE-%s-%s-EERGYGROUP' % (object.dte_code or 'DOC', object.dte_folio or object.name)</field>
        <field name="binding_model_id" ref="account.model_account_move"/>
        <field name="binding_type">report</field>
        <field name="paperformat_id" ref="base.paperformat_us"/>
    </record>
</odoo>
```

### FASE 3: Dashboard Analítico

#### 3.1 Vista Kanban DTE

**Archivo:** `l10n_cl_dte_enhanced/views/dashboard_dte_views.xml`

**Features:**
- Kanban por estado DTE (draft, sent, accepted, rejected)
- Filtros por fecha, tipo DTE, empresa
- Búsqueda rápida por folio
- Gráficos estadísticos
- Export a Excel

**Template:**
```xml
<record id="view_dte_dashboard_kanban" model="ir.ui.view">
    <field name="name">dte.dashboard.kanban</field>
    <field name="model">account.move</field>
    <field name="arch" type="xml">
        <kanban default_group_by="dte_status" quick_create="false">
            <field name="dte_code"/>
            <field name="dte_folio"/>
            <field name="dte_status"/>
            <field name="partner_id"/>
            <field name="amount_total"/>
            <field name="currency_id"/>
            <templates>
                <t t-name="kanban-box">
                    <div class="oe_kanban_global_click o_kanban_record_has_image_fill">
                        <div class="o_kanban_image">
                            <i class="fa fa-file-invoice fa-3x" t-att-style="'color: ' + get_status_color(record.dte_status.raw_value)"/>
                        </div>
                        <div class="oe_kanban_details">
                            <strong class="o_kanban_record_title">
                                <field name="name"/>
                            </strong>
                            <ul>
                                <li>DTE: <field name="dte_code"/> - <field name="dte_folio"/></li>
                                <li>Cliente: <field name="partner_id"/></li>
                                <li>Monto: <field name="amount_total" widget="monetary"/></li>
                            </ul>
                        </div>
                    </div>
                </t>
            </templates>
        </kanban>
    </field>
</record>
```

#### 3.2 Gráficos Estadísticos

**Archivo:** `l10n_cl_dte_enhanced/static/src/js/dashboard_dte.js`

**Gráficos Implementados:**
1. DTEs por Estado (Pie Chart)
2. DTEs por Mes (Line Chart)
3. Monto Facturado por Mes (Bar Chart)
4. Top 10 Clientes (Bar Chart)
5. Tiempo Promedio Aceptación SII (Gauge)

**Stack:** Chart.js 4.x + Owl Framework

### FASE 4: UX Enhancements

#### 4.1 Smart Buttons

**Ubicación:** account.move form view

**Buttons a Implementar:**
- "Referencias SII" (contador)
- "Enviar a SII" (acción rápida)
- "Descargar PDF" (reporte)
- "Ver en SII" (link externo)

#### 4.2 Tooltips Informativos

**Campos con Tooltips:**
- contact_id: "Persona que recibe la factura"
- forma_pago: "Descripción custom de forma de pago"
- cedible: "Permite factoring electrónico"
- reference_ids: "Referencias a documentos SII según Res. 80/2014"

---

## 📅 CRONOGRAMA

### Week 2 - Days 1-5

| Día | Tarea | Responsable | Horas Est. |
|-----|-------|-------------|------------|
| **Día 1** | FASE 1: Report Helpers & PDF417 | Pedro | 8h |
| | - Crear pdf417_generator.py | | 3h |
| | - Crear report_helper.py | | 3h |
| | - Tests unitarios | | 2h |
| **Día 2** | FASE 2.1: QWeb Templates Enhanced | Pedro | 8h |
| | - Heredar template base | | 4h |
| | - Integrar campos enhanced | | 2h |
| | - Tests visuales | | 2h |
| **Día 3** | FASE 2.2: Branding EERGYGROUP | Pedro | 6h |
| | - Template branded | | 3h |
| | - CSS customization | | 2h |
| | - Verificación visual | | 1h |
| **Día 4** | FASE 3: Dashboard Analítico | Pedro | 8h |
| | - Vista Kanban | | 3h |
| | - Gráficos Chart.js | | 4h |
| | - Tests funcionales | | 1h |
| **Día 5** | FASE 4 + Testing Completo | Pedro | 8h |
| | - UX Enhancements | | 3h |
| | - Testing E2E | | 3h |
| | - Documentación | | 2h |

**Total:** 38 horas (5 días de 8h con buffer)

---

## 🧪 TESTING STRATEGY

### Test Pyramid

```
           ╱╲
          ╱E2E╲         10% - Tests E2E (Selenium opcional)
         ╱─────╲
        ╱ INTEG ╲       30% - Tests Integración (Odoo Test Framework)
       ╱─────────╲
      ╱   UNIT    ╲     60% - Tests Unitarios (pytest)
     ╱─────────────╲
    ╱───────────────╲
```

### Test Coverage Targets

| Componente | Target Coverage | Herramienta |
|------------|-----------------|-------------|
| pdf417_generator.py | 95% | pytest + coverage |
| report_helper.py | 90% | Odoo Test Framework |
| Templates QWeb | Visual | Manual + Screenshots |
| Dashboard JS | 80% | Jest (opcional) |
| **OVERALL** | **85%** | Combined |

### Test Cases Críticos

**Report Helpers:**
- [ ] test_generate_pdf417_valid_ted()
- [ ] test_generate_pdf417_invalid_ted()
- [ ] test_get_dte_type_name_all_types()
- [ ] test_format_vat_chilean()
- [ ] test_get_payment_term_lines()

**Templates:**
- [ ] test_report_render_factura_33()
- [ ] test_report_render_nota_credito_61()
- [ ] test_report_contains_pdf417()
- [ ] test_report_contains_references()
- [ ] test_report_branded_eergygroup()

**Dashboard:**
- [ ] test_kanban_view_accessible()
- [ ] test_charts_render()
- [ ] test_filters_work()
- [ ] test_export_excel()

---

## 📚 DEPENDENCIAS

### Python Packages (requirements.txt)

```txt
# PDF417 Generation
pdf417==1.1.0
Pillow>=10.0.0

# Chart.js (via CDN, no pip needed)
# Bootstrap 5 (via CDN, no pip needed)
```

### Installation

```bash
# En el contenedor Odoo
pip install pdf417 Pillow

# O via Dockerfile
RUN pip install pdf417 Pillow
```

### Verificación

```python
# Verificar instalación
import pdf417
from PIL import Image
print("✅ Dependencias instaladas correctamente")
```

---

## 🚀 DEPLOYMENT

### Checklist Pre-Deploy

**BBDD TEST:**
- [ ] Módulos instalados (l10n_cl_dte, l10n_cl_dte_enhanced, eergygroup_branding)
- [ ] Dependencias Python instaladas
- [ ] Tests pasando (>85% coverage)
- [ ] Reportes PDF generándose correctamente
- [ ] Dashboard accesible

**BBDD STAGING:**
- [ ] Backup BBDD antes de deploy
- [ ] Deploy modules via -u flag
- [ ] Smoke tests
- [ ] UAT con usuarios reales

**PRODUCCIÓN:**
- [ ] Backup BBDD
- [ ] Ventana de mantenimiento programada
- [ ] Deploy durante horario de baja carga
- [ ] Rollback plan documentado
- [ ] Monitoring activo

---

## 📖 DOCUMENTACIÓN

### Documentos a Crear

1. **TECHNICAL_DOCUMENTATION.md**
   - Arquitectura de reportes
   - API Reference (métodos helper)
   - Guía de troubleshooting

2. **USER_MANUAL.md**
   - Cómo generar reportes PDF
   - Cómo usar dashboard
   - FAQ

3. **VIDEO_TUTORIAL.mp4**
   - 5 minutos
   - Demostración completa
   - En español

---

## ✅ DEFINITION OF DONE

### Criterios de Aceptación

**Reportes PDF:**
- [ ] PDF417 se genera correctamente
- [ ] Todos los campos enhanced visibles
- [ ] Branding EERGYGROUP aplicado
- [ ] Referencias SII mostradas
- [ ] Layout responsivo

**Dashboard:**
- [ ] Vista Kanban funcional
- [ ] 5 gráficos operativos
- [ ] Filtros funcionando
- [ ] Export Excel funcional

**Quality:**
- [ ] >85% test coverage
- [ ] 0 errores críticos
- [ ] 0 warnings funcionales
- [ ] Documentación completa
- [ ] Code review aprobado

---

## 🎓 LECCIONES APRENDIDAS

*(A completar post-implementación)*

### Challenges
- ...

### Solutions
- ...

### Improvements
- ...

---

**Firma Digital:**
Ing. Pedro Troncoso Willz
Senior Software Engineer - EERGYGROUP

**Fecha:** 2025-11-04
**Versión Plan:** 1.0.0
**Estado:** APPROVED - READY TO START

---

**© 2025 EERGYGROUP - Confidencial**
**Licencia:** LGPL-3
