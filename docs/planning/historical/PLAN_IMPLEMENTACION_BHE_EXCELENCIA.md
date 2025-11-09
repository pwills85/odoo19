# 📋 PLAN IMPLEMENTACIÓN BHE (BOLETA HONORARIOS ELECTRÓNICA) - EXCELENCIA

**Fecha:** 2025-10-23
**Estado:** READY TO IMPLEMENT
**Prioridad:** P1 - CRÍTICO para empresa ingeniería
**Inversión Estimada:** $2,800 USD (7 días)
**ROI:** ESENCIAL para compliance legal + operación B2B

---

## 🎯 RESUMEN EJECUTIVO

### Contexto Empresarial

**Empresa de Ingeniería y Desarrollo de Proyectos** requiere recepción y gestión de **Boletas de Honorarios Electrónicas (BHE - DTE 70)** emitidas por:

- Ingenieros consultores externos
- Arquitectos freelance
- Especialistas técnicos
- Profesionales independientes

**Flujo Típico:**
1. Ingeniero externo emite BHE por $1.000.000 (servicios profesionales)
2. Empresa receptora retiene 14.5% ($145.000) como retención de impuestos
3. Se paga al profesional $855.000 neto
4. Retención se declara mensualmente al SII en F29
5. Se genera Libro Mensual de Honorarios para control tributario

### Estado Actual del Stack

#### ✅ LO QUE TENEMOS (50% Implementado)

**DTE Service - Tests & Validators:**
- ✅ `dte-service/tests/test_bhe_reception.py` (215 líneas) - 5 test cases BHE
- ✅ `dte-service/validators/received_dte_validator.py` (521 líneas)
  - Método `_validate_bhe_specific()` (líneas 312-353)
  - Validación retención 10% (ahora 14.5% en 2025)
  - Validación sin IVA
  - VALID_DTE_TYPES incluye '70' y '71'

**Odoo Module - Parcial:**
- ✅ `models/dte_inbox.py` menciona BHE en selection field (línea 70: DTE 70)
- ✅ `models/retencion_iue.py` (100+ líneas) - Modelo retenciones IUE
- ✅ Views mencionan "Boletas de Honorarios" en wizards

#### ❌ LO QUE NOS FALTA (50% Missing)

**CRÍTICO - Modelo Core BHE:**
- ❌ Modelo `l10n_cl.bhe` (NO existe en Odoo 19)
- ❌ Modelo `l10n_cl.bhe.book` (Libro mensual - NO existe)
- ❌ Modelo `l10n_cl.bhe.book.line` (Líneas libro - NO existe)

**IMPORTANTE - UI/UX:**
- ❌ Views BHE (`l10n_cl_bhe_views.xml` - NO existe)
- ❌ Views Libro BHE (`l10n_cl_bhe_book_views.xml` - NO existe)
- ❌ Menús y acciones (NO existen)

**IMPORTANTE - Lógica Negocio:**
- ❌ Contabilización automática (Gasto + Retención + Por Pagar)
- ❌ Generación asiento contable
- ❌ Cálculo retención 14.5% (2025)
- ❌ Generación libro mensual

**DESEABLE - Extras:**
- ⚠️ Wizard importación desde PDF/XML
- ⚠️ Integración con F29 (declaración mensual)
- ⚠️ Reportes PDF BHE

---

## 📊 ANÁLISIS COMPARATIVO: ODOO 18 vs ODOO 19

### ODOO 18 - IMPLEMENTACIÓN COMPLETA (Referencia)

**Ubicación:** `/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/dev_odoo_18/addons/l10n_cl_fe/`

#### Modelo l10n_cl_bhe.py (16,068 líneas - COMPLETO)

```python
class L10nClBhe(models.Model):
    """
    Boleta de Honorarios Electrónica (BHE) - Chilean Electronic Fee Receipt
    Document Type 70 according to SII standards

    IMPORTANTE: Este modelo maneja SOLO la RECEPCIÓN de BHE emitidas por terceros.
    Las empresas NO emiten BHE, solo las reciben de prestadores de servicios.
    """
    _name = "l10n_cl.bhe"
    _description = "Boleta de Honorarios Electrónica"
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = "date desc, number desc"

    # Campos Principales:
    number = fields.Char("Número BHE", required=True)
    date = fields.Date("Fecha Emisión", required=True)
    partner_id = fields.Many2one("res.partner", "Prestador de Servicios")
    partner_vat = fields.Char(related="partner_id.vat", string="RUT Prestador")

    # Montos:
    amount_gross = fields.Monetary("Monto Bruto")
    retention_rate = fields.Float("Tasa de Retención (%)", default=14.5)  # 2025
    amount_retention = fields.Monetary("Monto Retención", compute="_compute_amounts")
    amount_net = fields.Monetary("Monto Líquido", compute="_compute_amounts")

    # Estados:
    state = fields.Selection([
        ("draft", "Borrador"),
        ("posted", "Emitido"),
        ("sent", "Enviado al SII"),
        ("accepted", "Aceptado por SII"),
        ("rejected", "Rechazado por SII"),
        ("cancelled", "Anulado")
    ], default="draft")

    # Contabilidad:
    move_id = fields.Many2one("account.move", "Asiento Contable")
    payment_id = fields.Many2one("account.payment", "Pago")

    # SII:
    sii_send_date = fields.Datetime("Fecha Envío SII")
    sii_track_id = fields.Char("Track ID SII")
    sii_status = fields.Char("Estado SII")
    xml_file = fields.Binary("XML Recibido")

    # Métodos:
    def action_post(self):
        """Contabilizar BHE"""
        # Crea asiento contable:
        # Débito: Gasto Honorarios (6301010)
        # Crédito: Retención Honorarios (2105020)
        # Crédito: Por Pagar Proveedor (2101010)

    def action_validate_sii(self):
        """Validar con SII"""

    def _compute_amounts(self):
        """Calcula retención y neto"""
        for rec in self:
            rec.amount_retention = rec.amount_gross * (rec.retention_rate / 100)
            rec.amount_net = rec.amount_gross - rec.amount_retention
```

**LOC Total:** ~600 líneas core logic + 15,468 líneas tests/comments

#### Modelo l10n_cl_bhe_book.py (COMPLETO)

```python
class L10nClBheBook(models.Model):
    """
    Libro de Boletas de Honorarios Electrónicas
    Monthly book for tax reporting of BHE documents
    """
    _name = "l10n_cl.bhe.book"
    _description = "Libro de Boletas de Honorarios"

    # Período:
    period_year = fields.Integer("Año")
    period_month = fields.Selection([...], "Mes")
    date_from = fields.Date("Desde", compute="_compute_dates")
    date_to = fields.Date("Hasta", compute="_compute_dates")

    # Líneas:
    line_ids = fields.One2many("l10n_cl.bhe.book.line", "book_id", "Líneas")

    # Totales:
    total_count = fields.Integer("Total BHE", compute="_compute_totals")
    total_gross = fields.Monetary("Total Monto Bruto", compute="_compute_totals")
    total_retention = fields.Monetary("Total Retenciones", compute="_compute_totals")
    total_net = fields.Monetary("Total Neto", compute="_compute_totals")

    # Estado:
    state = fields.Selection([
        ("draft", "Borrador"),
        ("posted", "Confirmado"),
        ("sent", "Enviado al SII")
    ])

    # Métodos:
    def action_generate_lines(self):
        """Genera líneas desde BHE del período"""

    def action_export_excel(self):
        """Exporta libro a Excel para SII"""

    def action_send_sii(self):
        """Envía libro al SII"""
```

**LOC Total:** ~400 líneas

#### Views l10n_cl_bhe_views.xml (343 líneas)

- Tree View: Lista BHE con totales
- Form View: Formulario detallado con:
  - Header: Botones (Contabilizar, Validar SII, Anular, Imprimir)
  - Panel izquierdo: Fecha, Prestador, RUT, Empresa
  - Panel derecho: Montos (Bruto, Retención %, Retención $, Neto)
  - Notebook:
    - Descripción Servicio (text field largo)
    - Información SII (track ID, XML request/response)
    - Contabilidad (asiento, pago)
    - Notas
  - Chatter: Mensajes, actividades
- Search View: Filtros por estado, mes, prestador
- Report Template: PDF BHE

#### Views l10n_cl_bhe_book_views.xml (239 líneas)

- Tree View: Lista libros con totales
- Form View: Formulario libro con líneas One2many
- Actions: Generar líneas, Exportar Excel, Enviar SII

#### Tests test_bhe_reception.py (303 líneas)

- 10 test cases:
  1. Recepción básica
  2. Tasas retención según fecha
  3. Contabilización
  4. Validaciones
  5. Anulación
  6. Procesamiento XML
  7. Validación SII
  8. Seguridad
  9. Reporte PDF
  10. Recepción masiva (50 BHE < 10s)

### ODOO 19 - ESTADO ACTUAL (50%)

**Ubicación:** `/Users/pedro/Documents/odoo19/`

#### DTE Service (50% - Validators OK)

**✅ COMPLETO:**
- `dte-service/validators/received_dte_validator.py` (521 líneas)
  - Método `_validate_bhe_specific()` implementado (líneas 312-353)
  - Validaciones:
    - Retención 10% esperada (⚠️ actualizar a 14.5%)
    - Sin IVA (correcto)
    - Monto bruto vs retención coherente
- `dte-service/tests/test_bhe_reception.py` (215 líneas)
  - 5 test cases básicos
  - Validación retención
  - Validación sin IVA
  - Validación XML

**⚠️ ACTUALIZAR:**
- Línea 338: `retencion_esperada = monto_bruto * 0.10` → Cambiar a 0.145 (14.5%)
- Comentarios: Actualizar referencias "10%" → "14.5%"

#### Odoo Module (10% - Solo Menciones)

**❌ FALTA TODO:**
- NO existe `models/l10n_cl_bhe.py`
- NO existe `models/l10n_cl_bhe_book.py`
- NO existe `views/l10n_cl_bhe_views.xml`
- NO existe `views/l10n_cl_bhe_book_views.xml`

**✅ BASE DISPONIBLE:**
- `models/dte_inbox.py` tiene DTE 70 en selection
- `models/retencion_iue.py` tiene estructura base retenciones

---

## 🎯 PLAN DE IMPLEMENTACIÓN - 7 DÍAS

### FASE 1: Actualizar DTE Service (Día 1 - 0.5 días)

**Objetivo:** Ajustar validadores BHE con tasa 2025

**Tareas:**
1. ✅ Actualizar `received_dte_validator.py`:
   - Línea 338: Cambiar 0.10 → 0.145
   - Línea 335: Mensaje "10%" → "14.5%"
   - Línea 343: Mensaje "10%" → "14.5%"

2. ✅ Actualizar `test_bhe_reception.py`:
   - Test `test_bhe_valid_with_retention`: retention 14.5%
   - Test `test_bhe_without_retention_warning`: Mensaje 14.5%
   - Test `test_bhe_incorrect_retention_warning`: Validar 14.5%

**Entregables:**
- `received_dte_validator.py` actualizado
- `test_bhe_reception.py` actualizado
- Tests pasando: `pytest test_bhe_reception.py -v`

**Tiempo:** 4 horas
**Costo:** $200 USD

---

### FASE 2: Modelo Core BHE (Día 1-2 - 1.5 días)

**Objetivo:** Crear modelo `l10n_cl.bhe` completo

**Ubicación:** `addons/localization/l10n_cl_dte/models/l10n_cl_bhe.py`

**Estructura:**

```python
# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import logging

_logger = logging.getLogger(__name__)


class L10nClBhe(models.Model):
    """
    Boleta de Honorarios Electrónica (BHE) - Chilean Electronic Fee Receipt
    Document Type 70 according to SII standards

    IMPORTANTE: Este modelo maneja SOLO la RECEPCIÓN de BHE emitidas por terceros.
    Las empresas NO emiten BHE, solo las reciben de prestadores de servicios.

    Contexto: Empresa de ingeniería recibe BHE de:
    - Ingenieros consultores externos
    - Arquitectos freelance
    - Especialistas técnicos
    - Profesionales independientes

    Flujo:
    1. Profesional emite BHE por $1.000.000
    2. Empresa retiene 14.5% ($145.000)
    3. Se paga al profesional $855.000 neto
    4. Retención se declara mensualmente al SII (F29)
    """
    _name = "l10n_cl.bhe"
    _description = "Boleta de Honorarios Electrónica"
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = "date desc, number desc"
    _check_company_auto = True

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    name = fields.Char(
        string="Nombre",
        compute="_compute_name",
        store=True
    )

    number = fields.Char(
        string="Número BHE",
        required=True,
        copy=False,
        index=True,
        tracking=True
    )

    date = fields.Date(
        string="Fecha Emisión",
        required=True,
        default=fields.Date.context_today,
        tracking=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.company.currency_id,
        required=True
    )

    # ═══════════════════════════════════════════════════════════
    # PRESTADOR DE SERVICIOS (Emisor)
    # ═══════════════════════════════════════════════════════════

    partner_id = fields.Many2one(
        'res.partner',
        string="Prestador de Servicios",
        required=True,
        domain="[('is_company', '=', False)]",  # Solo personas naturales
        tracking=True,
        help="Profesional independiente que emite la BHE"
    )

    partner_vat = fields.Char(
        related="partner_id.vat",
        string="RUT Prestador",
        store=True,
        readonly=True
    )

    # ═══════════════════════════════════════════════════════════
    # DESCRIPCIÓN DEL SERVICIO
    # ═══════════════════════════════════════════════════════════

    service_description = fields.Text(
        string="Descripción del Servicio",
        required=True,
        tracking=True,
        help="Detalle de los servicios profesionales prestados"
    )

    # ═══════════════════════════════════════════════════════════
    # MONTOS
    # ═══════════════════════════════════════════════════════════

    amount_gross = fields.Monetary(
        string="Monto Bruto",
        required=True,
        tracking=True,
        currency_field='currency_id',
        help="Monto total ANTES de retención"
    )

    retention_rate = fields.Float(
        string="Tasa de Retención (%)",
        default=14.5,  # 2025 rate (era 13.75% hasta 2024)
        required=True,
        digits=(5, 2),
        tracking=True,
        help="Tasa de retención: 14.5% desde enero 2025"
    )

    amount_retention = fields.Monetary(
        string="Monto Retención",
        compute="_compute_amounts",
        store=True,
        currency_field='currency_id',
        help="Retención = Bruto * Tasa%"
    )

    amount_net = fields.Monetary(
        string="Monto Líquido",
        compute="_compute_amounts",
        store=True,
        currency_field='currency_id',
        help="Neto = Bruto - Retención (monto a pagar al profesional)"
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('posted', 'Contabilizado'),
        ('sent', 'Enviado al SII'),
        ('accepted', 'Aceptado por SII'),
        ('rejected', 'Rechazado por SII'),
        ('cancelled', 'Anulado')
    ], string='Estado', default='draft', tracking=True, copy=False)

    # ═══════════════════════════════════════════════════════════
    # CONTABILIDAD
    # ═══════════════════════════════════════════════════════════

    move_id = fields.Many2one(
        'account.move',
        string="Asiento Contable",
        readonly=True,
        copy=False,
        help="Asiento generado automáticamente al contabilizar"
    )

    payment_id = fields.Many2one(
        'account.payment',
        string="Pago",
        readonly=True,
        copy=False,
        help="Pago asociado al profesional"
    )

    # ═══════════════════════════════════════════════════════════
    # SII
    # ═══════════════════════════════════════════════════════════

    sii_send_date = fields.Datetime(
        string="Fecha Envío SII",
        readonly=True,
        copy=False
    )

    sii_track_id = fields.Char(
        string="Track ID SII",
        readonly=True,
        copy=False
    )

    sii_status = fields.Char(
        string="Estado SII",
        readonly=True,
        copy=False
    )

    xml_file = fields.Binary(
        string="XML Recibido",
        attachment=True,
        copy=False
    )

    xml_filename = fields.Char(
        string="Nombre Archivo XML",
        compute="_compute_xml_filename",
        store=True
    )

    sii_xml_request = fields.Text(
        string="XML Request SII",
        readonly=True,
        copy=False
    )

    sii_xml_response = fields.Text(
        string="XML Response SII",
        readonly=True,
        copy=False
    )

    # ═══════════════════════════════════════════════════════════
    # NOTAS
    # ═══════════════════════════════════════════════════════════

    notes = fields.Text(
        string="Notas",
        help="Notas adicionales sobre la BHE"
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('number', 'partner_id')
    def _compute_name(self):
        for rec in self:
            if rec.number and rec.partner_id:
                rec.name = f"BHE {rec.number} - {rec.partner_id.name}"
            elif rec.number:
                rec.name = f"BHE {rec.number}"
            else:
                rec.name = "BHE Borrador"

    @api.depends('amount_gross', 'retention_rate')
    def _compute_amounts(self):
        for rec in self:
            rec.amount_retention = rec.amount_gross * (rec.retention_rate / 100)
            rec.amount_net = rec.amount_gross - rec.amount_retention

    @api.depends('number')
    def _compute_xml_filename(self):
        for rec in self:
            if rec.number:
                rec.xml_filename = f"BHE_{rec.number}_received.xml"
            else:
                rec.xml_filename = "BHE_received.xml"

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('amount_gross')
    def _check_amount_gross(self):
        for rec in self:
            if rec.amount_gross <= 0:
                raise ValidationError(
                    _("El monto bruto debe ser mayor a cero.")
                )

    @api.constrains('retention_rate')
    def _check_retention_rate(self):
        for rec in self:
            if rec.retention_rate < 0 or rec.retention_rate > 100:
                raise ValidationError(
                    _("La tasa de retención debe estar entre 0% y 100%.")
                )

    _sql_constraints = [
        ('number_partner_unique', 'unique(number, partner_id, company_id)',
         'Ya existe una BHE con este número para este prestador en esta compañía.')
    ]

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_post(self):
        """
        Contabilizar BHE:
        - Genera asiento contable con 3 líneas:
          1. Débito: Gasto Honorarios (cuenta 6301010)
          2. Crédito: Retención Honorarios (cuenta 2105020)
          3. Crédito: Por Pagar Proveedor (cuenta partner)
        """
        for rec in self:
            if rec.state != 'draft':
                raise UserError(_("Solo se pueden contabilizar BHE en estado Borrador."))

            # Obtener cuentas contables desde configuración empresa
            company = rec.company_id
            expense_account = company.l10n_cl_bhe_expense_account_id
            retention_account = company.l10n_cl_bhe_retention_account_id
            journal = company.l10n_cl_bhe_journal_id

            if not expense_account:
                raise UserError(
                    _("Configure la cuenta de gasto de honorarios en Configuración > BHE.")
                )
            if not retention_account:
                raise UserError(
                    _("Configure la cuenta de retención de honorarios en Configuración > BHE.")
                )
            if not journal:
                raise UserError(
                    _("Configure el diario de BHE en Configuración > BHE.")
                )

            # Crear asiento contable
            move_vals = {
                'journal_id': journal.id,
                'date': rec.date,
                'ref': f"BHE {rec.number} - {rec.partner_id.name}",
                'company_id': rec.company_id.id,
                'line_ids': [
                    # Línea 1: Débito Gasto Honorarios (total bruto)
                    (0, 0, {
                        'name': f"Honorarios - {rec.service_description[:50]}",
                        'account_id': expense_account.id,
                        'debit': rec.amount_gross,
                        'credit': 0.0,
                        'partner_id': rec.partner_id.id,
                    }),
                    # Línea 2: Crédito Retención Honorarios
                    (0, 0, {
                        'name': f"Retención {rec.retention_rate}% - BHE {rec.number}",
                        'account_id': retention_account.id,
                        'debit': 0.0,
                        'credit': rec.amount_retention,
                        'partner_id': rec.partner_id.id,
                    }),
                    # Línea 3: Crédito Por Pagar Proveedor (neto)
                    (0, 0, {
                        'name': f"BHE {rec.number} - Por Pagar",
                        'account_id': rec.partner_id.property_account_payable_id.id,
                        'debit': 0.0,
                        'credit': rec.amount_net,
                        'partner_id': rec.partner_id.id,
                    }),
                ]
            }

            move = self.env['account.move'].create(move_vals)
            move.action_post()

            rec.write({
                'move_id': move.id,
                'state': 'posted'
            })

            _logger.info(f"✅ BHE {rec.number} contabilizada - Asiento {move.name}")

    def action_validate_sii(self):
        """Validar BHE con SII (placeholder - implementar SOAP)"""
        for rec in self:
            if rec.state != 'posted':
                raise UserError(_("Solo se pueden validar BHE contabilizadas."))

            # TODO: Implementar validación SII
            rec.write({
                'state': 'accepted',
                'sii_send_date': fields.Datetime.now(),
                'sii_status': 'ACEPTADO'
            })

    def action_cancel(self):
        """Anular BHE y eliminar asiento contable"""
        for rec in self:
            if rec.state == 'cancelled':
                raise UserError(_("La BHE ya está anulada."))

            # Eliminar asiento contable si existe
            if rec.move_id:
                if rec.move_id.state == 'posted':
                    rec.move_id.button_draft()
                rec.move_id.unlink()

            rec.write({
                'state': 'cancelled',
                'move_id': False
            })

    def action_draft(self):
        """Volver a borrador"""
        for rec in self:
            if rec.state != 'cancelled':
                raise UserError(_("Solo se pueden volver a borrador BHE anuladas."))

            rec.write({'state': 'draft'})

    def print_bhe(self):
        """Imprimir BHE"""
        return self.env.ref('l10n_cl_dte.action_report_bhe').report_action(self)

    def _process_received_xml(self, xml_content):
        """Procesar XML recibido"""
        self.ensure_one()

        self.write({
            'xml_file': xml_content.encode('utf-8'),
            'sii_xml_request': xml_content
        })

    def get_bhe_report_values(self):
        """Obtener valores para reporte PDF"""
        self.ensure_one()

        return {
            'doc': self,
            'company': self.company_id,
            'partner': self.partner_id,
        }
```

**LOC Estimadas:** ~600 líneas

**Entregables:**
- `models/l10n_cl_bhe.py` creado
- `models/__init__.py` actualizado
- Security: `security/ir.model.access.csv` actualizado

**Tiempo:** 12 horas
**Costo:** $600 USD

---

### FASE 3: Modelo Libro BHE (Día 2-3 - 1 día)

**Objetivo:** Crear modelos `l10n_cl.bhe.book` y `l10n_cl.bhe.book.line`

**Ubicación:** `addons/localization/l10n_cl_dte/models/l10n_cl_bhe_book.py`

**Estructura:**

```python
# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class L10nClBheBook(models.Model):
    """
    Libro de Boletas de Honorarios Electrónicas
    Monthly book for tax reporting of BHE documents
    """
    _name = "l10n_cl.bhe.book"
    _description = "Libro de Boletas de Honorarios"
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = "period_year desc, period_month desc"

    name = fields.Char(
        string="Nombre",
        compute="_compute_name",
        store=True
    )

    display_name = fields.Char(
        string="Display Name",
        compute="_compute_display_name",
        store=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        default=lambda self: self.env.company.currency_id
    )

    # Período
    period_year = fields.Integer(
        string="Año",
        required=True,
        default=lambda self: fields.Date.today().year
    )

    period_month = fields.Selection([
        ('1', 'Enero'),
        ('2', 'Febrero'),
        ('3', 'Marzo'),
        ('4', 'Abril'),
        ('5', 'Mayo'),
        ('6', 'Junio'),
        ('7', 'Julio'),
        ('8', 'Agosto'),
        ('9', 'Septiembre'),
        ('10', 'Octubre'),
        ('11', 'Noviembre'),
        ('12', 'Diciembre'),
    ], string="Mes", required=True, default=lambda self: str(fields.Date.today().month))

    date_from = fields.Date(
        string="Desde",
        compute="_compute_dates",
        store=True
    )

    date_to = fields.Date(
        string="Hasta",
        compute="_compute_dates",
        store=True
    )

    # Líneas
    line_ids = fields.One2many(
        'l10n_cl.bhe.book.line',
        'book_id',
        string="Líneas del Libro"
    )

    # Totales
    total_count = fields.Integer(
        string="Total BHE",
        compute="_compute_totals",
        store=True
    )

    total_gross = fields.Monetary(
        string="Total Monto Bruto",
        compute="_compute_totals",
        store=True,
        currency_field='currency_id'
    )

    total_retention = fields.Monetary(
        string="Total Retenciones",
        compute="_compute_totals",
        store=True,
        currency_field='currency_id'
    )

    total_net = fields.Monetary(
        string="Total Neto",
        compute="_compute_totals",
        store=True,
        currency_field='currency_id'
    )

    # Estado
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('posted', 'Confirmado'),
        ('sent', 'Enviado al SII')
    ], string='Estado', default='draft', tracking=True)

    # Exportación
    export_file = fields.Binary(
        string="Archivo Exportado",
        attachment=True
    )

    export_filename = fields.Char(
        string="Nombre Archivo"
    )

    notes = fields.Text(string="Notas")

    # Computed
    @api.depends('period_year', 'period_month')
    def _compute_name(self):
        for rec in self:
            if rec.period_year and rec.period_month:
                month_name = dict(rec._fields['period_month'].selection)[rec.period_month]
                rec.name = f"Libro BHE {month_name} {rec.period_year}"
            else:
                rec.name = "Libro BHE"

    @api.depends('name')
    def _compute_display_name(self):
        for rec in self:
            rec.display_name = rec.name

    @api.depends('period_year', 'period_month')
    def _compute_dates(self):
        for rec in self:
            if rec.period_year and rec.period_month:
                month = int(rec.period_month)
                date_from = fields.Date(rec.period_year, month, 1)
                date_to = date_from + relativedelta(day=31)
                rec.date_from = date_from
                rec.date_to = date_to

    @api.depends('line_ids', 'line_ids.amount_gross', 'line_ids.amount_retention', 'line_ids.amount_net')
    def _compute_totals(self):
        for rec in self:
            rec.total_count = len(rec.line_ids)
            rec.total_gross = sum(rec.line_ids.mapped('amount_gross'))
            rec.total_retention = sum(rec.line_ids.mapped('amount_retention'))
            rec.total_net = sum(rec.line_ids.mapped('amount_net'))

    # Actions
    def action_generate_lines(self):
        """Generar líneas desde BHE del período"""
        for rec in self:
            if rec.state != 'draft':
                raise UserError(_("Solo se pueden generar líneas en estado Borrador."))

            # Buscar BHE del período
            bhes = self.env['l10n_cl.bhe'].search([
                ('company_id', '=', rec.company_id.id),
                ('date', '>=', rec.date_from),
                ('date', '<=', rec.date_to),
                ('state', 'in', ['posted', 'accepted'])
            ])

            if not bhes:
                raise UserError(
                    _("No se encontraron BHE contabilizadas en el período %s/%s.") %
                    (rec.period_month, rec.period_year)
                )

            # Limpiar líneas existentes
            rec.line_ids.unlink()

            # Crear líneas
            line_number = 1
            for bhe in bhes.sorted('date'):
                self.env['l10n_cl.bhe.book.line'].create({
                    'book_id': rec.id,
                    'line_number': line_number,
                    'bhe_id': bhe.id,
                    'bhe_date': bhe.date,
                    'bhe_number': bhe.number,
                    'partner_id': bhe.partner_id.id,
                    'partner_vat': bhe.partner_vat,
                    'partner_name': bhe.partner_id.name,
                    'service_description': bhe.service_description,
                    'amount_gross': bhe.amount_gross,
                    'retention_rate': bhe.retention_rate,
                    'amount_retention': bhe.amount_retention,
                    'amount_net': bhe.amount_net,
                })
                line_number += 1

            _logger.info(f"✅ Libro BHE generado: {len(bhes)} BHE del período")

    def action_post(self):
        """Confirmar libro"""
        for rec in self:
            if not rec.line_ids:
                raise UserError(_("El libro no tiene líneas. Genere las líneas primero."))

            rec.write({'state': 'posted'})

    def action_export_excel(self):
        """Exportar libro a Excel"""
        # TODO: Implementar exportación Excel
        pass

    def action_send_sii(self):
        """Enviar libro al SII"""
        # TODO: Implementar envío SII
        pass

    def action_draft(self):
        """Volver a borrador"""
        for rec in self:
            rec.write({'state': 'draft'})


class L10nClBheBookLine(models.Model):
    """Línea de Libro de Boletas de Honorarios"""
    _name = "l10n_cl.bhe.book.line"
    _description = "Línea de Libro de Boletas de Honorarios"
    _order = "book_id, line_number"

    book_id = fields.Many2one(
        'l10n_cl.bhe.book',
        string="Libro",
        required=True,
        ondelete='cascade'
    )

    line_number = fields.Integer(
        string="Nº Línea",
        required=True
    )

    bhe_id = fields.Many2one(
        'l10n_cl.bhe',
        string="BHE",
        readonly=True
    )

    bhe_date = fields.Date(
        string="Fecha BHE",
        required=True
    )

    bhe_number = fields.Char(
        string="Número BHE",
        required=True
    )

    partner_id = fields.Many2one(
        'res.partner',
        string="Prestador",
        required=True
    )

    partner_vat = fields.Char(
        string="RUT Prestador",
        required=True
    )

    partner_name = fields.Char(
        string="Nombre Prestador",
        required=True
    )

    service_description = fields.Text(
        string="Descripción Servicio"
    )

    currency_id = fields.Many2one(
        related='book_id.currency_id',
        string='Moneda'
    )

    amount_gross = fields.Monetary(
        string="Monto Bruto",
        required=True,
        currency_field='currency_id'
    )

    retention_rate = fields.Float(
        string="Tasa Retención (%)",
        required=True,
        digits=(5, 2)
    )

    amount_retention = fields.Monetary(
        string="Monto Retención",
        required=True,
        currency_field='currency_id'
    )

    amount_net = fields.Monetary(
        string="Monto Neto",
        required=True,
        currency_field='currency_id'
    )
```

**LOC Estimadas:** ~400 líneas

**Entregables:**
- `models/l10n_cl_bhe_book.py` creado
- `models/__init__.py` actualizado
- Security actualizado

**Tiempo:** 8 horas
**Costo:** $400 USD

---

### FASE 4: Views BHE (Día 3-4 - 1 día)

**Objetivo:** Crear `l10n_cl_bhe_views.xml` completo

**Ubicación:** `addons/localization/l10n_cl_dte/views/l10n_cl_bhe_views.xml`

**Componentes:**
1. Tree View (lista)
2. Form View (formulario detallado)
3. Search View (filtros y búsqueda)
4. Action
5. Menu
6. Report PDF Template

**LOC Estimadas:** ~350 líneas

**Tiempo:** 6 horas
**Costo:** $300 USD

---

### FASE 5: Views Libro BHE (Día 4 - 0.5 días)

**Objetivo:** Crear `l10n_cl_bhe_book_views.xml`

**Ubicación:** `addons/localization/l10n_cl_dte/views/l10n_cl_bhe_book_views.xml`

**LOC Estimadas:** ~250 líneas

**Tiempo:** 4 horas
**Costo:** $200 USD

---

### FASE 6: Configuración Empresa (Día 5 - 0.5 días)

**Objetivo:** Agregar campos configuración BHE en `res.company`

**Tareas:**
1. Agregar campos a `models/res_company_dte.py`:
   - `l10n_cl_bhe_journal_id` (Many2one account.journal)
   - `l10n_cl_bhe_expense_account_id` (Many2one account.account)
   - `l10n_cl_bhe_retention_account_id` (Many2one account.account)

2. Actualizar `views/res_config_settings_views.xml`:
   - Agregar sección "Configuración BHE"
   - 3 campos configuración

**LOC Estimadas:** ~100 líneas

**Tiempo:** 4 horas
**Costo:** $200 USD

---

### FASE 7: Tests Odoo (Día 5-6 - 1 día)

**Objetivo:** Crear `tests/test_l10n_cl_bhe.py`

**Test Cases:**
1. `test_create_bhe` - Crear BHE básica
2. `test_compute_amounts` - Validar cálculo retención
3. `test_post_bhe` - Contabilización y asiento
4. `test_cancel_bhe` - Anulación
5. `test_constraints` - Validaciones
6. `test_bhe_book_generation` - Generar libro
7. `test_bhe_book_totals` - Totales libro

**LOC Estimadas:** ~400 líneas

**Tiempo:** 8 horas
**Costo:** $400 USD

---

### FASE 8: Integración & QA (Día 6-7 - 1 día)

**Objetivo:** Integrar todo y testing completo

**Tareas:**
1. Actualizar `__manifest__.py`:
   - Agregar BHE a depends
   - Agregar views
   - Agregar data
   - Actualizar version

2. Rebuild Docker:
   ```bash
   docker-compose build odoo
   docker-compose up -d odoo
   ```

3. Install module:
   ```bash
   docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -u l10n_cl_dte --test-enable
   ```

4. Manual QA:
   - Crear 5 BHE test
   - Contabilizar
   - Generar libro mensual
   - Validar totales
   - Verificar reportes

5. Documentación:
   - Actualizar `CLAUDE.md`
   - Actualizar `README.md`
   - Crear guía usuario `docs/BHE_USER_GUIDE.md`

**Tiempo:** 8 horas
**Costo:** $400 USD

---

## 📊 RESUMEN INVERSIÓN

| Fase | Descripción | Días | Horas | Costo |
|------|-------------|------|-------|-------|
| 1 | Actualizar DTE Service | 0.5 | 4h | $200 |
| 2 | Modelo Core BHE | 1.5 | 12h | $600 |
| 3 | Modelo Libro BHE | 1.0 | 8h | $400 |
| 4 | Views BHE | 1.0 | 6h | $300 |
| 5 | Views Libro BHE | 0.5 | 4h | $200 |
| 6 | Configuración Empresa | 0.5 | 4h | $200 |
| 7 | Tests Odoo | 1.0 | 8h | $400 |
| 8 | Integración & QA | 1.0 | 8h | $400 |
| **TOTAL** | **BHE Completo** | **7.0** | **54h** | **$2,700** |

**Contingencia 10%:** +$300
**TOTAL FINAL:** **$3,000 USD**

---

## 🎯 ENTREGABLES

### Código
- ✅ `models/l10n_cl_bhe.py` (600 LOC)
- ✅ `models/l10n_cl_bhe_book.py` (400 LOC)
- ✅ `views/l10n_cl_bhe_views.xml` (350 LOC)
- ✅ `views/l10n_cl_bhe_book_views.xml` (250 LOC)
- ✅ `tests/test_l10n_cl_bhe.py` (400 LOC)
- ✅ DTE Service actualizado (validators + tests)
- ✅ Security actualizado
- ✅ Manifest actualizado

**Total LOC:** ~2,100 líneas

### Documentación
- ✅ `docs/BHE_USER_GUIDE.md` - Guía usuario final
- ✅ `CLAUDE.md` actualizado - Sección BHE
- ✅ `README.md` actualizado - Progress BHE

### Tests
- ✅ 7 test cases Odoo (`test_l10n_cl_bhe.py`)
- ✅ 5 test cases DTE Service (ya existen, actualizar)
- ✅ 100% funcionalidad crítica cubierta

---

## 🎓 CONOCIMIENTO LEGAL Y TÉCNICO

### Tasa Retención BHE

**Historial Tasas:**
- Hasta 2020: 10%
- 2021: 11.5%
- 2022: 12.25%
- 2023: 13.0%
- 2024: 13.75%
- **2025 (actual): 14.5%** ⭐

**Fuente:** Ley 21.133 (Reforma Tributaria), DFL 150, Art. 50 CT

### Compliance Legal

**Obligaciones Empresa Receptora:**
1. Retener 14.5% del monto bruto
2. Pagar al profesional el monto neto (85.5%)
3. Declarar retenciones mensualmente en F29
4. Generar Libro de Honorarios mensual
5. Entregar Certificado Anual al profesional (marzo año siguiente)

**SII:**
- Res. Ex. N° 34 del 2019 (Boleta Honorarios Electrónica)
- Circular N° 44 del 2019

### Asiento Contable BHE

**Ejemplo:** BHE $1.000.000 (retención 14.5%)

```
Debe:
  6301010 - Honorarios por Servicios Profesionales    $1.000.000

Haber:
  2105020 - Retención Honorarios (Impuesto)             $145.000
  2101010 - Por Pagar Proveedor (Profesional)          $855.000
```

**Cuentas Recomendadas:**
- **6301010:** Gasto Honorarios (Expense)
- **2105020:** Retención Honorarios (Current Liability)
- **2101010:** Por Pagar Proveedor (Accounts Payable)

---

## ✅ CRITERIOS DE ACEPTACIÓN

### Funcional
- ✅ Crear BHE manualmente desde UI
- ✅ Calcular automáticamente retención 14.5%
- ✅ Contabilizar BHE → Generar asiento 3 líneas
- ✅ Anular BHE → Eliminar asiento
- ✅ Generar Libro Mensual desde BHE del período
- ✅ Libro calcula totales correctamente
- ✅ Exportar libro a Excel (para SII)
- ✅ Workflow completo: Draft → Posted → Accepted

### Técnico
- ✅ Tests pasando: `pytest dte-service/tests/test_bhe_reception.py -v`
- ✅ Tests pasando: `docker-compose exec odoo odoo --test-enable -u l10n_cl_dte`
- ✅ Sin errores en logs Odoo
- ✅ Sin errores en logs DTE Service
- ✅ Coverage tests ≥ 80%

### UX
- ✅ Form view BHE intuitivo
- ✅ Cálculos en tiempo real (computed fields)
- ✅ Mensajes de error claros
- ✅ Chatter habilitado (mensajes, actividades)
- ✅ Filtros y búsquedas útiles

### Compliance
- ✅ Tasa retención 14.5% (2025)
- ✅ Asiento contable SII-compliant
- ✅ Libro mensual según formato SII
- ✅ Campos obligatorios según normativa

---

## 🚀 NEXT STEPS INMEDIATOS

### Paso 1: Aprobar Plan (DECISIÓN)

**Usuario decide:**
- [ ] ✅ **APROBAR** implementación BHE ($3,000, 7 días)
- [ ] ⏸️ **POSTERGAR** para después (actualizar prioridades)
- [ ] ❌ **RECHAZAR** (no necesario para empresa)

### Paso 2: Si Aprobado → Start Fase 1

```bash
# 1. Actualizar validators DTE Service
cd /Users/pedro/Documents/odoo19/dte-service
# Editar received_dte_validator.py líneas 335, 338, 343
# Cambiar 0.10 → 0.145, "10%" → "14.5%"

# 2. Actualizar tests
# Editar test_bhe_reception.py líneas 68, 111
# Cambiar retention_rate: 11.5 → 14.5

# 3. Run tests
pytest tests/test_bhe_reception.py -v

# 4. Commit
git add .
git commit -m "feat(bhe): Update retention rate to 14.5% (2025)"
```

### Paso 3: Fase 2-8 Secuencial

Seguir plan día por día, validando cada fase antes de avanzar.

---

## 📚 REFERENCIAS

### Odoo 18 (Referencia Completa)
- `/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/dev_odoo_18/addons/l10n_cl_fe/models/l10n_cl_bhe.py`
- `/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/dev_odoo_18/addons/l10n_cl_fe/views/l10n_cl_bhe_views.xml`
- `/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/dev_odoo_18/addons/l10n_cl_fe/tests/test_bhe_reception.py`

### SII Oficial
- https://www.sii.cl/servicios_online/1039-1289.html (Boletas Honorarios)
- https://www.sii.cl/preguntas_frecuentes/honorarios/ (FAQ)

### Legal
- Ley 21.133 (Reforma Tributaria)
- DFL 150 (Estatuto Tributario)
- Circular SII N° 44 del 2019

---

**Fecha Documento:** 2025-10-23
**Autor:** Claude Code (SuperClaude)
**Versión:** 1.0
**Estado:** ✅ READY TO IMPLEMENT
