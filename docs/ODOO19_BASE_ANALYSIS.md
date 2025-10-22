# 🔍 Análisis de Funcionalidades Base: Odoo 19 CE

## Objetivo
Identificar todas las funcionalidades de facturación, impuestos, validación y reportes que ya existen en Odoo 19 CE para **no duplicar** al desarrollar el módulo `l10n_cl_dte`, maximizando reutilización de código base y manteniendo altos estándares de programación.

**Fecha:** 2025-10-21  
**Versión:** Odoo 19.0 Community Edition  
**Enfoque:** DRY (Don't Repeat Yourself) - Máxima integración

---

## PARTE 1: MÓDULOS CORE A ANALIZAR

### 1.1 Módulo `account` (Contabilidad Base)

**Ya Existe en Odoo 19 CE:**

```python
# Modelos principales
account.account              # Plan de cuentas
account.move                 # Asientos contables (facturas/notas)
account.move.line           # Líneas de asientos
account.journal             # Diarios contables
account.payment             # Pagos
account.bank.account        # Cuentas bancarias
account.chart.template      # Plantillas de planes de cuentas
account.fiscal.year         # Años fiscales
account.tax                 # Impuestos
account.tax.group           # Grupos de impuestos
account.intrastat.code      # Códigos intrastat
```

**Funcionalidades Clave que YA EXISTEN:**

1. **Creación y Edición de Facturas:**
   - Creación de facturas/notas de crédito
   - Validación de sumas y moneda
   - Estados de documento (borrador, enviado, pagado, cancelado)
   - Control de acceso y permisos

2. **Gestión de Números/Folios:**
   ```python
   # Odoo 19 incluye:
   - journal.sequence  # Secuencias de numeración
   - account.move.name  # Campo name (número de factura)
   - Validación de unicidad
   - Control de secuencia por diario
   ```

3. **Impuestos:**
   ```python
   # Odoo 19 base tiene:
   - account.tax        # Modelo de impuesto
   - Cálculo automático de impuestos
   - Tipos: venta, compra, entrada
   - Posibilidad de múltiples impuestos por línea
   - account.tax.template (para plantillas)
   ```

4. **Validación de Datos:**
   ```python
   # Validaciones nativas de Odoo:
   - Validación de moneda
   - Validación de contacto requerido
   - Validación de líneas vacías
   - Validación de sumas
   - _onchange_* para actualizaciones automáticas
   ```

5. **Reportes PDF:**
   ```python
   # Odoo 19 incluye reportes para:
   - Factura PDF (account.report_invoice)
   - Pago PDF
   - Análisis contable
   - Métodos de reportes heredables
   - Uso de templates QWeb
   ```

6. **Campos de Control:**
   ```python
   # account.move tiene:
   - date: Fecha documento
   - invoice_date: Fecha factura
   - invoice_date_due: Fecha vencimiento
   - company_id: Empresa
   - partner_id: Contacto
   - currency_id: Moneda
   - amount_total: Total
   - amount_untaxed: Base imponible
   - amount_tax: Total impuestos
   - state: Estado (draft, posted, cancel)
   - ref: Referencia
   - memo: Memo/Descripción
   ```

---

### 1.2 Módulo `partner` (Gestión de Contactos)

**Ya Existe:**

```python
res.partner
├── name: Nombre
├── vat: RUT (RFC)
├── country_id: País
├── email: Email
├── phone: Teléfono
├── company_id: Empresa
├── category_ids: Categorías
└── property_account_*: Cuentas contables
```

**Importante para Chile:**
- Campo `vat` puede usarse para RUT
- Estructura flexible para agregar campos adicionales
- Validación de vat por plugin

---

### 1.3 Módulo `company` (Información Empresa)

**Ya Existe:**

```python
res.company
├── name: Nombre
├── vat: RUT empresa
├── phone: Teléfono
├── email: Email
├── country_id: País
├── currency_id: Moneda
├── chart_template_id: Plantilla plan cuentas
├── logo: Logo
├── bank_ids: Cuentas bancarias
└── (Personalizable con campos heredados)
```

**Lo que Podemos Extender:**
- Agregar campos específicos SII
- Datos tributarios adicionales
- Certificado digital

---

### 1.4 Módulo `stock` (Inventario)

**Ya Existe:**

```python
stock.move              # Movimientos de inventario
stock.picking          # Albaranes
account.move.line      # Relación con contabilidad
```

**Para Guías de Despacho (DTE 52):**
- `stock.picking` ya tiene estructura para guías
- Integración automática con account.move
- Campos: origin, name, date, partner_id

---

### 1.5 Módulo `purchase` (Compras)

**Ya Existe:**

```python
purchase.order
├── name: Número PO
├── partner_id: Proveedor
├── date_order: Fecha
├── amount_total: Total
├── state: Estado (draft, sent, to approve, purchase, done, cancel)
└── Integración con account.move (facturas de compra)
```

**Lo Importante:**
- Recepción de facturas de compra
- Validación de cantidad/monto
- Integración con diario de compras

---

### 1.6 Módulo `sale` (Ventas)

**Ya Existe:**

```python
sale.order
├── name: Número SO
├── partner_id: Cliente
├── date_order: Fecha
├── amount_total: Total
└── Relación automática con account.move (facturas de venta)
```

---

## PARTE 2: FUNCIONALIDADES A REUTILIZAR (NO DUPLICAR)

### 2.1 Validación de Datos

**YA EXISTE EN ODOO BASE:**

```python
# 1. Validación de campos obligatorios
_sql_constraints = [
    ('check_date', 'CHECK(date IS NOT NULL)', 'La fecha es obligatoria'),
]

# 2. Validación en métodos _check_*
@api.constrains('amount_total')
def _check_amount_positive(self):
    if self.amount_total < 0:
        raise ValidationError('El monto no puede ser negativo')

# 3. Onchanges automáticos
@api.onchange('partner_id')
def _onchange_partner_id(self):
    self.email = self.partner_id.email
    self.phone = self.partner_id.phone

# 4. Validación de moneda
_check_currency_match()
```

**LO QUE DEBEMOS HACER EN l10n_cl_dte:**
- Extender validación ESPECÍFICA DE CHILE (RUT, etc.)
- No reimplementar validaciones genéricas
- Usar herencia y mixins

### 2.2 Secuencias y Numeración

**YA EXISTE:**

```python
# Odoo 19 tiene sistema robusto de secuencias
account.journal.sequence_id  # Secuencia de facturación

# Métodos:
_auto_increment_sequential_fields()  # Auto-genera números
next_by_code()  # Siguiente número de secuencia
```

**LO QUE HACEMOS EN l10n_cl_dte:**
- Crear secuencia DTE específica (tipo Odoo)
- Gestionar folios en tabla `dte.folio.range`
- Respetar estructura de secuencias de Odoo

### 2.3 Reportes PDF

**YA EXISTE:**

```python
# Odoo tiene sistema de reportes robusto
class ReportAccountInvoice(models.AbstractModel):
    _name = 'report.account.report_invoice'
    
    def _get_report_values(self, docids, data=None):
        # Método heredable
        pass

# Templates QWeb disponibles
# /report/account/templates/report_invoice.html
```

**LO QUE HACEMOS EN l10n_cl_dte:**
- Heredar `report.report_invoice`
- Agregar secciones DTE (QR, timbre)
- NO reimplementar generación de PDF

---

## PARTE 3: ESTRUCTURA ÓPTIMA DEL MÓDULO l10n_cl_dte

### 3.1 Herencia Estratégica (Máximos Estándares)

**NUNCA hacer:**
```python
# ❌ MALO: Crear nuevo modelo sin herencia
class ChileInvoice(models.Model):
    _name = 'chile.invoice'
    # Duplicando account.move
```

**SIEMPRE hacer:**
```python
# ✅ BUENO: Heredar del modelo base
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    # Agregar campos específicos DTE
    dte_status = fields.Selection(...)
    dte_folio = fields.Char(...)
    dte_timestamp = fields.Datetime(...)
    
    # Extender métodos
    @api.constrains('amount_total')
    def _check_chile_specific_rules(self):
        # Validación específica DESPUÉS de padre
        pass
```

### 3.2 Estructura de Carpetas Recomendada

```
l10n_cl_dte/
│
├── __init__.py
├── __manifest__.py                 # Dependencias: account, purchase, sale, stock
│
├── models/
│   ├── __init__.py
│   ├── account_move.py            # Heredar account.move
│   ├── account_journal.py         # Heredar account.journal
│   ├── account_company.py         # Heredar res.company
│   ├── account_tax.py             # Heredar account.tax (códigos SII)
│   ├── partner.py                 # Heredar res.partner (RUT validación)
│   │
│   ├── dte_folio.py               # NUEVO: Gestión folios DTE
│   ├── dte_certificate.py         # NUEVO: Certificados digitales
│   ├── dte_audit_log.py           # NUEVO: Auditoría
│   └── dte_exception.py           # NUEVO: Excepciones personalizadas
│
├── tools/
│   ├── __init__.py
│   ├── dte_generator.py           # Generar XML
│   ├── dte_signer.py              # Firma digital
│   ├── dte_validator.py           # Validación DTE
│   ├── dte_sender.py              # Envío SOAP
│   ├── dte_receiver.py            # Recepción de DTEs
│   ├── certificate_manager.py     # Gestión certificados
│   ├── rut_validator.py           # RUT chileno
│   └── exceptions.py              # Excepciones
│
├── wizard/
│   ├── __init__.py
│   ├── upload_certificate.py      # Cargar certificado
│   └── regenerate_folios.py       # Regenerar folios
│
├── views/
│   ├── account_move_view.xml      # Heredar vistas invoice
│   ├── account_journal_view.xml   # Configuración folios
│   ├── res_company_view.xml       # Datos SII empresa
│   ├── dte_certificate_view.xml   # Gestión certificados
│   └── dte_folio_view.xml         # Rangos de folios
│
├── reports/
│   ├── dte_invoice_report.py      # Heredar report.report_invoice
│   ├── dte_receipt_report.py      # Comprobante pago
│   └── templates/
│       └── dte_invoice.html       # Template QWeb heredado
│
├── controllers/
│   ├── __init__.py
│   └── dte_webhook.py             # Webhooks SII
│
├── security/
│   ├── ir.model.access.csv        # Permisos
│   └── rules.xml                  # Reglas de seguridad
│
├── tests/
│   ├── __init__.py
│   ├── test_dte_generator.py
│   ├── test_dte_signer.py
│   ├── test_dte_validator.py
│   ├── test_dte_sender.py
│   └── fixtures/
│       ├── sample_certificate.pfx
│       └── sample_dte.xml
│
├── i18n/
│   └── es_CL.po                   # Traducciones
│
└── __manifest__.py
```

### 3.3 Manifest Correcto (Dependencias Limpias)

```python
# ✅ CORRECTO
{
    'name': 'Facturación Electrónica Chile (DTE)',
    'version': '19.0.1.0.0',
    'depends': [
        'base',           # Base Odoo
        'account',        # Contabilidad
        'purchase',       # Compras
        'sale',           # Ventas
        'stock',          # Inventario
        'web',            # Controllers
    ],
    'external_dependencies': {
        'python': [
            'pyOpenSSL',
            'cryptography',
            'lxml',
            'xmlsec',
            'zeep',
            'qrcode',
            'pillow',
            'python-rut',
            'reportlab',
            'weasyprint',
        ],
    },
    'data': [
        'security/ir.model.access.csv',
        'views/account_move_view.xml',
        'views/account_journal_view.xml',
        'views/res_company_view.xml',
        'views/dte_certificate_view.xml',
        'views/dte_folio_view.xml',
        'reports/dte_invoice_report.xml',
    ],
    'installable': True,
    'auto_install': False,
}
```

---

## PARTE 4: FUNCIONES A EXTENDER (NO REIMPLEMENTAR)

### 4.1 Métodos de Validación

**PATRÓN CORRECTO:**

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    # Campo específico DTE
    dte_status = fields.Selection(...)
    
    # HEREDAR método de validación base
    def _check_move_configuration(self):
        # Llama a padre primero
        result = super()._check_move_configuration()
        
        # LUEGO agregar validaciones específicas
        if self.is_chile_invoice():
            if not self.dte_folio:
                raise ValidationError('Folio DTE es requerido')
            self._validate_rut_format()
        
        return result
```

### 4.2 Métodos de Post-Validación

**PADRÓN CORRECTO:**

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    def action_post(self):
        # Llama a padre
        result = super().action_post()
        
        # LUEGO: Lógica DTE específica
        if self.is_chile_invoice():
            self._generate_dte_xml()
            self._schedule_dte_send()
        
        return result
```

### 4.3 Métodos de Pago/Cancelación

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    def action_register_payment(self):
        result = super().action_register_payment()
        
        if self.is_chile_invoice():
            self._update_dte_payment_status()
        
        return result
```

---

## PARTE 5: CAMPOS A EXTENDER (NO DUPLICAR)

### 5.1 Extensión de account.move

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    # ✅ EXTENSIÓN: Campos DTE específicos
    # NO duplicar: date, partner_id, amount_total, etc.
    
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado'),
        ('accepted', 'Aceptado'),
        ('rejected', 'Rechazado'),
        ('voided', 'Anulado'),
    ], default='draft')
    
    dte_folio = fields.Char('Folio DTE', copy=False, index=True)
    dte_type = fields.Selection([
        ('33', 'Factura'),
        ('39', 'Boleta'),
        ('61', 'Nota de Crédito'),
        ('56', 'Nota de Débito'),
    ])
    
    dte_timestamp = fields.Datetime('Timestamp SII', readonly=True)
    dte_track_id = fields.Char('Track ID SII', readonly=True)
    dte_xml_id = fields.Many2one('ir.attachment', string='XML DTE')
    
    # Relaciones
    dte_certificate_id = fields.Many2one('dte.certificate', 'Certificado DTE')
    dte_journal_id = fields.Many2one('account.journal', string='Journal DTE')
```

### 5.2 Extensión de account.journal

```python
class AccountJournal(models.Model):
    _inherit = 'account.journal'
    
    # Configuración de folios
    dte_folio_start = fields.Integer('Folio DTE Inicio')
    dte_folio_end = fields.Integer('Folio DTE Fin')
    dte_folio_next = fields.Integer('Próximo Folio', compute='_compute_dte_folio')
    
    dte_document_type = fields.Selection([
        ('33', 'Factura'),
        ('39', 'Boleta'),
        ('61', 'Nota de Crédito'),
        ('56', 'Nota de Débito'),
    ])
    
    dte_certificate_id = fields.Many2one('dte.certificate')
    is_dte_enabled = fields.Boolean('Usar DTE', default=False)
```

### 5.3 Extensión de res.company

```python
class ResCompany(models.Model):
    _inherit = 'res.company'
    
    # Datos SII
    sii_taxpayer_type = fields.Selection([
        ('1', 'Aporte'),
        ('2', 'Simplificado'),
        ('', 'No Afecto'),
    ])
    
    dte_email = fields.Char('Email notificaciones SII')
    dte_legal_representative = fields.Char('Representante Legal')
    dte_activity_description = fields.Char('Descripción Actividad')
    
    # Certificado default
    dte_certificate_id = fields.Many2one('dte.certificate', 'Certificado DTE Default')
```

### 5.4 Extensión de account.tax

```python
class AccountTax(models.Model):
    _inherit = 'account.tax'
    
    # Codes SII
    sii_tax_code = fields.Char('Código SII Impuesto')
    sii_tax_type = fields.Selection([
        ('IVA', 'IVA'),
        ('BOLETA', 'Boleta'),
        ('RETENCIÓN', 'Retención'),
        ('OTRO', 'Otro'),
    ])
```

---

## PARTE 6: MÉTODOS HEREDABLES A CREAR

### 6.1 Métodos de Configuración

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    def is_chile_invoice(self):
        """Determina si la factura es DTE Chile"""
        return (self.company_id.country_id.code == 'CL' and
                self.move_type in ['out_invoice', 'out_refund'])
    
    def get_dte_type(self):
        """Retorna tipo DTE según tipo de documento"""
        mapping = {
            'out_invoice': '33',    # Factura
            'out_refund': '61',     # Nota de Crédito
            'in_invoice': '46',     # Factura de compra
            'in_refund': '61',      # Nota de Crédito compra
        }
        return mapping.get(self.move_type, '33')
    
    def validate_for_dte(self):
        """Validación completa antes de enviar a SII"""
        # Validar RUT
        # Validar monto
        # Validar items
        # Validar impuestos
        pass
```

### 6.2 Métodos de Comunicación

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    def generate_dte_xml(self):
        """Genera XML DTE para envío a SII"""
        pass
    
    def send_to_sii(self):
        """Envía DTE a SII"""
        pass
    
    def check_sii_status(self):
        """Verifica estado en SII"""
        pass
    
    def download_dte_receipt(self):
        """Descarga comprobante de SII"""
        pass
```

---

## PARTE 7: ESTÁNDARES DE PROGRAMACIÓN ALTOS

### 7.1 Patrón MVC Riguroso

```python
# ✅ MODELO (models/account_move.py)
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    dte_status = fields.Selection(...)
    
    def generate_dte_xml(self):
        """Lógica de negocio"""
        from ..tools.dte_generator import DTEGenerator
        gen = DTEGenerator(self)
        return gen.generate()

# ✅ VISTA (views/account_move_view.xml)
<!-- Formularios heredados de account.move -->
<field name="dte_status" attrs="{'readonly': [('state', '!=', 'draft')]}"/>

# ✅ CONTROLADOR (controllers/dte_webhook.py)
class DTEWebhook(http.Controller):
    @http.route('/dte/webhook', auth='public')
    def webhook(self, **kwargs):
        # Recibir notificaciones SII
        pass
```

### 7.2 Principios SOLID

```python
# ✅ Single Responsibility Principle
class DTEGenerator:
    """Solo genera XML"""
    pass

class DTESigner:
    """Solo firma documentos"""
    pass

class DTESender:
    """Solo envía a SII"""
    pass

# ✅ Open/Closed Principle
class DTEProcessor:
    """Abierto para extensión"""
    def process(self):
        # Template method pattern
        self.validate()
        self.generate()
        self.sign()
        self.send()

# ✅ Liskov Substitution
class DTEValidator:
    def validate(self, dte):
        raise NotImplementedError

class ChileDTEValidator(DTEValidator):
    def validate(self, dte):
        # Implementación específica Chile
        pass
```

### 7.3 Logging y Auditoría

```python
# ✅ Logging estructurado
import logging
logger = logging.getLogger(__name__)

class AccountMove(models.Model):
    _inherit = 'account.move'
    
    def send_to_sii(self):
        logger.info(f'Sending DTE {self.name}', extra={
            'folio': self.dte_folio,
            'rut': self.partner_id.vat,
            'amount': self.amount_total,
        })
        
        try:
            # Lógica
            logger.info(f'DTE {self.name} sent successfully')
        except Exception as e:
            logger.error(f'Error sending DTE {self.name}', exc_info=True)
            raise

# ✅ Auditoría en BD
class DTEAuditLog(models.Model):
    _name = 'dte.audit.log'
    
    action = fields.Char()
    user_id = fields.Many2one('res.users')
    document_id = fields.Many2one('account.move')
    status = fields.Selection([('success', 'Success'), ('error', 'Error')])
    error_message = fields.Text()
    timestamp = fields.Datetime(default=fields.Datetime.now)
```

### 7.4 Testing

```python
# ✅ Tests unitarios
class TestDTEGenerator(TransactionCase):
    def setUp(self):
        super().setUp()
        self.invoice = self.env['account.move'].create({...})
    
    def test_generate_valid_xml(self):
        generator = DTEGenerator(self.invoice)
        xml = generator.generate()
        self.assertIn('<DTE>', xml)
    
    def test_validate_rut_format(self):
        validator = RUTValidator()
        self.assertTrue(validator.is_valid('11.111.111-1'))
        self.assertFalse(validator.is_valid('invalid'))
```

---

## PARTE 8: ANÁLISIS DE REUTILIZACIÓN

### 8.1 Matriz de Reutilización

| Funcionalidad | Odoo Base | Reutilizar | Extender | Nueva |
|---|---|---|---|---|
| Creación de facturas | account.move | ✓ | ✓ | - |
| Gestión de impuestos | account.tax | ✓ | ✓ | - |
| Numeración/Folios | account.journal | ✓ | ✓ | - |
| Validación básica | account.move | ✓ | - | - |
| Reportes PDF | report module | ✓ | ✓ | - |
| RUT validación | - | - | - | ✓ |
| Firma digital XML | - | - | - | ✓ |
| Comunicación SOAP SII | - | - | - | ✓ |
| Códigos QR | - | - | - | ✓ |
| Auditoría DTE | - | - | - | ✓ |

---

## CONCLUSIÓN

Para desarrollar `l10n_cl_dte` con altos estándares:

✅ **REUTILIZAR:**
- account.move (no crear nuevo modelo)
- account.journal (secuencias)
- account.tax (impuestos)
- report module (reportes)

✅ **EXTENDER INTELIGENTEMENTE:**
- Heredar modelos base
- Agregar campos específicos DTE
- Extender métodos con `super()`

✅ **CREAR SOLO LO NECESARIO:**
- dte.certificate (gestión certificados)
- dte.folio (control folios)
- dte.audit.log (auditoría)
- Herramientas: DTEGenerator, DTESigner, DTESender

✅ **ESTÁNDARES ALTOS:**
- MVC separado
- SOLID principles
- Testing robusto
- Logging estructurado
- Documentación

**Resultado:** Módulo limpio, mantenible, integrado, sin duplicaciones
