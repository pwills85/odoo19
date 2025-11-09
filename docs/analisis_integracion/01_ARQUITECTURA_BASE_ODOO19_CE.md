# 🏗️ ARQUITECTURA BASE ODOO 19 CE - LOCALIZACIÓN CHILENA

**Fecha:** 2025-10-22  
**Versión:** 1.0  
**Autor:** Análisis Técnico Integral

---

## 📋 RESUMEN EJECUTIVO

Este documento analiza la arquitectura modular de Odoo 19 CE para localización chilena, identificando los componentes base que **NO debemos duplicar** y los puntos exactos de integración para nuestro desarrollo.

---

## 🎯 MÓDULOS BASE ODOO 19 CE - CHILE

### **1. l10n_latam_base** (Fundación LATAM)

**Propósito:** Base común para todas las localizaciones latinoamericanas.

**Componentes Clave:**

```python
# Modelo: l10n_latam.identification.type
- name: Nombre del tipo de identificación
- description: Descripción larga
- country_id: País al que pertenece
- is_vat: Marca si es el VAT del país
- sequence: Orden de presentación
- active: Activar/desactivar
```

**Extensión en res.partner:**
```python
class ResPartner(models.Model):
    _inherit = 'res.partner'
    
    l10n_latam_identification_type_id = fields.Many2one(
        'l10n_latam.identification.type',
        string='Identification Type'
    )
```

**Dependencias:**
- `contacts`
- `base_vat`

**⚠️ REGLA:** NO duplicar gestión de RUT/identificaciones. Usar `l10n_latam_identification_type`.

---

### **2. l10n_latam_invoice_document** (Documentos Tributarios LATAM)

**Propósito:** Gestión de tipos de documentos tributarios (facturas, notas, etc.)

**Componentes Clave:**

```python
# Modelo: l10n_latam.document.type
- name: Nombre del documento
- code: Código SII (33, 34, 52, 56, 61, etc.)
- doc_code_prefix: Prefijo para secuencia
- country_id: País
- internal_type: Tipo interno (invoice, debit_note, credit_note, etc.)
- active: Activar/desactivar
```

**Extensión en account.move:**
```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    l10n_latam_document_type_id = fields.Many2one(
        'l10n_latam.document.type',
        string='Document Type'
    )
    l10n_latam_use_documents = fields.Boolean(
        related='journal_id.l10n_latam_use_documents'
    )
```

**⚠️ REGLA:** NO crear modelo propio de tipos DTE. Usar `l10n_latam_document_type_id`.

---

### **3. l10n_cl** (Localización Chile)

**Propósito:** Implementación específica para Chile.

**Dependencias:**
```python
'depends': [
    'contacts',
    'base_vat',
    'l10n_latam_base',
    'l10n_latam_invoice_document',
    'uom',
    'account',
]
```

**Componentes Implementados:**

#### **3.1 res.partner (Extensión)**
```python
class ResPartner(models.Model):
    _inherit = 'res.partner'
    
    l10n_cl_sii_taxpayer_type = fields.Selection([
        ('1', 'VAT Affected (1st Category)'),
        ('2', 'Fees Receipt Issuer (2nd category)'),
        ('3', 'End Consumer'),
        ('4', 'Foreigner'),
    ])
    l10n_cl_activity_description = fields.Char('Activity Description')
    
    def _run_check_identification(self, validation='error'):
        # Validación RUT con módulo 11
        # Formato: 76086428-5
```

**⚠️ REGLA:** Usar `l10n_cl_sii_taxpayer_type` existente. NO crear campo propio.

---

#### **3.2 account.move (Extensión)**
```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    partner_id_vat = fields.Char(related='partner_id.vat')
    l10n_latam_internal_type = fields.Selection(
        related='l10n_latam_document_type_id.internal_type'
    )
    
    def _get_l10n_latam_documents_domain(self):
        # Lógica de filtrado de documentos según:
        # - Tipo de contribuyente
        # - País
        # - Tipo de movimiento (in/out, invoice/refund)
```

**Validaciones Implementadas:**
- Tipo de contribuyente + VAT obligatorios
- Documentos de exportación (110, 111, 112) solo para extranjeros
- DIN (914) solo para RUT 60805000-0 (Tesorería)
- Boletas de honorarios (71) solo para tipo 2

**⚠️ REGLA:** Extender validaciones existentes con `super()`. NO reemplazar.

---

#### **3.3 Tipos de Documentos Incluidos**

**Archivo:** `data/l10n_latam.document.type.csv`

Documentos ya definidos en Odoo 19 CE:
- **33:** Factura Electrónica
- **34:** Factura Exenta Electrónica
- **39:** Boleta Electrónica
- **41:** Boleta Exenta Electrónica
- **46:** Factura de Compra Electrónica
- **52:** Guía de Despacho Electrónica
- **56:** Nota de Débito Electrónica
- **61:** Nota de Crédito Electrónica
- **70:** Boleta de Honorarios
- **71:** Boleta de Honorarios Electrónica
- **110, 111, 112:** Facturas de Exportación

**⚠️ REGLA:** NO crear registros duplicados. Usar códigos existentes.

---

## 🔍 ANÁLISIS DE FUNCIONALIDADES BASE

### **✅ LO QUE YA EXISTE EN ODOO 19 CE**

| Funcionalidad | Módulo | Modelo/Campo | Estado |
|---------------|--------|--------------|--------|
| **Gestión RUT** | l10n_latam_base | res.partner.vat | ✅ Completo |
| **Validación RUT** | l10n_cl | _run_check_identification() | ✅ Módulo 11 |
| **Tipos Identificación** | l10n_latam_base | l10n_latam.identification.type | ✅ Completo |
| **Tipos Documento** | l10n_latam_invoice_document | l10n_latam.document.type | ✅ Completo |
| **Tipo Contribuyente** | l10n_cl | l10n_cl_sii_taxpayer_type | ✅ Completo |
| **Actividad Económica** | l10n_cl | l10n_cl_activity_description | ✅ Completo |
| **Secuencias DTE** | l10n_cl | _get_starting_sequence() | ✅ Completo |
| **Validaciones SII** | l10n_cl | _check_document_types_post() | ✅ Completo |
| **Plan Contable CL** | l10n_cl | account.chart.template | ✅ Completo |
| **Impuestos CL** | l10n_cl | account.tax | ✅ IVA 19% |

---

### **❌ LO QUE NO EXISTE (Nuestro Desarrollo)**

| Funcionalidad | Razón | Solución |
|---------------|-------|----------|
| **Generación XML DTE** | No incluido en CE | Microservicio DTE |
| **Firma Digital XMLDsig** | No incluido en CE | Microservicio DTE |
| **Envío SOAP a SII** | No incluido en CE | Microservicio DTE |
| **Gestión CAF** | No incluido en CE | Módulo l10n_cl_dte |
| **Gestión Certificados** | No incluido en CE | Módulo l10n_cl_dte |
| **TED (Timbre QR)** | No incluido en CE | Microservicio DTE |
| **Validación XSD** | No incluido en CE | Microservicio DTE |
| **Recepción DTEs** | No incluido en CE | Microservicio DTE |
| **Monitoreo SII** | No incluido en CE | Microservicio AI |
| **Chat IA** | No incluido en CE | Microservicio AI |

---

## 🎯 PUNTOS DE INTEGRACIÓN EXACTOS

### **1. Extensión de account.move (Facturas)**

**Archivo:** `addons/localization/l10n_cl_dte/models/account_move_dte.py`

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS ADICIONALES DTE (NO duplicar campos base)
    # ═══════════════════════════════════════════════════════════
    
    # ✅ USAR: l10n_latam_document_type_id (YA EXISTE)
    # ❌ NO CREAR: dte_type (redundante)
    
    dte_code = fields.Char(
        related='l10n_latam_document_type_id.code',  # ← Relacionado, no duplicado
        store=True,
        readonly=True
    )
    
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado'),
        ('accepted', 'Aceptado'),
        ('rejected', 'Rechazado'),
    ])
    
    dte_folio = fields.Integer('Folio DTE')
    dte_xml = fields.Text('XML DTE')
    dte_track_id = fields.Char('Track ID SII')
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS DE INTEGRACIÓN
    # ═══════════════════════════════════════════════════════════
    
    def action_post(self):
        """Extender (NO reemplazar) método base"""
        result = super().action_post()  # ← Llamar método padre
        
        # Agregar lógica DTE
        for move in self:
            if move.dte_code and move.move_type in ['out_invoice', 'out_refund']:
                move.write({'dte_status': 'to_send'})
        
        return result
```

**⚠️ PRINCIPIO:** Siempre usar `super()` para extender, nunca reemplazar.

---

### **2. Extensión de res.partner (Clientes/Proveedores)**

**Archivo:** `addons/localization/l10n_cl_dte/models/res_partner_dte.py`

```python
class ResPartner(models.Model):
    _inherit = 'res.partner'
    
    # ✅ USAR: vat (YA EXISTE en l10n_latam_base)
    # ✅ USAR: l10n_cl_sii_taxpayer_type (YA EXISTE en l10n_cl)
    # ✅ USAR: l10n_cl_activity_description (YA EXISTE en l10n_cl)
    
    # ❌ NO CREAR: rut, tipo_contribuyente, giro (redundantes)
    
    # Solo agregar campos específicos DTE
    dte_email = fields.Char('Email DTE')
    dte_reception_enabled = fields.Boolean('Recepción DTE Habilitada')
```

**⚠️ PRINCIPIO:** Reutilizar campos base, solo agregar lo específico de DTE.

---

### **3. Nuevos Modelos (Solo lo que NO existe)**

#### **3.1 dte.certificate (Certificados Digitales)**
```python
class DTECertificate(models.Model):
    _name = 'dte.certificate'
    _description = 'Certificado Digital SII'
    
    name = fields.Char('Nombre')
    certificate_file = fields.Binary('Archivo .pfx/.p12')
    password = fields.Char('Contraseña')
    valid_from = fields.Date('Válido Desde')
    valid_to = fields.Date('Válido Hasta')
    company_id = fields.Many2one('res.company')
```

**Justificación:** No existe en Odoo CE. Necesario para firma digital.

---

#### **3.2 dte.caf (Folios Autorizados)**
```python
class DTECAF(models.Model):
    _name = 'dte.caf'
    _description = 'CAF - Código de Autorización de Folios'
    
    name = fields.Char('Nombre')
    dte_type_id = fields.Many2one(
        'l10n_latam.document.type',  # ← Relacionar con modelo base
        domain=[('country_id.code', '=', 'CL')]
    )
    folio_desde = fields.Integer('Folio Desde')
    folio_hasta = fields.Integer('Folio Hasta')
    folio_actual = fields.Integer('Folio Actual')
    caf_file = fields.Binary('Archivo CAF XML')
    company_id = fields.Many2one('res.company')
```

**Justificación:** No existe en Odoo CE. Necesario para gestión de folios SII.

---

## 📊 DIAGRAMA DE HERENCIA

```
┌─────────────────────────────────────────────────────────────┐
│                    ODOO 19 CE BASE                          │
└─────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                │                           │
        ┌───────▼────────┐         ┌───────▼────────┐
        │ l10n_latam_base│         │    account     │
        │                │         │                │
        │ - RUT/VAT      │         │ - account.move │
        │ - Identif.Type │         │ - account.tax  │
        └───────┬────────┘         └───────┬────────┘
                │                           │
        ┌───────▼────────────────────────────▼────────┐
        │      l10n_latam_invoice_document            │
        │                                             │
        │      - l10n_latam.document.type             │
        │      - Códigos DTE (33, 52, 56, 61, etc.)   │
        └───────┬─────────────────────────────────────┘
                │
        ┌───────▼────────┐
        │     l10n_cl    │
        │                │
        │ - Taxpayer Type│
        │ - Validaciones │
        │ - Secuencias   │
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │  l10n_cl_dte   │  ← NUESTRO MÓDULO
        │                │
        │ - CAF          │
        │ - Certificados │
        │ - DTE Status   │
        │ - Integración  │
        │   Microservicios│
        └────────────────┘
```

---

## ✅ CONCLUSIONES ARQUITECTURA BASE

### **Principios de Integración:**

1. **NO DUPLICAR** campos/modelos existentes en l10n_cl
2. **EXTENDER** con `_inherit` y `super()`
3. **RELACIONAR** con `l10n_latam.document.type` para tipos DTE
4. **REUTILIZAR** validaciones RUT de l10n_cl
5. **AGREGAR** solo funcionalidades específicas DTE (CAF, certificados, XML, firma)

### **Compatibilidad Garantizada:**

✅ Usa `l10n_latam_document_type_id` (estándar Odoo)  
✅ Respeta herencia modular ORM  
✅ No modifica modelos base  
✅ Compatible con actualizaciones Odoo  
✅ Sigue convenciones l10n_*

---

**Próximo Documento:** `02_MATRIZ_INTEGRACION.md`
