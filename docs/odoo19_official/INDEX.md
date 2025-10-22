# 📚 Índice de Documentación Odoo 19 CE

**Versión:** 19.0  
**Fecha Descarga:** 2025-10-21  
**Archivos:** 68 referencias  

---

## 🚀 ACCESO RÁPIDO POR TAREA

### 🏗️ CREAR MODELOS

#### Documentación
- [ORM API Reference](01_developer/orm_api_reference.html) - API completa del ORM
- [Module Structure](01_developer/module_structure.html) - Estructura de módulos

#### Código Fuente de Referencia
- [account_move.py](02_models_base/account_move.py) - **Facturas** (crítico para DTE)
- [account_journal.py](02_models_base/account_journal.py) - **Diarios** (folios)
- [account_tax.py](02_models_base/account_tax.py) - **Impuestos** (códigos SII)
- [purchase_order.py](02_models_base/purchase_order.py) - **Compras** (DTE 34)
- [stock_picking.py](02_models_base/stock_picking.py) - **Guías** (DTE 52)

---

### 📝 EXTENDER MODELOS EXISTENTES

#### Patrones de Herencia
```python
# Extender modelo existente (más común)
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    dte_folio = fields.Char('Folio DTE')

# Crear modelo nuevo
class DTECertificate(models.Model):
    _name = 'dte.certificate'
    name = fields.Char('Nombre')
```

#### Referencia por Módulo

**Para DTE 33, 61, 56 (Facturas/NC/ND):**
- Base: [account_move.py](02_models_base/account_move.py)
- Vistas: [account_move_views.xml](04_views_ui/account_move_views.xml)
- Seguridad: [account_access.csv](05_security/account_access.csv)

**Para DTE 34 (Liquidación Honorarios):**
- Base: [purchase_order.py](02_models_base/purchase_order.py)
- Vistas: [purchase_views.xml](04_views_ui/purchase_views.xml)

**Para DTE 52 (Guías Despacho):**
- Base: [stock_picking.py](02_models_base/stock_picking.py)
- Vistas: [stock_picking_views.xml](04_views_ui/stock_picking_views.xml)

---

### 🎨 CREAR VISTAS (XML)

#### Documentación
- [Views Reference](04_views_ui/views_reference.html) - Referencia completa de vistas

#### Ejemplos Reales
- [account_move_views.xml](04_views_ui/account_move_views.xml) - Form, Tree, Search de facturas
- [purchase_views.xml](04_views_ui/purchase_views.xml) - Vistas de compras
- [stock_picking_views.xml](04_views_ui/stock_picking_views.xml) - Vistas de guías

#### Tipos de Vista Principales
- **Form View:** Formulario de edición
- **Tree View:** Lista/tabla
- **Search View:** Filtros y búsqueda
- **Kanban View:** Vista de tarjetas
- **Calendar View:** Vista de calendario

---

### 🔐 SEGURIDAD

#### Documentación
- [Security Reference](05_security/access_rights.html) - Referencia completa

#### Ejemplos Reales
- [account_access.csv](05_security/account_access.csv) - Permisos de módulo account

#### Archivos Necesarios
```
security/
├── ir.model.access.csv    # Permisos de acceso a modelos
└── rules.xml              # Record rules (reglas de registro)
```

---

### 📄 REPORTES Y PDF

#### Documentación
- [QWeb Reference](06_reports/qweb_reference.html) - Templates QWeb para reportes

#### Generación de PDFs
Para generar PDFs de facturas con QR:
1. Crear template QWeb
2. Usar `reportlab` o `weasyprint` (ya instalados en imagen)
3. Generar QR con `qrcode` (ya instalado)

---

### 🌐 CONTROLLERS HTTP

#### Documentación
- [HTTP Controllers](07_controllers/http_controllers.html) - Controllers y routing

#### Uso Típico
```python
from odoo import http

class DTEController(http.Controller):
    @http.route('/dte/webhook', type='json', auth='user')
    def dte_webhook(self):
        # Lógica del webhook
        pass
```

---

### ✅ TESTING

#### Documentación
- [Testing Framework](08_testing/testing_framework.html) - Framework de testing

#### Tipos de Tests
- **Unit Tests:** Tests unitarios de funciones
- **Integration Tests:** Tests de integración entre módulos
- **Transactional Tests:** Tests con rollback automático

---

### 📦 DATA FILES

#### Documentación
- [Data Files Format](09_data_files/xml_data_format.html) - Formato de archivos XML/CSV

#### Archivos de Datos
```
data/
├── dte_document_types.xml    # Tipos de documentos DTE
├── account_tax_cl.xml         # Impuestos chilenos
└── res_company_data.xml       # Datos de empresa
```

---

## 🇨🇱 LOCALIZACIÓN CHILE

### Módulos de Referencia

#### l10n_latam_base (Base LATAM)
- **Ubicación:** [03_localization/l10n_latam_base/](03_localization/l10n_latam_base/)
- **Uso:** Referencia para estructura de módulos de localización
- **Contiene:** 
  - Modelos base para LATAM
  - Vistas comunes
  - Patrones de localización

#### l10n_cl (Chile Existente)
- **Ubicación:** [03_localization/l10n_cl/](03_localization/l10n_cl/)
- **Uso:** Referencia para localización chilena actual
- **Contiene:**
  - Plan contable Chile
  - Impuestos
  - Identificación fiscal

**⚠️ IMPORTANTE:** Nuestro módulo `l10n_cl_dte` extenderá estos módulos para DTE.

---

## 🔍 BÚSQUEDA RÁPIDA

### Por Concepto

| Concepto | Archivo de Referencia |
|----------|----------------------|
| **Facturas** | [account_move.py](02_models_base/account_move.py) |
| **Diarios/Folios** | [account_journal.py](02_models_base/account_journal.py) |
| **Impuestos SII** | [account_tax.py](02_models_base/account_tax.py) |
| **Compras/Honorarios** | [purchase_order.py](02_models_base/purchase_order.py) |
| **Guías Despacho** | [stock_picking.py](02_models_base/stock_picking.py) |
| **Contactos/RUT** | res_partner.py |
| **Empresa** | res_company.py |
| **ORM Base** | odoo_models_base.py |
| **Fields Base** | odoo_fields_base.py |

### Por Tarea de Desarrollo

| Tarea | Documentación | Código Ejemplo |
|-------|--------------|----------------|
| Crear modelo nuevo | [ORM API](01_developer/orm_api_reference.html) | [account_move.py](02_models_base/account_move.py) |
| Extender modelo | [ORM API](01_developer/orm_api_reference.html) | Ver `_inherit` en archivos .py |
| Crear vista form | [Views Ref](04_views_ui/views_reference.html) | [account_move_views.xml](04_views_ui/account_move_views.xml) |
| Definir seguridad | [Security](05_security/access_rights.html) | [account_access.csv](05_security/account_access.csv) |
| Generar reporte | [QWeb](06_reports/qweb_reference.html) | Ver l10n_cl/reports/ |
| Testing | [Testing](08_testing/testing_framework.html) | Ver tests/ en módulos |

---

## 📂 ESTRUCTURA COMPLETA

```
docs/odoo19_official/
├── 01_developer/              # Docs desarrolladores (2 archivos)
│   ├── orm_api_reference.html
│   └── module_structure.html
│
├── 02_models_base/            # Código fuente (7 archivos)
│   ├── account_move.py        ⭐ CRÍTICO
│   ├── account_journal.py     ⭐ CRÍTICO
│   ├── account_tax.py         ⭐ CRÍTICO
│   ├── account_payment.py
│   ├── purchase_order.py      ⭐ DTE 34
│   ├── stock_picking.py       ⭐ DTE 52
│   └── account_manifest.py
│
├── 03_localization/           # Localización (70+ archivos)
│   ├── l10n_latam_base/       ⭐ Referencia LATAM
│   └── l10n_cl/               ⭐ Referencia Chile
│
├── 04_views_ui/               # Vistas XML (4 archivos)
│   ├── views_reference.html
│   ├── account_move_views.xml ⭐ CRÍTICO
│   ├── purchase_views.xml
│   └── stock_picking_views.xml
│
├── 05_security/               # Seguridad (2 archivos)
│   ├── access_rights.html
│   └── account_access.csv     ⭐ CRÍTICO
│
├── 06_reports/                # Reportes (1 archivo)
│   └── qweb_reference.html
│
├── 07_controllers/            # Controllers (1 archivo)
│   └── http_controllers.html
│
├── 08_testing/                # Testing (1 archivo)
│   └── testing_framework.html
│
├── 09_data_files/             # Data files (1 archivo)
│   └── xml_data_format.html
│
└── 10_api_reference/          # API Reference (vacío)
```

---

## 🎯 DESARROLLO MÓDULO l10n_cl_dte

### Archivos Críticos a Consultar

**FASE 1: Modelos Base**
1. [account_move.py](02_models_base/account_move.py) - Para extender facturas
2. [account_journal.py](02_models_base/account_journal.py) - Para control de folios
3. [purchase_order.py](02_models_base/purchase_order.py) - Para DTE 34

**FASE 2: Vistas**
1. [account_move_views.xml](04_views_ui/account_move_views.xml) - Cómo crear vistas form/tree

**FASE 3: Seguridad**
1. [account_access.csv](05_security/account_access.csv) - Formato de permisos

**FASE 4: Localización**
1. [l10n_latam_base/](03_localization/l10n_latam_base/) - Patrones de localización
2. [l10n_cl/](03_localization/l10n_cl/) - Estructura actual Chile

---

## 📚 RECURSOS ADICIONALES

### Documentación Online (si necesitas más detalles)
- https://www.odoo.com/documentation/19.0/
- https://github.com/odoo/odoo/tree/19.0

### Cheatsheet de Desarrollo
- Ver [CHEATSHEET.md](CHEATSHEET.md) en este mismo directorio

---

**Última Actualización:** 2025-10-21  
**Archivos Totales:** 68  
**Tamaño:** ~50-80 MB

---

## ✅ VERIFICACIÓN RÁPIDA

```bash
# Ver archivos Python descargados
ls -1 docs/odoo19_official/02_models_base/*.py

# Ver módulos de localización
ls -1 docs/odoo19_official/03_localization/

# Ver documentación HTML
open docs/odoo19_official/01_developer/orm_api_reference.html
```

**Status:** ✅ Documentación completa y lista para uso

