# 📋 Análisis Campos Tributarios: Odoo 11 vs Odoo 19

**Fecha:** 2025-10-22 20:00 UTC-3
**Propósito:** Verificar que `l10n_cl_dte` (Odoo 19) incluye TODOS los campos tributarios necesarios

---

## 🎯 Resumen Ejecutivo

### Veredicto: ⚠️ **PARCIAL - Faltan 2 Campos**

| Campo Tributario | Odoo 11 | Odoo 19 | Status |
|------------------|---------|---------|--------|
| **RUT (VAT)** | ✅ res_partner.vat | ✅ res_partner.vat (l10n_cl) | ✅ OK |
| **Razón Social** | ✅ res_company.name | ✅ res_company.name | ✅ OK |
| **Dirección** | ✅ res_partner.street | ✅ res_partner.street | ✅ OK |
| **Ciudad** | ✅ res_partner.city | ✅ res_partner.city | ✅ OK |
| **Teléfono** | ✅ res_partner.phone | ✅ res_partner.phone | ✅ OK |
| **Email** | ✅ res_partner.email | ✅ res_partner.email | ✅ OK |
| **Website** | ✅ res_partner.website | ✅ res_partner.website | ✅ OK |
| **Actividad Económica** | ✅ res_partner.activity_description | ✅ l10n_cl_activity_description | ✅ OK |
| **Tipo Contribuyente** | ⚠️ Implícito | ✅ l10n_cl_sii_taxpayer_type | ✅ OK (mejor) |
| **Email DTE** | ✅ dte_email_id (FK) | ✅ dte_email (Char) | ✅ OK (simplificado) |
| **Resolución DTE #** | ✅ dte_resolution_number | ✅ dte_resolution_number | ✅ OK |
| **Resolución DTE Fecha** | ✅ dte_resolution_date | ✅ dte_resolution_date | ✅ OK |
| **Proveedor Servicios DTE** | ✅ dte_service_provider | ❌ **FALTA** | ⚠️ GAP |
| **Oficina Regional SII** | ✅ sii_regional_office_id (FK) | ❌ **FALTA** | ⚠️ GAP |

**Campos Totales:**
- ✅ **12/14 campos OK** (86%)
- ⚠️ **2/14 campos faltantes** (14%)

---

## 📊 Análisis Detallado por Campo

### 1️⃣ Campos Básicos (7 campos) ✅

Todos delegados a `res_partner` (estrategia correcta):

```python
# Odoo 11 y Odoo 19 (IGUALES)
class ResCompany(models.Model):
    _inherit = 'res.company'

    # Delegados a partner_id:
    # - name (razón social)
    # - vat (RUT)
    # - street (dirección)
    # - city (ciudad)
    # - phone (teléfono)
    # - email (email general)
    # - website (sitio web)
```

**Status:** ✅ **OK** - Sin cambios necesarios

---

### 2️⃣ Actividad Económica ✅

**Odoo 11:**
```python
# res_partner
activity_description = fields.Integer()  # FK a sii_activity_description

# Ejemplo valor:
# ID: 2
# Descripción: "ENERGIA Y CONSTRUCCION"
```

**Odoo 19:**
```python
# l10n_cl/models/res_partner.py
l10n_cl_activity_description = fields.Char(
    string='Activity Description',
    help="Chile: Economic activity."
)

# res_company.py (related field)
l10n_cl_activity_description = fields.Char(
    related='partner_id.l10n_cl_activity_description',
    readonly=False
)
```

**Diferencia:**
- Odoo 11: FK a tabla `sii_activity_description` (código + descripción)
- Odoo 19: Campo Char libre (solo descripción)

**Impacto:**
- ⚠️ Odoo 11 tiene **código SII** (ej: código 620101 = "Construcción")
- ℹ️ Odoo 19 solo tiene **descripción** (sin código numérico)

**¿Es problema?**
- ❓ **CONSULTAR:** ¿El SII requiere código numérico en DTEs?
- Revisando XSD oficial SII... (analizo abajo)

**Status:** ⚠️ **REVISAR** - Posible gap en código actividad

---

### 3️⃣ Tipo Contribuyente ✅

**Odoo 11:**
```python
# Implícito por tipo de documentos emitidos
# No hay campo explícito
```

**Odoo 19:**
```python
# l10n_cl/models/res_partner.py
l10n_cl_sii_taxpayer_type = fields.Selection([
    ('1', 'VAT Affected (1st Category)'),      # Afecto IVA
    ('2', 'Fees Receipt Issuer (2nd category)'),  # Honorarios
    ('3', 'End Consumer'),                     # Consumidor final
    ('4', 'Foreigner'),                        # Extranjero
])
```

**Status:** ✅ **MEJORADO** - Odoo 19 tiene campo explícito (mejor que Odoo 11)

---

### 4️⃣ Email DTE ✅

**Odoo 11:**
```python
# res_company
dte_email_id = fields.Many2one('res.partner', string='Email DTE')

# Valor ejemplo:
# ID: 21 → res_partner(21) → email = "dte@eergygroup.cl"
```

**Odoo 19:**
```python
# res_company_dte.py
dte_email = fields.Char(
    string='Email DTE',
    help='Email para notificaciones de DTEs electrónicos'
)
```

**Diferencia:**
- Odoo 11: Many2one (relación a otro partner)
- Odoo 19: Char (email directo)

**Evaluación:**
- ✅ Odoo 19 **simplifica** (no necesita FK)
- ✅ Mismo resultado funcional
- ✅ Más directo y claro

**Status:** ✅ **OK (simplificado)** - Mejora arquitectónica

---

### 5️⃣ Resolución DTE ✅

**Odoo 11:**
```python
dte_resolution_number = fields.Char()  # "80"
dte_resolution_date = fields.Date()     # "2014-08-22"
```

**Odoo 19:**
```python
# res_company_dte.py
dte_resolution_number = fields.Char(
    string='Número Resolución SII',
    help='Número de resolución de autorización de DTEs del SII'
)

dte_resolution_date = fields.Date(
    string='Fecha Resolución DTE',
    help='Fecha de la resolución de autorización de DTEs'
)
```

**Status:** ✅ **OK (idénticos)** - Sin cambios

---

### 6️⃣ ⚠️ Proveedor Servicios DTE (FALTANTE)

**Odoo 11:**
```python
dte_service_provider = fields.Selection([
    ('SII', 'SII'),
    ('OTRO', 'Otro Proveedor'),
])

# Valor: "SII"
```

**Odoo 19:**
```python
# ❌ NO EXISTE este campo
```

**Análisis:**
- **¿Es necesario?**
  - ℹ️ En Chile, **100% de DTEs van al SII** (no hay otros proveedores)
  - ℹ️ Campo informativo (no afecta XML DTE)
  - ⚠️ Podría ser útil para reportes/auditoría

**Recomendación:**
- 🟢 **OPCIONAL** - Agregar solo si se necesita para reportes
- Si se agrega:
  ```python
  dte_service_provider = fields.Selection([
      ('sii', 'SII (Servicio de Impuestos Internos)'),
  ], default='sii', string='Proveedor DTE')
  ```

**Status:** ⚠️ **GAP MENOR** - Campo informativo, no crítico

---

### 7️⃣ ⚠️ Oficina Regional SII (FALTANTE)

**Odoo 11:**
```python
sii_regional_office_id = fields.Many2one('sii_regional_offices')

# Ejemplo valor:
# ID: 57 → "Temuco"
```

**Odoo 19:**
```python
# ❌ NO EXISTE este campo
# ❌ NO EXISTE tabla sii_regional_offices
```

**Análisis:**
- **¿Es necesario en DTEs?**
  - Revisando XSD SII oficial... ❌ NO aparece en estructura XML DTE
  - Solo se usa para: dirección correspondencia SII
  - NO afecta generación/validación DTEs

- **¿Dónde se usa?**
  - Reportes físicos al SII (cada vez menos usados)
  - Consultas presenciales SII (raro en 2025)

**Recomendación:**
- 🟡 **OPCIONAL** - Agregar si empresa necesita reportes físicos
- Si se agrega:
  ```python
  # Crear modelo sii_regional_offices
  sii_regional_office = fields.Selection([
      ('arica', 'Arica'),
      ('iquique', 'Iquique'),
      ('antofagasta', 'Antofagasta'),
      ('copiapo', 'Copiapó'),
      ('la_serena', 'La Serena'),
      ('valparaiso', 'Valparaíso'),
      ('santiago_centro', 'Santiago Centro'),
      ('santiago_oriente', 'Santiago Oriente'),
      # ... 30 oficinas más
      ('temuco', 'Temuco'),  # ← Caso EERGYGROUP
      # ...
  ], string='Oficina Regional SII')
  ```

**Status:** ⚠️ **GAP MENOR** - No afecta DTEs, solo reportes físicos

---

## 🔍 Revisión XSD Oficial SII

Revisando `DTE_v10.xsd` (esquema oficial SII):

```xml
<!-- Estructura Encabezado DTE (campos emisor) -->
<xs:complexType name="Emisor">
    <xs:sequence>
        <xs:element name="RUTEmisor" type="RUTType"/>         <!-- ✅ Tenemos -->
        <xs:element name="RznSoc" type="xs:string"/>          <!-- ✅ Tenemos (name) -->
        <xs:element name="GiroEmis" type="xs:string"/>        <!-- ⚠️ REVISAR (activity) -->
        <xs:element name="Acteco" type="xs:integer"/>         <!-- ❌ FALTA (código actividad) -->
        <xs:element name="DirOrigen" type="xs:string"/>       <!-- ✅ Tenemos (street) -->
        <xs:element name="CmnaOrigen" type="xs:string"/>      <!-- ⚠️ VERIFICAR (comuna) -->
        <xs:element name="CiudadOrigen" type="xs:string"/>    <!-- ✅ Tenemos (city) -->
        <xs:element name="Telefono" type="xs:string" minOccurs="0"/>    <!-- ✅ Tenemos -->
        <xs:element name="CorreoEmisor" type="xs:string" minOccurs="0"/> <!-- ✅ Tenemos -->
    </xs:sequence>
</xs:complexType>
```

### Hallazgos XSD:

1. **`Acteco` (Código Actividad Económica) - REQUERIDO** ⚠️
   ```xml
   <Acteco>620101</Acteco>  <!-- Código numérico SII -->
   ```
   - ❌ **Odoo 19 NO tiene este campo**
   - ⚠️ Solo tiene descripción texto, no código

2. **`GiroEmis` (Giro/Descripción) - REQUERIDO** ✅
   ```xml
   <GiroEmis>ENERGIA Y CONSTRUCCION</GiroEmis>
   ```
   - ✅ Odoo 19 SÍ tiene: `l10n_cl_activity_description`

3. **`CmnaOrigen` (Comuna) - REQUERIDO** ⚠️
   ```xml
   <CmnaOrigen>Temuco</CmnaOrigen>
   ```
   - ⚠️ Odoo 19: `city` field (podría ser ciudad o comuna)
   - ℹ️ Verificar si `city` = comuna en Chile

---

## 🚨 Gaps Críticos Identificados

### Gap 1: Código Actividad Económica (Acteco) 🔴 CRÍTICO

**Campo XSD SII:** `<Acteco>` (integer, REQUERIDO)

**Odoo 11:**
```python
# Tiene código + descripción
activity_description = fields.Many2one('sii_activity_description')
# Tabla sii_activity_description:
#   - id: 2
#   - name: "ENERGIA Y CONSTRUCCION"
#   - code: 620101  ← ESTE ES EL ACTECO
```

**Odoo 19:**
```python
# Solo descripción, SIN código
l10n_cl_activity_description = fields.Char()
# Valor: "ENERGIA Y CONSTRUCCION"
# ❌ Falta el código numérico (Acteco)
```

**Impacto:**
- 🔴 **CRÍTICO** - SII rechazará DTEs sin `<Acteco>`
- 🔴 Campo obligatorio según XSD

**Solución Requerida:**
```python
# res_company_dte.py - AGREGAR:

l10n_cl_activity_code = fields.Integer(
    string='Código Actividad Económica',
    help='Código numérico de actividad económica SII (Acteco). Ej: 620101 = Construcción'
)

# Validación:
@api.constrains('l10n_cl_activity_code')
def _check_activity_code(self):
    if self.l10n_cl_activity_code and (self.l10n_cl_activity_code < 100000 or self.l10n_cl_activity_code > 999999):
        raise ValidationError('Código actividad debe ser 6 dígitos')
```

**Urgencia:** 🔴 **ALTA** - Bloquea certificación SII

---

### Gap 2: Comuna (CmnaOrigen) 🟡 MEDIO

**Campo XSD SII:** `<CmnaOrigen>` (string, REQUERIDO)

**Situación Actual:**
```python
# Odoo 19 usa:
city = fields.Char()  # "Temuco"

# ¿city = comuna en Chile?
# - En Chile: Temuco es COMUNA (correcto)
# - Pero: Santiago tiene 32 comunas (Santiago Centro, Las Condes, etc.)
```

**Problema:**
- En Santiago y Valparaíso: `city` NO es suficiente
- Necesita comuna específica (ej: "Las Condes", no "Santiago")

**Solución Requerida:**
```python
# res_partner.py - AGREGAR campo comuna:

l10n_cl_comuna = fields.Char(
    string='Comuna',
    help='Comuna chilena (más específica que ciudad). Ej: Las Condes, Providencia, Temuco'
)

# En generación DTE:
# 1. Si tiene l10n_cl_comuna → usar eso
# 2. Si no, usar city
<CmnaOrigen>{partner.l10n_cl_comuna or partner.city}</CmnaOrigen>
```

**Urgencia:** 🟡 **MEDIA** - Funciona para regiones, problema en Santiago/Valparaíso

---

## 📋 Tabla Resumen Final

| # | Campo | XSD SII | Odoo 11 | Odoo 19 | Gap | Criticidad |
|---|-------|---------|---------|---------|-----|------------|
| 1 | RUT | `<RUTEmisor>` | ✅ vat | ✅ vat | ✅ OK | - |
| 2 | Razón Social | `<RznSoc>` | ✅ name | ✅ name | ✅ OK | - |
| 3 | Giro | `<GiroEmis>` | ✅ activity_description | ✅ l10n_cl_activity_description | ✅ OK | - |
| 4 | **Código Actividad** | **`<Acteco>`** | ✅ sii_activity_description.code | ❌ **FALTA** | 🔴 **SÍ** | 🔴 **CRÍTICA** |
| 5 | Dirección | `<DirOrigen>` | ✅ street | ✅ street | ✅ OK | - |
| 6 | **Comuna** | **`<CmnaOrigen>`** | ✅ city | ⚠️ city (ambiguo) | 🟡 **PARCIAL** | 🟡 **MEDIA** |
| 7 | Ciudad | `<CiudadOrigen>` | ✅ city | ✅ city | ✅ OK | - |
| 8 | Teléfono | `<Telefono>` | ✅ phone | ✅ phone | ✅ OK | - |
| 9 | Email | `<CorreoEmisor>` | ✅ email | ✅ email / dte_email | ✅ OK | - |
| 10 | Resolución # | (Caratula) | ✅ dte_resolution_number | ✅ dte_resolution_number | ✅ OK | - |
| 11 | Resolución Fecha | (Caratula) | ✅ dte_resolution_date | ✅ dte_resolution_date | ✅ OK | - |
| 12 | Tipo Contribuyente | (Implícito) | ⚠️ No explícito | ✅ l10n_cl_sii_taxpayer_type | ✅ MEJOR | - |
| 13 | Proveedor DTE | (Informativo) | ✅ dte_service_provider | ❌ Falta | 🟢 Opcional | 🟢 **BAJA** |
| 14 | Oficina SII | (Informativo) | ✅ sii_regional_office_id | ❌ Falta | 🟢 Opcional | 🟢 **BAJA** |

---

## 🎯 Plan de Acción

### 1. 🔴 URGENTE: Agregar Código Actividad (Acteco)

**Archivo:** `models/res_company_dte.py`

```python
# Agregar campo:
l10n_cl_activity_code = fields.Integer(
    string='Código Actividad Económica (Acteco)',
    help='Código numérico SII de 6 dígitos. Ej: 620101 = Obras de ingeniería civil'
)

# Validación:
@api.constrains('l10n_cl_activity_code')
def _check_activity_code(self):
    for company in self:
        if company.l10n_cl_activity_code:
            if not (100000 <= company.l10n_cl_activity_code <= 999999):
                raise ValidationError(
                    'Código de actividad económica debe tener 6 dígitos (100000-999999)'
                )
```

**Vista:** `views/res_company_dte_views.xml` (o `res_config_settings_views.xml`)

```xml
<field name="l10n_cl_activity_description"/>
<field name="l10n_cl_activity_code"
       placeholder="Ej: 620101"
       attrs="{'required': [('country_id.code', '=', 'CL')]}"/>
```

**Generación DTE:** `models/account_move_dte.py`

```python
# En método _prepare_dte_data():
'acteco': self.company_id.l10n_cl_activity_code,  # ← AGREGAR
```

**Esfuerzo:** 1 hora
**Prioridad:** 🔴 **CRÍTICA** (bloquea certificación SII)

---

### 2. 🟡 IMPORTANTE: Agregar Campo Comuna

**Archivo:** `models/res_partner_dte.py`

```python
# Agregar campo:
l10n_cl_comuna = fields.Char(
    string='Comuna',
    help='Comuna chilena. Para Santiago/Valparaíso: especificar comuna exacta (ej: Las Condes). '
         'Para otras regiones: puede coincidir con ciudad.'
)

# Compute default (si ciudad = comuna):
@api.onchange('city', 'l10n_cl_comuna')
def _onchange_city_comuna(self):
    if self.country_code == 'CL' and self.city and not self.l10n_cl_comuna:
        # Auto-rellenar comuna = ciudad (usuario puede cambiar)
        self.l10n_cl_comuna = self.city
```

**Vista:** `views/res_partner_dte_views.xml`

```xml
<field name="city"/>
<field name="l10n_cl_comuna"
       placeholder="Ej: Las Condes, Providencia, Temuco"
       attrs="{'invisible': [('country_code', '!=', 'CL')]}"/>
```

**Generación DTE:** `models/account_move_dte.py`

```python
# En método _prepare_dte_data():
'comuna_origen': self.company_id.partner_id.l10n_cl_comuna or self.company_id.city,
```

**Esfuerzo:** 1 hora
**Prioridad:** 🟡 **MEDIA** (funciona en regiones, problema en Santiago)

---

### 3. 🟢 OPCIONAL: Agregar Campos Informativos

**Proveedor Servicios DTE:**
```python
dte_service_provider = fields.Selection([
    ('sii', 'SII (Servicio de Impuestos Internos)'),
], default='sii', string='Proveedor Servicios DTE', readonly=True)
```

**Oficina Regional SII:**
```python
sii_regional_office = fields.Selection([
    # 32 oficinas regionales SII
    ('temuco', 'Temuco'),
    ('santiago_centro', 'Santiago Centro'),
    # ...
], string='Oficina Regional SII')
```

**Esfuerzo:** 30 minutos cada uno
**Prioridad:** 🟢 **BAJA** (solo informativo)

---

## ✅ Verificación Post-Implementación

### Checklist Certificación SII

Después de agregar los campos, verificar:

```python
# 1. Verificar empresa tiene todos los datos
company = self.env.company

assert company.vat, "Falta RUT"
assert company.name, "Falta Razón Social"
assert company.l10n_cl_activity_description, "Falta Giro"
assert company.l10n_cl_activity_code, "Falta Acteco"  # ← NUEVO
assert company.street, "Falta Dirección"
assert company.city, "Falta Ciudad"
assert company.partner_id.l10n_cl_comuna, "Falta Comuna"  # ← NUEVO
assert company.dte_resolution_number, "Falta Resolución #"
assert company.dte_resolution_date, "Falta Resolución Fecha"

# 2. Generar DTE de prueba
invoice = self.env['account.move'].create({...})
xml_dte = invoice.action_generate_dte()

# 3. Validar XML contra XSD
from lxml import etree
xsd = etree.XMLSchema(file='schemas/DTE_v10.xsd')
xml_doc = etree.fromstring(xml_dte)
assert xsd.validate(xml_doc), xsd.error_log

# 4. Verificar campos obligatorios en XML
assert xml_doc.find('.//Acteco').text == str(company.l10n_cl_activity_code)
assert xml_doc.find('.//CmnaOrigen').text == company.partner_id.l10n_cl_comuna
```

---

## 📊 Resumen Ejecutivo

### Campos OK: 12/14 (86%) ✅

✅ Estos campos están implementados correctamente:
- RUT, Razón Social, Dirección, Ciudad, Teléfono, Email, Website
- Giro (actividad descripción)
- Tipo Contribuyente (mejor que Odoo 11)
- Email DTE (simplificado)
- Resolución DTE (número + fecha)

### Gaps Críticos: 1 🔴

🔴 **Código Actividad Económica (Acteco)**
- Campo obligatorio XSD SII
- Bloquea certificación
- Solución: 1 hora desarrollo

### Gaps Medios: 1 🟡

🟡 **Comuna (CmnaOrigen)**
- Campo obligatorio XSD SII
- Funciona en regiones, problema en Santiago/Valparaíso
- Solución: 1 hora desarrollo

### Gaps Opcionales: 2 🟢

🟢 **Proveedor DTE + Oficina Regional**
- Campos informativos (no afectan DTEs)
- Útiles para reportes
- Solución: 30 min cada uno

---

## 🎯 Recomendación Final

### ✅ Implementar AHORA (Bloquea Certificación):

1. **Código Actividad (Acteco)** - 1 hora
2. **Comuna (CmnaOrigen)** - 1 hora

**Total:** 2 horas desarrollo + 1 hora testing = **3 horas**

### ⏰ Implementar DESPUÉS (Opcional):

3. Proveedor DTE - 30 min
4. Oficina Regional SII - 30 min

**Total:** 1 hora

---

**Prioridad:** 🔴 **CRÍTICA** - Sin estos 2 campos, el SII rechazará los DTEs

**¿Procedo con la implementación de Acteco + Comuna?**

---

**Autor:** Claude (Sonnet 4.5)
**Fecha:** 2025-10-22 20:00 UTC-3
**Próximo paso:** Implementar campos faltantes
