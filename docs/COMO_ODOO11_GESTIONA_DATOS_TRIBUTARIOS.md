# 🔍 Cómo Odoo 11 Gestiona Datos Tributarios - Análisis Completo

**Fecha:** 2025-10-22 20:30 UTC-3
**Módulo Odoo 11:** `l10n_cl_fe` (Facturación Electrónica Chile)
**Propósito:** Entender arquitectura tributaria para replicar en Odoo 19

---

## 🎯 Resumen Ejecutivo

### Arquitectura Odoo 11: Modelos Dedicados + Many2many

Odoo 11 usa **5 modelos** dedicados para gestión tributaria:

| Modelo | Tabla DB | Propósito | Registros EERGYGROUP |
|--------|----------|-----------|---------------------|
| `partner.activities` | partner_activities | **Códigos actividad SII (Acteco)** | 674 total, 4 asignados |
| `sii.activity.description` | sii_activity_description | Glosa giro (descripción texto) | ~20 descripciones |
| `res.city` | res_city | Ciudades/Comunas con código SII | Temuco (CL09101) |
| `sii.regional.offices` | sii_regional_offices | Oficinas regionales SII | Temuco (ID 57) |
| `sii.responsability` | sii_responsability | Tipo responsabilidad tributaria | IVA RI |

**Ventaja vs Odoo 19:**
- ✅ Datos normalizados (1 solo lugar)
- ✅ Reutilizables entre partners/companies
- ✅ Actualizables centralmente (ej: nuevo código SII)
- ✅ Validación consistente

**Desventaja:**
- ⚠️ Mayor complejidad (5 tablas vs campos simples)
- ⚠️ Requiere datos seed (carga inicial de 674 actividades)

---

## 📋 Tabla de Contenidos

1. [Modelo: partner.activities (Códigos Actividad SII)](#1-modelo-partner-activities)
2. [Modelo: sii.activity.description (Glosa Giro)](#2-modelo-sii-activity-description)
3. [Modelo: res.city (Ciudades/Comunas)](#3-modelo-res-city)
4. [Modelo: sii.regional.offices (Oficinas SII)](#4-modelo-sii-regional-offices)
5. [Modelo: sii.responsability (Responsabilidad Tributaria)](#5-modelo-sii-responsability)
6. [Integración en res.partner](#6-integracion-en-res-partner)
7. [Integración en res.company](#7-integracion-en-res-company)
8. [Comparación con Odoo 19](#8-comparacion-con-odoo-19)
9. [Recomendaciones para Odoo 19](#9-recomendaciones-para-odoo-19)

---

## 1️⃣ Modelo: partner.activities (Códigos Actividad SII)

### Definición del Modelo

**Archivo:** `models/partner_activities.py`

```python
class PartnerActivities(models.Model):
    _name = 'partner.activities'
    _description = 'SII Economical Activities'

    code = fields.Char(
        string='Activity Code',
        required=True,
    )
    parent_id = fields.Many2one(
        'partner.activities',
        string='Parent Activity',
        ondelete='cascade',
    )
    name = fields.Char(
        string='Nombre Completo',
        required=True,
        translate=True,
    )
    vat_affected = fields.Selection([
        ('SI', 'Si'),
        ('NO', 'No'),
        ('ND', 'ND'),
    ], string='VAT Affected', required=True, default='SI')

    tax_category = fields.Selection([
        ('1', '1'),
        ('2', '2'),
        ('ND', 'ND'),
    ], string='TAX Category', required=True, default='1')

    internet_available = fields.Boolean(
        string='Available at Internet',
        default=True,
    )
    active = fields.Boolean(
        string='Active',
        default=True,
    )

    @api.multi
    def name_get(self):
        res = []
        for r in self:
            # Formato: [620100] Actividades de programación informática
            res.append((r.id, (r.code and '[' + r.code + '] ' + r.name or '')))
        return res

    @api.model
    def name_search(self, name, args=None, operator='ilike', limit=100):
        # Busca por código o nombre
        args = args or []
        recs = self.browse()
        if name:
            recs = self.search(['|',('name', '=', name),('code', '=', name)] + args, limit=limit)
        if not recs:
            recs = self.search(['|',('name', operator, name),('code', operator, name)] + args, limit=limit)
        return recs.name_get()
```

### Estructura Base de Datos

```sql
-- Tabla: partner_activities
CREATE TABLE partner_activities (
    id SERIAL PRIMARY KEY,
    code VARCHAR NOT NULL,              -- Código SII 6 dígitos (ej: 421000)
    parent_id INTEGER,                  -- Jerarquía (opcional)
    name VARCHAR NOT NULL,              -- Descripción completa
    vat_affected VARCHAR NOT NULL,      -- SI/NO/ND
    tax_category VARCHAR NOT NULL,      -- 1ra o 2da categoría
    internet_available BOOLEAN,
    active BOOLEAN DEFAULT TRUE
);

-- Datos ejemplo:
INSERT INTO partner_activities (id, code, name, vat_affected, tax_category) VALUES
(689, '702000', 'Actividades de consultoría de gestión', 'SI', '1'),
(1125, '421000', 'Construcción de carreteras y líneas de ferrocarril', 'SI', '1'),
(1133, '433000', 'Terminación y acabado de edificios', 'SI', '1'),
(1123, '410010', 'Construcción de edificios para uso residencial', 'SI', '1');
```

### Datos Actuales EERGYGROUP

```sql
SELECT pa.id, pa.code, pa.name
FROM partner_activities pa
JOIN partner_activities_res_partner_rel rel
  ON pa.id = rel.partner_activities_id
WHERE rel.res_partner_id = 1;

-- Resultado (4 actividades):
689  | 702000 | Actividades de consultoría de gestión
1125 | 421000 | Construcción de carreteras y líneas de ferrocarril
1133 | 433000 | Terminación y acabado de edificios
1123 | 410010 | Construcción de edificios para uso residencial
```

### Catálogo Completo

**Total registros:** 674 actividades económicas

**Clasificación CIIU Rev. 4 Chile:**
- **Códigos 1-3 dígitos:** Categorías principales (ej: 42 = Construcción)
- **Códigos 4 dígitos:** Subcategorías (ej: 4210 = Construcción carreteras)
- **Códigos 5-6 dígitos:** Detalle específico (ej: 421000 = Carreteras)

**Ejemplo categoría Construcción (42-43):**
```
421000 - Construcción de carreteras y líneas de ferrocarril
422000 - Construcción de proyectos de servicio público
429000 - Construcción de otras obras de ingeniería civil
431100 - Demolición
431200 - Preparación del terreno
432100 - Instalaciones eléctricas
432200 - Instalaciones de gasfitería, calefacción y aire acondicionado
432900 - Otras instalaciones para obras de construcción
433000 - Terminación y acabado de edificios
439000 - Otras actividades especializadas de construcción
```

**Ejemplo categoría Servicios profesionales (71):**
```
711001 - Servicios de arquitectura (diseño de edificios, dibujo de planos)
711002 - Empresas de servicios de ingeniería y consultoría técnica
711003 - Servicios profesionales de ingeniería y consultoría técnica
712001 - Actividades de plantas de revisión técnica para vehículos
```

### Integración Many2many con Partners

**Relación:** Un partner puede tener **múltiples actividades económicas**

```python
# models/res_partner.py
class ResPartner(models.Model):
    _inherit = 'res.partner'

    acteco_ids = fields.Many2many(
        'partner.activities',
        string='Activities Names',
    )
```

**Tabla relación:**
```sql
-- partner_activities_res_partner_rel
CREATE TABLE partner_activities_res_partner_rel (
    partner_activities_id INTEGER NOT NULL,
    res_partner_id INTEGER NOT NULL,
    PRIMARY KEY (partner_activities_id, res_partner_id)
);
```

### Uso en Generación DTE

```python
# En XML DTE, se incluye el PRIMER código de actividad:
company = self.company_id
activities = company.partner_id.acteco_ids
if activities:
    acteco = activities[0].code  # Toma el primero
else:
    acteco = '000000'  # Código genérico (error)

xml_dte += f'<Acteco>{acteco}</Acteco>'
```

**Importante:** SII permite **múltiples** actividades por empresa, pero en el DTE **solo va 1** (la principal).

---

## 2️⃣ Modelo: sii.activity.description (Glosa Giro)

### Definición del Modelo

**Archivo:** `models/sii_activity_description.py`

```python
class partner_activities(models.Model):
    _description = 'SII Economical Activities Printable Description'
    _name = 'sii.activity.description'

    name = fields.Char(
        string='Glosa',
        required=True,
        translate=True,
    )
    vat_affected = fields.Selection([
        ('SI', 'Si'),
        ('NO', 'No'),
        ('ND', 'ND')
    ], string='VAT Affected', required=True, default='SI')

    active = fields.Boolean(
        string='Active',
        default=True,
    )
```

### Diferencia con `partner.activities`

| Campo | partner.activities | sii.activity.description |
|-------|-------------------|-------------------------|
| **Propósito** | Código numérico SII (Acteco) | Descripción legible (Giro) |
| **Formato** | `421000` | `"ENERGIA Y CONSTRUCCION"` |
| **Uso XML** | `<Acteco>421000</Acteco>` | `<GiroEmis>ENERGIA Y CONSTRUCCION</GiroEmis>` |
| **Cantidad** | 674 opciones (catálogo SII) | ~20 opciones (glosas genéricas) |
| **Relación** | Many2many (múltiples) | Many2one (1 solo) |

### Datos EERGYGROUP

```sql
SELECT name FROM sii_activity_description WHERE id = 2;
-- Resultado: "ENERGIA Y CONSTRUCCION"
```

### Catálogo Típico

```sql
-- Glosas comunes en Chile:
1. COMERCIO AL POR MAYOR Y MENOR
2. ENERGIA Y CONSTRUCCION
3. SERVICIOS PROFESIONALES
4. TRANSPORTE Y LOGISTICA
5. INDUSTRIA MANUFACTURERA
6. AGRICULTURA Y GANADERIA
7. MINERIA
8. TURISMO Y HOTELERIA
9. TECNOLOGIA E INFORMATICA
10. EDUCACION
... (~20 glosas genéricas)
```

**Uso:** Se muestra en **PDF impreso** del DTE (más legible que código 421000).

---

## 3️⃣ Modelo: res.city (Ciudades/Comunas)

### Extensión del Modelo Base

**Archivo:** `models/res_city.py`

```python
class ResCity(models.Model):
    _inherit = 'res.city'

    code = fields.Char(
        string='City Code',
        help='The city code.\n',
        required=True,
    )
```

### Estructura Base de Datos

```sql
-- Tabla base Odoo (res.city):
CREATE TABLE res_city (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    zipcode VARCHAR,
    country_id INTEGER NOT NULL,
    state_id INTEGER,
    code VARCHAR NOT NULL  -- ← Agregado por l10n_cl_fe
);
```

### Sistema de Códigos SII

**Formato código:** `CLSSXXX`
- `CL` = Chile (país)
- `SS` = Estado/región (2 dígitos)
- `XXX` = Comuna (3 dígitos)

**Ejemplo Temuco:**
```sql
SELECT id, name, code, state_id FROM res_city WHERE name = 'Temuco';
-- Resultado:
-- 196 | Temuco | CL09101 | 708

-- Desglose código CL09101:
-- CL = Chile
-- 09 = Región de La Araucanía (state_id 708)
-- 101 = Comuna Temuco
```

### Catálogo Región Metropolitana (Santiago)

```sql
-- Código CL13XXX (región 13 = RM Santiago)
CL13101 - Santiago (comuna)
CL13102 - Independencia
CL13103 - Conchalí
CL13104 - Huechuraba
CL13105 - Recoleta
CL13106 - Providencia
CL13107 - Vitacura
CL13108 - Lo Barnechea
CL13109 - Las Condes
CL13110 - Ñuñoa
CL13111 - La Reina
CL13112 - Macul
CL13113 - Peñalolén
CL13114 - La Florida
... (32 comunas total)
```

**Importante:** En Santiago, `city = "Santiago"` NO es suficiente. Necesita **comuna específica**.

### Integración en Partners/Companies

```python
# models/company.py
class DTECompany(models.Model):
    _inherit = 'res.company'

    city_id = fields.Many2one(
        related='partner_id.city_id',
        relation="res.city",
        string='City',
    )

    @api.onchange('city_id')
    def _asign_city(self):
        if self.city_id:
            # Auto-asigna país, estado y nombre ciudad
            self.country_id = self.city_id.state_id.country_id.id
            self.state_id = self.city_id.state_id.id
            self.city = self.city_id.name
```

### Uso en Generación DTE

```python
# XML DTE incluye comuna (name) no código
company = self.company_id
comuna = company.city_id.name if company.city_id else company.city

xml_dte += f'<CmnaOrigen>{comuna}</CmnaOrigen>'
# Output: <CmnaOrigen>Temuco</CmnaOrigen>
```

---

## 4️⃣ Modelo: sii.regional.offices (Oficinas SII)

### Definición del Modelo

**Archivo:** `models/sii_regional_offices.py`

```python
class SiiRegionalOffices(models.Model):
    _name='sii.regional.offices'

    name = fields.Char('Regional Office Name')
    city_ids = fields.Many2many(
        'res.city',
        id1='sii_regional_office_id',
        id2='city_id',
        string='Ciudades',
    )
```

### Estructura Base de Datos

```sql
CREATE TABLE sii_regional_offices (
    id SERIAL PRIMARY KEY,
    name VARCHAR  -- Nombre oficina (ej: "Temuco")
);

-- Relación con ciudades:
CREATE TABLE res_city_sii_regional_offices_rel (
    sii_regional_office_id INTEGER,
    city_id INTEGER,
    PRIMARY KEY (sii_regional_office_id, city_id)
);
```

### Datos EERGYGROUP

```sql
SELECT name FROM sii_regional_offices WHERE id = 57;
-- Resultado: "Temuco"

SELECT sii_regional_office_id FROM res_company WHERE id = 1;
-- Resultado: 57
```

### Catálogo Oficinas Regionales SII

**Total:** 32 oficinas regionales

```
1  - Arica
2  - Iquique
3  - Antofagasta
4  - Copiapó
5  - La Serena
6  - Valparaíso
7  - Santiago Centro
8  - Santiago Oriente
9  - Santiago Sur
10 - Santiago Poniente
11 - Rancagua
12 - Talca
13 - Chillán
14 - Concepción
15 - Los Angeles
16 - Temuco  ← EERGYGROUP
17 - Valdivia
18 - Puerto Montt
19 - Coyhaique
20 - Punta Arenas
... (otras subdirecciones)
```

### Uso

**Propósito:** Identificar oficina SII de **jurisdicción** para:
- Correspondencia física al SII
- Consultas presenciales
- Reclamos tributarios

**¿Se usa en DTE XML?** ❌ **NO** - Solo informativo interno

---

## 5️⃣ Modelo: sii.responsability (Responsabilidad Tributaria)

### Definición del Modelo

**Archivo:** `models/sii.py` (modelo no mostrado, inferido)

```python
class SIIResponsability(models.Model):
    _name = 'sii.responsability'

    name = fields.Char('Responsability Name')
    code = fields.Char('Code')
```

### Tipos de Responsabilidad SII Chile

```sql
-- Valores comunes:
1. IVA RI - IVA Responsable Inscrito (más común)
2. IVA RE - IVA Responsable Exento
3. IVA NR - IVA No Responsable
4. Segunda Categoría - Honorarios
5. Consumidor Final
6. Extranjero
```

### Datos EERGYGROUP

```python
# Default:
responsability_id = self.env.ref('l10n_cl_fe.res_IVARI')
# Valor: IVA RI (IVA Responsable Inscrito)
```

**Significado para EERGYGROUP:**
- ✅ Empresa afecta a IVA 19%
- ✅ Debe emitir facturas con IVA
- ✅ Puede recuperar IVA compras (crédito fiscal)

### Uso en Generación DTE

```python
# Determina campos XML según responsabilidad:
if partner.responsability_id.code == 'IVARI':
    # Factura con IVA discriminado
    xml_dte += f'<MntNeto>{monto_neto}</MntNeto>'
    xml_dte += f'<IVA>{iva}</IVA>'
    xml_dte += f'<MntTotal>{total}</MntTotal>'
elif partner.responsability_id.code == 'CF':
    # Consumidor final (boleta, sin discriminar IVA)
    xml_dte += f'<MntTotal>{total}</MntTotal>'
```

---

## 6️⃣ Integración en res.partner

### Campos Agregados

**Archivo:** `models/res_partner.py`

```python
class ResPartner(models.Model):
    _inherit = 'res.partner'

    # ═══════════════════════════════════════════════════════════
    # DATOS TRIBUTARIOS
    # ═══════════════════════════════════════════════════════════

    document_type_id = fields.Many2one(
        'sii.document_type',
        string='Document type',
        default=lambda self: self.env.ref('l10n_cl_fe.dt_RUT'),
    )

    document_number = fields.Char(
        string='Document number',  # RUT formateado: 76.489.218-6
        size=64,
    )

    responsability_id = fields.Many2one(
        'sii.responsability',
        string='Responsability',
        default=lambda self: self.env.ref('l10n_cl_fe.res_IVARI'),
    )

    activity_description = fields.Many2one(
        'sii.activity.description',
        string='Glosa Giro',  # Descripción legible
        ondelete="restrict",
    )

    acteco_ids = fields.Many2many(
        'partner.activities',
        string='Activities Names',  # Códigos numéricos SII (múltiples)
    )

    start_date = fields.Date(
        string='Start-up Date',  # Fecha inicio actividades
    )

    dte_email = fields.Char(
        string='DTE Email',  # Email para recibir DTEs
    )

    dte_email_id = fields.Many2one(
        'res.partner',
        string='DTE Email Principal',
        compute='_compute_dte_email',
    )

    es_mipyme = fields.Boolean(
        string="Es MiPyme",
        help="Usa el sistema gratuito del SII"
    )

    # ═══════════════════════════════════════════════════════════
    # UTILIDADES
    # ═══════════════════════════════════════════════════════════

    def rut(self):
        """Retorna RUT sin formato (solo dígitos + guion)"""
        rut = '66666666-6'
        if self.document_number:
            d = self.document_number.replace('.', '').split('-')
            rut = str(int(d[0])) + '-' + d[1]
        return rut
```

### Validación RUT

```python
@api.onchange('document_number', 'document_type_id')
def onchange_document(self):
    if self.document_number and self.document_type_id == self.env.ref('l10n_cl_fe.dt_RUT'):
        # Limpia RUT: solo dígitos + K
        document_number = re.sub('[^1234567890Kk]', '', str(self.document_number))
        document_number = document_number.zfill(9).upper()

        # Valida con módulo 11
        if not self.check_vat_cl(document_number):
            self.vat = ''
            self.document_number = ''
            return {'warning': {'title': 'Rut Erróneo', 'message': 'Rut Erróneo'}}

        # Formatea: 76.489.218-6
        vat = 'CL%s' % document_number
        self.vat = vat
        self.document_number = '%s.%s.%s-%s' % (
            document_number[0:2],
            document_number[2:5],
            document_number[5:8],
            document_number[-1],
        )
```

---

## 7️⃣ Integración en res.company

### Campos Agregados (Related)

**Archivo:** `models/company.py`

```python
class DTECompany(models.Model):
    _inherit = 'res.company'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS PROPIOS (NO RELATED)
    # ═══════════════════════════════════════════════════════════

    dte_email_id = fields.Many2one(
        'mail.alias',
        string='DTE EMail',
        help="Email para recepción automática DTEs proveedores"
    )

    dte_service_provider = fields.Selection([
        ('SIICERT', 'SII - Certification process'),
        ('SII', 'www.sii.cl'),
    ], string='DTE Service Provider', default='SIICERT')

    dte_resolution_number = fields.Char(
        string='SII Exempt Resolution Number',
        default='0',
    )

    dte_resolution_date = fields.Date('SII Exempt Resolution Date')

    sii_regional_office_id = fields.Many2one(
        'sii.regional.offices',
        string='SII Regional Office',
    )

    invoice_vat_discrimination_default = fields.Selection([
        ('no_discriminate_default', 'Yes, No Discriminate Default'),
        ('discriminate_default', 'Yes, Discriminate Default')
    ], string='Invoice VAT discrimination default', default='no_discriminate_default')

    # ═══════════════════════════════════════════════════════════
    # CAMPOS RELATED (delegados a partner_id)
    # ═══════════════════════════════════════════════════════════

    state_id = fields.Many2one(
        related='partner_id.state_id',
        relation="res.country.state",
        string='Ubication',
    )

    company_activities_ids = fields.Many2many(
        'partner.activities',
        related="partner_id.acteco_ids",
        string='Activities Names',
    )

    responsability_id = fields.Many2one(
        related='partner_id.responsability_id',
        relation='sii.responsability',
        string="Responsability",
    )

    start_date = fields.Date(
        related='partner_id.start_date',
        string='Start-up Date',
    )

    activity_description = fields.Many2one(
        string='Glosa Giro',
        related='partner_id.activity_description',
        relation='sii.activity.description',
    )

    city_id = fields.Many2one(
        related='partner_id.city_id',
        relation="res.city",
        string='City',
    )

    document_number = fields.Char(
        related='partner_id.document_number',
        string="Document Number",
        required=True,
    )

    document_type_id = fields.Many2one(
        related="partner_id.document_type_id",
        relation='sii.document_type',
        string='Document type',
        required=True,
    )
```

**Estrategia:** Campos tributarios en `res.partner`, `res.company` los expone vía `related`.

---

## 8️⃣ Comparación con Odoo 19

### Tabla Comparativa

| Campo Tributario | Odoo 11 Approach | Odoo 19 Approach | Ventaja |
|------------------|------------------|------------------|---------|
| **Código Actividad (Acteco)** | ✅ `partner.activities` (M2M, 674 registros) | ❌ **FALTA** | ✅ Odoo 11 |
| **Giro (descripción)** | ✅ `sii.activity.description` (M2O, ~20 opciones) | ✅ `l10n_cl_activity_description` (Char) | ⚖️ Empate |
| **Ciudad/Comuna** | ✅ `res.city` con código SII (M2O, catálogo) | ⚠️ `city` (Char libre) | ✅ Odoo 11 |
| **Oficina Regional SII** | ✅ `sii.regional.offices` (M2O, 32 oficinas) | ❌ **FALTA** | ⚠️ Odoo 11 (opcional) |
| **Responsabilidad** | ✅ `sii.responsability` (M2O, 6 tipos) | ✅ `l10n_cl_sii_taxpayer_type` (Selection) | ⚖️ Empate |
| **RUT** | ✅ `document_number` (formateado) + `vat` | ✅ `vat` (formateado) | ⚖️ Empate |
| **Email DTE** | ✅ `dte_email` (Char) + `dte_email_id` (M2O) | ✅ `dte_email` (Char) | ✅ Odoo 19 (simplificado) |
| **Resolución DTE** | ✅ `dte_resolution_number` + `dte_resolution_date` | ✅ Idénticos | ⚖️ Empate |
| **Proveedor DTE** | ✅ `dte_service_provider` (Selection) | ❌ **FALTA** | ⚠️ Odoo 11 (opcional) |

### Ventajas Odoo 11

1. **Código Actividad (Acteco) - CRÍTICO** 🔴
   - Odoo 11: ✅ Catálogo normalizado 674 códigos SII
   - Odoo 19: ❌ Campo faltante
   - **Impacto:** SII rechaza DTEs sin `<Acteco>`

2. **Ciudad/Comuna con Código SII** 🟡
   - Odoo 11: ✅ Catálogo `res.city` con código oficial (ej: CL09101)
   - Odoo 19: ⚠️ Campo `city` texto libre (ambiguo en Santiago)
   - **Impacto:** Confusión en Santiago (32 comunas)

3. **Normalización de Datos** ✅
   - Odoo 11: Datos centralizados, reutilizables, actualizables
   - Odoo 19: Campos Char libres (sin validación)

### Ventajas Odoo 19

1. **Simplificación Email DTE** ✅
   - Odoo 11: `dte_email_id` (Many2one) + `dte_email` (Char) → complejidad
   - Odoo 19: `dte_email` (Char simple)

2. **Tipo Contribuyente Explícito** ✅
   - Odoo 11: ⚠️ `responsability_id` (concepto poco claro)
   - Odoo 19: ✅ `l10n_cl_sii_taxpayer_type` (4 opciones claras)

3. **Menos Tablas** ✅
   - Odoo 11: 5 modelos adicionales
   - Odoo 19: Campos simples en modelos base

---

## 9️⃣ Recomendaciones para Odoo 19

### Opción A: Replicar Arquitectura Odoo 11 (Completa)

**Implementar 2 modelos críticos:**

#### 1. Modelo `l10n_cl_dte.activity` (Códigos Acteco)

```python
# models/l10n_cl_activity.py
class L10nClActivity(models.Model):
    _name = 'l10n_cl_dte.activity'
    _description = 'Chilean SII Economic Activity Codes (Acteco)'
    _order = 'code'

    code = fields.Char(
        string='Activity Code',
        required=True,
        size=6,
        help='6-digit SII activity code (CIIU Rev. 4 Chile). Ex: 421000'
    )
    name = fields.Char(
        string='Activity Name',
        required=True,
        translate=True,
    )
    parent_id = fields.Many2one(
        'l10n_cl_dte.activity',
        string='Parent Activity',
        ondelete='cascade',
    )
    vat_affected = fields.Selection([
        ('yes', 'Yes (IVA 19%)'),
        ('no', 'No (Exempt)'),
        ('na', 'Not Applicable'),
    ], string='VAT Affected', default='yes', required=True)

    tax_category = fields.Selection([
        ('1', '1st Category (Companies)'),
        ('2', '2nd Category (Personal services)'),
    ], string='Tax Category', default='1', required=True)

    active = fields.Boolean(default=True)

    _sql_constraints = [
        ('code_unique', 'UNIQUE(code)', 'Activity code must be unique!')
    ]

    def name_get(self):
        res = []
        for rec in self:
            name = f'[{rec.code}] {rec.name}'
            res.append((rec.id, name))
        return res

    @api.model
    def name_search(self, name, args=None, operator='ilike', limit=100):
        args = args or []
        if name:
            recs = self.search([
                '|', ('code', operator, name), ('name', operator, name)
            ] + args, limit=limit)
            return recs.name_get()
        return super().name_search(name, args, operator, limit)
```

**Vista:**
```xml
<record id="view_l10n_cl_activity_tree" model="ir.ui.view">
    <field name="name">l10n_cl_dte.activity.tree</field>
    <field name="model">l10n_cl_dte.activity</field>
    <field name="arch" type="xml">
        <tree>
            <field name="code"/>
            <field name="name"/>
            <field name="vat_affected"/>
            <field name="tax_category"/>
        </tree>
    </field>
</record>
```

**Integración en res.company:**
```python
# models/res_company_dte.py
class ResCompanyDTE(models.Model):
    _inherit = 'res.company'

    l10n_cl_activity_ids = fields.Many2many(
        'l10n_cl_dte.activity',
        string='Economic Activities (Acteco)',
        help='Multiple activities allowed, first one used in DTEs'
    )

    l10n_cl_main_activity_id = fields.Many2one(
        'l10n_cl_dte.activity',
        string='Main Activity',
        compute='_compute_main_activity',
        store=True,
    )

    @api.depends('l10n_cl_activity_ids')
    def _compute_main_activity(self):
        for company in self:
            company.l10n_cl_main_activity_id = company.l10n_cl_activity_ids[:1]
```

**Datos seed (674 registros):**
```python
# data/l10n_cl_activities.xml
<odoo>
    <record id="activity_421000" model="l10n_cl_dte.activity">
        <field name="code">421000</field>
        <field name="name">Construcción de carreteras y líneas de ferrocarril</field>
        <field name="vat_affected">yes</field>
        <field name="tax_category">1</field>
    </record>
    <!-- ... 673 registros más -->
</odoo>
```

**Esfuerzo:** 8-10 horas (modelo + 674 datos + vistas)

---

#### 2. Modelo `res.city` (Con Código SII)

**Extender modelo base:**
```python
# models/res_city_dte.py
class ResCityDTE(models.Model):
    _inherit = 'res.city'

    l10n_cl_code = fields.Char(
        string='SII City Code',
        help='Chilean SII city code. Format: CLSSXXX (CL + state + city)',
        size=7,
    )

    @api.constrains('l10n_cl_code')
    def _check_cl_code(self):
        for city in self:
            if city.country_id.code == 'CL' and city.l10n_cl_code:
                if not re.match(r'^CL\d{5}$', city.l10n_cl_code):
                    raise ValidationError(
                        'Chilean city code must be format CLXXXXX (CL + 5 digits)'
                    )
```

**Datos seed (346 comunas Chile):**
```xml
<record id="city_temuco" model="res.city">
    <field name="name">Temuco</field>
    <field name="state_id" ref="base.state_cl_09"/>
    <field name="country_id" ref="base.cl"/>
    <field name="l10n_cl_code">CL09101</field>
</record>
<!-- ... 345 comunas más -->
```

**Esfuerzo:** 6-8 horas (extensión + 346 datos)

---

### Opción B: Solución Minimalista (Solo Campos Críticos)

**Implementar solo lo mínimo XSD SII:**

```python
# models/res_company_dte.py
class ResCompanyDTE(models.Model):
    _inherit = 'res.company'

    # Campo crítico 1: Código Actividad
    l10n_cl_activity_code = fields.Char(
        string='Código Actividad Económica (Acteco)',
        size=6,
        help='Código SII 6 dígitos. Ej: 421000 = Construcción carreteras.\n'
             'Ver catálogo: https://www.sii.cl/ayudas/ayudas_por_servicios/1956-codigos-1959.html'
    )

    @api.constrains('l10n_cl_activity_code')
    def _check_activity_code(self):
        for company in self:
            if company.l10n_cl_activity_code:
                if not company.l10n_cl_activity_code.isdigit():
                    raise ValidationError('Código actividad debe ser numérico')
                code = int(company.l10n_cl_activity_code)
                if not (10000 <= code <= 999999):
                    raise ValidationError('Código actividad debe tener 5 o 6 dígitos')

# models/res_partner_dte.py
class ResPartnerDTE(models.Model):
    _inherit = 'res.partner'

    # Campo crítico 2: Comuna
    l10n_cl_comuna = fields.Char(
        string='Comuna',
        help='Comuna chilena. Santiago: especificar comuna exacta (Las Condes, Providencia, etc.)'
    )

    @api.onchange('city', 'country_id')
    def _onchange_city_comuna(self):
        # Auto-rellenar comuna = ciudad (usuario puede cambiar si es Santiago)
        if self.country_id.code == 'CL' and self.city and not self.l10n_cl_comuna:
            self.l10n_cl_comuna = self.city
```

**Esfuerzo:** 2 horas (solo 2 campos + validación)

---

### Comparación Opciones

| Aspecto | Opción A (Completa) | Opción B (Minimalista) |
|---------|---------------------|------------------------|
| **Esfuerzo** | 14-18 horas | 2 horas |
| **Datos seed** | 674 + 346 = 1,020 registros | 0 (usuario ingresa manual) |
| **Validación** | ✅ Automática (catálogo) | ⚠️ Manual (usuario responsable) |
| **UX** | ✅ Dropdown con búsqueda | ⚠️ Input texto libre |
| **Mantenibilidad** | ✅ Actualizar catálogo central | ⚠️ Cada usuario actualiza |
| **Certifica SII** | ✅ Sí (con datos correctos) | ✅ Sí (si usuario ingresa bien) |
| **Riesgo error** | 🟢 Bajo (catálogo validado) | 🟡 Medio (typos posibles) |

---

### Recomendación Final

**Para EERGYGROUP:**
- ✅ **Opción B (Minimalista)** es suficiente para certificar
- Razones:
  1. Solo necesitan 1 código: `421000` (construcción)
  2. Solo 1 comuna: `Temuco` (no ambigua)
  3. Ahorro: 12-16 horas desarrollo
  4. Igualmente certifica en SII

**Para producto comercial:**
- ✅ **Opción A (Completa)** es mejor
- Razones:
  1. UX superior (dropdown vs texto libre)
  2. Validación automática (reduce errores)
  3. Escalable (múltiples clientes)
  4. Profesional (catálogo oficial SII)

---

## ✅ Conclusión

### Hallazgos Clave

1. **Odoo 11 usa arquitectura normalizada** con 5 modelos dedicados:
   - ✅ `partner.activities` (674 códigos Acteco)
   - ✅ `sii.activity.description` (~20 glosas)
   - ✅ `res.city` (346 comunas con código SII)
   - ✅ `sii.regional.offices` (32 oficinas)
   - ✅ `sii.responsability` (6 tipos)

2. **Ventaja:** Datos centralizados, reutilizables, validados

3. **Desventaja:** Mayor complejidad (1,020 registros seed)

4. **Odoo 19 puede certificar** con solo 2 campos adicionales:
   - `l10n_cl_activity_code` (Char 6 dígitos)
   - `l10n_cl_comuna` (Char)

5. **Para EERGYGROUP:** Opción minimalista suficiente (2 horas vs 16 horas)

---

**Documento generado:** 2025-10-22 20:30 UTC-3
**Próximo paso:** Implementar Opción B (2 campos críticos) en Odoo 19

---

**¿Procedo con la implementación de los 2 campos críticos (Opción B)?**
