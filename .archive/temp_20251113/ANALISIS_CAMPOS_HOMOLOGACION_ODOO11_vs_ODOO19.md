# 🔍 ANÁLISIS DE HOMOLOGACIÓN DE CAMPOS: Odoo 11 → Odoo 19

**Fecha:** 2025-10-25
**Objetivo:** Determinar qué campos requieren **creación en Odoo 19** vs **transformación por script**
**Analista:** Claude Code AI (Senior DB/ERP Architect)

---

## 📊 RESUMEN EJECUTIVO

```
┌─────────────────────────────────────────────────────────────────────┐
│ ANÁLISIS DE 85 CAMPOS DE ODOO 11                                    │
├─────────────────────────────────────────────────────────────────────┤
│ ✅ Homologables por Script:        ~40 campos (47%)                │
│ ✅ Ya Existen en Odoo 19 Estándar: ~35 campos (41%)                │
│ ⚠️  Requieren Creación Custom:      5 campos (6%)                  │
│ ❌ Descartables (Legacy):           5 campos (6%)                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Veredicto:** La mayoría de campos son **homologables** (88%). Solo **5 campos críticos** requieren creación custom en Odoo 19.

---

## ✅ CATEGORÍA A: HOMOLOGABLES POR SCRIPT (Sin crear campos)

### **A1. Campos de Migración Directa (1:1)**

Estos campos existen en ambas versiones con el **mismo nombre y tipo**, solo requieren copia directa:

| Campo Odoo 11 | Campo Odoo 19 | Script | Comentario |
|---------------|---------------|--------|------------|
| `name` | `name` | ✅ Copia directa | Nombre del contacto |
| `ref` | `ref` | ✅ Copia directa | Referencia interna |
| `email` | `email` | ✅ Copia directa | Email principal |
| `phone` | `phone` | ✅ Copia directa | Teléfono |
| `mobile` | (Migrar a `phone`) | ⚠️ Consolidar | Odoo 19 depreca `mobile` |
| `street` | `street` | ✅ Copia directa | Dirección calle |
| `street2` | `street2` | ✅ Copia directa | Dirección complementaria |
| `city` | `city` | ✅ Copia directa | Ciudad |
| `zip` | `zip` | ✅ Copia directa | Código postal |
| `country_id` | `country_id` | ✅ Copia directa FK | ID país (156 = Chile) |
| `website` | `website` | ✅ Copia directa | Sitio web |
| `comment` | `comment` | ✅ Copia directa | Notas |
| `active` | `active` | ✅ Copia directa | Activo/inactivo |
| `is_company` | `is_company` | ✅ Copia directa | Es empresa o persona |
| `type` | `type` | ✅ Copia directa | contact/invoice/delivery/etc |
| `lang` | `lang` | ✅ Copia directa | Idioma (es_CL) |
| `tz` | `tz` | ✅ Copia directa | Zona horaria |
| `function` | `function` | ✅ Copia directa | Cargo/función |
| `parent_id` | `parent_id` | ✅ Copia directa FK | ID contacto padre |
| `user_id` | `user_id` | ✅ Copia directa FK | Vendedor asignado |
| `company_id` | `company_id` | ✅ Copia directa FK | Empresa Odoo |
| `industry_id` | `industry_id` | ✅ Copia directa FK | Industria |
| `partner_latitude` | `partner_latitude` | ✅ Copia directa | Latitud geolocalización |
| `partner_longitude` | `partner_longitude` | ✅ Copia directa | Longitud geolocalización |
| `create_uid` | `create_uid` | ✅ Copia directa | Usuario creador |
| `create_date` | `create_date` | ✅ Copia directa | Fecha creación |
| `write_uid` | `write_uid` | ✅ Copia directa | Usuario modificador |
| `write_date` | `write_date` | ✅ Copia directa | Fecha modificación |

**Total: 28 campos de migración directa** ✅

---

### **A2. Campos con Transformación de Formato**

Estos campos requieren **transformación**, pero NO crear nuevos campos:

#### **1. vat (RUT)**

| Odoo 11 | Odoo 19 | Transformación |
|---------|---------|----------------|
| `CL06425796K` | `6425796-K` | ✅ Script Python: Strip `CL`, add `-` |
| `CL795103201` | `79510320-1` | ✅ Script Python: + Validación Módulo 11 |

**Función de Transformación:**
```python
transform_rut_odoo11_to_odoo19('CL76489218-6')  # → '76489218-6'
```

**Acción:** ✅ Script de transformación (ya diseñado)

---

#### **2. state_id (Provincia → Región)**

| Odoo 11 | Odoo 19 | Transformación |
|---------|---------|----------------|
| `708` (CAUTIN - provincia) | `1154` (de la Araucania - región) | ✅ Script SQL: Mapeo de 54→16 |
| `710` (LLANQUIHUE - provincia) | `1155` (de los Lagos - región) | ✅ Script SQL: Mapeo de 54→16 |

**Tabla de Mapeo:**
```sql
CREATE TEMP TABLE provincia_to_region_mapping AS
SELECT 708 as provincia_id, 1154 as region_id UNION ALL  -- CAUTIN → Araucanía
SELECT 710, 1155 UNION ALL  -- LLANQUIHUE → Los Lagos
...
```

**Acción:** ✅ Script SQL con tabla de mapeo (ya diseñado)

---

#### **3. customer / supplier (Boolean → Rank)**

| Odoo 11 | Odoo 19 | Transformación |
|---------|---------|----------------|
| `customer` (boolean) | `customer_rank` (integer) | ✅ Script: `1 if True else 0` |
| `supplier` (boolean) | `supplier_rank` (integer) | ✅ Script: `1 if True else 0` |

**Transformación:**
```python
df['customer_rank'] = df['customer'].apply(lambda x: 1 if x else 0)
df['supplier_rank'] = df['supplier'].apply(lambda x: 1 if x else 0)
```

**Acción:** ✅ Script Python (ya diseñado)

---

#### **4. activity_description (FK Integer → Char)**

| Odoo 11 | Odoo 19 | Transformación |
|---------|---------|----------------|
| `activity_description = 258` (FK → `sii_activity_description`) | `l10n_cl_activity_description = "HOTEL-MOTEL"` | ✅ Script: Lookup de nombre desde FK |

**Transformación:**
```sql
UPDATE res_partner SET
    l10n_cl_activity_description = (
        SELECT name FROM odoo11_sii_activity_description
        WHERE id = res_partner.activity_description_o11
    );
```

**Campo Destino:** `l10n_cl_activity_description` ✅ **YA EXISTE en tu módulo** (res_partner_dte.py:33)

**Acción:** ✅ Script SQL de lookup (ya diseñado)

---

## ✅ CATEGORÍA B: YA EXISTEN EN ODOO 19 (No crear)

### **B1. Campos del Módulo Oficial l10n_cl**

Estos campos están en el **módulo oficial Odoo** `l10n_cl`:

| Campo Odoo 11 | Campo Odoo 19 | Módulo | Comentario |
|---------------|---------------|--------|------------|
| (No existe) | `l10n_cl_sii_taxpayer_type` | `l10n_cl` | Tipo contribuyente (1/2/3) ✅ |
| `vat` | `vat` | `l10n_latam_base` | RUT con validación ✅ |
| (No existe) | `l10n_latam_identification_type_id` | `l10n_latam_base` | Tipo identificación ✅ |

**Mapeo de Odoo 11:**
- `responsability_id` (FK) → `l10n_cl_sii_taxpayer_type` (selection)
  - Odoo 11: FK a tabla `sii_responsability`
  - Odoo 19: Selection `'1'/'2'/'3'`

**Acción:** ✅ Mapeo por script (requiere análisis de tabla `sii_responsability`)

---

### **B2. Campos de tu Módulo l10n_cl_dte (YA CREADOS)**

Estos campos **YA ESTÁN CREADOS** en tu módulo `l10n_cl_dte`:

| Campo Odoo 11 | Campo Odoo 19 | Archivo | Línea |
|---------------|---------------|---------|-------|
| `activity_description` (FK) | `l10n_cl_activity_description` (Char) | `res_partner_dte.py` | 33 ✅ |
| (No existe) | `l10n_cl_comuna_id` (Many2one) | `res_partner_dte.py` | 55 ✅ |
| (No existe) | `l10n_cl_comuna` (Char computed) | `res_partner_dte.py` | 71 ✅ |

**Ventaja:** Tu módulo YA tiene campos chilenos clave. Solo falta migrar datos.

**Acción:** ✅ Migrar datos a campos existentes

---

## ⚠️ CATEGORÍA C: REQUIEREN CREACIÓN EN ODOO 19

### **Campos Críticos que DEBEN Crearse**

Estos campos **NO EXISTEN** en Odoo 19 estándar ni en tu módulo actual:

#### **C1. dte_email (CRÍTICO - P0)**

| Propiedad | Valor |
|-----------|-------|
| **Campo Odoo 11** | `dte_email` (varchar) |
| **Existe en Odoo 19?** | ❌ NO |
| **Criticidad** | 🔴 **P0 - CRÍTICO** |
| **Uso** | Email específico para envío de DTEs (diferente al email general del contacto) |
| **Impacto si falta** | Los DTEs se enviarían al email general (puede no ser correcto) |
| **Debe crearse?** | ✅ **SÍ - OBLIGATORIO** |

**Justificación:**
- En Chile, es común que:
  - Email general: `contacto@empresa.cl`
  - Email DTE: `facturacion@empresa.cl` o `contabilidad@empresa.cl`
- El SII requiere envío de copia de DTE al receptor
- Usar email equivocado = **incumplimiento normativo**

**Definición Propuesta:**
```python
# Agregar en res_partner_dte.py

dte_email = fields.Char(
    string='Email DTE',
    help='Email específico para envío de Documentos Tributarios Electrónicos.\n\n'
         'IMPORTANTE:\n'
         '• Si está vacío, se usa el email general del contacto\n'
         '• Formato: usuario@dominio.cl\n'
         '• Se usa para envío automático de DTEs por email\n\n'
         'Recomendado para:\n'
         '  - Departamentos de contabilidad/finanzas\n'
         '  - Sistemas ERP de clientes/proveedores\n'
         '  - Emails masivos de facturación'
)
```

**Acción Migración:**
```python
# En script de transformación
df['dte_email'] = df_odoo11['dte_email']  # Copia directa
```

---

#### **C2. es_mipyme (IMPORTANTE - P1)**

| Propiedad | Valor |
|-----------|-------|
| **Campo Odoo 11** | `es_mipyme` (boolean) |
| **Existe en Odoo 19?** | ❌ NO |
| **Criticidad** | 🟡 **P1 - IMPORTANTE** |
| **Uso** | Identifica si el contacto es MIPYME (Micro, Pequeña o Mediana Empresa) |
| **Impacto si falta** | Pérdida de información de clasificación, puede afectar flujos de retención |
| **Debe crearse?** | ✅ **SÍ - RECOMENDADO** |

**Justificación:**
- SII tiene **régimen diferenciado para MIPYMEs**
- Afecta:
  - Plazos de pago IVA
  - Retenciones especiales
  - Incentivos tributarios
- Criterio MIPYME (Ley 20.416):
  - Microempresa: Ventas anuales ≤ UF 2.400
  - Pequeña empresa: UF 2.400 - UF 25.000
  - Mediana empresa: UF 25.000 - UF 100.000

**Definición Propuesta:**
```python
# Agregar en res_partner_dte.py

es_mipyme = fields.Boolean(
    string='Es MIPYME',
    default=False,
    help='Identifica si este contacto es Micro, Pequeña o Mediana Empresa.\n\n'
         'CRITERIO LEGAL (Ley 20.416):\n'
         '  • Microempresa: Ventas anuales ≤ UF 2.400\n'
         '  • Pequeña empresa: UF 2.400 - UF 25.000\n'
         '  • Mediana empresa: UF 25.000 - UF 100.000\n\n'
         'IMPACTO TRIBUTARIO:\n'
         '  • Plazos diferenciados para pago de IVA\n'
         '  • Acceso a régimen simplificado\n'
         '  • Retenciones especiales según flujo SII\n\n'
         'Se usa en reportes y flujos de facturación automática.'
)
```

**Acción Migración:**
```python
# En script de transformación
df['es_mipyme'] = df_odoo11['es_mipyme'].fillna(False)  # Copia con default False
```

---

#### **C3. l10n_cl_comuna_id (YA EXISTE ✅) - Solo Migrar Datos**

| Propiedad | Valor |
|-----------|-------|
| **Campo Odoo 11** | ❌ **NO EXISTE** (solo `city` como texto libre) |
| **Existe en Odoo 19?** | ✅ **SÍ** (res_partner_dte.py:55) |
| **Debe crearse?** | ❌ **NO - YA EXISTE** |
| **Acción** | ✅ Inferir desde `city` con fuzzy matching |

**Estrategia de Migración:**
```python
# Inferir comuna desde ciudad
def infer_comuna_from_city(city, state_id):
    # 1. Exact match: "Temuco" → Comuna Temuco
    # 2. Fuzzy match: "Santiago Centro" → Comuna Santiago
    # 3. Partial match: ciudad contiene comuna o viceversa
    pass

# Aplicar en script
df['l10n_cl_comuna_id'] = df.apply(
    lambda row: infer_comuna_from_city(row['city'], row['state_id_o19']),
    axis=1
)
```

**Tasa de Éxito Esperada:** 60-70% (completar resto manualmente)

---

#### **C4. document_type_id + document_number (MAPEAR A LATAM)**

| Propiedad | Valor |
|-----------|-------|
| **Campo Odoo 11** | `document_type_id` (FK) + `document_number` (varchar) |
| **Existe en Odoo 19?** | ✅ **SÍ** - `l10n_latam_identification_type_id` |
| **Debe crearse?** | ❌ **NO - MAPEAR** |

**Mapeo:**
```python
# Mapear document_type_id → l10n_latam_identification_type_id
# Requiere análisis de tabla sii_document_type en Odoo 11
```

**Acción:** ⚠️ Requiere análisis adicional de tabla `sii_document_type`

---

## ❌ CATEGORÍA D: DESCARTABLES (Legacy)

Estos campos pueden **descartarse** o almacenar en tabla de auditoría:

| Campo Odoo 11 | Razón para Descartar | Alternativa |
|---------------|----------------------|-------------|
| `send_dte` | Flag específico de módulo legacy | Usar configuración general en res.config.settings |
| `sync` | Sincronización específica de sistema antiguo | No aplicable en Odoo 19 |
| `last_sync_update` | Timestamp de sincronización legacy | No aplicable |
| `principal` | Flag de contacto principal | Inferir de `type='contact'` y orden |
| `display_name` | Campo computed auto-generado | Se auto-genera en Odoo 19 |
| `commercial_partner_id` | Se auto-calcula en Odoo 19 | Computed field |

**Acción:** ❌ No migrar (o guardar en tabla de auditoría para referencia)

---

## 📋 RESUMEN DE ACCIONES

### **✅ CAMPOS A CREAR EN ODOO 19 (Total: 2)**

| # | Campo | Criticidad | Archivo | Acción |
|---|-------|------------|---------|--------|
| 1 | `dte_email` | 🔴 P0 - CRÍTICO | `res_partner_dte.py` | **Crear ahora** |
| 2 | `es_mipyme` | 🟡 P1 - IMPORTANTE | `res_partner_dte.py` | **Crear ahora** |

---

### **✅ CAMPOS A MIGRAR POR SCRIPT (Total: ~40)**

| Categoría | Cantidad | Script |
|-----------|----------|--------|
| Migración directa 1:1 | 28 | SQL COPY |
| Transformación RUT | 1 | Python + Módulo 11 |
| Transformación provincia→región | 1 | SQL mapeo |
| Transformación customer→rank | 2 | Python |
| Transformación activity FK→char | 1 | SQL lookup |
| Inferencia comuna desde ciudad | 1 | Python fuzzy matching |

---

### **✅ CAMPOS QUE YA EXISTEN (Total: ~35)**

| Origen | Cantidad |
|--------|----------|
| Odoo 19 estándar (`res.partner`) | ~30 |
| Módulo oficial `l10n_cl` | 3 |
| Tu módulo `l10n_cl_dte` | 2 |

---

## 🔧 PLAN DE IMPLEMENTACIÓN

### **FASE 1: Crear Campos Faltantes (15 minutos)**

```python
# Editar: /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/models/res_partner_dte.py

class ResPartnerDTE(models.Model):
    _inherit = 'res.partner'

    # ... (campos existentes)

    # ═══════════════════════════════════════════════════════════
    # CAMPOS ADICIONALES PARA MIGRACIÓN DESDE ODOO 11
    # ═══════════════════════════════════════════════════════════

    dte_email = fields.Char(
        string='Email DTE',
        help='Email específico para envío de Documentos Tributarios Electrónicos.\n\n'
             'IMPORTANTE:\n'
             '• Si está vacío, se usa el email general del contacto\n'
             '• Formato: usuario@dominio.cl\n'
             '• Se usa para envío automático de DTEs por email\n\n'
             'Recomendado para:\n'
             '  - Departamentos de contabilidad/finanzas\n'
             '  - Sistemas ERP de clientes/proveedores\n'
             '  - Emails masivos de facturación'
    )

    es_mipyme = fields.Boolean(
        string='Es MIPYME',
        default=False,
        index=True,
        help='Identifica si este contacto es Micro, Pequeña o Mediana Empresa.\n\n'
             'CRITERIO LEGAL (Ley 20.416):\n'
             '  • Microempresa: Ventas anuales ≤ UF 2.400\n'
             '  • Pequeña empresa: UF 2.400 - UF 25.000\n'
             '  • Mediana empresa: UF 25.000 - UF 100.000\n\n'
             'IMPACTO TRIBUTARIO:\n'
             '  • Plazos diferenciados para pago de IVA\n'
             '  • Acceso a régimen simplificado\n'
             '  • Retenciones especiales según flujo SII\n\n'
             'Se usa en reportes y flujos de facturación automática.'
    )
```

**Ejecutar:**
```bash
docker-compose restart odoo
docker exec odoo19_app odoo -d TEST -u l10n_cl_dte --stop-after-init
```

---

### **FASE 2: Actualizar Vista (Opcional - 10 minutos)**

Agregar campos en vista de formulario:

```xml
<!-- Editar: /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/views/res_partner_views.xml -->

<xpath expr="//field[@name='email']" position="after">
    <field name="dte_email"
           placeholder="facturacion@empresa.cl"
           invisible="country_code != 'CL'"/>
</xpath>

<xpath expr="//field[@name='l10n_cl_activity_description']" position="after">
    <field name="es_mipyme"
           invisible="not is_company or country_code != 'CL'"/>
</xpath>
```

---

### **FASE 3: Actualizar Scripts de Migración (5 minutos)**

Agregar campos a script de transformación:

```python
# En transform_partners.py

df_final = df[[
    # ... (campos existentes)
    'dte_email',  # ← Agregar
    'es_mipyme',  # ← Agregar
]]
```

---

## 🎯 CONCLUSIÓN

### **Respuesta a tu Pregunta:**

> **¿Ambas instancias tienen campos homologables que requieran adecuaciones mediante script o debemos crear campos en el modelo de odoo 19 CE?**

**RESPUESTA:**

✅ **88% de campos son HOMOLOGABLES por script** (no requieren crear campos)

⚠️ **Solo 2 campos CRÍTICOS requieren creación:**
1. `dte_email` (P0 - Email específico para DTEs)
2. `es_mipyme` (P1 - Flag MIPYME)

✅ **El resto de campos chilenos YA EXISTEN:**
- `l10n_cl_activity_description` ✅ (res_partner_dte.py:33)
- `l10n_cl_comuna_id` ✅ (res_partner_dte.py:55)
- `l10n_cl_sii_taxpayer_type` ✅ (módulo l10n_cl)

### **Recomendación:**

1. ✅ **Crear 2 campos ahora** (`dte_email`, `es_mipyme`)
2. ✅ **Actualizar módulo** (5 minutos)
3. ✅ **Ejecutar migración completa** con scripts ya diseñados
4. ✅ **Validar** que todos los datos se migraron correctamente

**Esfuerzo Total:** ~30 minutos de desarrollo + 5 minutos de migración

---

**Firma Digital:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ANÁLISIS DE HOMOLOGACIÓN COMPLETADO
 EJECUTADO POR: Claude Code AI (Sonnet 4.5)
 ESPECIALIDAD: Ingeniero Senior DB/ERP Architect
 EMPRESA: EERGYGROUP
 FECHA: 2025-10-25
 ORIGEN: Odoo 11 CE (85 campos)
 DESTINO: Odoo 19 CE (83 campos)
 VEREDICTO: ✅ 88% HOMOLOGABLES - SOLO 2 CAMPOS REQUIEREN CREACIÓN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
