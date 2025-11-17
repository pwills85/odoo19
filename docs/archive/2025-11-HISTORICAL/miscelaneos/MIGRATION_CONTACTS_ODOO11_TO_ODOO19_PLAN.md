# 🔄 PLAN DE MIGRACIÓN: Contactos Odoo 11 CE → Odoo 19 CE

**Fecha:** 2025-10-24 23:05 UTC-3
**Origen:** EERGYGROUP (Odoo 11 CE - PostgreSQL 13.15)
**Destino:** TEST (Odoo 19 CE - PostgreSQL 15)
**Total Contactos:** 3,929 (1,814 empresas, 2,115 personas)

---

## 📊 ANÁLISIS DE DATOS

### **Stack Odoo 11 CE (Producción)**

**Conexión PostgreSQL:**
- Host: prod_odoo-11_eergygroup_db (Docker container)
- Usuario: `odoo`
- Password: `l&UKgl^9046hPo7K!AowqV&g`
- Base de datos: `EERGYGROUP`
- Puerto: 5432 (interno Docker)

**Estadísticas:**
- Total contactos: 3,929
- Empresas: 1,814
- Personas: 2,115
- Activos: 3,922
- Contactos chilenos (empresas): ~1,500+

### **Estructura res.partner Odoo 11**

**Campos disponibles:**
```sql
id, name, vat, street, street2, city, zip,
country_id, state_id, email, phone, mobile,
is_company, parent_id, company_id, active
```

**Campos NO disponibles (Odoo 11):**
- ❌ `l10n_cl_activity_description` (Giro)
- ❌ `l10n_cl_comuna_id` (Comuna SII)
- ❌ `l10n_cl_sii_taxpayer_type` (Tipo contribuyente)

**Formato RUT:**
- Odoo 11: `CL764892186` (código país + número)
- Odoo 19: `76489218-6` (formato chileno con dígito verificador)

**Provincias vs Regiones:**
- Odoo 11: 57 provincias (CAUTIN, LLANQUIHUE, BIOBIO, SANTIAGO, etc.)
- Odoo 19: 16 regiones administrativas (Araucanía, Los Lagos, BíoBio, Metropolitana, etc.)

---

## 🗺️ MAPEO PROVINCIA → REGIÓN

### **Provincias Odoo 11 (code) → Regiones Odoo 19 (code)**

| Odoo 11 ID | Odoo 11 Province | Code     | → | Odoo 19 Region | Code | Odoo 19 ID |
|------------|------------------|----------|---|----------------|------|------------|
| 708        | CAUTIN           | CL09100  | → | de la Araucania | 09   | 1154       |
| 709        | MALLECO          | CL09200  | → | de la Araucania | 09   | 1154       |
| 710        | LLANQUIHUE       | CL10100  | → | de los Lagos   | 10   | 1155       |
| 711        | CHILOE           | CL10200  | → | de los Lagos   | 10   | 1155       |
| 712        | OSORNO           | CL10300  | → | de los Lagos   | 10   | 1155       |
| 713        | PALENA           | CL10400  | → | de los Lagos   | 10   | 1155       |
| 706        | BIOBIO           | CL08300  | → | del BíoBio     | 08   | 1153       |
| 704        | CONCEPCIÓN       | CL08100  | → | del BíoBio     | 08   | 1153       |
| 705        | ARAUCO           | CL08200  | → | del BíoBio     | 08   | 1153       |
| 707        | ÑUBLE            | CL08400  | → | del Ñuble      | 16   | 1161       |
| 722        | SANTIAGO         | CL13100  | → | Metropolitana  | 13   | 1158       |
| 723        | CORDILLERA       | CL13200  | → | Metropolitana  | 13   | 1158       |
| 724        | CHACABUCO        | CL13300  | → | Metropolitana  | 13   | 1158       |
| 725        | MAIPO            | CL13400  | → | Metropolitana  | 13   | 1158       |
| 726        | MELIPILLA        | CL13500  | → | Metropolitana  | 13   | 1158       |
| 727        | TALAGANTE        | CL13600  | → | Metropolitana  | 13   | 1158       |
| 728        | VALDIVIA         | CL14100  | → | Los Ríos       | 14   | 1159       |
| 729        | RANCO            | CL14200  | → | Los Ríos       | 14   | 1159       |

**Algoritmo de mapeo:**
```python
# Extraer región del código provincia
province_code = "CL09100"  # CAUTIN
region_code = province_code[2:4]  # "09"

# Buscar región en Odoo 19
SELECT id FROM res_country_state
WHERE code = region_code
  AND country_id = (SELECT id FROM res_country WHERE code = 'CL')
```

---

## 🔧 ESTRATEGIA DE MIGRACIÓN

### **Fase 1: Extracción de Datos (Odoo 11)**

**Consulta SQL:**
```sql
-- Extraer contactos chilenos activos con todos los campos
SELECT
    id,
    name,
    vat,
    street,
    street2,
    city,
    zip,
    state_id,
    CASE
        WHEN state_id IS NOT NULL
        THEN (SELECT code FROM res_country_state WHERE id = rp.state_id)
        ELSE NULL
    END as province_code,
    email,
    phone,
    mobile,
    is_company,
    parent_id,
    active
FROM res_partner rp
WHERE active = true
  AND country_id = 46  -- Chile
ORDER BY is_company DESC, id;
```

**Archivo de salida:**
- `/tmp/odoo11_contacts_export.csv`
- Formato: CSV con encoding UTF-8
- ~1,500 contactos chilenos empresas

### **Fase 2: Transformación de Datos**

**Script Python: `/Users/pedro/Documents/odoo19/scripts/migrate_contacts_odoo11_to_19.py`**

**Transformaciones necesarias:**

1. **RUT (vat):**
   ```python
   # Odoo 11: "CL764892186"
   # Odoo 19: "76489218-6"

   def transform_rut(vat_odoo11):
       if not vat_odoo11 or not vat_odoo11.startswith('CL'):
           return None
       rut_sin_cl = vat_odoo11[2:]  # "764892186"
       rut_numero = rut_sin_cl[:-1]  # "76489218"
       rut_dv = rut_sin_cl[-1]      # "6"
       return f"{rut_numero}-{rut_dv}"
   ```

2. **Provincia → Región (state_id):**
   ```python
   # Mapeo: código provincia → código región
   def map_province_to_region(province_code, odoo19_conn):
       if not province_code:
           return None

       # Extraer código región (primeros 2 dígitos después de CL)
       region_code = province_code[2:4]  # "CL09100" → "09"

       # Buscar región en Odoo 19
       cursor = odoo19_conn.cursor()
       cursor.execute("""
           SELECT id FROM res_country_state
           WHERE code = %s
             AND country_id = (SELECT id FROM res_country WHERE code = 'CL')
       """, (region_code,))

       result = cursor.fetchone()
       return result[0] if result else None
   ```

3. **country_id:**
   ```python
   # Odoo 11: 46
   # Odoo 19: ? (buscar dinámicamente)

   def get_chile_country_id(odoo19_conn):
       cursor = odoo19_conn.cursor()
       cursor.execute("SELECT id FROM res_country WHERE code = 'CL'")
       return cursor.fetchone()[0]
   ```

4. **Campos nuevos Odoo 19 (valores por defecto):**
   ```python
   # Campos que no existen en Odoo 11
   new_fields = {
       'l10n_cl_activity_description': None,  # NULL (completar manualmente después)
       'l10n_cl_comuna_id': None,             # NULL (requiere selección manual)
       'l10n_cl_sii_taxpayer_type': '1',      # '1' = Contribuyente (default)
   }
   ```

### **Fase 3: Validación Pre-Import**

**Checklist:**
- [ ] Verificar RUTs únicos (no duplicados)
- [ ] Validar formato RUT chileno (dígito verificador correcto)
- [ ] Verificar mapeo provincia → región (100% cobertura)
- [ ] Confirmar emails válidos
- [ ] Revisar teléfonos con formato internacional

**Script validación:**
```python
def validate_rut_dv(rut):
    """Valida dígito verificador RUT chileno"""
    rut_numero, dv = rut.split('-')
    # Algoritmo módulo 11 SII
    suma = 0
    multiplicador = 2
    for digito in reversed(rut_numero):
        suma += int(digito) * multiplicador
        multiplicador = multiplicador + 1 if multiplicador < 7 else 2

    dv_calculado = 11 - (suma % 11)
    if dv_calculado == 11:
        dv_calculado = '0'
    elif dv_calculado == 10:
        dv_calculado = 'K'
    else:
        dv_calculado = str(dv_calculado)

    return dv.upper() == dv_calculado
```

### **Fase 4: Importación a Odoo 19 TEST**

**Método 1: SQL Direct (Rápido - Recomendado para testing)**

```python
import psycopg2

# Conexión Odoo 19 TEST
conn = psycopg2.connect(
    host='localhost',
    port=5432,
    user='odoo',
    password='<ODOO19_DB_PASSWORD>',
    database='TEST'
)

# Inserción masiva
cursor = conn.cursor()
for contact in transformed_contacts:
    cursor.execute("""
        INSERT INTO res_partner (
            name, vat, street, street2, city, zip,
            state_id, country_id, email, phone, mobile,
            is_company, active, create_date, write_date,
            create_uid, write_uid
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            NOW(), NOW(), 1, 1
        )
        ON CONFLICT (vat) DO UPDATE SET
            name = EXCLUDED.name,
            street = EXCLUDED.street,
            email = EXCLUDED.email;
    """, contact_tuple)

conn.commit()
```

**Método 2: CSV Import via Odoo UI (Manual - Producción)**

1. Generar CSV con campos Odoo 19:
   ```csv
   name,vat,street,street2,city,zip,state_id/.id,country_id/.id,email,phone,is_company
   ```

2. Importar vía: Contactos → ⚙️ → Importar

### **Fase 5: Post-Import (Completar Manualmente)**

**Campos a completar:**

1. **Comuna SII (`l10n_cl_comuna_id`)**
   - Usar widget de búsqueda filtrado por región
   - Proceso: Región → Comuna (auto-filtrado)

2. **Giro (`l10n_cl_activity_description`)**
   - Copiar/pegar desde documentos existentes
   - Máximo 80 caracteres
   - Ejemplos: "SERVICIOS DE CONSTRUCCION", "CONSULTORIA INFORMATICA"

3. **Actividades Económicas (`l10n_cl_activity_ids`)**
   - Seleccionar de catálogo SII (1,300+ códigos)
   - Widget many2many_tags

---

## 📋 PLAN DE EJECUCIÓN

### **Sprint 1: Preparación (30 min)**

1. ✅ Analizar estructura Odoo 11 - COMPLETADO
2. ✅ Crear mapeo provincia → región - COMPLETADO
3. ⏭️ Escribir script Python de transformación
4. ⏭️ Escribir validador RUT chileno

### **Sprint 2: Extracción (15 min)**

1. ⏭️ Exportar contactos chilenos desde Odoo 11
2. ⏭️ Validar datos exportados (RUTs, emails, teléfonos)
3. ⏭️ Backup Odoo 19 TEST antes de importar

### **Sprint 3: Transformación (30 min)**

1. ⏭️ Ejecutar script de transformación
2. ⏭️ Generar CSV para Odoo 19
3. ⏭️ Validar RUTs con dígito verificador
4. ⏭️ Verificar mapeo provincia → región (100%)

### **Sprint 4: Importación (30 min)**

1. ⏭️ Importar vía SQL Direct a TEST
2. ⏭️ Verificar conteo: contactos insertados vs. esperados
3. ⏭️ Revisar duplicados (constraint vat unique)
4. ⏭️ Testing manual en UI Odoo 19

### **Sprint 5: Validación (30 min)**

1. ⏭️ Verificar 10 contactos aleatorios en UI
2. ⏭️ Confirmar mapeo regiones correcto
3. ⏭️ Probar creación de factura con contacto migrado
4. ⏭️ Documentar issues encontrados

---

## 🎯 MÉTRICAS DE ÉXITO

| Métrica | Target | Actual |
|---------|--------|--------|
| **Contactos migrados** | 1,500+ | TBD |
| **RUTs válidos** | 100% | TBD |
| **Regiones mapeadas** | 100% | TBD |
| **Duplicados** | 0 | TBD |
| **Errores importación** | <1% | TBD |

---

## ⚠️ RIESGOS Y MITIGACIONES

### **Riesgo 1: RUTs duplicados**
- **Probabilidad:** Media
- **Impacto:** Alto (constraint violation)
- **Mitigación:** Validación pre-import, usar ON CONFLICT DO UPDATE

### **Riesgo 2: Provincias sin mapeo región**
- **Probabilidad:** Baja
- **Impacto:** Medio (contactos sin región)
- **Mitigación:** Script de validación que lista provincias sin mapeo

### **Riesgo 3: Pérdida de datos Odoo 11**
- **Probabilidad:** Muy baja
- **Impacto:** Crítico
- **Mitigación:** Solo lectura (SELECT), NO modificar Odoo 11

### **Riesgo 4: Corrupción DB Odoo 19**
- **Probabilidad:** Baja
- **Impacto:** Alto
- **Mitigación:** Backup TEST antes de importar, usar transacciones

---

## 📝 NOTAS TÉCNICAS

### **Campos especiales Odoo**

```python
# create_uid, write_uid: usar admin (id=1)
# create_date, write_date: NOW()
# company_id: NULL (multi-company no usado en TEST)
# parent_id: mantener relaciones (importar en 2 pasadas)
```

### **Sequence handling**

```sql
-- Después de import, resetear sequence
SELECT setval(
    'res_partner_id_seq',
    (SELECT MAX(id) FROM res_partner) + 1
);
```

---

## 🚀 PRÓXIMO PASO

**Recomendado:** Escribir script Python de extracción y transformación

```bash
# Crear script
cd /Users/pedro/Documents/odoo19
touch scripts/migrate_contacts_odoo11_to_19.py
chmod +x scripts/migrate_contacts_odoo11_to_19.py
```

**¿Procedo con la creación del script de migración?**
