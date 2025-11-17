# 🔍 AUDITORÍA INICIAL - Cierre Brechas (P4-Deep)

**Versión:** 1.0.0  
**Nivel:** P4-Deep  
**Propósito:** Auditar exhaustivamente el módulo para identificar brechas de compliance, calidad y arquitectura

---

## 📋 CONTEXTO

Eres un auditor senior de código Odoo 19 CE con especialización en compliance de la plataforma y localización chilena.

**Tu tarea:** Realizar una auditoría arquitectónica profunda (nivel P4-Deep) del módulo especificado, identificando brechas en:

1. **Compliance Odoo 19 CE** (deprecaciones P0/P1/P2)
2. **Calidad de código** (PEP8, type hints, docstrings)
3. **Arquitectura** (monolitos, acoplamiento, complejidad cíclica)
4. **Testing** (coverage, tests faltantes, tests obsoletos)
5. **Seguridad** (OWASP Top 10, SQL injection, XSS)
6. **Performance** (N+1 queries, indexación, caching)
7. **Localización chilena** (SII compliance, Previred, DTE)

---

## 🎯 INSTRUCCIONES

### 1. ANÁLISIS ESTRUCTURAL

Examina la estructura del módulo:

```bash
# Analizar estructura
find addons/localization/{MODULO}/ -type f -name "*.py" | wc -l
find addons/localization/{MODULO}/ -type f -name "*.xml" | wc -l
find addons/localization/{MODULO}/tests/ -type f | wc -l

# Analizar complejidad
radon cc addons/localization/{MODULO}/ -a -nc
radon mi addons/localization/{MODULO}/ -nc

# Analizar dependencias
grep -r "^import\|^from" addons/localization/{MODULO}/ | sort | uniq
```

**Output esperado:**
- Conteo archivos Python/XML/Tests
- Índice complejidad cíclica promedio
- Índice mantenibilidad
- Mapa dependencias externas

---

### 2. COMPLIANCE ODOO 19 CE

Audita deprecaciones críticas según `/scripts/odoo19_migration/config/deprecations.yaml`:

#### P0 (Breaking Changes - Deadline: 2025-03-01)

```bash
# 1. QWeb: t-esc → t-out
grep -r "t-esc" addons/localization/{MODULO}/views/ | wc -l

# 2. HTTP Controllers: type='json' → type='jsonrpc'
grep -r "type=['\"]json['\"]" addons/localization/{MODULO}/controllers/ | wc -l

# 3. XML Views: attrs= (deprecated)
grep -r "attrs=" addons/localization/{MODULO}/views/ | wc -l

# 4. ORM: _sql_constraints → models.Constraint
grep -r "_sql_constraints" addons/localization/{MODULO}/models/ | wc -l
```

#### P1 (High Priority - Deadline: 2025-06-01)

```bash
# 5. Database: self._cr → self.env.cr
grep -r "self\._cr" addons/localization/{MODULO}/models/ | wc -l

# 6. View Methods: fields_view_get() → get_view()
grep -r "fields_view_get" addons/localization/{MODULO}/models/ | wc -l

# 7. Decorators: @api.depends duplicados en herencia
grep -r "@api\.depends" addons/localization/{MODULO}/models/ | wc -l
```

**Output esperado:**
- Tabla con conteo por tipo deprecación
- Lista archivos afectados (top 10 por prioridad)
- Severity score (0-100, donde 100 = compliance perfecto)

---

### 3. CALIDAD CÓDIGO

#### PEP8 & Formateo

```bash
# Linting
flake8 addons/localization/{MODULO}/ --count --statistics

# Formateo
black addons/localization/{MODULO}/ --check --diff
```

#### Docstrings & Type Hints

```bash
# Docstrings faltantes
pydocstyle addons/localization/{MODULO}/ --count

# Type hints coverage
mypy addons/localization/{MODULO}/ --strict --show-error-codes
```

**Output esperado:**
- Conteo errores PEP8 por categoría
- % cobertura docstrings
- % cobertura type hints
- Score calidad (0-100)

---

### 4. TESTING

```bash
# Tests coverage
pytest addons/localization/{MODULO}/tests/ --cov=addons/localization/{MODULO}/ --cov-report=json

# Tests passing
pytest addons/localization/{MODULO}/tests/ -v --tb=short

# Tests duration
pytest addons/localization/{MODULO}/tests/ --durations=10
```

**Output esperado:**
- Coverage total (%)
- Coverage por archivo (top 5 peores)
- Tests passing/failing (absolutos y %)
- Tests lentos (>5s)

---

### 5. SEGURIDAD

Audita vulnerabilidades OWASP Top 10:

```bash
# SQL Injection (uso raw SQL sin sanitizar)
grep -r "self\.env\.cr\.execute\|self\._cr\.execute" addons/localization/{MODULO}/ | grep -v "sanitize\|quote"

# XSS (uso t-raw sin sanitizar)
grep -r "t-raw" addons/localization/{MODULO}/views/

# Hardcoded credentials
grep -ri "password.*=.*['\"][^'\"]*['\"]" addons/localization/{MODULO}/

# XML External Entities (DTE signatures)
grep -r "ET\.fromstring\|ET\.parse" addons/localization/{MODULO}/ | grep -v "defusedxml"
```

**Output esperado:**
- Vulnerabilidades detectadas (tipo + archivo + línea)
- Severity (Critical/High/Medium/Low)
- Score seguridad (0-100)

---

### 6. PERFORMANCE

```bash
# N+1 queries (buscar loops con ORM accesses)
grep -r "for.*in.*\." addons/localization/{MODULO}/models/ -A 3 | grep -E "\.search\(|\.browse\("

# Indexación (analizar _sql_constraints y migrations)
grep -r "CREATE INDEX\|_sql_constraints" addons/localization/{MODULO}/

# Caching (verificar uso @tools.ormcache)
grep -r "@tools\.ormcache\|@api\.depends.*store=True" addons/localization/{MODULO}/
```

**Output esperado:**
- N+1 queries potenciales (líneas)
- Índices definidos vs recomendados
- Uso caching (% métodos que deberían usar cache)
- Score performance (0-100)

---

### 7. LOCALIZACIÓN CHILENA (Si aplica)

#### DTE (l10n_cl_dte)

```bash
# Validación SII schemas
xmllint --noout --schema /path/to/DTE_v10.xsd addons/localization/l10n_cl_dte/data/dte_examples/*.xml

# Digital signatures (xmlsec)
grep -r "xmlsec\|sign_dte" addons/localization/l10n_cl_dte/models/

# CAF management
grep -r "l10n_cl_caf\|folio" addons/localization/l10n_cl_dte/models/
```

#### Payroll (l10n_cl_hr_payroll)

```bash
# Economic indicators sync
grep -r "UF\|UTM\|IPC\|minimum_wage" addons/localization/l10n_cl_hr_payroll/models/

# AFP/ISAPRE calculations
grep -r "afp_amount\|isapre_amount" addons/localization/l10n_cl_hr_payroll/models/

# Previred file format
grep -r "previred_file\|txt_format" addons/localization/l10n_cl_hr_payroll/models/
```

**Output esperado:**
- Compliance SII (% schemas válidos)
- Firmas digitales (correctamente implementadas?)
- Cálculos nómina (precisión validada?)
- Score localización (0-100)

---

## 📊 OUTPUT REQUERIDO

**Formato:** JSON estructurado (machine-readable)

```json
{
  "auditoria": {
    "timestamp": "2025-11-12T10:30:00Z",
    "modulo": "{MODULO}",
    "version": "1.0.0",
    "auditor": "Claude Sonnet 4.5 (Copilot CLI)"
  },
  "estructura": {
    "archivos_python": 45,
    "archivos_xml": 23,
    "archivos_tests": 12,
    "loc_total": 5420,
    "complejidad_ciclica_promedio": 3.2,
    "indice_mantenibilidad": 82.5
  },
  "compliance_odoo19": {
    "P0": {
      "t_esc_deprecated": 12,
      "type_json_deprecated": 3,
      "attrs_deprecated": 8,
      "sql_constraints_deprecated": 2,
      "compliance_percentage": 85.4
    },
    "P1": {
      "self_cr_deprecated": 26,
      "fields_view_get_deprecated": 1,
      "compliance_percentage": 92.1
    },
    "score_total": 88.3
  },
  "calidad_codigo": {
    "errores_pep8": 23,
    "cobertura_docstrings": 78.5,
    "cobertura_type_hints": 45.2,
    "score": 74.2
  },
  "testing": {
    "coverage_total": 87.3,
    "tests_passing": 42,
    "tests_failing": 3,
    "tests_passing_percentage": 93.3,
    "score": 90.3
  },
  "seguridad": {
    "vulnerabilidades_criticas": 0,
    "vulnerabilidades_altas": 2,
    "vulnerabilidades_medias": 5,
    "score": 88.0
  },
  "performance": {
    "n_plus_one_queries": 4,
    "indices_faltantes": 3,
    "uso_caching_percentage": 65.0,
    "score": 79.5
  },
  "localizacion_chilena": {
    "compliance_sii": 95.0,
    "firmas_digitales_ok": true,
    "calculos_nomina_precisos": true,
    "score": 95.0
  },
  "brechas_identificadas": {
    "total": 67,
    "P0": 25,
    "P1": 32,
    "P2": 10
  },
  "score_general": 86.2,
  "recomendacion": "El módulo presenta brechas moderadas en compliance P0 (12 deprecaciones t-esc) y calidad de código (45% type hints). Se recomienda priorizar cierre P0 antes de 2025-03-01."
}
```

**Adicionalmente, generar:**

1. **Reporte Markdown** (`auditoria_{MODULO}_{TIMESTAMP}.md`) con:
   - Resumen ejecutivo (2-3 párrafos)
   - Tablas de métricas
   - Top 10 brechas críticas
   - Trade-offs y recomendaciones

2. **Lista brechas priorizadas** (`brechas_{MODULO}_{TIMESTAMP}.json`) con:
   ```json
   {
     "brechas": {
       "P0": [
         {
           "id": "P0-001",
           "tipo": "deprecacion_t_esc",
           "archivo": "views/account_move_views.xml",
           "linea": 125,
           "descripcion": "Uso de t-esc en QWeb template (deprecated)",
           "fix_estimado": "Reemplazar por t-out",
           "complejidad": "baja",
           "impacto": "breaking_change"
         }
       ],
       "P1": [...],
       "P2": [...]
     }
   }
   ```

---

## ✅ CRITERIOS ÉXITO

Auditoría se considera completa cuando:

1. ✅ Todos los comandos bash ejecutados exitosamente
2. ✅ JSON output validado contra schema
3. ✅ Reporte markdown generado (>1000 palabras)
4. ✅ Lista brechas priorizadas generada
5. ✅ Score general calculado (promedio ponderado)
6. ✅ Recomendaciones accionables (mínimo 5)

---

## 🚫 RESTRICCIONES

- **NO** modificar código en esta fase (solo auditar)
- **NO** ejecutar tests que puedan modificar BD
- **NO** asumir valores - si un comando falla, reportar como "N/A"
- **SÍ** ejecutar comandos de forma segura (read-only)
- **SÍ** usar herramientas nativas (grep, find, radon, pytest)

---

## 📚 REFERENCIAS

- **Deprecaciones Odoo 19:** `/scripts/odoo19_migration/config/deprecations.yaml`
- **Estrategia prompts:** `/docs/prompts/00_metodologia/PROMPT_ENGINEERING_ESTRATEGIA.md`
- **Compliance baseline:** `/CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md`
- **SII schemas:** `/addons/localization/l10n_cl_dte/data/sii_schemas/`

---

**🔍 Procede con máxima precisión y reporta resultados en formato JSON + Markdown.**

