# 🤖 GitHub Copilot CLI - Modo Autónomo

**Versión:** 1.0.0  
**Fecha:** 2025-11-12  
**Autor:** Pedro Troncoso (@pwills85)  
**Propósito:** Documentar uso autónomo de Copilot CLI para tareas complejas hasta su finalización

---

## 🎯 ¿Qué es el Modo Autónomo de Copilot CLI?

GitHub Copilot CLI puede ejecutar **tareas complejas de forma autónoma**, ejecutando múltiples comandos, leyendo/escribiendo archivos y generando reportes completos **hasta dar correcto término a la tarea**, sin requerir intervención humana en cada paso.

**Diferencia clave:**
- **❌ Modo interactivo:** Solicita aprobación en cada comando → Lento para tareas largas
- **✅ Modo autónomo:** Ejecuta todos los comandos necesarios hasta completar → Rápido para auditorías/análisis

---

## 📦 Instalación y Configuración

### Requisitos Previos

- Suscripción: GitHub Copilot Pro, Pro+, Business o Enterprise
- Node.js ≥ v22
- npm ≥ v10
- Autenticación GitHub válida

### Instalación

```bash
# Instalar Copilot CLI globalmente
npm install -g @github/copilot

# Verificar instalación
copilot --version
# Output esperado: 0.0.354 o superior

# Autenticar (si es primera vez)
copilot
> /login
[Sigue instrucciones OAuth en navegador]
```

### Verificar Autenticación

```bash
# Verificar token GitHub
env | grep GITHUB_TOKEN

# Esperado: GITHUB_TOKEN=ghp_XXXXXXXXX o similar

# Probar comando simple
copilot -p "¿Cuál es la versión de Python en este proyecto?"
```

---

## 🚀 Modos de Operación

### 1. Modo Interactivo (Aprobación Manual)

**Uso:** Desarrollo interactivo, exploración, tareas sensibles

```bash
# Iniciar sesión interactiva
copilot

# Copilot solicita aprobación en cada comando
Copilot: ¿En qué puedo ayudarte?

> Audita módulo l10n_cl_dte contra checklist Odoo 19

Copilot: Voy a ejecutar:
  grep -rn "t-esc" addons/localization/l10n_cl_dte/
¿Aprobar? (y/n): y

[Ejecuta comando, muestra resultados]

Copilot: Siguiente comando:
  grep -rn "type='json'" addons/localization/l10n_cl_dte/
¿Aprobar? (y/n): y

[... continúa hasta completar tarea ...]
```

**Ventajas:**
- ✅ Control total sobre cada acción
- ✅ Seguro para operaciones destructivas
- ✅ Aprendizaje de comandos ejecutados

**Desventajas:**
- ❌ Lento para tareas largas (20-50 aprobaciones)
- ❌ Requiere atención constante
- ❌ NO puede ejecutarse en CI/CD

---

### 2. Modo Autónomo (Ejecución Completa)

**Uso:** Auditorías, análisis, validaciones, generación reportes

```bash
# Ejecutar tarea completa sin aprobaciones
copilot -p "TU_TAREA_COMPLETA_AQUÍ" --allow-all-tools --allow-all-paths
```

**⚠️ CRÍTICO: Permisos Autónomos**

| Flag | Comportamiento | Riesgo | Uso Recomendado |
|------|---------------|--------|-----------------|
| **`--allow-all-tools`** | Ejecuta comandos shell sin aprobación | 🔴 Alto | Auditorías read-only, CI/CD controlado |
| **`--allow-all-paths`** | Lee/escribe cualquier archivo proyecto | 🟡 Medio | Generación reportes, análisis completos |
| **Ambos combinados** | Autonomía total (shell + filesystem) | 🔴 Muy Alto | SOLO entornos confiables |

**Ventajas:**
- ✅ Rápido (completa en minutos vs horas)
- ✅ Scripteable (CI/CD, automatización)
- ✅ Sin intervención humana necesaria
- ✅ Genera reportes completos estructurados

**Desventajas:**
- ❌ Riesgo seguridad si mal configurado
- ❌ Puede ejecutar comandos destructivos
- ❌ Requiere prompt bien definido

---

## 🎯 Casos de Uso: Modo Autónomo

### Caso 1: Auditoría Compliance Odoo 19 CE

**Tarea:** Validar módulo DTE contra 8 patrones deprecación P0/P1/P2

```bash
copilot -p "Audita compliance Odoo 19 CE en módulo addons/localization/l10n_cl_dte/ siguiendo checklist docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md.

Ejecuta validaciones para los 8 patrones:
- P0-01: t-esc → t-out (QWeb templates)
- P0-02: type='json' → type='jsonrpc' (HTTP routes)
- P0-03: attrs={} → Python expressions (XML views)
- P0-04: _sql_constraints → models.Constraint (ORM)
- P0-05: <dashboard> → <kanban class=\"o_kanban_dashboard\">
- P1-06: self._cr → self.env.cr (Database)
- P1-07: fields_view_get() → get_view() (Views)
- P2-08: _() → _lt() (lazy translations)

Por cada patrón:
1. Ejecuta comando grep correspondiente
2. Cuenta ocurrencias
3. Lista archivos:líneas afectados

Genera reporte markdown estructurado con:
- Tabla resumen (8 patrones con counts)
- Compliance rate (% patrones OK)
- Deadline countdown (P0: 2025-03-01)
- Archivos críticos pendientes (si aplica)
- Verificaciones reproducibles (comandos ejecutados)

Guarda reporte en: docs/prompts/06_outputs/2025-11/auditorias/$(date +%Y%m%d)_AUDIT_DTE_COMPLIANCE_COPILOT.md" --allow-all-tools --allow-all-paths
```

**Output esperado:**
- ✅ Ejecuta 16+ comandos grep automáticamente
- ✅ Analiza 38 archivos Python + 63 archivos XML
- ✅ Genera reporte completo en 1-2 minutos
- ✅ Guarda en ubicación especificada
- ✅ Métricas cuantitativas: compliance rate, counts, deadlines

---

### Caso 2: Auditoría P4-Deep Módulo Completo

**Tarea:** Análisis arquitectónico profundo con 10 dimensiones (A-J)

```bash
copilot -p "Ejecuta auditoría P4-Deep del módulo addons/localization/l10n_cl_hr_payroll/ siguiendo estrategia en docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md.

**Template base:** docs/prompts/04_templates/TEMPLATE_AUDITORIA.md

**Dimensiones a analizar (A-J):**

A) Arquitectura y modularidad
   - Identificar modelos principales (herencia de hr.payslip)
   - Detectar monolitos (archivos >800 LOC)
   - Evaluar separación responsabilidades

B) Patrones diseño Odoo
   - Validar @api.depends correctos
   - Verificar computed fields con store justificado
   - Analizar @api.constrains para validaciones legales

C) Integraciones externas
   - Previred API (envío nóminas)
   - APIs indicadores económicos (UF, UTM, IPC)
   - Timeout, retry, circuit breaker configurados

D) Seguridad y protección datos
   - API keys hardcoded (grep \"api_key.*=.*\\\"\")
   - SQL injection (grep \"self.env.cr.execute.*%\")
   - Datos sensibles en logs (salarios, RUT)

E) Observabilidad
   - Structured logging implementado
   - Métricas performance (duraciones cálculos)
   - Health checks Previred integration

F) Testing
   - Coverage actual (pytest --cov)
   - Gaps críticos (tests faltantes cálculos AFP, ISAPRE)
   - Tests escenarios borde (tope imponible, gratificaciones)

G) Performance
   - N+1 queries (analizar loops sobre recordsets)
   - Índices DB faltantes
   - Batch processing nóminas masivas

H) Dependencias externas
   - CVEs conocidos (requests, httpx, etc)
   - Versiones pinned en requirements.txt
   - Deprecaciones librerías terceros

I) Configuración y deployment
   - Secrets en variables entorno (NO hardcoded)
   - Docker health checks
   - __manifest__.py completo (dependencias declaradas)

J) Recomendaciones priorizadas
   - P0 (críticos): Seguridad, compliance, data loss
   - P1 (altos): Performance, availability
   - P2 (medios): Code quality, maintainability

**Verificaciones reproducibles (≥6):**
- 1 P0 (seguridad crítica)
- 2 P1 (performance/availability)
- 3 P2 (calidad código)

**Output:** docs/prompts/06_outputs/2025-11/auditorias/$(date +%Y%m%d)_AUDIT_PAYROLL_P4_DEEP_COPILOT.md

Formato markdown profesional con:
- Resumen ejecutivo (3-5 hallazgos críticos)
- 10 secciones dimensionales (A-J)
- Matriz hallazgos (ID, archivo:línea, descripción, criticidad P0/P1/P2)
- Verificaciones ejecutables (comandos con outputs)
- Métricas cuantitativas (LOC, coverage, complexity)" --allow-all-tools --allow-all-paths
```

**Output esperado:**
- ✅ Análisis profundo 40-60 minutos (vs 3-4 horas manual)
- ✅ 30-50 referencias código específicas (archivo:línea)
- ✅ ≥6 verificaciones reproducibles con comandos
- ✅ Reporte completo 1,500-2,000 palabras
- ✅ Especificidad ≥0.85 (métricas validadas)

---

### Caso 3: Validación Pre-Commit Automatizada

**Tarea:** Hook Git que bloquea commits con deprecaciones

```bash
#!/bin/bash
# .git/hooks/pre-commit - Hook Git automatizado con Copilot CLI

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|xml)$')

if [ -z "$STAGED_FILES" ]; then
  echo "✅ No hay archivos Python/XML staged"
  exit 0
fi

echo "🔍 Validando compliance Odoo 19 CE con Copilot CLI..."

# Ejecutar validación autónoma
copilot -p "Valida deprecaciones P0+P1 Odoo 19 CE en archivos staged para commit:

$STAGED_FILES

Checklist: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md

Buscar patrones P0 (breaking changes):
- t-esc en XML (debe ser t-out)
- type='json' en routes (debe ser type='jsonrpc')
- attrs={} en views (debe ser Python expressions)
- _sql_constraints en models (debe ser models.Constraint)
- <dashboard> tags (debe ser <kanban class=\"o_kanban_dashboard\">)

Buscar patrones P1 (high priority):
- self._cr (debe ser self.env.cr)
- fields_view_get() (debe ser get_view())

Si encuentras CUALQUIER deprecación:
- Lista archivos:líneas afectados
- Exit code 1 (bloquear commit)
- Mensaje: \"❌ Commit bloqueado: X deprecaciones P0/P1 detectadas\"

Si NO encuentras deprecaciones:
- Exit code 0 (permitir commit)
- Mensaje: \"✅ Compliance Odoo 19 OK\"" --allow-all-tools --allow-all-paths

if [ $? -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOQUEADO"
  echo "Corrige deprecaciones antes de commitear."
  echo "Ver checklist: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md"
  exit 1
fi

echo "✅ Compliance OK - Commit permitido"
exit 0
```

**Instalación hook:**
```bash
# Copiar script a hooks Git
cp scripts/pre-commit-copilot.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Probar hook
git add addons/localization/l10n_cl_dte/models/test.py
git commit -m "test: validación hook"
# Copilot ejecuta validación automáticamente
```

---

### Caso 4: Generación Automática Prompts desde Templates

**Tarea:** Crear prompt P4-Deep para nuevo módulo desde template

```bash
copilot -p "Genera prompt P4-Deep para auditar módulo addons/localization/l10n_cl_financial_reports/ usando template base docs/prompts/04_templates/TEMPLATE_AUDITORIA.md.

**Pasos:**
1. Lee template TEMPLATE_AUDITORIA.md
2. Identifica variables a reemplazar:
   - [MODULE_NAME] → l10n_cl_financial_reports
   - [INTEGRATION] → Reportes financieros (Balance, P&L, Flujo Caja)
   - [FECHA] → $(date +%Y-%m-%d)
   - [COMPLIANCE_DEADLINE_P0] → 2025-03-01

3. Analiza módulo target:
   - Lista modelos Python en models/
   - Identifica integraciones (APIs contables, exportación XLSX/PDF)
   - Detecta dependencias Odoo (account, account_report)

4. Adapta secciones template:
   - **CONTEXTO CRÍTICO:** Añade descripción reportes financieros chilenos
   - **CRITERIOS AUDITORÍA:** Enfoca en compliance contable + performance queries
   - **VERIFICACIONES:** Define ≥6 verificaciones específicas módulo

5. Incluye sección compliance Odoo 19 obligatoria (8 patrones P0/P1/P2)

6. Genera dimensiones A-J adaptadas:
   - A) Arquitectura: Herencia account.report
   - C) Integraciones: APIs SII, XLSX generation
   - F) Testing: Coverage reportes (Balance, P&L)
   - G) Performance: Queries complejas multi-tabla

**Output:** docs/prompts/05_prompts_produccion/modulos/l10n_cl_financial_reports/AUDIT_FINANCIAL_P4_DEEP_$(date +%Y%m%d).md

Formato: Prompt ejecutable completo (1,200-1,500 palabras)" --allow-all-tools --allow-all-paths
```

**Output esperado:**
- ✅ Prompt generado en 2-3 minutos (vs 45 min manual)
- ✅ Variables reemplazadas correctamente
- ✅ Dimensiones adaptadas al módulo específico
- ✅ Verificaciones reproducibles incluidas
- ✅ Listo para ejecutar con Copilot CLI o Claude

---

### Caso 5: Consolidación Multi-Módulo

**Tarea:** Consolidar hallazgos de 4 auditorías en reporte único

```bash
copilot -p "Consolida hallazgos de auditorías P4-Deep de 4 módulos en reporte único:

**Auditorías fuente:**
- docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_DTE_DEEP.md
- docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_PAYROLL.md
- docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_AI_SERVICE.md
- docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_FINANCIAL.md

**Análisis consolidado:**

1. Extrae todos los hallazgos P0+P1 de cada auditoría
2. Clasifica hallazgos por categoría:
   - Compliance Odoo 19 CE (deprecaciones)
   - Seguridad (API keys, SQL injection, XXE)
   - Performance (N+1 queries, índices faltantes)
   - Testing (gaps coverage, tests faltantes)
   - Integraciones (timeouts, retry, circuit breaker)

3. Identifica hallazgos transversales (afectan múltiples módulos):
   - Ejemplo: \"API keys hardcoded\" encontrado en DTE + Payroll + AI Service
   - Ejemplo: \"Deprecación self._cr\" encontrada en 3 módulos

4. Prioriza por impacto cross-módulo:
   - P0 Transversal (afecta ≥3 módulos): Prioridad máxima
   - P0 Individual (1 módulo): Prioridad alta
   - P1 Transversal: Prioridad alta
   - P1 Individual: Prioridad media

5. Calcula métricas agregadas:
   - Total hallazgos: P0 (X), P1 (Y), P2 (Z)
   - Compliance rate promedio: (suma compliance rates / 4)
   - Effort estimado total: Suma esfuerzos individuales
   - Módulo con más hallazgos críticos

**Output:** docs/prompts/06_outputs/2025-11/auditorias/$(date +%Y%m%d)_CONSOLIDACION_HALLAZGOS_4_MODULOS_COPILOT.md

Formato markdown con:
- Resumen ejecutivo (top 10 hallazgos críticos)
- Tabla consolidada (ID, módulo, hallazgo, criticidad, esfuerzo)
- Hallazgos transversales destacados
- Roadmap priorizado (Fase 1 P0 transversal, Fase 2 P0 individual, etc)
- Métricas agregadas (dashboard)
- Recomendaciones estratégicas" --allow-all-tools --allow-all-paths
```

**Output esperado:**
- ✅ Consolida 28+ hallazgos en reporte único
- ✅ Identifica 8 hallazgos transversales
- ✅ Roadmap priorizado 3 fases
- ✅ Métricas agregadas cuantitativas
- ✅ Tiempo: 5-8 minutos (vs 2-3 horas manual)

---

## 🎓 Mejores Prácticas: Modo Autónomo

### 1. Define Tareas con Máxima Claridad

**❌ Prompt Vago (Resultados Pobres):**
```bash
copilot -p "Audita el módulo DTE" --allow-all-tools
```

**✅ Prompt Específico (Resultados Excelentes):**
```bash
copilot -p "Audita módulo addons/localization/l10n_cl_dte/ contra checklist compliance Odoo 19 CE en docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md.

Valida 8 patrones deprecación (P0/P1/P2).
Genera reporte markdown con tabla resumen, compliance rate, archivos críticos.
Guarda en: docs/prompts/06_outputs/2025-11/auditorias/$(date +%Y%m%d)_AUDIT_DTE_COMPLIANCE.md" --allow-all-tools --allow-all-paths
```

**Elementos clave prompt autónomo:**
1. ✅ **Input explícito:** Rutas específicas (módulo, checklist, docs)
2. ✅ **Tareas concretas:** Lista numerada de pasos
3. ✅ **Output definido:** Ubicación archivo, formato, contenido esperado
4. ✅ **Criterios validación:** Métricas, checks, condiciones éxito

---

### 2. Usa Referencias Explícitas a Documentación

**Incluye paths absolutos a docs del proyecto:**

```bash
copilot -p "Ejecuta auditoría P4-Deep siguiendo:

**Estrategia:** docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
**Template:** docs/prompts/04_templates/TEMPLATE_AUDITORIA.md
**Compliance:** docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
**Máximas:** docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md

[... resto del prompt ...]" --allow-all-tools --allow-all-paths
```

**Beneficio:** Copilot lee los docs automáticamente y aplica estándares correctos.

---

### 3. Solicita Outputs Estructurados

**❌ Output no estructurado:**
```bash
copilot -p "Analiza el módulo y dime qué problemas tiene"
```

**✅ Output estructurado (machine-readable):**
```bash
copilot -p "Analiza módulo y genera reporte markdown con:

## Resumen Ejecutivo
- 3-5 hallazgos críticos (bullet list)

## Compliance Odoo 19 CE
| Patrón | Occurrences | Status |
|--------|-------------|--------|
| t-esc | X | ✅/❌ |
[... 8 patrones ...]

## Hallazgos Detallados
### P0-01: [Título]
**Archivo:** path/to/file.py:línea
**Problema:** [Descripción]
**Impacto:** [Criticidad]
**Solución:** [Recomendación]

## Verificaciones Reproducibles
\`\`\`bash
grep -rn \"patrón\" addons/
# Output: [resultado esperado]
\`\`\`

## Métricas
- Compliance rate: XX%
- Hallazgos P0: X
- Hallazgos P1: Y
- Effort estimado: Z horas"
```

---

### 4. Define Verificaciones Reproducibles

**Cada hallazgo debe incluir comando verificable:**

```bash
copilot -p "Para cada hallazgo crítico, incluye verificación reproducible:

**Ejemplo:**
### P0-01: API Keys Hardcoded

**Verificación:**
\`\`\`bash
grep -rn \"api_key.*=.*\\\"\" addons/localization/l10n_cl_dte/
# Esperado: 0 matches (actualmente: 2 en controllers/webhook.py:45, libs/sii_client.py:23)
\`\`\`

**Fix:**
\`\`\`bash
# Mover a variables entorno
export SII_API_KEY=\"secret_key_here\"
# Usar en código: os.getenv('SII_API_KEY')
\`\`\`"
```

---

### 5. Especifica Criterios de Éxito

**Define cuándo la tarea está "completa":**

```bash
copilot -p "Audita módulo DTE.

**Criterios éxito (tarea completada cuando):**
✅ 8 patrones deprecación validados (tabla completa)
✅ Compliance rate calculado (%)
✅ Hallazgos P0+P1 listados con archivo:línea
✅ ≥6 verificaciones reproducibles incluidas
✅ Reporte guardado en docs/prompts/06_outputs/2025-11/auditorias/
✅ Métricas cuantitativas (counts, percentages, effort)

Si falta alguno de estos 6 criterios, la tarea NO está completa."
```

---

## ⚠️ Seguridad: Uso Responsable Modo Autónomo

### Riesgos del Modo Autónomo

| Riesgo | Descripción | Mitigación |
|--------|-------------|-----------|
| **Comandos destructivos** | `rm -rf`, `git push --force` | ✅ Auditar prompts antes de ejecutar |
| **Exposición secretos** | Leer `.env`, `secrets.yml` | ✅ Copilot hereda políticas GitHub Org |
| **Sobrescritura archivos** | Modificar código producción | ✅ Usar `--allow-all-paths` solo read-only |
| **Ejecución código malicioso** | Scripts third-party no validados | ✅ Revisar comandos en prompt |
| **Costo tokens** | Prompts largos = alto costo | ✅ Monitorear usage con `/usage` |

---

### Checklist Pre-Ejecución Autónoma

**Antes de ejecutar `--allow-all-tools --allow-all-paths`, verificar:**

- [ ] **Prompt revisado:** ¿Los comandos son seguros?
- [ ] **Scope limitado:** ¿Rutas específicas, NO wildcards globales?
- [ ] **Read-only preferido:** ¿La tarea requiere escritura o solo lectura?
- [ ] **Backup código:** ¿Git commit limpio antes de ejecutar?
- [ ] **Entorno correcto:** ¿Desarrollo/staging, NO producción?
- [ ] **Output definido:** ¿Ubicación archivo salida especificada?
- [ ] **Criterios éxito:** ¿Tarea tiene condiciones verificables de completitud?

---

### Comandos Peligrosos (NUNCA en Modo Autónomo)

**❌ EVITAR en prompts autónomos:**

```bash
# Comandos destructivos
rm -rf /
git push --force
docker system prune -a --volumes

# Modificación producción
ssh production "..."
kubectl delete namespace production

# Exposición secretos
cat .env >> public_file.txt
git add .env && git commit
```

**✅ Alternativas seguras:**

```bash
# Análisis sin modificación
find . -name "*.pyc" -print  # NO -delete
git diff --staged  # NO git commit
docker ps  # NO docker rm

# Read-only en scope limitado
grep -rn "pattern" addons/localization/l10n_cl_dte/  # Ruta específica
pytest --collect-only  # NO --cov (más lento)
```

---

## 📊 Monitoreo y Métricas

### Comando `/usage` - Tracking Sesión

```bash
copilot
> /usage

Estadísticas Sesión Actual:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Duración:           1h 15m
Premium requests:   8/100 (8%)
Comandos shell:     45 (42 OK, 3 rechazados)
Archivos leídos:    23
Archivos escritos:  2

Tokens por modelo:
  claude-sonnet-4.5:  450k input, 12k output
  gpt-5:              0 tokens

Costo estimado:     $1.85 USD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### Métricas Recomendadas Trackear

**Dashboard métricas Copilot CLI (añadir a `docs/prompts/06_outputs/metricas/`):**

```json
{
  "copilot_cli_usage": {
    "month": "2025-11",
    "autonomous_executions": 12,
    "tasks_completed": {
      "audits_p4_deep": 4,
      "compliance_checks": 6,
      "report_generation": 2
    },
    "avg_duration_seconds": {
      "compliance_check": 72,
      "p4_deep_audit": 1800,
      "consolidation": 480
    },
    "tokens_consumed": {
      "total_input": 2450000,
      "total_output": 85000,
      "cost_usd": 24.50
    },
    "success_rate": 0.917,
    "commands_executed": 245,
    "files_analyzed": 156,
    "reports_generated": 12
  }
}
```

---

## 🎯 Plantillas de Comandos Autónomos

### Template 1: Auditoría Compliance

```bash
#!/bin/bash
# Script: audit_compliance_autonomous.sh
# Uso: ./audit_compliance_autonomous.sh [MODULO]

MODULE="${1:-l10n_cl_dte}"
OUTPUT_DIR="docs/prompts/06_outputs/$(date +%Y-%m)/auditorias"
OUTPUT_FILE="${OUTPUT_DIR}/$(date +%Y%m%d)_AUDIT_${MODULE}_COMPLIANCE_COPILOT.md"

mkdir -p "$OUTPUT_DIR"

copilot -p "Audita compliance Odoo 19 CE en módulo addons/localization/${MODULE}/ siguiendo checklist docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md.

Valida 8 patrones deprecación P0/P1/P2:
- t-esc, type='json', attrs=, _sql_constraints, <dashboard>, self._cr, fields_view_get(), _()

Por cada patrón: grep, count, listar archivos:líneas.

Genera reporte markdown con:
- Tabla resumen 8 patrones
- Compliance rate (%)
- Archivos críticos pendientes
- Verificaciones reproducibles

Guarda en: ${OUTPUT_FILE}

Criterios éxito:
✅ 8 patrones validados
✅ Compliance rate calculado
✅ Reporte guardado
✅ ≥8 comandos ejecutados" --allow-all-tools --allow-all-paths

echo "✅ Auditoría completada: ${OUTPUT_FILE}"
```

---

### Template 2: Auditoría P4-Deep

```bash
#!/bin/bash
# Script: audit_p4_deep_autonomous.sh
# Uso: ./audit_p4_deep_autonomous.sh [MODULO]

MODULE="${1:-l10n_cl_hr_payroll}"
OUTPUT_DIR="docs/prompts/06_outputs/$(date +%Y-%m)/auditorias"
OUTPUT_FILE="${OUTPUT_DIR}/$(date +%Y%m%d)_AUDIT_${MODULE}_P4_DEEP_COPILOT.md"

mkdir -p "$OUTPUT_DIR"

copilot -p "Ejecuta auditoría P4-Deep de addons/localization/${MODULE}/ siguiendo:

**Estrategia:** docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
**Template:** docs/prompts/04_templates/TEMPLATE_AUDITORIA.md
**Compliance:** docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
**Máximas:** docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md

Dimensiones A-J (10):
A) Arquitectura y modularidad
B) Patrones diseño Odoo
C) Integraciones externas
D) Seguridad y protección datos
E) Observabilidad
F) Testing
G) Performance
H) Dependencias externas
I) Configuración y deployment
J) Recomendaciones priorizadas

Verificaciones: ≥6 (1 P0, 2 P1, 3 P2)
Referencias: ≥30 (archivo:línea)
Palabras: 1,500-2,000

Output: ${OUTPUT_FILE}

Criterios éxito:
✅ 10 dimensiones analizadas
✅ ≥30 referencias código
✅ ≥6 verificaciones reproducibles
✅ Hallazgos P0+P1 listados
✅ Reporte guardado" --allow-all-tools --allow-all-paths

echo "✅ Auditoría P4-Deep completada: ${OUTPUT_FILE}"
```

---

### Template 3: Validación Pre-Commit

```bash
#!/bin/bash
# .git/hooks/pre-commit
# Hook Git con validación autónoma Copilot CLI

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|xml)$')

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

echo "🔍 Validando compliance Odoo 19 CE..."

TEMP_REPORT=$(mktemp)

copilot -p "Valida deprecaciones P0+P1 Odoo 19 CE en archivos staged:

$STAGED_FILES

Checklist: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md

Buscar patrones P0+P1 (7 total).
Si encuentras ≥1 deprecación: exit 1, lista archivos:líneas.
Si 0 deprecaciones: exit 0, mensaje \"✅ Compliance OK\".

Output temporal: ${TEMP_REPORT}" --allow-all-tools --allow-all-paths

RESULT=$?

if [ $RESULT -ne 0 ]; then
  cat "$TEMP_REPORT"
  rm "$TEMP_REPORT"
  echo ""
  echo "❌ COMMIT BLOQUEADO: Deprecaciones detectadas"
  echo "Corrige antes de commitear."
  exit 1
fi

rm "$TEMP_REPORT"
echo "✅ Compliance OK"
exit 0
```

---

## 🚀 Integración CI/CD

### GitHub Actions Workflow

```yaml
# .github/workflows/audit-compliance-copilot.yml
name: Audit Compliance Odoo 19 CE (Copilot CLI)

on:
  pull_request:
    paths:
      - 'addons/localization/**/*.py'
      - 'addons/localization/**/*.xml'
  workflow_dispatch:

jobs:
  audit-compliance:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '22'
      
      - name: Install Copilot CLI
        run: npm install -g @github/copilot
      
      - name: Authenticate Copilot
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          # Token ya disponible en env, Copilot lo detecta automáticamente
          copilot --version
      
      - name: Audit Compliance Autonomous
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          copilot -p "Audita compliance Odoo 19 CE en módulos modificados en este PR.
          
          Archivos modificados:
          $(git diff --name-only origin/main...HEAD | grep -E 'addons/localization/.*\.(py|xml)$')
          
          Checklist: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
          
          Valida 8 patrones P0/P1/P2.
          
          Si ≥1 deprecación P0/P1 encontrada: exit 1 (bloquear PR).
          Si 0 deprecaciones: exit 0 (aprobar PR).
          
          Output: compliance_report_pr_${{ github.event.pull_request.number }}.md" \
          --allow-all-tools --allow-all-paths
      
      - name: Upload Compliance Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: compliance_report_pr_*.md
      
      - name: Comment PR with Results
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('compliance_report_pr_${{ github.event.pull_request.number }}.md', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## ❌ Compliance Odoo 19 CE Failed\n\n${report}`
            });
```

---

## 📚 Recursos Adicionales

### Documentación Oficial

- **GitHub Copilot CLI:** https://docs.github.com/en/copilot/using-github-copilot/using-github-copilot-in-the-command-line
- **Copilot CLI Agents:** https://docs.github.com/en/copilot/about-github-copilot/github-copilot-features#copilot-in-the-cli

### Documentación Proyecto

- **Sistema Prompts:** [README.md](README.md)
- **Compliance Odoo 19:** [02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md](02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md)
- **Estrategia P4-Deep:** [01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md](01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md)
- **Máximas Auditoría:** [03_maximas/MAXIMAS_AUDITORIA.md](03_maximas/MAXIMAS_AUDITORIA.md)

---

## 🎯 Próximos Pasos

### Implementación Inmediata

1. **Probar Modo Autónomo:**
   ```bash
   ./docs/prompts/08_scripts/audit_compliance_autonomous.sh l10n_cl_dte
   ```

2. **Instalar Pre-Commit Hook:**
   ```bash
   cp scripts/pre-commit-copilot.sh .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit
   ```

3. **Configurar GitHub Actions:**
   ```bash
   cp .github/workflows/audit-compliance-copilot.yml.example \
      .github/workflows/audit-compliance-copilot.yml
   git add .github/workflows/audit-compliance-copilot.yml
   git commit -m "ci: add Copilot CLI compliance audit workflow"
   ```

---

## 📞 Soporte

**Mantenedor:** Pedro Troncoso (@pwills85)  
**Última actualización:** 2025-11-12  
**Versión documento:** 1.0.0

**Reportar problemas:**
- Copilot CLI no autentica: Verificar `GITHUB_TOKEN` en env
- Comandos fallan en sandbox: Usar `--allow-all-tools`
- Outputs incompletos: Mejorar especificidad prompt (criterios éxito)
- Tareas no finalizan: Definir límites temporales/comandos máximos

---

**🤖 Copilot CLI: Autonomía Completa para Tareas Complejas**

**Ejecuta. Valida. Reporta. Todo automáticamente hasta dar correcto término.**

