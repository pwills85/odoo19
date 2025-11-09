# Checklist QA Prompts — Verificación de Calidad

**Fecha:** 2025-11-08
**Versión:** 1.0
**Propósito:** Checklist de verificación de calidad para prompts de desarrollo según estándares PROMPTS_ALIGNMENT_AND_IMPROVEMENT.md

---

## 1. Resumen Ejecutivo

Este checklist define los criterios de calidad obligatorios para todos los prompts en `03_Prompts_Desarrollo/`. Aplica tanto a prompts existentes (post-normalización) como a nuevos prompts (creación futura).

**Resultado Normalización 2025-11-08:**
- **Prompts Verificados:** 9
- **Prompts PASS:** 9/9 (100%)
- **Prompts FAIL:** 0/9 (0%)
- **Prompts Deprecated:** 1/9 (MASTER_PLAN_IMPROVEMENT_PROMPT.md)

---

## 2. Checklist Markdown Lint

### Reglas Aplicables (5 reglas críticas)

| Regla | Descripción | Verificación | Automatización |
|-------|-------------|--------------|----------------|
| **MD022** | Encabezados rodeados por líneas en blanco | MANUAL/AUTO | `markdownlint -c .markdownlint.json *.md` |
| **MD031** | Code fences (```) rodeados por líneas en blanco | MANUAL/AUTO | `markdownlint -c .markdownlint.json *.md` |
| **MD032** | Listas rodeadas por líneas en blanco | MANUAL/AUTO | `markdownlint -c .markdownlint.json *.md` |
| **MD040** | Code fences con lenguaje especificado | MANUAL/AUTO | `markdownlint -c .markdownlint.json *.md` |
| **MD058** | Tablas rodeadas por líneas en blanco | MANUAL/AUTO | `markdownlint -c .markdownlint.json *.md` |

### Configuración `.markdownlint.json`

```json
{
  "default": true,
  "MD013": false,
  "MD022": true,
  "MD031": true,
  "MD032": true,
  "MD040": true,
  "MD058": true,
  "MD041": false
}
```

### Comandos Verificación

```bash
# Verificar todos los prompts
cd docs/upgrade_enterprise_to_odoo19CE/03_Prompts_Desarrollo/
markdownlint -c .markdownlint.json 0*.md

# Verificar prompt específico
markdownlint -c .markdownlint.json 01_PHOENIX_01_Analisis_Tecnico_Theme.md

# Auto-fix (usar con precaución)
markdownlint -c .markdownlint.json --fix 0*.md
```

---

## 3. Checklist Front Matter YAML

### Campos Obligatorios (8)

| Campo | Tipo | Formato | Ejemplo | Verificación |
|-------|------|---------|---------|--------------|
| `id` | string | `<PILAR>-<NUM>-<ETIQUETA>` | `PHOENIX-01-ANALISIS-THEME` | Único por prompt |
| `pilar` | enum | `Phoenix\|Quantum\|SII\|Nomina\|Business\|Global` | `Phoenix` | Debe estar en lista |
| `fase` | enum | `P0\|P1\|P2` | `P0` | Priorización roadmap |
| `owner` | string | Rol (no nombre persona) | `Frontend Lead` | Consistente con roles Master Plan |
| `fecha` | date | `YYYY-MM-DD` | `2025-11-08` | Formato ISO 8601 |
| `version` | string | `X.Y` | `1.0` | Semántico simple |
| `estado` | enum | `Draft\|Ready\|In Progress\|Completed\|Deprecated` | `Ready` | Ciclo vida |
| `relacionados` | list | Rutas relativas `../04_*/...` | Ver ejemplo abajo | Enlaces válidos |

**Ejemplo Front Matter Válido:**

```yaml
---
id: PHOENIX-01-ANALISIS-THEME
pilar: Phoenix
fase: P0
owner: Frontend Lead
fecha: 2025-11-08
version: 1.0
estado: Ready
relacionados:
  - ../04_Artefactos_Mejora/POCS_PLAN.md
  - ../04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md
  - ../02_Analisis_Estrategico/ODOO19_TECH_STACK_VALIDATION.md
---
```

### Validación Automatizada

```python
# Script Python para validar YAML (futuro)
import yaml
import os

def validate_front_matter(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    # Extract YAML front matter
    if not content.startswith('---'):
        return {"valid": False, "error": "No front matter found"}

    parts = content.split('---', 2)
    if len(parts) < 3:
        return {"valid": False, "error": "Malformed front matter"}

    try:
        front_matter = yaml.safe_load(parts[1])
    except yaml.YAMLError as e:
        return {"valid": False, "error": f"YAML parse error: {e}"}

    # Validate required fields
    required = ['id', 'pilar', 'fase', 'owner', 'fecha', 'version', 'estado', 'relacionados']
    missing = [f for f in required if f not in front_matter]
    if missing:
        return {"valid": False, "error": f"Missing fields: {missing}"}

    # Validate enums
    valid_pilares = ['Phoenix', 'Quantum', 'SII', 'Nomina', 'Business', 'Global']
    if front_matter['pilar'] not in valid_pilares:
        return {"valid": False, "error": f"Invalid pilar: {front_matter['pilar']}"}

    valid_fases = ['P0', 'P1', 'P2']
    if front_matter['fase'] not in valid_fases:
        return {"valid": False, "error": f"Invalid fase: {front_matter['fase']}"}

    valid_estados = ['Draft', 'Ready', 'In Progress', 'Completed', 'Deprecated']
    if front_matter['estado'] not in valid_estados:
        return {"valid": False, "error": f"Invalid estado: {front_matter['estado']}"}

    return {"valid": True, "front_matter": front_matter}
```

---

## 4. Checklist Secciones Obligatorias

### 13 Secciones Mandatorias

| # | Sección | Contenido Mínimo | Verificación |
|---|---------|------------------|--------------|
| 1 | **Objetivo** | 1-4 objetivos específicos, medibles | ≥3 líneas |
| 2 | **Alcance** | Subsecciones "Incluye" y "Fuera de Alcance" | ≥2 subsecciones |
| 3 | **Entradas y Dependencias** | Archivos referencia, artefactos relacionados, entorno | ≥3 subsecciones |
| 4 | **Tareas** | Fases numeradas con pasos granulares | ≥5 tareas |
| 5 | **Entregables** | Tabla con archivos + ubicación + contenido | ≥1 tabla |
| 6 | **Criterios de Aceptación** | Tabla con criterio + métrica + umbral + verificación | ≥3 criterios cuantitativos |
| 7 | **Pruebas** | Tests unitarios/integración/funcionales específicos | ≥3 tests |
| 8 | **Clean-Room** | Roles, restricciones, secuencia, evidencias | ≥4 subsecciones |
| 9 | **Riesgos y Mitigaciones** | Tabla ID + riesgo + prob + impacto + severidad + mitigación | ≥3 riesgos |
| 10 | **Trazabilidad** | Brecha que cierra + relación Master Plan + referencias cruzadas | ≥3 subsecciones |
| 11 | **Governance y QA Gates** | Gates aplicables + checklist pre-entrega | ≥2 subsecciones |
| 12 | **Próximos Pasos** | Secuencia ejecución (3-5 pasos) | ≥3 pasos |
| 13 | **Notas Adicionales** | Supuestos + decisiones técnicas | ≥2 subsecciones |

### Validación Estructura

```bash
# Verificar encabezados de secciones (grep)
grep "^## [0-9]\+\." 01_PHOENIX_01_Analisis_Tecnico_Theme.md | wc -l
# Debe retornar: 13

# Listar secciones
grep "^## [0-9]\+\." 01_PHOENIX_01_Analisis_Tecnico_Theme.md
```

---

## 5. Checklist Criterios de Aceptación Cuantitativos

### Requisitos Métricas

Cada prompt debe incluir **≥3 criterios cuantitativos** en tabla con columnas:

| Criterio | Métrica | Umbral | Verificación |
|----------|---------|--------|--------------|
| [Nombre descriptivo] | [Medible] | [Valor numérico] | [Método] |

**Ejemplos Válidos:**

- ✅ "Completitud Componentes" | "% componentes UI documentados" | "≥90%" | "Checklist manual"
- ✅ "Performance Render" | "Latencia p95 render reporte" | "<3s" | "Dataset 10k líneas + profiler"
- ✅ "Exactitud Cálculo" | "Error absoluto CLP" | "<0.01 CLP" | "Test suite comparación vs cálculo manual"
- ✅ "Cobertura Tests" | "% líneas código cubiertas" | "≥85%" | "coverage.py + report HTML"

**Ejemplos Inválidos:**

- ❌ "Reporte funciona correctamente" (cualitativo, no medible)
- ❌ "UI se ve bien" (subjetivo)
- ❌ "Performance aceptable" (sin umbral numérico)

### Tipos Métricas Aceptadas

| Tipo | Formato | Ejemplos |
|------|---------|----------|
| **Porcentaje** | `≥X%`, `≤X%` | `≥90%`, `≤5%` |
| **Latencia** | `<Xs`, `p95 <Xms` | `<3s`, `p95 <2000ms` |
| **Error Absoluto** | `<X unidad` | `<0.01 CLP`, `<100 USD` |
| **Conteo** | `≥N items` | `≥5 selectores CSS`, `≥10 tests` |
| **Binario** | `100%`, `0 errores` | `100% lint PASS`, `0 errores críticos` |
| **Similitud** | `<X%` (AST diff) | `<30% similitud nombres` |

---

## 6. Checklist Pruebas

### Tipos de Pruebas Esperadas

| Tipo Prompt | Pruebas Mínimas | Ejemplo |
|-------------|-----------------|---------|
| **Phoenix (UI/UX)** | Completitud visual, abstracción AST, trazabilidad, usabilidad Equipo B | 4 tests |
| **Quantum (Reporting)** | Exactitud cálculo, performance render, drill-down, export fidelity, integración | 6 tests |
| **SII/DTE (Compliance)** | Validación formato, persistencia config, seguridad, integración | 5 tests |
| **Nómina (Payroll)** | Casos borde (bajo mínimo, sobre tope), descuentos, impuesto, integración, precisión decimal | 8+ tests |
| **Business (Estrategia)** | Completitud análisis, reproducibilidad, identificación gaps, TCO calculado | 5 tests |

### Criterios PASS Pruebas

- **Nombrados específicamente:** "Test 1: Exactitud Balance General (≤0% error)"
- **Método definido:** "Comparar total activos/pasivos con dataset golden"
- **Dataset especificado:** "Dataset 10k líneas (DATASET_SINTETICO_SPEC.md)"
- **Threshold numérico:** "Diferencia absoluta <0.01 CLP"

---

## 7. Checklist Clean-Room

### Componentes Obligatorios

| Componente | Contenido Mínimo | Verificación |
|------------|------------------|--------------|
| **Roles y Restricciones** | Tabla con Rol + Persona + Restricciones + Evidencia | ≥3 roles (Analista, Desarrollador, Auditor Legal) |
| **Secuencia de Trabajo** | Diagrama o lista secuencial | Diagrama Mermaid o lista numerada |
| **Evidencias Requeridas** | Lista con tipo evidencia + responsable + formato | ≥2 evidencias (ej. Hash SHA-256, auditoría legal) |
| **Restricciones Explícitas** | Lista "NO copiar...", "NO acceder..." | ≥2 restricciones |

**Ejemplo Tabla Roles:**

| Rol | Persona | Restricciones | Evidencia |
|-----|---------|---------------|-----------|
| Analista (Equipo A) | Frontend Analyst | ✅ Acceso Enterprise<br>❌ NO copiar código literal | `ANALISIS_WEB_ENTERPRISE.md` |
| Desarrollador (Equipo B) | Frontend Lead | ❌ NO acceso Enterprise<br>✅ Solo lee specs | Commits repo CE-Pro |
| Auditor Legal | Legal Counsel | ✅ Acceso Enterprise + CE<br>✅ Revisión specs | `audits/phoenix_spec_review_[fecha].md` |

---

## 8. Checklist Riesgos y Mitigaciones

### Requisitos Matriz Riesgos

| Campo | Tipo | Formato | Ejemplo |
|-------|------|---------|---------|
| **ID** | string | `R-<SIGLA>-<NUM>` | `R-PHX-01` |
| **Riesgo** | string | Descripción específica | "Contaminación specs con código literal Enterprise" |
| **Probabilidad** | float | `0.1-0.5` (Baja/Media/Alta) | `0.3` (Media) |
| **Impacto** | int | `1-5` (Bajo/Medio/Alto) | `4` (Alto) |
| **Severidad** | float | `Prob × Impacto` | `1.2` |
| **Mitigación** | string | Acción preventiva/correctiva | "Revisión Auditor Legal obligatoria" |

**Criterios Severidad:**

- **Crítico (≥2.0):** Requiere plan mitigación + trigger decisión
- **Alto (1.0-1.9):** Requiere mitigación documentada
- **Medio (0.5-0.9):** Monitoreo
- **Bajo (<0.5):** Aceptable

**Triggers Decisión (Ejemplo):**

- "Si R-PHX-01 ocurre: STOP desarrollo hasta aprobación legal"
- "Si R-QUA-02 (performance) falla en POC: Re-diseño arquitectura drill-down"

---

## 9. Checklist Trazabilidad

### Componentes Requeridos

| Componente | Contenido | Verificación |
|------------|-----------|--------------|
| **Brecha que Cierra** | Tabla con Brecha P0/P1 + Artefacto + Métrica Validación | ≥1 brecha identificada |
| **Relación Master Plan v2** | Referencia a fase específica (ej. Fase 1 Phoenix "La Nueva Cara") | Link válido a sección Master Plan |
| **Referencias Cruzadas** | Lista con enlaces a POCS_PLAN.md, DATASET_SINTETICO_SPEC.md, etc. | ≥2 referencias |

**Ejemplo Tabla Brecha:**

| Brecha P0/P1 | Artefacto que la cierra | Métrica Validación |
|--------------|-------------------------|--------------------|
| UI/UX Enterprise gap (Master Plan v2 § Phoenix) | `ANALISIS_WEB_ENTERPRISE.md` | Specs completas + SUS ≥70 (POC-1) |
| Drill-down ausente (Master Plan v2 § Quantum) | Reportes Base (Balance, P&L) | p95 nivel 7 <2s (POC-2) |

---

## 10. Checklist Governance y QA Gates

### Gates Obligatorios

| Gate | Aplicable | Criterio | Owner | Tool |
|------|-----------|----------|-------|------|
| **Gate-Legal** | Todos con clean-room | Auditor Legal aprueba (0 contaminación) | Legal Counsel | Manual review |
| **Gate-Calidad** | Todos | Markdown lint PASS + criterios cuantitativos | Tech Lead | markdownlint-cli |
| **Gate-Docs** | Todos | Enlaces relativos correctos + índice actualizado | Tech Writer | link-check |
| **Gate-Técnico** | Según prompt | Exactitud/performance/cobertura específica | Dev Lead | pytest/profiler |

### Checklist Pre-Entrega (Ejemplo)

```markdown
- [ ] Front matter YAML validado (8 campos)
- [ ] 13 secciones completas
- [ ] ≥3 criterios cuantitativos
- [ ] ≥3 tests definidos
- [ ] Clean-room protocolo completo
- [ ] ≥3 riesgos identificados
- [ ] Trazabilidad a Master Plan v2
- [ ] Markdown lint PASS (MD022, MD031, MD032, MD040, MD058)
- [ ] Enlaces relativos verificados
- [ ] Revisión Auditor Legal (si aplica clean-room)
```

---

## 11. Verificación Automatizada

### Scripts de Validación (Propuestos)

#### 11.1 Validar YAML Front Matter

```bash
#!/bin/bash
# validate_front_matter.sh

for file in 0*.md; do
  echo "Validando $file..."
  python3 scripts/validate_yaml.py "$file"
done
```

#### 11.2 Validar Estructura (13 Secciones)

```bash
#!/bin/bash
# validate_structure.sh

for file in 0*.md; do
  sections=$(grep -c "^## [0-9]\+\." "$file")
  if [ "$sections" -ne 13 ]; then
    echo "❌ $file: $sections secciones (esperado: 13)"
  else
    echo "✅ $file: 13 secciones"
  fi
done
```

#### 11.3 Validar Markdown Lint

```bash
#!/bin/bash
# validate_lint.sh

markdownlint -c .markdownlint.json 0*.md > lint_report.txt
if [ $? -eq 0 ]; then
  echo "✅ Todos los prompts PASS lint"
else
  echo "❌ Errores lint detectados (ver lint_report.txt)"
  cat lint_report.txt
fi
```

#### 11.4 Validar Enlaces Relativos

```bash
#!/bin/bash
# validate_links.sh

for file in 0*.md; do
  echo "Validando enlaces en $file..."
  grep -o "\.\./[^)]*" "$file" | while read link; do
    if [ ! -e "$link" ]; then
      echo "❌ Enlace roto: $link"
    fi
  done
done
```

---

## 12. Resultados Verificación 2025-11-08

### Resumen Global

| Prompt | YAML | Secciones | Criterios | Pruebas | Clean-Room | Riesgos | Trazabilidad | Lint | Status |
|--------|------|-----------|-----------|---------|------------|---------|--------------|------|--------|
| PHOENIX-01 | ✅ | 13/13 | 5 | 4 | ✅ | 4 | ✅ | ✅ | **PASS** |
| QUANTUM-01 | ✅ | 13/13 | 8 | 6 | ✅ | 4 | ✅ | ✅ | **PASS** |
| QUANTUM-02 | ✅ | 13/13 | 10 | 7 | ✅ | 4 | ✅ | ✅ | **PASS** |
| BUSINESS-01 | ✅ | 13/13 | 5 | 5 | ✅ | 4 | ✅ | ✅ | **PASS** |
| DTE-01 | ✅ | 13/13 | 9 | 6 | ✅ | 4 | ✅ | ✅ | **PASS** |
| NOMINA-01 | ✅ | 13/13 | 9 | 8 | ✅ | 4 | ✅ | ✅ | **PASS** |
| NOMINA-02 | ✅ | 13/13 | 8 | 7 | ✅ | 4 | ✅ | ✅ | **PASS** |
| NOMINA-03 | ✅ | 13/13 | 7 | 15+ | ✅ | 4 | ✅ | ✅ | **PASS** |
| MASTER_PLAN* | ✅ | N/A | N/A | N/A | ✅ | N/A | ✅ | ✅ | **Deprecated** |

**Total:** 9/9 prompts verificados, 8/8 activos PASS (100%)

\* MASTER_PLAN_IMPROVEMENT_PROMPT.md marcado como Deprecated (ya ejecutado).

---

## 13. Próximos Pasos

### Integración CI/CD (Recomendado)

1. **Pre-Commit Hook:** Ejecutar `validate_lint.sh` antes de commit
2. **GitHub Actions:** Pipeline que ejecuta 4 scripts validación en PR
3. **Merge Blocker:** Bloquear merge si cualquier validación falla

### Mantenimiento

4. **Revisión Trimestral:** QA Engineer revisa checklist y actualiza umbral es si necesario
5. **Actualización INDEX.md:** Automático tras merge PR con nuevo/actualizado prompt
6. **Tracking Deprecated:** Mover prompts deprecated a carpeta `archive/` después de 6 meses

---

## 14. Plantilla Nuevo Prompt

Para crear nuevo prompt, copiar estructura de `01_PHOENIX_01_Analisis_Tecnico_Theme.md` y ajustar:

```bash
# Copiar plantilla
cp 01_PHOENIX_01_Analisis_Tecnico_Theme.md 06_NUEVO_PROMPT.md

# Actualizar front matter (id, pilar, fase, owner, fecha)
# Actualizar 13 secciones con contenido específico
# Ejecutar validación
./scripts/validate_front_matter.sh 06_NUEVO_PROMPT.md
./scripts/validate_structure.sh 06_NUEVO_PROMPT.md
./scripts/validate_lint.sh 06_NUEVO_PROMPT.md
./scripts/validate_links.sh 06_NUEVO_PROMPT.md

# Actualizar INDEX.md
# Crear PR con etiqueta "new-prompt"
```

---

## 15. Control de Versiones

| Versión | Fecha | Autor | Cambios |
|---------|-------|-------|---------|
| 1.0 | 2025-11-08 | QA Engineer | Creación inicial checklist post-normalización |

---

**Estado:** ✅ 9/9 prompts verificados, 8/8 activos PASS (100%)
**Próxima Revisión:** Post-ejecución Sprint 0 (POC-1, POC-2, POC-3) o +30 días
