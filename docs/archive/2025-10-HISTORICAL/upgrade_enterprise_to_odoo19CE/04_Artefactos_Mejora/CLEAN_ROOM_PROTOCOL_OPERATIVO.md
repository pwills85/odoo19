# Protocolo Clean-Room Operativo — Cumplimiento Legal OEEL-1

**Fecha:** 2025-11-08
**Versión:** 1.0
**Autor:** Legal + Arquitectura Técnica
**Estado:** Propuesta para Aprobación

---

## 1. Propósito

Este documento establece el protocolo operativo **clean-room** (sala limpia) para el desarrollo de módulos Odoo 19 CE-Pro (Phoenix + Quantum + SII), garantizando que no se infringe la licencia OEEL-1 (Odoo Enterprise Edition License v1.0) de módulos Enterprise, mediante procesos documentados, trazables y auditables.

---

## 2. Fundamento Legal

### 2.1 Contexto Licencia OEEL-1

**Odoo Enterprise** se distribuye bajo licencia propietaria **OEEL-1**, que:
- ✅ Permite **uso** de módulos Enterprise con licencia válida
- ✅ Permite **lectura** del código fuente (distribuido con producto)
- ❌ **Prohíbe** copia, modificación, redistribución o creación de obras derivadas sin autorización
- ❌ **Prohíbe** extracción de lógica de negocio para reimplementación en productos competidores

**Odoo Community Edition** se distribuye bajo **LGPL v3**, que:
- ✅ Permite uso, modificación, redistribución libremente
- ✅ Permite creación de módulos propietarios que **usen** Odoo CE (sin modificar core)

### 2.2 Estrategia Legal CE-Pro

**Posición:** Desarrollar módulos **funcionalmente equivalentes** a Enterprise, pero con **implementación independiente** bajo LGPL v3, sin violar OEEL-1.

**Método:** Protocolo clean-room de **dos equipos aislados**:
1. **Equipo A (Análisis):** Estudia funcionalidad Enterprise (caja negra), genera especificaciones abstractas
2. **Equipo B (Desarrollo):** Implementa desde especificaciones, sin acceso a código Enterprise

**Precedentes legales:** IBM vs Compaq (BIOS), Oracle vs Google (APIs), WINE (Windows API), ReactOS (Windows NT kernel). Todos validados como legales bajo clean-room correcto.

---

## 3. Roles y Responsabilidades

### 3.1 Equipo A: Analistas Funcionales (Spec Writers)

| Rol | Responsabilidad | Restricciones | Artefacto Output |
|-----|-----------------|---------------|------------------|
| **Analista Funcional Phoenix** | Documentar comportamiento UI Enterprise (capturas, flujos UX) | ❌ NO copiar nombres variables/clases específicas Enterprise | `specs/phoenix_ui_spec.md` |
| **Analista Funcional Quantum** | Documentar lógica reportes Enterprise (casos uso, cálculos) | ❌ NO copiar SQL queries literales Enterprise | `specs/quantum_reports_spec.md` |
| **Auditor Legal** | Revisar specs para eliminar contaminación | Acceso a ambos códigos (Enterprise + CE) | `audits/spec_review_[fecha].md` |

**Reglas Equipo A:**
- ✅ Pueden **instalar y usar** Odoo Enterprise con licencia demo/trial
- ✅ Pueden **leer** código Enterprise para entender funcionalidad
- ✅ Pueden **ejecutar** módulos Enterprise y documentar comportamiento observable
- ❌ NO pueden **copiar** código, nombrado específico, estructuras de datos literales
- ❌ NO pueden **comunicar** detalles de implementación a Equipo B

**Formato Specs Permitido (Ejemplo Phoenix):**

```markdown
## Requisito: Menú Home de Aplicaciones

**Comportamiento Observable:**
- Al hacer clic en ícono home (esquina superior izquierda), se despliega grid de aplicaciones
- Cada aplicación muestra: ícono (SVG/PNG), nombre, tooltip con descripción
- Grid es responsivo: 4 columnas desktop, 2 tablet, 1 móvil
- Animación de apertura: fade-in 200ms
- Búsqueda en tiempo real (debounce 300ms) filtra por nombre

**NO especificar:**
- Nombres de componentes OWL Enterprise específicos (ej. "AppMenuComponent")
- Estructura HTML exacta (ej. `<div class="o_app_menu_container">`)
- Nombres de assets bundles Enterprise

**Especificación Abstracta:**
- Componente: "Selector de Aplicaciones Tipo Grid"
- Input: Lista de aplicaciones (id, nombre, ícono, descripción)
- Output: Navegación a aplicación seleccionada
- Estilos: Variables CSS reutilizables (color primario, espaciado, sombras)
```

---

### 3.2 Equipo B: Desarrolladores CE-Pro (Implementadores)

| Rol | Responsabilidad | Restricciones | Artefacto Output |
|-----|-----------------|---------------|------------------|
| **Dev Frontend CE** | Implementar Phoenix desde specs | ❌ NO acceder a código Enterprise | `addons/theme_enterprise_ce/**/*.js` |
| **Dev Backend CE** | Implementar Quantum desde specs | ❌ NO acceder a código Enterprise | `addons/financial_reports_dynamic/**/*.py` |
| **Auditor Técnico** | Validar ausencia de copia vía análisis AST | Acceso a ambos códigos | `audits/ast_diff_[módulo]_[fecha].json` |

**Reglas Equipo B:**
- ✅ Pueden **leer** specs funcionales de Equipo A
- ✅ Pueden **usar** APIs públicas Odoo CE (ORM, OWL, QWeb)
- ✅ Pueden **consultar** documentación oficial Odoo (odoo.com/documentation)
- ❌ NO pueden **ver** código fuente Enterprise (ni siquiera 1 línea)
- ❌ NO pueden **instalar** Odoo Enterprise en sus entornos desarrollo
- ❌ NO pueden **preguntar** detalles implementación a Equipo A más allá de specs escritas

---

### 3.3 Auditor Legal/Técnico (Gatekeeper)

| Rol | Responsabilidad | Método | Frecuencia |
|-----|-----------------|--------|------------|
| **Auditor Legal** | Validar specs abstractas (no contaminadas) | Revisión manual specs + checklist | Por cada spec antes de pasar a Equipo B |
| **Auditor Técnico** | Detectar similitudes código Enterprise vs CE-Pro | Análisis AST (Abstract Syntax Tree) automatizado | Por cada PR antes de merge |

**Herramientas Auditoría:**
- **AST Diff:** Script Python que compara árboles sintácticos (no texto literal)
- **Token Analysis:** Detecta nombres de variables/funciones sospechosamente idénticos
- **Firma Digital:** Hash SHA-256 de specs + código para trazabilidad

---

## 4. Flujo de Trabajo Clean-Room

### 4.1 Diagrama de Flujo

```
┌─────────────────────────────────────────────────────────────┐
│  FASE 1: Análisis Funcional (Equipo A)                      │
├─────────────────────────────────────────────────────────────┤
│  1. Instalar Odoo Enterprise (licencia demo/trial)          │
│  2. Usar funcionalidad target (ej. menú apps, reportes)     │
│  3. Documentar comportamiento observable (UX, cálculos)     │
│  4. Escribir spec abstracta (SIN detalles implementación)   │
│     └─> Output: specs/[feature]_spec.md                     │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│  FASE 2: Auditoría Spec (Auditor Legal)                     │
├─────────────────────────────────────────────────────────────┤
│  1. Leer spec                                                │
│  2. Verificar checklist clean-room (ver sección 5)          │
│  3. Eliminar cualquier referencia específica Enterprise     │
│     └─> Output: specs/[feature]_spec.APPROVED.md            │
│            + audits/spec_review_[fecha].md (firma SHA-256)  │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│  FASE 3: Implementación (Equipo B)                          │
├─────────────────────────────────────────────────────────────┤
│  1. Leer SOLO spec aprobada (NO código Enterprise)          │
│  2. Diseñar arquitectura CE-Pro propia                      │
│  3. Implementar usando APIs Odoo CE estándar                │
│  4. Crear PR con código + tests                             │
│     └─> Output: addons/[módulo]/**/*.py|js|xml              │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│  FASE 4: Auditoría Código (Auditor Técnico)                 │
├─────────────────────────────────────────────────────────────┤
│  1. Ejecutar script AST diff (Enterprise vs CE-Pro)         │
│  2. Analizar similitudes: ratio < 30% (umbral legal)        │
│  3. Revisar manualmente matches sospechosos                 │
│  4. Aprobar/Rechazar PR                                      │
│     └─> Output: audits/ast_diff_[módulo]_[fecha].json      │
│            + audits/approval_[módulo]_[fecha].SIGNED        │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│  FASE 5: Merge y Trazabilidad                               │
├─────────────────────────────────────────────────────────────┤
│  1. Merge PR a rama develop                                 │
│  2. Generar artifact bundle (spec + código + auditorías)    │
│  3. Almacenar en vault inmutable (Git + S3)                 │
│  4. Firma digital bundle (GPG key auditor)                  │
│     └─> Output: artifacts/[módulo]_v[X.Y.Z].tar.gz.sig     │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Checklist Clean-Room por Fase

### 5.1 Checklist Auditoría Spec (Fase 2)

**Auditor Legal debe verificar:**

| ID | Criterio | PASS/FAIL | Evidencia |
|----|----------|-----------|-----------|
| CR-SPEC-01 | Spec describe **comportamiento observable** (qué hace), NO implementación (cómo lo hace) | [ ] | Revisión manual |
| CR-SPEC-02 | NO contiene nombres específicos de clases/variables/métodos Enterprise (ej. evitar `o_web_enterprise_menu`, usar `app_grid_menu`) | [ ] | Búsqueda regex `o_.*enterprise` |
| CR-SPEC-03 | NO incluye código fuente literal (Python, JS, SQL) | [ ] | Búsqueda regex <code>```</code> |
| CR-SPEC-04 | NO incluye capturas de pantalla con código visible (consola dev, sources) | [ ] | Inspección imágenes |
| CR-SPEC-05 | Usa terminología genérica industria (no jerga interna Odoo SA) | [ ] | Glosario aprobado |
| CR-SPEC-06 | Incluye casos de uso / user stories, NO algoritmos | [ ] | Formato validado |
| CR-SPEC-07 | Especifica inputs/outputs, NO estructuras de datos internas | [ ] | Diagrama flujo |

**Criterio Aprobación:** 7/7 PASS

---

### 5.2 Checklist Auditoría Código (Fase 4)

**Auditor Técnico debe verificar:**

| ID | Criterio | Método | Umbral | Resultado |
|----|----------|--------|--------|-----------|
| CR-CODE-01 | Similitud AST Enterprise vs CE-Pro | Script `ast_diff.py` | < 30% | ___% |
| CR-CODE-02 | Nombres variables/funciones NO idénticos a Enterprise | Token analysis regex | 0 matches exactos | ___ matches |
| CR-CODE-03 | Estructura de archivos NO idéntica a Enterprise | Diff tree dirs | < 50% overlap | ___% |
| CR-CODE-04 | Comentarios código NO copiados de Enterprise | String diff | 0 comentarios duplicados | ___ duplicados |
| CR-CODE-05 | SQL queries NO idénticas (si aplica) | SQL parser diff | < 40% similitud | ___% |
| CR-CODE-06 | Assets (SCSS/JS) NO copiados de Enterprise | Hash diff | 0 archivos idénticos | ___ archivos |
| CR-CODE-07 | Documentación interna (docstrings) es original | Plagiarism check | < 20% similitud | ___% |

**Criterio Aprobación:** Todos < umbral

**Acción si FAIL:** Developer debe reescribir sección flaggeada, re-auditoría.

---

## 6. Tooling Automatizado

### 6.1 Script AST Diff (Python)

**Propósito:** Comparar árboles sintácticos de código Python Enterprise vs CE-Pro.

**Ubicación:** `tools/clean_room/ast_diff.py`

**Ejemplo de uso:**

```bash
python tools/clean_room/ast_diff.py \
  --enterprise /path/to/enterprise/addons/web_enterprise \
  --ce-pro /path/to/ce-pro/addons/theme_enterprise_ce \
  --output audits/ast_diff_phoenix_2025-11-08.json \
  --threshold 0.30
```

**Output (JSON):**

```json
{
  "timestamp": "2025-11-08T10:30:00Z",
  "modules_compared": {
    "enterprise": "web_enterprise",
    "ce_pro": "theme_enterprise_ce"
  },
  "similarity_score": 0.18,
  "threshold": 0.30,
  "status": "PASS",
  "details": {
    "files_compared": 42,
    "identical_functions": 0,
    "similar_functions": 7,
    "flagged_names": ["_compute_menu_data"]
  },
  "signature": "sha256:a3f5b2c..."
}
```

**Algoritmo (simplificado):**

1. Parsear ambos directorios con `ast.parse()`
2. Extraer nombres de clases, funciones, variables
3. Normalizar (lowercase, eliminar prefijos `_odoo`, `_oe`)
4. Calcular Jaccard similarity: `intersección / unión`
5. Si `similarity > threshold`: FLAG
6. Generar reporte JSON firmado

**Implementación (pseudocódigo):**

```python
import ast
import hashlib
from pathlib import Path

def extract_names(tree):
    """Extrae nombres de funciones, clases, variables."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Name):
            names.add(node.id)
    return names

def compare_modules(enterprise_path, ce_pro_path):
    enterprise_files = Path(enterprise_path).rglob("*.py")
    ce_pro_files = Path(ce_pro_path).rglob("*.py")

    enterprise_names = set()
    for file in enterprise_files:
        tree = ast.parse(file.read_text())
        enterprise_names.update(extract_names(tree))

    ce_pro_names = set()
    for file in ce_pro_files:
        tree = ast.parse(file.read_text())
        ce_pro_names.update(extract_names(tree))

    intersection = enterprise_names & ce_pro_names
    union = enterprise_names | ce_pro_names

    similarity = len(intersection) / len(union) if union else 0
    return similarity, intersection

similarity, flagged = compare_modules("/enterprise/web_enterprise", "/ce-pro/theme_enterprise_ce")
print(f"Similarity: {similarity:.2%}, Flagged: {flagged}")
```

---

### 6.2 Script Firma Digital

**Propósito:** Generar hash inmutable de spec + código + auditorías para trazabilidad legal.

**Ubicación:** `tools/clean_room/sign_artifact.sh`

**Uso:**

```bash
./tools/clean_room/sign_artifact.sh \
  --module theme_enterprise_ce \
  --version 1.0.0 \
  --gpg-key auditor@empresa.cl
```

**Output:**

```
artifacts/theme_enterprise_ce_v1.0.0.tar.gz
artifacts/theme_enterprise_ce_v1.0.0.tar.gz.sig (GPG signature)
artifacts/theme_enterprise_ce_v1.0.0.MANIFEST (lista archivos + SHA-256)
```

**MANIFEST (ejemplo):**

```
# Clean-Room Artifact Manifest
# Module: theme_enterprise_ce
# Version: 1.0.0
# Signed: 2025-11-08T12:00:00Z
# Auditor: auditor@empresa.cl (GPG fingerprint: ABCD1234...)

specs/phoenix_ui_spec.APPROVED.md                    sha256:f3a2b1c...
audits/spec_review_2025-11-08.md                     sha256:d4c5e6f...
addons/theme_enterprise_ce/__manifest__.py           sha256:a1b2c3d...
addons/theme_enterprise_ce/static/src/scss/main.scss sha256:e7f8g9h...
audits/ast_diff_phoenix_2025-11-08.json              sha256:b2c3d4e...
audits/approval_phoenix_2025-11-08.SIGNED            sha256:c3d4e5f...
```

**Firma GPG:** `gpg --detach-sign --armor artifacts/theme_enterprise_ce_v1.0.0.tar.gz`

---

## 7. Almacenamiento y Trazabilidad

### 7.1 Estructura de Artefactos

```
clean_room/
├── specs/
│   ├── phoenix_ui_spec.md (draft)
│   ├── phoenix_ui_spec.APPROVED.md (post-auditoría)
│   ├── quantum_reports_spec.md
│   └── quantum_reports_spec.APPROVED.md
├── audits/
│   ├── spec_review_2025-11-08_phoenix.md
│   ├── ast_diff_phoenix_2025-11-08.json
│   ├── approval_phoenix_2025-11-08.SIGNED (GPG)
│   └── ...
├── artifacts/
│   ├── theme_enterprise_ce_v1.0.0.tar.gz
│   ├── theme_enterprise_ce_v1.0.0.tar.gz.sig
│   ├── theme_enterprise_ce_v1.0.0.MANIFEST
│   └── ...
└── tools/
    ├── ast_diff.py
    ├── sign_artifact.sh
    └── verify_artifact.sh
```

### 7.2 Repositorio Inmutable

**Método:** Git repo + S3 bucket con versionado + WORM (Write Once Read Many)

**Política retención:** 10 años (precedente legal: statute of limitations copyright Chile/USA)

**Acceso:**
- **Lectura:** Equipo técnico, legal
- **Escritura:** SOLO Auditor Técnico (via CI/CD automatizado)
- **Eliminación:** PROHIBIDA (immutable)

---

## 8. Formación y Certificación Equipo

### 8.1 Capacitación Obligatoria

**Pre-Kick-off Proyecto:**

| Curso | Duración | Audiencia | Contenido |
|-------|----------|-----------|-----------|
| "Clean-Room Legal Basics" | 2h | Todos (A + B + Auditores) | Fundamentos OEEL-1, casos legales, consecuencias infracción |
| "Writing Clean Specs" | 3h | Equipo A | Técnicas especificación abstracta, ejemplos PASS/FAIL |
| "Developing Without Contamination" | 2h | Equipo B | Coding desde specs, uso APIs Odoo CE, red flags |
| "Audit Tools Training" | 4h | Auditores | Uso ast_diff.py, firma GPG, análisis similitud |

**Certificación:**
- Examen 20 preguntas (80% aprobación)
- Firma NDA (Non-Disclosure Agreement) específico proyecto
- Declaración jurada: "No copiaré código Enterprise"

---

### 8.2 Recordatorios Continuos

**Durante Desarrollo:**
- Banner en IDE: "🔒 Clean-Room Mode: NO acceder a código Enterprise"
- Checklist diario standup: "¿Alguien necesitó consultar Enterprise ayer? → Escalar a Auditor"
- Review mensual: Auditor presenta stats similitud (deben bajar con el tiempo)

---

## 9. Gestión de Riesgos Clean-Room

| ID | Riesgo | Probabilidad | Impacto | Severidad | Mitigación | Contingencia |
|----|--------|--------------|---------|-----------|------------|--------------|
| CR-R1 | Developer accede accidentalmente a código Enterprise | Media (0.3) | Crítico (5) | 1.5 | Bloqueo firewall repos Enterprise + training | Re-auditoría full módulo, posible rewrite |
| CR-R2 | Spec contaminada pasa auditoría legal | Baja (0.1) | Crítico (5) | 0.5 | Doble auditoría (2 auditores independientes) | Reescribir spec + notificar legal |
| CR-R3 | AST diff da falso negativo (código copiado no detectado) | Baja (0.15) | Crítico (5) | 0.75 | Revisión manual adicional PRs críticos | Auditoría externa pre-release |
| CR-R4 | Pérdida evidencias (specs, auditorías) | Muy Baja (0.05) | Alto (4) | 0.2 | Backup 3-2-1 (3 copias, 2 medios, 1 offsite) | Reconstruir evidencia via Git history + S3 versioning |
| CR-R5 | Empleado descontento filtra que se copió código | Baja (0.1) | Crítico (5) | 0.5 | NDA + cultura transparencia (mostrar proceso clean-room es legítimo) | Defensa legal con artefactos firmados |

**Riesgo Crítico (Severidad ≥ 1.0):** CR-R1
**Plan:** Training reforzado, auditoría sorpresa aleatorio 10% commits.

---

## 10. Procedimiento Escalación

### 10.1 Detección Contaminación

**Si se detecta posible contaminación (ej. AST diff > 30%):**

1. **[Inmediato]** Auditor Técnico bloquea PR, notifica PM + Legal
2. **[1h]** Developer autor explica similitud (puede ser coincidencia legítima)
3. **[4h]** Auditor Legal revisa explicación + contexto
4. **[24h]** Decisión:
   - **Aprobado:** Similitud es coincidencia (ej. uso API Odoo estándar) → Merge con nota justificativa
   - **Rechazado:** Similitud es sospechosa → Developer reescribe sección flagged
5. **[48h]** Re-auditoría código reescrito
6. **[72h]** Decisión final GO/NO-GO

**Criterio Reescritura:**
- Cambiar arquitectura (ej. si Enterprise usa Mixin, CE-Pro usa herencia)
- Renombrar todas variables/funciones
- Reorganizar estructura archivos
- Re-auditoría hasta AST diff < 20%

---

### 10.2 Auditoría Externa (Pre-Release)

**Trigger:** Antes de lanzar versión 1.0 de Phoenix/Quantum a producción

**Proceso:**
1. Contratar firma legal externa especializada en IP software
2. Proveer:
   - Specs aprobadas
   - Código CE-Pro completo
   - Auditorías internas (ast_diff, approvals)
   - Artefactos firmados
3. Auditoría externa (2 semanas):
   - Revisión legal documentos
   - Análisis similitud independiente (tools propios)
   - Entrevistas a equipo (validar proceso seguido)
4. **Dictamen Legal:**
   - "Clean-room process fue seguido correctamente, riesgo infracción OEEL-1 es BAJO"
   - Firma + sello legal

**Costo:** $5,000-$10,000 USD (incluido en budget contingencia)

---

## 11. Criterios de Éxito Clean-Room

| Métrica | Objetivo | Medición | Frecuencia |
|---------|----------|----------|------------|
| **Specs aprobadas en primera auditoría** | ≥ 80% | Count specs PASS / Total | Por spec |
| **Similitud AST promedio** | < 25% | Promedio ast_diff.py todos módulos | Por PR |
| **PRs rechazados por contaminación** | < 5% | Count PRs rechazados / Total PRs | Mensual |
| **Tiempo spec → código → merge** | < 2 semanas | Tracking Git timestamps | Por feature |
| **Auditorías externas aprobadas** | 100% | Dictamen legal | Pre-release |
| **Incidentes legales** | 0 | Demandas, cease & desist | Continuo |

---

## 12. Comunicación y Transparencia

### 12.1 Interna (Equipo)

**Documentar públicamente (repo interno):**
- Este protocolo clean-room
- Training materials
- Auditorías (anonimizadas si sensibles)
- Stats similitud mensual

**Objetivo:** Cultura de legalidad, transparencia, orgullo de hacer las cosas bien.

---

### 12.2 Externa (Comunidad Odoo)

**Blog post técnico (post-release):**
- "Cómo construimos Phoenix/Quantum sin violar OEEL-1"
- Mostrar proceso clean-room (sin revelar specs detalladas)
- Compartir tooling (ast_diff.py) como open source
- Invitar contribuciones OCA

**Objetivo:** Validación comunidad, precedente para otros proyectos CE-Pro.

---

## 13. Anexos

### 13.1 Glosario Términos Permitidos vs Prohibidos

| Término Genérico (✅ USAR) | Término Enterprise Específico (❌ EVITAR) |
|---------------------------|------------------------------------------|
| "Menú de aplicaciones tipo grid" | "o_web_enterprise_menu" |
| "Reporte financiero con drill-down" | "account.financial.html.report" (clase exacta) |
| "Vista de lista responsiva" | "o_list_view_enterprise" |
| "Dashboard de KPIs" | "web_dashboard Enterprise module" |
| "Comparador de períodos" | "account_reports_followup comparison engine" |

---

### 13.2 Template Spec Aprobada

```markdown
# Spec: [Nombre Feature Genérico]

**Fecha:** YYYY-MM-DD
**Analista:** [Nombre Equipo A]
**Auditor Legal:** [Nombre]
**Estado:** APPROVED

---

## Comportamiento Observable (UX)

[Describir qué hace el usuario, qué ve, qué pasa]

## Inputs

[Datos que recibe la feature]

## Outputs

[Datos que produce la feature]

## Casos de Uso

1. Usuario hace X → Sistema responde Y
2. ...

## Restricciones No Funcionales

- Performance: < Zs
- Compatibilidad: Browsers X, Y
- Accesibilidad: WCAG 2.1 AA

## Referencias

- Estándar industria: [link público]
- Documentación Odoo CE: [link odoo.com/documentation]

---

**Checklist Auditoría Legal:**

- [ ] CR-SPEC-01 a CR-SPEC-07 PASS

**Firma Digital (SHA-256):** [hash]
**GPG Signature:** [firma auditor]
```

---

## 14. Aprobaciones

| Stakeholder | Rol | Aprobación | Fecha | Firma |
|-------------|-----|------------|-------|-------|
| Legal Counsel | Validador Legal | ✅ Protocolo Clean-Room | _______ | _______ |
| CTO | Sponsor Técnico | ✅ Tooling y Proceso | _______ | _______ |
| Auditor Técnico Lead | Ejecutor Auditorías | ✅ Scripts y Checklists | _______ | _______ |
| PM Proyecto | Coordinador | ✅ Integración Roadmap | _______ | _______ |

---

**Versión:** 1.0
**Próxima Revisión:** Post cada auditoría externa (≥1/año)
**Contacto:** [legal@empresa.cl](mailto:legal@empresa.cl) | [auditor-tecnico@empresa.cl](mailto:auditor-tecnico@empresa.cl)
