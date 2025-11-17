# Workflow Failures - Root Cause Analysis & Solutions

**Proyecto:** Odoo 19 CE - Localización Chile
**Fecha Análisis:** 2025-11-15
**Workflows Analizados:** 4 failing de 5 total
**Commit:** e97996d4bf2daa815fe3287cefa030ccd23961ef

---

## 📊 RESUMEN EJECUTIVO

### Estado Actual

| Workflow | Status | Severidad | Tiempo Fix |
|----------|--------|-----------|------------|
| **CodeQL Security Analysis** | ❌ FAILURE | 🟡 Media | 15 min |
| **Dependency Review** | ❌ FAILURE | 🟢 Baja | 5 min |
| **Quality Gates - Strict** | ❌ FAILURE | 🟡 Media | 30 min |
| **QA Checks** | ❌ FAILURE | 🟢 Baja | 20 min |

**Tiempo Total Fix:** ~70 minutos (1h 10min)
**Complejidad:** Baja-Media (todas son configuración o code quality)
**Riesgo:** Bajo (ningún error bloqueante de producción)

---

## 🔍 ANÁLISIS DETALLADO POR WORKFLOW

### 1. CodeQL Security Analysis ❌

#### Run ID: 19394197953
#### Status: FAILURE
#### Severidad: 🟡 Media

#### Problemas Identificados (3)

##### **Problema 1.1: SARIF File Path Mismatch** (CRÍTICO)

```yaml
Error:
  ##[error]Path does not exist: results/python.sarif

Root Cause:
  - CodeQL genera el SARIF en /home/runner/work/odoo19/results/
  - El step upload-sarif busca en results/python.sarif (relativo)
  - Mismatch de rutas

Impact:
  - Análisis se completa exitosamente
  - Upload falla → No se publican resultados
  - Security tab no se actualiza

Archivo:
  .github/workflows/codeql.yml

Línea Problemática:
  sarif_file: results/python.sarif  # Ruta incorrecta
```

**Solución:**

```yaml
# ANTES (.github/workflows/codeql.yml)
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/python.sarif

# DESPUÉS
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ../results/python.sarif
    # O mejor: usar variable de entorno
    # sarif_file: ${{ runner.temp }}/codeql_databases/python/results/python.sarif
```

---

##### **Problema 1.2: Syntax Error in Template File**

```yaml
Error:
  A parse error occurred while processing:
  /ai-service/docs/PLUGIN_TEMPLATE.py (Line 24)

Root Cause:
  - Archivo de template con syntax Python inválido
  - Probablemente contiene placeholders no válidos

Impact:
  - No bloquea análisis completo
  - 1 archivo excluido de análisis (282/283 analizados)
  - Warning en diagnostic

Archivo:
  ai-service/docs/PLUGIN_TEMPLATE.py:24

Recomendación:
  - Renombrar a .txt si es solo documentación
  - Corregir syntax si debe ser código válido
  - Agregar a .gitignore si es archivo temporal
```

**Solución:**

```bash
# Opción A: Renombrar (recomendado)
mv ai-service/docs/PLUGIN_TEMPLATE.py ai-service/docs/PLUGIN_TEMPLATE.py.example

# Opción B: Excluir de CodeQL
# En .github/workflows/codeql.yml
paths-ignore:
  - 'ai-service/docs/PLUGIN_TEMPLATE.py'

# Opción C: Corregir syntax
# Revisar línea 24 de ai-service/docs/PLUGIN_TEMPLATE.py
```

---

##### **Problema 1.3: Orphan Git Submodule**

```yaml
Error:
  fatal: No url found for submodule path 'docs/facturacion_electronica' in .gitmodules

Root Cause:
  - Directorio docs/facturacion_electronica existe localmente
  - Configurado como submodule en .git/config local
  - NO está en .gitmodules (huérfano)

Impact:
  - Warning en cleanup (no bloquea workflow)
  - Puede causar problemas en fresh clones
  - Inconsistencia git

Evidencia:
  - .gitmodules solo tiene: odoo-docker-base
  - docs/facturacion_electronica existe como directorio

Verificación:
  git config --file .gitmodules --list | grep facturacion
  # (No output → confirmado huérfano)
```

**Solución:**

```bash
# SOLUCIÓN RECOMENDADA: Limpiar submodule huérfano

# 1. Verificar contenido
ls -la docs/facturacion_electronica/

# 2a. Si es código importante → Convertir a directorio normal
git rm --cached docs/facturacion_electronica
git add docs/facturacion_electronica/
git commit -m "fix: convert orphan submodule to regular directory"

# 2b. Si es basura → Eliminar
git rm -rf docs/facturacion_electronica
git commit -m "chore: remove orphan submodule directory"

# 3. Limpiar config local (opcional, automático en CI)
git config --local --remove-section submodule.docs/facturacion_electronica 2>/dev/null || true
```

---

### 2. Dependency Review ❌

#### Run ID: 19394197945
#### Status: FAILURE
#### Severidad: 🟢 Baja

#### Problema Identificado

```yaml
Error:
  {
    "code": "custom",
    "message": "You cannot specify both allow-licenses and deny-licenses"
  }

Root Cause:
  - Workflow configurado con allow-licenses Y deny-licenses
  - actions/dependency-review-action@v4 no permite ambos simultáneamente
  - Error de configuración

Impact:
  - Workflow falla inmediatamente
  - No se ejecuta dependency review
  - PRs no tienen protección de licencias

Archivo:
  .github/workflows/dependency-review.yml

Línea Problemática:
  fail-on-severity: high
  deny-licenses: GPL-3.0, AGPL-3.0
  allow-licenses: MIT, Apache-2.0, BSD-3-Clause, LGPL-3.0, LGPL-2.1
```

**Solución:**

```yaml
# ANTES (.github/workflows/dependency-review.yml)
- name: Review Dependencies
  uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: high
    deny-licenses: GPL-3.0, AGPL-3.0  # ❌ Conflicto
    allow-licenses: MIT, Apache-2.0, BSD-3-Clause, LGPL-3.0, LGPL-2.1  # ❌ Conflicto

# DESPUÉS (OPCIÓN A - Usar solo deny-licenses)
- name: Review Dependencies
  uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: high
    deny-licenses: GPL-3.0, AGPL-3.0, Proprietary, Unknown
    # Deniega licencias problemáticas, permite el resto

# DESPUÉS (OPCIÓN B - Usar solo allow-licenses) [RECOMENDADO]
- name: Review Dependencies
  uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: high
    allow-licenses: MIT, Apache-2.0, BSD-3-Clause, BSD-2-Clause, LGPL-3.0, LGPL-2.1, ISC, MPL-2.0
    # Lista explícita de licencias permitidas (whitelist approach)
```

**Recomendación:** Usar **OPCIÓN B** (allow-licenses solo) - Approach más seguro y explícito.

---

### 3. Quality Gates - Strict ❌

#### Run ID: 19394197944
#### Status: FAILURE
#### Severidad: 🟡 Media

#### Problema Identificado

```yaml
Error:
  Gate 3: Security (Bandit)
  ##[error]Process completed with exit code 1.

Summary:
  | 1️⃣ Syntax Check    | success |
  | 2️⃣ Code Quality    | success |
  | 3️⃣ Security Scan   | failure |  ← BLOQUEANTE
  | 4️⃣ Module Structure| success |
  | 5️⃣ Unit Tests      | success |

Root Cause:
  - Bandit (security scanner) encontró vulnerabilidades en código
  - Configurado para fallar en severidad media/alta
  - 4/5 gates pasaron, pero 1 failure bloquea todo

Impact:
  - Workflow completo falla
  - PR no puede mergearse (si required check)
  - Código tiene security issues reales

Tool: Bandit (Python security linter)
Artifact: bandit-security-report.json (generado)
```

**Análisis de Vulnerabilidades:**

Para ver detalle de las vulnerabilidades:

```bash
# Descargar artifact
gh run download 19394197944 --name bandit-security-report

# Ver reporte
cat bandit-report.json | jq '.results[] | {
  issue: .issue_text,
  severity: .issue_severity,
  confidence: .issue_confidence,
  file: .filename,
  line: .line_number
}'
```

**Soluciones Típicas:**

```python
# ISSUE COMÚN 1: Assert used (B101)
# ANTES
assert user.is_authenticated, "User must be authenticated"

# DESPUÉS
if not user.is_authenticated:
    raise ValueError("User must be authenticated")

# ISSUE COMÚN 2: Hardcoded password (B105, B106)
# ANTES
password = "admin123"  # ❌

# DESPUÉS
password = os.getenv('ADMIN_PASSWORD')  # ✅

# ISSUE COMÚN 3: SQL injection (B608)
# ANTES
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # ❌

# DESPUÉS
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # ✅

# ISSUE COMÚN 4: Use of exec (B102)
# ANTES
exec(user_input)  # ❌ NUNCA

# DESPUÉS
# Validar y sanitizar input, evitar exec()
```

**Solución Workflow:**

Si quieres hacer el workflow menos estricto temporalmente:

```yaml
# .github/workflows/quality-gates.yml

# ANTES
- name: Gate 3 - Security (Bandit)
  run: |
    bandit -r . -f json -o bandit-report.json
    # Falla si encuentra issues

# DESPUÉS (menos estricto)
- name: Gate 3 - Security (Bandit)
  run: |
    bandit -r . -f json -o bandit-report.json -ll  # Solo low-severity
    # O con continue-on-error
  continue-on-error: true  # ⚠️ No recomendado para production

# MEJOR: Configurar baseline
- name: Gate 3 - Security (Bandit)
  run: |
    # Generar baseline inicial
    bandit -r . -f json -o bandit-baseline.json
    # Luego solo fallar en nuevos issues
    bandit -r . -f json -o bandit-report.json --baseline bandit-baseline.json
```

**Recomendación:** ⚠️ **NO ignorar security issues**. Revisar y corregir cada vulnerabilidad.

---

### 4. QA Checks ❌

#### Run ID: 19394197941
#### Status: FAILURE
#### Severidad: 🟢 Baja

#### Problemas Identificados (Linting - Ruff)

```yaml
Tool: Ruff (Fast Python linter)
Total Issues: ~15+
Categories:
  - F401: Imports not used
  - F841: Variable assigned but never used
  - F541: f-string without placeholders

Impact:
  - Código funciona correctamente
  - Code quality degradada
  - Workflow falla en strict mode

Archivos Afectados:
  - addons/localization/l10n_cl_dte/libs/exceptions.py
  - addons/localization/l10n_cl_dte/libs/i18n.py
  - addons/localization/l10n_cl_dte/libs/sii_soap_client.py
  - addons/localization/l10n_cl_dte/libs/sii_token_manager.py
  - addons/localization/l10n_cl_dte/migrations/19.0.1.0.4/post-migrate_preserve_signatures.py
  - addons/localization/l10n_cl_dte/models/__init__.py
```

#### Detalle de Issues

##### **Issue 1: F401 - Unused Imports**

```python
# ARCHIVO: libs/exceptions.py:52
# ANTES
import sys
module = sys.modules[__name__]  # ❌ F841: module never used

# DESPUÉS (Opción A - Usar la variable)
import sys
module = sys.modules[__name__]
module.SIIAuthError = DTEAuthenticationError  # Usar para aliases

# DESPUÉS (Opción B - Eliminar si no se usa)
# Simplemente eliminar líneas 51-52

---

# ARCHIVO: libs/i18n.py:70
# ANTES
try:
    from odoo import api  # ❌ F401: imported but unused

# DESPUÉS
try:
    from odoo import api
    # Si realmente no se usa, eliminar
    # O agregar noqa si es intencional para imports condicionales
    from odoo import api  # noqa: F401

---

# ARCHIVO: libs/sii_token_manager.py:26
# ANTES
from cryptography.hazmat.backends import default_backend  # ❌ F401

# DESPUÉS
# Si default_backend ya no se usa en cryptography moderna:
# Eliminar import

# Si se usaba antes:
# Verificar que la funcionalidad siga funcionando sin él

---

# ARCHIVO: libs/sii_soap_client.py:32
# ANTES
import logging  # ❌ F401: imported but unused

# DESPUÉS
# Si no se usa logging en este archivo:
# Eliminar import

# O si se usará estructlog:
import structlog  # ✅ Reemplazar
```

##### **Issue 2: F541 - f-string Without Placeholders**

```python
# ARCHIVO: libs/sii_soap_client.py:263
# ANTES
raise UserError(f"Token de autenticación inválido")  # ❌ No placeholders

# DESPUÉS
raise UserError("Token de autenticación inválido")  # ✅ String normal

---

# ARCHIVO: migrations/.../post-migrate_preserve_signatures.py:278
# ANTES
_logger.info(f"Iniciando migración de firmas")  # ❌

# DESPUÉS
_logger.info("Iniciando migración de firmas")  # ✅
```

##### **Issue 3: F401 - Import Without `__all__`**

```python
# ARCHIVO: models/__init__.py:28-29
# ANTES
from . import dte_backup  # ❌ Implicit export
from . import dte_failed_queue  # ❌ Implicit export

# DESPUÉS (Opción A - Explicit re-export)
from . import dte_backup as dte_backup
from . import dte_failed_queue as dte_failed_queue

# DESPUÉS (Opción B - Add to __all__)
__all__ = ['dte_backup', 'dte_failed_queue']
from . import dte_backup
from . import dte_failed_queue

# DESPUÉS (Opción C - noqa si intencional)
from . import dte_backup  # noqa: F401
from . import dte_failed_queue  # noqa: F401
```

#### Auto-Fix con Ruff

```bash
# Auto-fix todos los issues (RECOMENDADO)
ruff check --fix addons/localization/l10n_cl_dte/

# Preview cambios antes de aplicar
ruff check addons/localization/l10n_cl_dte/

# Fix por categoría
ruff check --fix --select F401 addons/  # Solo unused imports
ruff check --fix --select F541 addons/  # Solo f-string issues

# Verificar después del fix
ruff check addons/localization/l10n_cl_dte/
```

---

## 🛠️ PLAN DE CORRECCIÓN COMPLETO

### Prioridad 1: Fixes Rápidos (15 minutos)

#### Fix 1: Dependency Review (5 min)

```bash
# Editar workflow
nano .github/workflows/dependency-review.yml

# Cambiar a:
# allow-licenses: MIT, Apache-2.0, BSD-3-Clause, LGPL-3.0, LGPL-2.1, ISC
# Eliminar: deny-licenses

# Commit
git add .github/workflows/dependency-review.yml
git commit -m "fix(ci): resolve dependency-review license conflict"
```

#### Fix 2: QA Checks - Linting (10 min)

```bash
# Auto-fix con Ruff
cd /Users/pedro/Documents/odoo19
ruff check --fix addons/localization/l10n_cl_dte/

# Review cambios
git diff

# Commit
git add -A
git commit -m "style(l10n_cl_dte): auto-fix linting issues (F401, F541, F841)"
```

---

### Prioridad 2: Fixes Medios (30 minutos)

#### Fix 3: CodeQL SARIF Path (5 min)

```bash
# Editar workflow
nano .github/workflows/codeql.yml

# Buscar línea con sarif_file
# Cambiar a: ../results/python.sarif

# Commit
git add .github/workflows/codeql.yml
git commit -m "fix(ci): correct CodeQL SARIF file path"
```

#### Fix 4: Orphan Submodule (5 min)

```bash
# Verificar contenido
ls -la docs/facturacion_electronica/

# Si está vacío o es temporal:
git rm -rf docs/facturacion_electronica
git commit -m "chore: remove orphan submodule directory"

# Si tiene contenido importante:
git rm --cached docs/facturacion_electronica
git add docs/facturacion_electronica/
git commit -m "fix: convert orphan submodule to regular directory"
```

#### Fix 5: Template Syntax Error (5 min)

```bash
# Revisar archivo
python3 -m py_compile ai-service/docs/PLUGIN_TEMPLATE.py

# Si falla:
mv ai-service/docs/PLUGIN_TEMPLATE.py ai-service/docs/PLUGIN_TEMPLATE.py.example

# Commit
git add ai-service/docs/
git commit -m "fix: rename template to avoid CodeQL parse error"
```

#### Fix 6: Security Issues - Bandit (15 min)

```bash
# Generar reporte detallado
cd /Users/pedro/Documents/odoo19
pip install bandit
bandit -r addons/localization/l10n_cl_dte/ -f json -o bandit-report.json

# Review issues
cat bandit-report.json | jq '.results[] | {issue, severity, file, line}'

# Fix cada issue manualmente
# (Depende de los issues específicos encontrados)

# Verificar
bandit -r addons/localization/l10n_cl_dte/

# Commit
git add -A
git commit -m "fix(security): resolve Bandit security issues"
```

---

### Prioridad 3: Verificación (10 minutos)

```bash
# Push todos los fixes
git push origin develop

# Esperar workflows (o trigger manual)
gh workflow run "CodeQL Security Analysis"
gh workflow run "Dependency Review"
gh workflow run "Quality Gates - Strict"
gh workflow run "QA Checks"

# Monitorear
gh run list --limit 10

# Verificar success
gh run view <run-id>
```

---

## 📋 COMANDOS COMPLETOS (Copy-Paste Ready)

### Script de Fix Automático

```bash
#!/bin/bash
# fix_workflows.sh - Auto-fix todos los workflows failing

set -e  # Exit on error
cd /Users/pedro/Documents/odoo19

echo "🔧 Starting workflow fixes..."

# ═══════════════════════════════════════════════════════════
# FIX 1: Dependency Review (5 min)
# ═══════════════════════════════════════════════════════════
echo "📦 Fix 1: Dependency Review license conflict..."

cat > .github/workflows/dependency-review.yml.tmp <<'EOF'
name: 📦 Dependency Review

on:
  pull_request:
    branches: [ main, develop ]

jobs:
  review:
    name: 📦 Review Dependencies
    runs-on: ubuntu-latest

    steps:
      - name: 📥 Checkout code
        uses: actions/checkout@v4

      - name: 📦 Dependency Review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          allow-licenses: MIT, Apache-2.0, BSD-3-Clause, BSD-2-Clause, LGPL-3.0, LGPL-2.1, ISC, MPL-2.0
          # Removed: deny-licenses (conflicts with allow-licenses)
EOF

mv .github/workflows/dependency-review.yml.tmp .github/workflows/dependency-review.yml
git add .github/workflows/dependency-review.yml

# ═══════════════════════════════════════════════════════════
# FIX 2: QA Checks - Linting (10 min)
# ═══════════════════════════════════════════════════════════
echo "🧹 Fix 2: Auto-fix linting issues..."

# Install ruff if needed
command -v ruff >/dev/null 2>&1 || pip install ruff

# Auto-fix
ruff check --fix addons/localization/l10n_cl_dte/ || true
git add addons/localization/l10n_cl_dte/

# ═══════════════════════════════════════════════════════════
# FIX 3: CodeQL SARIF Path (5 min)
# ═══════════════════════════════════════════════════════════
echo "🔒 Fix 3: CodeQL SARIF path..."

# Backup
cp .github/workflows/codeql.yml .github/workflows/codeql.yml.backup

# Fix path (buscar y reemplazar)
sed -i.bak 's|sarif_file: results/python.sarif|sarif_file: ../results/python.sarif|g' .github/workflows/codeql.yml
rm .github/workflows/codeql.yml.bak
git add .github/workflows/codeql.yml

# ═══════════════════════════════════════════════════════════
# FIX 4: Orphan Submodule (5 min)
# ═══════════════════════════════════════════════════════════
echo "📁 Fix 4: Remove orphan submodule..."

if [ -d "docs/facturacion_electronica" ]; then
    git rm -rf docs/facturacion_electronica || true
fi

# ═══════════════════════════════════════════════════════════
# FIX 5: Template Syntax Error (5 min)
# ═══════════════════════════════════════════════════════════
echo "📄 Fix 5: Rename template file..."

if [ -f "ai-service/docs/PLUGIN_TEMPLATE.py" ]; then
    mv ai-service/docs/PLUGIN_TEMPLATE.py ai-service/docs/PLUGIN_TEMPLATE.py.example
    git add ai-service/docs/
fi

# ═══════════════════════════════════════════════════════════
# COMMIT ALL FIXES
# ═══════════════════════════════════════════════════════════
echo "💾 Committing all fixes..."

git commit -m "fix(ci): resolve all workflow failures

- fix(ci/dependency-review): remove deny-licenses conflict
- style(l10n_cl_dte): auto-fix linting issues (Ruff)
- fix(ci/codeql): correct SARIF file path
- chore(git): remove orphan submodule directory
- fix(docs): rename template to avoid parse error

Resolves 4 failing workflows:
- CodeQL Security Analysis
- Dependency Review
- Quality Gates - Strict (partial)
- QA Checks

🤖 Generated with automation script
" || echo "Nothing to commit (already fixed?)"

echo "✅ Fixes completed!"
echo ""
echo "Next steps:"
echo "  1. Review changes: git show"
echo "  2. Push: git push origin develop"
echo "  3. Monitor: gh run list --limit 10"
```

**Guardar como:** `scripts/fix_workflows.sh`

**Ejecutar:**

```bash
chmod +x scripts/fix_workflows.sh
./scripts/fix_workflows.sh
```

---

## 🎯 RESULTADOS ESPERADOS

### Después de Aplicar Fixes

| Workflow | ANTES | DESPUÉS | Status |
|----------|-------|---------|--------|
| **CodeQL Security Analysis** | ❌ | ✅ | Fixed |
| **Dependency Review** | ❌ | ✅ | Fixed |
| **Quality Gates - Strict** | ❌ | ⚠️ | Depende Security Issues |
| **QA Checks** | ❌ | ✅ | Fixed |

**Overall Success Rate:** 75-100% (depende de Bandit issues)

---

## ⚠️ ADVERTENCIAS Y CONSIDERACIONES

### Security Issues (Bandit)

**NO aplicar fixes automáticos sin revisar.**

Cada vulnerabilidad requiere análisis:
- ¿Es falso positivo?
- ¿Es riesgo real?
- ¿Cuál es el fix correcto?

**Workflow:**
1. Generar reporte: `bandit -r . -f json`
2. Revisar cada issue manualmente
3. Fix uno por uno
4. Test después de cada fix
5. Commit con descripción detallada

---

## 📊 MÉTRICAS DE ÉXITO

### KPIs Post-Fix

```yaml
Workflow Success Rate:
  Target: >95%
  Before: 20% (1/5 success)
  After: 80-100% (4-5/5 success)

Linting Issues:
  Target: 0
  Before: ~15+
  After: 0

Security Issues:
  Target: 0 high/critical
  Before: TBD (pending Bandit review)
  After: 0
```

---

## 📝 CHANGELOG

### 2025-11-15

**Analyzed:**
- ✅ CodeQL Security Analysis (3 issues)
- ✅ Dependency Review (1 issue)
- ✅ Quality Gates - Strict (1 issue)
- ✅ QA Checks (15+ issues)

**Created:**
- Script de fix automático
- Documentación completa
- Comandos copy-paste ready

**Pending:**
- Ejecutar fixes
- Validar resultados
- Update branch protection si needed

---

**Mantenido por:** @pwills85
**Última actualización:** 2025-11-15
**Versión:** 1.0

