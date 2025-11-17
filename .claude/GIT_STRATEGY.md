# Git & GitHub Strategy - Odoo 19 CE Localization Chile

**Versión**: 1.0.0
**Fecha**: 2025-11-15
**Estado**: Activo
**Última Revisión**: Análisis post-merge audit-p1-ciclo4

---

## 📋 Resumen Ejecutivo

Esta estrategia define cómo gestionar el control de versiones en nuestro proyecto de localización Odoo 19 CE para Chile, balanceando:
- ✅ Cohesión entre módulos relacionados
- ✅ Versionado independiente por componente
- ✅ Prevención de conflictos de merge
- ✅ Integración continua efectiva

**Problema Identificado**: Monorepo accidental con merges masivos, conflictos frecuentes y código ocasionalmente "destruido" por resolución automática.

**Solución**: Monorepo curado + migración gradual a multi-repo temático.

---

## 🎯 Objetivos Estratégicos

### Corto Plazo (0-3 meses)

1. **Eliminar merges destructivos**
   - Integración diaria a `develop`
   - Feature branches max 3 días
   - Pre-commit hooks de validación

2. **Separar concerns principales**
   - AI-service → Repositorio independiente
   - Documentación → GitHub Pages/Wiki
   - Solo código productivo en repo principal

3. **Versionado granular**
   - Tags por módulo: `l10n_cl_dte/19.0.7.0.0`
   - Releases independientes
   - CHANGELOG por módulo

### Medio Plazo (3-6 meses)

1. **CI/CD selectivo**
   - Solo test módulos modificados
   - Caché inteligente
   - Builds paralelos

2. **Workflow profesional**
   - Conventional Commits obligatorios
   - Semantic versioning estricto
   - Release automation

3. **Documentación técnica**
   - Architecture Decision Records (ADRs)
   - API documentation automática
   - Change management process

### Largo Plazo (6-12 meses)

1. **Evaluación multi-repo**
   - Módulos maduros → repos independientes
   - Estilo OCA (repos temáticos)
   - Gestión de dependencias avanzada

2. **Tooling enterprise**
   - Evaluación Pants/Bazel para monorepo
   - Monorepo profesional si se mantiene
   - Performance optimization

---

## 🏗️ Arquitectura de Repositorios

### Estado Actual (Noviembre 2025)

```
pwills85/odoo19 (MONOREPO)
├── addons/
│   ├── localization/          # 4 módulos custom (69MB)
│   │   ├── l10n_cl_dte/
│   │   ├── l10n_cl_hr_payroll/
│   │   ├── l10n_cl_financial_reports/
│   │   └── eergygroup_branding/
│   └── [187 módulos Odoo estándar]
├── ai-service/                # 7.7MB - Microservicio
├── docs/                      # 207MB - Documentación
├── scripts/                   # 2.7MB - Automatización
├── docker-compose.yml
└── [20+ directorios de soporte]

Problemas:
- ❌ 305 commits/mes (alta velocidad)
- ❌ 17 conflictos en 2 meses
- ❌ Merges masivos (176 commits hoy)
- ❌ Documentación 3x código
```

### Estado Objetivo (Fase 1 - 3 meses)

```
REPOSITORIO PRINCIPAL (Curado)
pwills85/odoo19
├── addons/
│   └── localization/          # Solo módulos custom
│       ├── l10n_cl_dte/
│       ├── l10n_cl_hr_payroll/
│       ├── l10n_cl_financial_reports/
│       └── eergygroup_branding/
├── docker/                    # Infraestructura mínima
├── .github/                   # CI/CD workflows
└── scripts/                   # Solo scripts esenciales

REPOSITORIOS SEPARADOS
eergygroup/ai-service          # Microservicio independiente
├── FastAPI backend
├── Claude API integration
└── Independent versioning (v1.2.3)

DOCUMENTACIÓN
GitHub Wiki / Pages             # Docs separados del código
├── Architecture
├── Deployment guides
└── API reference

MÓDULOS ESTÁNDAR ODOO
NO tracked en Git               # Gestionados por pip/apt
├── Instalados via requirements.txt
└── O via Odoo package manager
```

### Estado Objetivo (Fase 2 - 6-12 meses - OPCIONAL)

```
MULTI-REPO TEMÁTICO (Estilo OCA)

eergygroup/l10n-chile
├── l10n_cl_dte/
├── l10n_cl_hr_payroll/
├── l10n_cl_financial_reports/
└── eergygroup_branding/
Branches: 18.0, 19.0, 20.0 (por versión Odoo)

eergygroup/ai-service
└── Microservicio FastAPI
Branches: main, develop

eergygroup/odoo-deployment
├── docker-compose.yml
├── config/
└── scripts/
Branches: main, develop, staging, production
```

---

## 📊 Estrategia de Branching

### Modelo: **Simplified Git Flow**

```
main (production-ready)
  │
  ├── Tag: v19.0.1.0 (release completa)
  │   ├── Tag: l10n_cl_dte/19.0.6.0.0
  │   ├── Tag: l10n_cl_payroll/19.0.2.1.0
  │   └── Tag: l10n_cl_financial_reports/19.0.3.0.0
  │
develop (integration)
  │
  ├── feature/dte-new-validation (max 3 días)
  ├── fix/payroll-afp-calculation (max 3 días)
  └── refactor/finrep-performance (max 3 días)
```

### Reglas de Branches

**Branch `main`**:
- ✅ Solo código en producción
- ✅ Merge solo desde `develop` via PR
- ✅ Requiere: Tests pasan + Code review + QA approval
- ✅ Auto-deploy a producción (si configurado)
- 🚫 NO commits directos
- 🚫 NO force push NUNCA

**Branch `develop`**:
- ✅ Código integrado y testeado
- ✅ Merge diario desde feature branches
- ✅ Requiere: Tests pasan + Pre-commit hooks
- ✅ Deploy a staging automático
- 🚫 NO commits directos (usar feature branches)
- 🚫 NO branches >100 commits sin merge

**Feature Branches**:
- ✅ Naming: `feature/module-description`
  - Ejemplos: `feature/dte-commercial-validator`
  - `fix/payroll-previred-integration`
  - `refactor/finrep-database-indexes`
- ✅ Max 3 días de vida
- ✅ Max 50 commits antes de merge
- ✅ Squash merge a `develop` (historia limpia)
- ✅ Delete después de merge
- 🚫 NO long-lived branches (>1 semana)
- 🚫 NO acumular >100 commits

**Release Branches** (opcional):
- ✅ Naming: `release/19.0.7.0.0`
- ✅ Solo para preparar release
- ✅ Bug fixes menores permitidos
- ✅ Merge a `main` y back-merge a `develop`
- 🚫 NO nuevas features

---

## 🔖 Estrategia de Versionado

### Semantic Versioning para Módulos Odoo

**Formato**: `ODOO_VERSION.MAJOR.MINOR.PATCH`

```
Ejemplo: 19.0.6.2.1
         │   │ │ │
         │   │ │ └─ PATCH: Bug fixes, no breaking changes
         │   │ └─── MINOR: New features, backward compatible
         │   └───── MAJOR: Breaking changes
         └───────── ODOO VERSION: 19.0 (Odoo 19 CE)
```

**Reglas de Bump**:

```python
# PATCH (19.0.6.2.0 → 19.0.6.2.1)
- Bug fixes
- Typo corrections
- Documentation updates
- Performance improvements (no API changes)

# MINOR (19.0.6.2.1 → 19.0.6.3.0)
- New features
- New fields/models (backward compatible)
- New API endpoints
- Dependencies updates (compatible)

# MAJOR (19.0.6.3.0 → 19.0.7.0.0)
- Breaking API changes
- Database migrations required
- Removed features/fields
- Incompatible dependency updates
- Consolidation/refactoring major

# ODOO VERSION (19.0.7.0.0 → 20.0.1.0.0)
- Migration to new Odoo version
- Only when Odoo core version changes
```

### Git Tags por Módulo

```bash
# Cada módulo tiene su propio versionado
git tag l10n_cl_dte/19.0.6.0.0 -m "Release: DTE v6.0.0 - Commercial Validator"
git tag l10n_cl_hr_payroll/19.0.2.1.0 -m "Release: Payroll v2.1.0 - Previred API v2"
git tag l10n_cl_financial_reports/19.0.3.0.0 -m "Release: Reports v3.0.0 - F29 automation"

# Tag de release completa (todos los módulos juntos)
git tag v19.0.1.0 -m "Release 19.0.1.0 - Production Ready"

# Push tags
git push origin --tags
```

### CHANGELOG por Módulo

```markdown
# addons/localization/l10n_cl_dte/CHANGELOG.md

## [19.0.6.0.0] - 2025-11-15

### Added
- Commercial Validator (377 LOC) for automatic DTE validation
- 8-day SII deadline validation (Art. 54 DL 824)
- 2% tolerance for PO matching
- Reference coherence validation for NC/ND

### Changed
- Improved performance metrics (5ms avg per validation)
- Updated exception handling to Pure Python pattern

### Fixed
- Dependabot security vulnerabilities (5 CVEs)
- XPath deprecations for Odoo 19 CE compliance

### Deprecated
- Old validation methods (will be removed in 20.0.1.0.0)

## [19.0.5.0.0] - 2025-11-13
...
```

---

## 🔄 Workflow de Desarrollo

### Ciclo Diario Ideal

```bash
# ============================================
# INICIO DEL DÍA
# ============================================

# 1. Actualizar develop
git checkout develop
git pull origin develop

# 2. Crear feature branch
git checkout -b feature/dte-add-validation

# ============================================
# DURANTE EL DÍA (Commits frecuentes)
# ============================================

# 3. Trabajar y commit frecuentemente
git add addons/localization/l10n_cl_dte/libs/validator.py
git commit -m "feat(l10n_cl_dte): add CAF expiration validator"

# Pre-commit hooks corren automáticamente:
# ✓ Black (formatting)
# ✓ Flake8 (linting)
# ✓ isort (imports)
# ✓ pylint (quality)
# ✓ Unit tests affected modules

# 4. Más trabajo
git add addons/localization/l10n_cl_dte/tests/test_caf_validator.py
git commit -m "test(l10n_cl_dte): add CAF validator tests (coverage 95%)"

# 5. Push frecuente (backup en cloud)
git push origin feature/dte-add-validation

# ============================================
# FIN DEL DÍA (Merge a develop)
# ============================================

# 6. Actualizar con develop (por si hay cambios)
git checkout develop
git pull origin develop
git checkout feature/dte-add-validation
git rebase develop  # O merge develop si prefieres

# 7. Crear Pull Request
gh pr create --title "feat(l10n_cl_dte): Add CAF expiration validator" \
  --body "$(cat <<EOF
## Summary
- Adds CAF (Código de Autorización de Folios) expiration validation
- Prevents using expired CAF for DTE emission
- Adds comprehensive test coverage (95%)

## Changes
- \`libs/caf_validator.py\`: New validator class
- \`tests/test_caf_validator.py\`: Unit tests
- \`models/dte_caf.py\`: Integration with existing CAF model

## Testing
- [ ] Unit tests pass (pytest)
- [ ] Integration tests pass
- [ ] Manual testing in staging
- [ ] Code review by @team-dte

## Breaking Changes
None - backward compatible

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)" \
  --base develop

# 8. Esperar CI/CD y Code Review
# - GitHub Actions corre tests
# - Reviewers aprueban
# - Squash merge a develop

# 9. Delete feature branch
git checkout develop
git pull origin develop
git branch -d feature/dte-add-validation
git push origin --delete feature/dte-add-validation
```

### Reglas de Commits

**Conventional Commits** (Obligatorio):

```bash
# Formato:
<type>(<scope>): <subject>

<body (opcional)>

<footer (opcional)>

# Types permitidos:
feat:     Nueva funcionalidad
fix:      Bug fix
refactor: Refactoring (sin cambio funcional)
perf:     Performance improvement
test:     Añadir/modificar tests
docs:     Documentación
style:    Formatting, missing semicolons, etc.
chore:    Mantenimiento, dependencies, etc.
ci:       CI/CD changes
build:    Build system changes

# Scopes (módulos):
l10n_cl_dte
l10n_cl_hr_payroll
l10n_cl_financial_reports
eergygroup_branding
ai-service
infra
docs

# Ejemplos CORRECTOS:
feat(l10n_cl_dte): add commercial validator with SII compliance
fix(l10n_cl_hr_payroll): correct AFP calculation for mixed contracts
refactor(l10n_cl_financial_reports): optimize F29 report query (10x faster)
test(l10n_cl_dte): increase coverage to 95% for validators
docs(l10n_cl_hr_payroll): add Previred API integration guide
chore(deps): bump anthropic SDK to v0.8.1

# Ejemplos INCORRECTOS:
❌ "fixed bug"              # No scope, no description
❌ "WIP"                    # No informativo
❌ "changes"                # Demasiado genérico
❌ "Update file.py"         # No dice QUÉ ni POR QUÉ
❌ "Merge branch..."        # Usar squash merge
```

**Commit Size Guidelines**:

```yaml
🟢 IDEAL (Atomic Commit):
  Lines changed: 1-100
  Files: 1-5
  Focus: Single concern
  Example: "feat(l10n_cl_dte): add email validation in DTE receiver"

🟡 ACCEPTABLE:
  Lines changed: 100-300
  Files: 5-15
  Focus: Related changes
  Example: "refactor(l10n_cl_dte): consolidate validation logic"

🔴 TOO LARGE (Split it):
  Lines changed: >300
  Files: >15
  Focus: Multiple concerns
  Action: Split into multiple commits
```

---

## 🚀 Release Process

### Preparación de Release

```bash
# ============================================
# PASO 1: Decidir qué liberar
# ============================================

# Revisar cambios desde último release
git log l10n_cl_dte/19.0.6.0.0..develop --oneline -- addons/localization/l10n_cl_dte/

# Determinar tipo de bump (PATCH, MINOR, MAJOR)
# MINOR si hay nuevas features

# ============================================
# PASO 2: Actualizar versión en código
# ============================================

# Editar __manifest__.py
# addons/localization/l10n_cl_dte/__manifest__.py:
{
    'name': 'Chilean Localization - Electronic Invoicing (DTE)',
    'version': '19.0.7.0.0',  # ← Bump version
    ...
}

# Commit version bump
git add addons/localization/l10n_cl_dte/__manifest__.py
git commit -m "chore(l10n_cl_dte): bump version to 19.0.7.0.0"

# ============================================
# PASO 3: Generar CHANGELOG
# ============================================

# Usar script automático (crear si no existe)
python scripts/generate_changelog.py l10n_cl_dte 19.0.7.0.0

# Review y editar CHANGELOG.md
# addons/localization/l10n_cl_dte/CHANGELOG.md

git add addons/localization/l10n_cl_dte/CHANGELOG.md
git commit -m "docs(l10n_cl_dte): update CHANGELOG for v19.0.7.0.0"

# ============================================
# PASO 4: Crear Tag y Release
# ============================================

# Merge a main si es producción
git checkout main
git merge develop --no-ff

# Crear tag anotado
git tag -a l10n_cl_dte/19.0.7.0.0 -m "Release: DTE v7.0.0

Features:
- CAF expiration validation
- Enhanced error messages
- Performance improvements (20% faster)

Bug Fixes:
- Fixed timezone handling in DTE timestamps
- Corrected RUT validation for edge cases

Breaking Changes:
None - fully backward compatible
"

# Push tag
git push origin l10n_cl_dte/19.0.7.0.0

# ============================================
# PASO 5: GitHub Release (Opcional)
# ============================================

gh release create l10n_cl_dte/19.0.7.0.0 \
  --title "l10n_cl_dte v19.0.7.0.0 - CAF Validation" \
  --notes-file addons/localization/l10n_cl_dte/CHANGELOG.md \
  --target main

# ============================================
# PASO 6: Back-merge a develop
# ============================================

git checkout develop
git merge main --no-ff
git push origin develop
```

### Release Checklist

```markdown
## Pre-Release
- [ ] Todos los tests pasan (CI/CD green)
- [ ] Code review completado
- [ ] Documentation actualizada
- [ ] CHANGELOG generado
- [ ] Version bumped en __manifest__.py
- [ ] Breaking changes documentados
- [ ] Migration scripts creados (si aplica)

## Release
- [ ] Tag creado: `l10n_cl_dte/19.0.X.Y.Z`
- [ ] GitHub Release publicado
- [ ] Release notes publicadas
- [ ] Stakeholders notificados

## Post-Release
- [ ] Monitoring 24h sin errores
- [ ] Back-merge a develop completado
- [ ] Documentación deployment actualizada
- [ ] Lessons learned documentadas
```

---

## 🛡️ Prevención de Conflictos

### Estrategias Proactivas

**1. Integración Continua Agresiva**

```yaml
Regla de Oro: "Integrate Early, Integrate Often"

✅ DO:
  - Merge a develop DIARIAMENTE
  - Feature branches max 3 días
  - Rebase desde develop antes de PR
  - Squash merge para historia limpia

❌ DON'T:
  - Branches >100 commits sin merge
  - Acumular cambios por semanas
  - "Big bang merges" (176 commits)
  - Ignorar conflictos hasta el final
```

**2. Ownership de Código**

```bash
# .github/CODEOWNERS
addons/localization/l10n_cl_dte/          @team-dte @pedro
addons/localization/l10n_cl_hr_payroll/   @team-payroll @maria
addons/localization/l10n_cl_financial_reports/ @team-reports @juan
ai-service/                               @team-ai @pedro

# Beneficios:
# - Menos conflictos (equipos separados)
# - Review automático por owners
# - Responsabilidad clara
```

**3. Pre-commit Hooks Estrictos**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: check-commit-size
        name: Check commit size (<500 lines)
        entry: python scripts/check_commit_size.py
        language: system
        pass_filenames: false

      - id: validate-manifest-version
        name: Validate __manifest__.py version
        entry: python scripts/validate_manifest_version.py
        language: system
        files: '__manifest__\.py$'

      - id: prevent-large-files
        name: Prevent files >5MB
        entry: python scripts/prevent_large_files.py
        language: system

# Bloquea commits problemáticos ANTES de push
```

**4. Comunicación de Cambios Grandes**

```markdown
# PROTOCOL: Large Changes

Si vas a hacer cambios que afectan:
- >5 archivos en módulo compartido
- Refactoring de arquitectura
- Changes en modelos core
- Database migrations

DEBES:
1. Crear RFC (Request for Comments) en GitHub Discussions
2. Notificar en Slack #dev-odoo
3. Coordinar con owners del código
4. Crear feature branch con nombre descriptivo
5. Merge en horario coordinado (no viernes 5pm)
```

### Resolución de Conflictos

**Cuando Ocurren Conflictos**:

```bash
# ============================================
# NUNCA usar resolución automática ciega
# ============================================

# ❌ MALO (lo que causó código destruido):
git merge develop -X ours  # Acepta todo de develop
# Puede sobrescribir trabajo importante

# ✅ BUENO (resolución consciente):
git merge develop
# Revisar CADA conflicto manualmente
# Entender QUÉ cambió y POR QUÉ
# Test después de resolver

# ============================================
# Herramientas recomendadas
# ============================================

# VSCode merge editor (built-in)
code --merge <file>

# Meld (visual diff/merge)
git mergetool --tool=meld

# P4Merge (3-way merge)
git mergetool --tool=p4merge

# ============================================
# Proceso de resolución
# ============================================

1. Entender el conflicto
   git log --oneline develop..feature/my-branch -- <conflicted-file>
   git log --oneline feature/my-branch..develop -- <conflicted-file>

2. Resolver manualmente
   # Editar archivo, elegir cambios apropiados

3. Verificar con tests
   pytest addons/localization/<module>/tests/

4. Commit de resolución
   git add <resolved-file>
   git commit -m "merge: resolve conflicts in <file> - keep both changes"

5. Pedir code review si no estás 100% seguro
```

---

## 📈 Métricas de Salud Git

### KPIs a Monitorear

```python
# scripts/git_health_metrics.py

METRICS = {
    "merge_frequency": {
        "target": "daily",
        "alert_if": ">7 days without merge to develop",
        "critical_if": ">14 days"
    },

    "branch_size": {
        "target": "<50 commits",
        "alert_if": ">100 commits",
        "critical_if": ">200 commits"
    },

    "conflict_rate": {
        "target": "<5% of merges",
        "alert_if": ">10%",
        "critical_if": ">20%"
    },

    "commit_size": {
        "target": "<200 lines",
        "alert_if": ">500 lines",
        "critical_if": ">1000 lines"
    },

    "test_coverage": {
        "target": ">85%",
        "alert_if": "<75%",
        "critical_if": "<60%"
    },

    "code_review_time": {
        "target": "<4 hours",
        "alert_if": ">24 hours",
        "critical_if": ">72 hours"
    }
}
```

### Dashboard Semanal

```bash
# Generar reporte semanal
python scripts/git_health_report.py --week-ago 1

# Output:
# ============================================
# Git Health Report - Week 46 (Nov 11-17)
# ============================================
#
# ✅ Merges: 5/7 days (71% - Target: 100%)
# ⚠️  Avg branch size: 87 commits (Target: <50)
# ✅ Conflict rate: 2/5 merges (40% - High!)
# ✅ Avg commit size: 156 lines
# ✅ Test coverage: 87.3%
# ⚠️  Avg review time: 6.2 hours
#
# 🔴 ALERTS:
# - feature/finrep-phase1: 134 commits (Split recommended)
# - Conflict rate high (40% vs 5% target)
#
# 💡 RECOMMENDATIONS:
# 1. Split large feature branches
# 2. Increase merge frequency
# 3. Add pre-merge rebase from develop
```

---

## 🎓 Capacitación y Onboarding

### Recursos de Aprendizaje

```markdown
## Nuevo en el Equipo

1. **Leer primero** (2 horas):
   - Este documento (GIT_STRATEGY.md)
   - CONTRIBUTING.md
   - docs/development/GIT_WORKFLOW.md

2. **Setup local** (1 hora):
   - Instalar pre-commit hooks
   - Configurar Git aliases
   - Setup GPG signing (opcional)

3. **Primer PR supervisado** (1 día):
   - Fix simple o docs update
   - Revisión con mentor
   - Feedback en proceso

## Git Cheat Sheet

Ver: docs/development/GIT_CHEAT_SHEET.md
```

### Comandos Útiles

```bash
# Aliases recomendados (.gitconfig)
[alias]
  # Logs bonitos
  lg = log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit

  # Status corto
  st = status -sb

  # Commit con template
  ci = commit -v

  # Push con force-with-lease (más seguro)
  pf = push --force-with-lease

  # Squash últimos N commits
  squash = "!f(){ git reset --soft HEAD~${1} && git commit --edit -m\"$(git log --format=%B --reverse HEAD..HEAD@{1})\"; };f"

  # Ver branches por fecha
  br-recent = branch --sort=-committerdate

  # Diff de archivos staged
  ds = diff --staged

  # Amend último commit sin edit message
  amend = commit --amend --no-edit

  # Cleanup branches mergeadas
  cleanup = "!git branch --merged | grep -v '\\*\\|main\\|develop' | xargs -n 1 git branch -d"
```

---

## 📞 Soporte y Escalación

### Cuando las Cosas Salen Mal

```yaml
Problema: "Destruí código con un merge"
Solución:
  1. NO PANIC
  2. git reflog (ver historia completa)
  3. git reset --hard <commit-antes-del-merge>
  4. Pedir ayuda en Slack #dev-odoo
  5. Documentar en post-mortem

Problema: "Branch tiene 200 commits, muchos conflictos"
Solución:
  1. Considerar rewrite con cherry-pick
  2. O crear nueva branch, copiar cambios manualmente
  3. Pedir review de estrategia a lead
  4. Lección: NO dejar acumular tanto

Problema: "Force push a main/develop"
Solución:
  1. ¡NUNCA hacer esto!
  2. Si ocurrió: git reflog en servidor
  3. Notificar INMEDIATO a todo el equipo
  4. Restore desde backup (GitHub retiene 90 días)
  5. Post-mortem obligatorio

Contactos:
  Git Lead: Pedro (@pedro)
  DevOps: María (@maria)
  Emergency: Slack #emergencies
```

---

## 🔄 Revisión y Mejora Continua

### Retrospectivas Mensuales

```markdown
## Agenda Retrospectiva Git/GitHub

1. **Métricas del mes** (15 min)
   - Merges frequency
   - Conflict rate
   - Branch sizes
   - Review times

2. **Problemas enfrentados** (20 min)
   - Conflictos complicados
   - Código perdido/destruido
   - Delays por Git issues

3. **Qué funcionó bien** (15 min)
   - Wins del mes
   - Mejoras observadas

4. **Acciones para próximo mes** (10 min)
   - 2-3 mejoras concretas
   - Owner y deadline

5. **Actualizar estrategia** (10 min)
   - ¿Necesita cambios este doc?
   - ¿Nuevas herramientas/procesos?
```

### Versionado de Este Documento

```markdown
## Changelog - GIT_STRATEGY.md

### [1.0.0] - 2025-11-15
- Initial version based on audit analysis
- Post-merge audit-p1-ciclo4 lessons learned
- Established monorepo curado + gradual migration strategy

### [Future]
- 1.1.0: After AI-service extraction
- 1.2.0: After docs migration
- 2.0.0: If moving to multi-repo
```

---

## 📚 Referencias

- **Conventional Commits**: https://www.conventionalcommits.org/
- **Semantic Versioning**: https://semver.org/
- **OCA Guidelines**: https://github.com/OCA/odoo-community.org
- **Git Best Practices**: https://www.atlassian.com/git/tutorials
- **Monorepo Tools**: https://monorepo.tools/

---

**Mantenido por**: DevOps Team
**Contacto**: pedro@eergygroup.com
**Last Updated**: 2025-11-15
**Next Review**: 2025-12-15
