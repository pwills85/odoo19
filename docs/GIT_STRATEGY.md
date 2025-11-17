# Git & GitHub Strategy - Odoo19 Chilean Localization

**Version:** 2.0  
**Updated:** 2025-11-13  
**Owner:** @pwills85

---

## 🎯 Objetivos

1. **Historial limpio y semántico** mediante Conventional Commits
2. **Desarrollo colaborativo seguro** con branch protection
3. **CI/CD automatizado** con GitHub Actions
4. **Code review obligatorio** antes de merge
5. **Trazabilidad completa** de features y bugs

---

## 📊 Branching Model

### Estructura de Branches

```
main (producción - protegida)
  ↓ [PR con approval]
develop (staging - protegida)
  ↑ [PR automático]
feature/*, fix/*, docs/*, refactor/* (trabajo)
```

### Descripción de Branches

| Branch | Propósito | Protección | Deploy |
|--------|-----------|------------|--------|
| `main` | Producción estable | ✅ Alta | Automático |
| `develop` | Integración/staging | ✅ Media | Manual |
| `feature/*` | Nuevas características | ❌ No | N/A |
| `fix/*` | Corrección de bugs | ❌ No | N/A |
| `docs/*` | Documentación | ❌ No | N/A |
| `refactor/*` | Refactorización | ❌ No | N/A |
| `test/*` | Testing experiments | ❌ No | N/A |
| `chore/*` | Mantenimiento | ❌ No | N/A |

### Nomenclatura de Branches

**Formato:** `<type>/<descripcion-corta>`

**Ejemplos válidos:**
```bash
feature/dte-56-nota-debito
fix/afp-calculation-cap
docs/update-readme-docker
refactor/payroll-calculation-engine
test/integration-previred-api
chore/update-dependencies
```

**❌ Evitar:**
```bash
my-branch           # Sin tipo
fix_bug             # Usar guión, no underscore
FEATURE/NEW-STUFF   # Usar minúsculas
descripcion-muy-larga-que-no-cabe-en-terminal  # Máximo 50 chars
```

---

## 📝 Conventional Commits

### Formato Estricto

```
<type>(<scope>): <subject>

[optional body]

[optional footer(s)]
```

### Types Permitidos

| Type | Uso | Breaking Change |
|------|-----|-----------------|
| `feat` | Nueva característica | ❌ |
| `fix` | Corrección de bug | ❌ |
| `docs` | Solo documentación | ❌ |
| `style` | Formato, punto y coma (sin cambio lógico) | ❌ |
| `refactor` | Refactorización sin cambio funcional | ❌ |
| `perf` | Mejora de performance | ❌ |
| `test` | Añadir/corregir tests | ❌ |
| `build` | Cambios en sistema de build | ⚠️ |
| `ci` | Cambios en CI/CD | ❌ |
| `chore` | Mantenimiento, dependencias | ⚠️ |
| `revert` | Revertir commit anterior | ⚠️ |

### Scopes Comunes

- `l10n_cl_dte` - Facturación electrónica
- `l10n_cl_hr_payroll` - Nóminas
- `l10n_cl_financial_reports` - Reportes financieros
- `ai-service` - Microservicio AI
- `docker` - Docker Compose, Dockerfiles
- `ci` - GitHub Actions workflows
- `docs` - Documentación
- `deps` - Dependencias

### Ejemplos Reales

```bash
# Feature nueva
feat(l10n_cl_dte): add DTE 56 (Nota de Débito) support

Implementa generación completa de DTE tipo 56 según
Resolución SII 80/2014.

Includes:
- XML generation with XSD validation
- CAF signature for DTE 56
- TED barcode (PDF417)
- SII webservice submission

Refs: #123
Co-authored-by: John Doe <john@example.com>

# Bug fix
fix(payroll): correct AFP calculation for salaries > 90.3 UF

AFP contribution was not respecting the 90.3 UF legal cap,
causing incorrect calculations for high earners.

Before: AFP = salary * 0.10 (no cap)
After: AFP = min(salary, 90.3 * UF) * 0.10

Closes: #456

# Breaking change
feat(l10n_cl_dte)!: migrate to SII API v2

BREAKING CHANGE: SII API v1 deprecated. All DTE submissions
now use v2 endpoints. Migration required.

Migration guide: docs/MIGRATION_SII_API_V2.md

Refs: #789

# Documentación
docs(README): update Docker setup instructions

Add troubleshooting section for M1/M2 Mac users.

# Refactor
refactor(payroll): extract calculation logic to pure Python libs/

Move calculation logic from Odoo models to libs/ directory
for better testability and reusability.

No functional changes.

# Multiple scopes
feat(l10n_cl_dte,l10n_cl_hr_payroll): add company currency validation

Ensure all Chilean companies use CLP currency across DTE and payroll.
```

### Pre-commit Hook Validation

El pre-commit hook automático valida:
- Formato de mensaje (conventional commits)
- Tamaño de commit (max 2000 líneas, recomendado 500)
- Linters (pylint, black para Python)

**Bypass (solo emergencias):**
```bash
git commit --no-verify -m "..."
```

---

## 🔄 Workflow de Desarrollo

### 1. Crear Feature Branch

```bash
# Asegurar develop actualizado
git checkout develop
git pull origin develop

# Crear nueva branch
git checkout -b feature/mi-nueva-feature

# Verificar
git branch --show-current
```

### 2. Desarrollo y Commits

```bash
# Hacer cambios
# ...

# Stage selectivo (recomendado)
git add -p  # Interactivo por hunk

# O stage completo
git add archivo1.py archivo2.xml

# Commit con mensaje semántico
git commit -m "feat(l10n_cl_dte): add DTE 56 support"

# Commits frecuentes (atomic commits)
# Preferir muchos commits pequeños vs pocos commits grandes
```

### 3. Push y Pull Request

```bash
# Push a remote
git push origin feature/mi-nueva-feature

# Crear PR via gh CLI
gh pr create \
  --base develop \
  --head feature/mi-nueva-feature \
  --title "feat(l10n_cl_dte): add DTE 56 support" \
  --body "Descripción detallada..." \
  --assignee @me \
  --label "type: feature,module: dte"

# O crear PR via web
open https://github.com/pwills85/odoo19/compare/develop...feature/mi-nueva-feature
```

### 4. Code Review

- **Mínimo 1 approval requerido**
- CI/CD workflows deben pasar
- Conversaciones deben resolverse
- Cambios solicitados deben atenderse

```bash
# Atender feedback
git commit -m "fix: address code review comments"
git push origin feature/mi-nueva-feature

# PR se actualiza automáticamente
```

### 5. Merge

**Método: Squash Merge (preferido)**

Razones:
- Historial limpio en develop/main
- 1 commit por feature/fix
- Mensaje semántico consolidado

```bash
# Merge automático (si protections permiten)
gh pr merge 123 --squash --delete-branch

# O via web UI
# GitHub → Pull Request → Squash and merge
```

---

## 🛡️ Branch Protection

### Main Branch

**Reglas activas:**
- ✅ Require pull request before merging
- ✅ Require approvals (1 minimum)
- ✅ Dismiss stale pull request approvals
- ✅ Require review from Code Owners
- ✅ Require status checks to pass (CI, quality-gates, security)
- ✅ Require branches to be up to date
- ✅ Require conversation resolution
- ❌ Allow force pushes (disabled)
- ❌ Allow deletions (disabled)

### Develop Branch

**Reglas activas:**
- ✅ Require pull request before merging
- ✅ Require approvals (1 minimum)
- ✅ Require status checks to pass (CI, quality-gates)
- ❌ Allow force pushes (disabled)
- ❌ Allow deletions (disabled)

### Configuración

```bash
# Ejecutar script de configuración
./scripts/configure_github_repo.sh

# O configurar manualmente:
# Settings → Branches → Add rule
```

---

## 🤖 GitHub Actions CI/CD

### Workflows Activos

| Workflow | Trigger | Propósito |
|----------|---------|-----------|
| `ci.yml` | Push, PR | Build, lint, test |
| `quality-gates.yml` | PR | Coverage, complexity |
| `security-scan.yml` | Push a main | Bandit, safety |
| `codeql.yml` | Schedule | CodeQL analysis |
| `dependency-review.yml` | PR | Dependabot checks |
| `pr-checks.yml` | PR | Conventional commits |
| `qa.yml` | PR | QA automation |

### Status Checks Requeridos

- ✅ `CI` - Build y tests unitarios
- ✅ `quality-gates` - Coverage 80%+, complejidad
- ✅ `security-scan` - Sin vulnerabilidades críticas

---

## 📦 Release Strategy

### Semantic Versioning

Formato: `vMAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

**Ejemplos:**
```
v1.0.0 → v1.0.1  (bug fix)
v1.0.1 → v1.1.0  (new feature)
v1.1.0 → v2.0.0  (breaking change)
```

### Release Process

```bash
# 1. Merge develop → main via PR
gh pr create --base main --head develop --title "Release v1.2.0"

# 2. Aprobar y merge PR

# 3. Tag release en main
git checkout main
git pull origin main
git tag -a v1.2.0 -m "Release v1.2.0 - DTE 56 support"
git push origin v1.2.0

# 4. Create GitHub Release
gh release create v1.2.0 \
  --title "v1.2.0 - DTE 56 Support" \
  --notes-file CHANGELOG.md \
  --target main

# 5. Update CHANGELOG.md
# Documenta todos los cambios desde v1.1.0
```

---

## 🏷️ Etiquetas (Labels)

### Uso en Issues

```bash
# Crear issue con etiquetas
gh issue create \
  --title "Bug: AFP calculation incorrect" \
  --body "Description..." \
  --label "type: bug,priority: high,module: payroll"

# Añadir etiquetas a issue existente
gh issue edit 456 --add-label "status: in-progress"
```

### Uso en PRs

```bash
# Crear PR con etiquetas
gh pr create \
  --title "feat: add DTE 56" \
  --label "type: feature,module: dte,status: needs-review"

# Añadir etiquetas a PR existente
gh pr edit 123 --add-label "priority: high"
```

---

## 🔍 Code Review Guidelines

### Para Reviewers

**Checklist:**
- [ ] Código sigue estándares del proyecto
- [ ] Tests añadidos/actualizados y pasando
- [ ] Documentación actualizada
- [ ] Sin vulnerabilidades de seguridad
- [ ] Performance aceptable
- [ ] Conventional commits respetados
- [ ] Sin conflictos con base branch

**Comandos útiles:**
```bash
# Checkout PR localmente
gh pr checkout 123

# Ver diff
gh pr diff 123

# Comentar en PR
gh pr comment 123 --body "LGTM! 🚀"

# Aprobar PR
gh pr review 123 --approve

# Solicitar cambios
gh pr review 123 --request-changes --body "Please address..."
```

### Para Contributors

**Responder a feedback:**
```bash
# Hacer cambios solicitados
git add .
git commit -m "fix: address code review comments"
git push origin feature/mi-feature

# Responder a comentarios
gh pr comment 123 --body "Fixed in latest commit"

# Resolver conversaciones
# Via web UI: Resolve conversation
```

---

## 📊 Métricas y Monitoreo

### GitHub Insights

- **Pulse**: Actividad reciente
- **Contributors**: Contribuciones por autor
- **Traffic**: Clones, views, visitors
- **Network**: Grafo de branches

**Acceso:** https://github.com/pwills85/odoo19/pulse

### Code Quality Badges

Añadidos en README.md:
- CI/CD status
- Coverage percentage
- Odoo 19 CE compliance
- SII certification
- Previred compatibility

---

## 🚨 Troubleshooting

### Conflictos de Merge

```bash
# Actualizar branch con develop
git checkout feature/mi-feature
git fetch origin
git rebase origin/develop

# Resolver conflictos manualmente
# Editar archivos con conflictos

# Continuar rebase
git add archivo_resuelto.py
git rebase --continue

# Push forzado (rebase cambió historial)
git push --force-with-lease origin feature/mi-feature
```

### Commit Message Incorrecto

```bash
# Último commit
git commit --amend -m "feat(scope): correct message"
git push --force-with-lease

# Múltiples commits
git rebase -i HEAD~3  # Últimos 3 commits
# Cambiar 'pick' por 'reword' en commits a corregir
# Editar mensajes
git push --force-with-lease
```

### Branch Desactualizada

```bash
# Sincronizar con develop
git checkout develop
git pull origin develop

git checkout feature/mi-feature
git rebase develop

# Resolver conflictos si hay
git push --force-with-lease origin feature/mi-feature
```

---

## 📖 Referencias

- [Conventional Commits](https://www.conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)
- [Git Best Practices](https://git-scm.com/book/en/v2)
- [CONTRIBUTING.md](../CONTRIBUTING.md)

---

**Última actualización:** 2025-11-13  
**Maintainer:** Pedro Troncoso (@pwills85)
