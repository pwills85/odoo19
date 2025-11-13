# 🌿 ESTRATEGIA DE BRANCHING - Proyecto Odoo19 EERGYGROUP

**Versión**: 1.0
**Última actualización**: 9 de noviembre de 2025
**Estado**: ✅ ACTIVO - Aplicar en todo el proyecto
**Basado en**: GitHub Flow simplificado + mejores prácticas de la industria

---

## 🎯 OBJETIVO

Mantener un flujo de trabajo Git **simple, predecible y escalable** que permita:

1. ✅ **Desarrollo paralelo** sin conflictos
2. ✅ **Integración continua** con CI/CD
3. ✅ **Rollback rápido** en caso de problemas
4. ✅ **Code review efectivo** con PRs
5. ✅ **Historial limpio** y trazable

---

## 📐 MODELO: GITHUB FLOW SIMPLIFICADO

Utilizamos **GitHub Flow**, un modelo simplificado que se adapta perfectamente a proyectos con CI/CD y despliegue continuo.

### Características

- **1 rama permanente**: `main` (producción)
- **Ramas de trabajo efímeras**: `feat/*`, `fix/*`, `hotfix/*`
- **Integración mediante PRs** con code review
- **Despliegue desde main** (cuando esté configurado)

### Ventajas sobre Git Flow

| Aspecto | Git Flow | GitHub Flow (nuestro) |
|---------|----------|----------------------|
| Complejidad | Alta (5+ tipos de ramas) | Baja (3 tipos) |
| Learning curve | Larga | Corta |
| Overhead | Alto | Bajo |
| CI/CD friendly | Medio | Alto |
| Adecuado para | Releases programados | Despliegue continuo |

---

## 🌳 ESTRUCTURA DE RAMAS

### Ramas Permanentes

#### `main` - Rama Principal (Producción)

- **Propósito**: Código estable, listo para producción
- **Protección**: ✅ ESTRICTA
  - Requiere PR para merge
  - Requiere 1+ aprobación
  - Requiere CI/CD pasando
  - No permite force push
  - No permite eliminación
- **Despliegue**: Automático a producción (cuando esté configurado)
- **Calidad**: Solo código 100% funcional y testeado

```bash
# Nunca commitear directamente a main
git checkout main  # ❌ NO hacer commits aquí
```

---

### Ramas de Trabajo (Efímeras)

#### `feat/*` - Nuevas Funcionalidades

**Propósito**: Desarrollo de nuevas características

**Naming Convention**:
```
feat/descripcion-kebab-case
```

**Ejemplos**:
```
✅ feat/cierre-gaps-p0-payroll
✅ feat/dashboard-kanban-export
✅ feat/dte-boleta-39-support
✅ feat/apv-calculation-rules

❌ feature/some-long-name    (usar feat/, no feature/)
❌ feat/fix-bug              (esto es fix/, no feat/)
❌ my-feature                (sin tipo)
```

**Workflow**:
```bash
# 1. Crear rama desde main actualizado
git checkout main
git pull origin main
git checkout -b feat/dashboard-export

# 2. Desarrollar con commits atómicos
git add archivo1.py
git commit -m "feat(dashboard): add export to Excel functionality"

# 3. Push frecuente (al menos diario)
git push -u origin feat/dashboard-export

# 4. Mantener actualizado con main
git checkout main && git pull
git checkout feat/dashboard-export
git rebase main  # O merge main si prefieres

# 5. Crear PR cuando esté listo
gh pr create --title "feat(dashboard): Export to Excel" --base main
```

---

#### `fix/*` - Correcciones de Bugs

**Propósito**: Arreglar bugs identificados en desarrollo

**Naming Convention**:
```
fix/descripcion-del-bug
```

**Ejemplos**:
```
✅ fix/dte-xml-validation-timeout
✅ fix/payroll-rounding-error
✅ fix/sii-authentication-retry

❌ fix-bug              (sin tipo al inicio)
❌ fix/new-feature     (esto es feat/)
```

**Workflow**:
```bash
# Similar a feat/, pero desde main o desde la rama afectada
git checkout main
git pull origin main
git checkout -b fix/dte-validation-error

# Commits con referencia al issue/hallazgo
git commit -m "fix(dte): validate RUT format before XML generation

Problema: RUTs sin formato causaban rechazo SII
Solución: Validar con stdnum.cl.rut antes de XML

Refs: #42"
```

---

#### `hotfix/*` - Correcciones Urgentes de Producción

**Propósito**: Arreglar bugs críticos en producción **inmediatamente**

**Naming Convention**:
```
hotfix/descripcion-urgente
```

**Ejemplos**:
```
✅ hotfix/critical-sii-timeout
✅ hotfix/p0-payroll-calculation
✅ hotfix/security-xxe-vulnerability
```

**Workflow**:
```bash
# Desde main (producción)
git checkout main
git pull origin main
git checkout -b hotfix/critical-sii-timeout

# Fix rápido y directo
git commit -m "fix(sii)!: increase timeout from 30s to 120s - P0 critical

BREAKING: Requires restart of all services

Impact: Critical - SII requests timing out
Refs: INCIDENT-2025-11-09"

# PR urgente con fast-track review
gh pr create --title "HOTFIX: Critical SII timeout" \
  --label "priority:critical" \
  --assignee @reviewer

# Merge inmediato tras aprobación
# Deploy inmediato a producción
```

**Criterios para Hotfix**:
- ✅ Bug P0/P1 en producción
- ✅ Impacto a usuarios/clientes
- ✅ Requiere fix inmediato (<4 horas)
- ❌ Bugs que pueden esperar → usar `fix/`

---

### Ramas Especiales (Uso Ocasional)

#### `refactor/*` - Refactorizaciones Grandes

Para refactorizaciones que no cambian funcionalidad pero requieren múltiples commits.

```
refactor/extract-dte-libs-pure-python
refactor/consolidate-duplicate-menus
```

#### `docs/*` - Documentación Extensa

Para trabajos de documentación que no caben en un commit.

```
docs/api-reference-complete
docs/migration-guide-v19
```

#### `chore/*` - Tareas de Mantenimiento

Para actualizaciones de dependencias, configuraciones, etc.

```
chore/update-dependencies-nov-2025
chore/migrate-docker-compose-v2
```

---

## 🔄 WORKFLOW COMPLETO

### Caso 1: Feature Normal

```bash
# 1. Crear rama
git checkout main && git pull
git checkout -b feat/nueva-funcionalidad

# 2. Desarrollar (commits pequeños y frecuentes)
# ... hacer cambios ...
git add .
git commit  # (se abre editor con template)

# 3. Push frecuente
git push -u origin feat/nueva-funcionalidad

# 4. Mantener actualizado
git fetch origin
git rebase origin/main  # O git merge origin/main

# 5. Crear PR
gh pr create --title "feat(modulo): descripción" \
  --body "## Descripción
  ...
  ## Testing
  - [ ] Tests unitarios
  - [ ] Tests integración
  - [ ] Revisión manual"

# 6. Code review + CI/CD
# (GitHub Actions ejecuta quality gates)

# 7. Merge (squash si muchos commits)
# (Via GitHub UI o CLI)

# 8. Limpiar
git checkout main
git pull
git branch -d feat/nueva-funcionalidad
```

---

### Caso 2: Hotfix Urgente

```bash
# 1. Crear desde main
git checkout main && git pull
git checkout -b hotfix/critical-bug

# 2. Fix mínimo y directo
git add archivo_afectado.py
git commit -m "fix(modulo)!: descripción urgente - P0 critical"

# 3. PR urgente
gh pr create --title "HOTFIX: Critical bug" \
  --label "priority:critical" \
  --reviewer @lead-dev

# 4. Fast-track review (15-30 min)

# 5. Merge inmediato
gh pr merge --squash

# 6. Deploy inmediato
# (Automático o manual según configuración)

# 7. Post-mortem
# (Documentar incidente y prevención)
```

---

### Caso 3: Feature con Múltiples Desarrolladores

```bash
# Developer 1: Crea rama base
git checkout -b feat/gran-feature

# Developer 1: Push rama base
git push -u origin feat/gran-feature

# Developer 2: Crea sub-rama
git checkout feat/gran-feature
git checkout -b feat/gran-feature-parte-a

# Developer 2: Desarrolla su parte
git commit -m "feat(modulo): parte A"
git push -u origin feat/gran-feature-parte-a

# Developer 2: PR hacia feat/gran-feature
gh pr create --base feat/gran-feature

# Coordinador: Merge sub-ramas
gh pr merge feat/gran-feature-parte-a

# Coordinador: PR final hacia main
gh pr create --base main --title "feat(modulo): gran feature completa"
```

---

## 🔀 ESTRATEGIAS DE MERGE

### Cuándo Usar Cada Estrategia

| Estrategia | Cuándo Usar | Ventajas | Desventajas |
|------------|-------------|----------|-------------|
| **Squash Merge** | Features con >10 commits WIP | Historial limpio | Pierde detalle |
| **Rebase Merge** | Features limpias <5 commits | Historial lineal | Más complejo |
| **Merge Commit** | Integraciones grandes | Preserva contexto | Historial complejo |

### Configuración Recomendada

**Para este proyecto usamos**:
- **Squash merge** por defecto (90% de casos)
- **Merge commit** para features grandes con múltiples PRs
- **Rebase** raramente (solo para historiales muy limpios)

**Configurar en GitHub**:
- Settings → General → Pull Requests
- ✅ Allow squash merging
- ✅ Allow merge commits
- ✅ Allow rebase merging
- ✅ Default to squash merge

---

## 🧹 LIMPIEZA Y MANTENIMIENTO

### Limpieza Automática (GitHub)

**Configurar en GitHub**:
- Settings → General → Pull Requests
- ✅ Automatically delete head branches

### Limpieza Local (Manual)

```bash
# Actualizar referencias
git fetch --prune

# Ver ramas ya mergeadas
git branch --merged main

# Eliminar ramas locales ya mergeadas
git branch --merged main | grep -v "^\*" | grep -v "main" | xargs git branch -d

# Eliminar ramas remotas obsoletas
git remote prune origin

# Eliminar ramas huérfanas (gone)
git fetch --prune
git branch -vv | grep '\[gone\]' | awk '{print $1}' | xargs git branch -D
```

### Limpieza Programada (Semanal)

**Todos los viernes**:
```bash
# Script: scripts/weekly-cleanup.sh
#!/bin/bash

echo "🧹 Limpieza semanal de ramas..."

# Fetch y prune
git fetch --prune

# Listar ramas obsoletas
echo "Ramas locales ya mergeadas a main:"
git branch --merged main | grep -v "^\*" | grep -v "main"

# Confirmar eliminación
read -p "¿Eliminar estas ramas? (y/N) " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git branch --merged main | grep -v "^\*" | grep -v "main" | xargs git branch -d
    echo "✅ Ramas eliminadas"
fi
```

---

## 📏 NAMING CONVENTIONS

### Reglas Generales

1. **Usar kebab-case**: `feat/mi-nueva-funcionalidad`
2. **Ser descriptivo**: `feat/dashboard-export` > `feat/export`
3. **Incluir contexto**: `fix/dte-xml-timeout` > `fix/timeout`
4. **Máximo 50 caracteres**: Para compatibilidad con tools
5. **Solo ASCII**: Evitar acentos y caracteres especiales

### Template

```
{tipo}/{módulo}-{descripción-breve}

Ejemplos:
feat/payroll-apv-calculation
fix/dte-sii-authentication
hotfix/critical-rut-validation
refactor/extract-xml-signer-lib
docs/deployment-guide
```

### Anti-Patrones

```
❌ mi-rama                    (sin tipo)
❌ feat/fix-bug              (tipo incorrecto)
❌ feature/something         (usar feat/)
❌ feat/añadir-función      (evitar acentos)
❌ feat/this-is-a-very-long-branch-name-that-exceeds-fifty-characters
```

---

## 🛡️ PROTECCIÓN DE RAMAS

### Configuración de `main`

**En GitHub** (Settings → Branches → Branch protection rules):

```
Branch name pattern: main

✅ Require a pull request before merging
   ✅ Require approvals: 1
   ✅ Dismiss stale pull request approvals when new commits are pushed
   ✅ Require review from Code Owners (si existe CODEOWNERS)

✅ Require status checks to pass before merging
   ✅ Require branches to be up to date before merging
   Status checks required:
   - quality-gates-summary
   - syntax-check
   - code-quality
   - security-scan

✅ Require conversation resolution before merging

✅ Require signed commits (opcional - recomendado)

✅ Require linear history (opcional)

✅ Do not allow bypassing the above settings
   Excepciones: @admin (solo para emergencias)

✅ Restrict who can push to matching branches
   Permitir: Solo via PR (nadie puede push directo)
```

### Verificación Local

```bash
# Ver protección actual
gh api repos/pwills85/odoo19/branches/main/protection

# Configurar protección via CLI
gh api -X PUT repos/pwills85/odoo19/branches/main/protection \
  --input protection-config.json
```

---

## 🎯 MÉTRICAS DE ÉXITO

### KPIs de Branching

| Métrica | Target | Medición |
|---------|--------|----------|
| **Ramas activas** | ≤10 | `git branch \| wc -l` |
| **Ramas desincronizadas** | 0 | `git branch -vv \| grep ahead` |
| **Ramas huérfanas** | 0 | `git branch -vv \| grep gone` |
| **Tiempo de vida branch** | <7 días | Desde creación a merge |
| **Time to merge PR** | <48h | Desde creación PR a merge |
| **PRs abiertos >7 días** | 0 | `gh pr list` |

### Dashboard de Monitoreo

Usar el script `scripts/git-health-check.sh`:

```bash
./scripts/git-health-check.sh

# Output esperado:
# 🌿 3. BRANCH MANAGEMENT
# ─────────────────────────────────────────────────────────
#    Ramas locales: 7 ✅ (Target: ≤10)
#    Ramas ahead: 0 ✅
#    Ramas huérfanas: 0 ✅
```

---

## 📋 CHECKLIST DIARIA

### Al Iniciar el Día

```bash
# 1. Actualizar main
git checkout main
git pull origin main

# 2. Revisar ramas activas
git branch -vv

# 3. Verificar sincronización
git fetch origin

# 4. Si hay rama ahead, pushear
git push origin <branch-name>
```

### Al Finalizar el Día

```bash
# 1. Commitear trabajo en progreso
git add .
git commit -m "wip(modulo): descripción del progreso"

# 2. Push a remoto (backup)
git push origin <branch-name>

# 3. Verificar PRs pendientes
gh pr list

# 4. Actualizar Jira/Trello si aplica
```

### Semanal (Viernes)

```bash
# 1. Ejecutar health check
./scripts/git-health-check.sh

# 2. Limpiar ramas mergeadas
git branch --merged main | grep -v main | xargs git branch -d

# 3. Revisar PRs antiguas
gh pr list --state open

# 4. Planificar próxima semana
```

---

## 🆘 TROUBLESHOOTING

### Problema: "Rama desincronizada (ahead)"

```bash
# Síntoma
git branch -vv
# feat/mi-rama [origin/feat/mi-rama: ahead 5]

# Solución
git push origin feat/mi-rama
```

### Problema: "Rama huérfana (gone)"

```bash
# Síntoma
git branch -vv
# old-branch [origin/old-branch: gone]

# Solución 1: Eliminar si ya fue mergeada
git branch -D old-branch

# Solución 2: Re-crear remoto si aún se necesita
git push -u origin old-branch
```

### Problema: "Conflictos con main"

```bash
# Opción 1: Rebase (preferido)
git checkout feat/mi-rama
git fetch origin
git rebase origin/main

# Resolver conflictos
git add archivo_resuelto.py
git rebase --continue

# Opción 2: Merge (más seguro)
git checkout feat/mi-rama
git merge origin/main

# Resolver conflictos
git add archivo_resuelto.py
git commit
```

### Problema: "PR bloqueado por CI/CD"

```bash
# 1. Ver logs del CI/CD
gh pr checks <pr-number>

# 2. Corregir el problema localmente
git add .
git commit -m "fix(ci): resolve linting errors"

# 3. Push (re-ejecuta CI/CD)
git push
```

### Problema: "Demasiadas ramas activas"

```bash
# 1. Ver todas las ramas
git branch -a

# 2. Identificar obsoletas
git branch --merged main

# 3. Eliminar locales mergeadas
git branch --merged main | grep -v main | xargs git branch -d

# 4. Eliminar remotas obsoletas
git fetch --prune
```

---

## 🎓 MEJORES PRÁCTICAS

### DO ✅

1. **Crear rama para cada cambio** (no commitear a main)
2. **Usar nombres descriptivos** (`feat/dashboard-export` > `feat/export`)
3. **Push diario** (mínimo 1 vez al día)
4. **Mantener ramas actualizadas** con main (rebase/merge frecuente)
5. **Commits pequeños y atómicos** (<500 líneas)
6. **PR cuando esté listo** (no esperar perfección)
7. **Limpiar después del merge** (eliminar rama local y remota)
8. **Usar template de commit** (se configura automáticamente)

### DON'T ❌

1. **NO commitear directamente a main** (siempre via PR)
2. **NO usar ramas eternas** (>14 días = problema)
3. **NO pushear commits WIP** a ramas compartidas
4. **NO crear ramas sin tipo** (`mi-rama` ❌)
5. **NO acumular >100 líneas sin commit** (commitear frecuente)
6. **NO ignorar conflictos** (resolverlos inmediatamente)
7. **NO dejar PRs abiertos** sin seguimiento (>48h = problema)
8. **NO eliminar ramas remotas** sin coordinar con equipo

---

## 📚 RECURSOS

### Documentación Relacionada

- **COMMIT_STRATEGY.md**: Convención de mensajes de commit
- **PR_TEMPLATE.md**: Template para Pull Requests (crear)
- **CONTRIBUTING.md**: Guía general de contribución (crear)
- **CODEOWNERS**: Ownership de módulos (crear)

### Tools

- **GitHub CLI**: `gh` para gestión de PRs
- **git-health-check.sh**: Monitoreo de calidad Git
- **weekly-cleanup.sh**: Limpieza automática (crear)

### Comandos Útiles

```bash
# Ver ramas gráficamente
git log --all --graph --oneline --decorate

# Ver estado de todas las ramas
git branch -vv

# Ver PRs del proyecto
gh pr list

# Crear PR rápido
gh pr create --web

# Ver protección de main
gh api repos/pwills85/odoo19/branches/main/protection
```

---

## 🔄 MIGRACIÓN DESDE ESTRATEGIA ANTERIOR

Si estás migrando desde otra estrategia (Git Flow, Feature Branch, etc.):

### Paso 1: Audit de Ramas Actuales

```bash
# Ejecutar health check
./scripts/git-health-check.sh

# Identificar ramas obsoletas
git branch --merged main

# Identificar ramas desincronizadas
git branch -vv | grep -E "ahead|behind|gone"
```

### Paso 2: Limpieza

```bash
# Eliminar ramas mergeadas
git branch --merged main | grep -v main | xargs git branch -d

# Eliminar ramas huérfanas
git branch -vv | grep '\[gone\]' | awk '{print $1}' | xargs git branch -D

# Pushear ramas ahead
git push --all origin
```

### Paso 3: Renombrar Ramas Activas

```bash
# Si tienes feature/nombre → feat/nombre
git branch -m feature/mi-rama feat/mi-rama
git push origin -u feat/mi-rama
git push origin --delete feature/mi-rama
```

### Paso 4: Configurar Protección

Aplicar configuración de protección a `main` según sección anterior.

---

## ✅ CHECKLIST DE IMPLEMENTACIÓN

### Setup Inicial (Una Vez)
- [x] Configurar protección de `main` en GitHub
- [x] Crear template `.gitmessage`
- [x] Configurar template localmente
- [x] Instalar hooks (commit-msg, pre-commit)
- [ ] Crear CODEOWNERS (opcional)
- [x] Documentar strategy (este documento)

### Para Cada Desarrollador
- [ ] Leer `COMMIT_STRATEGY.md`
- [ ] Leer `BRANCHING_STRATEGY.md` (este doc)
- [ ] Configurar template: `git config commit.template .gitmessage`
- [ ] Verificar hooks: `ls -la .git/hooks/`
- [ ] Ejecutar health check: `./scripts/git-health-check.sh`
- [ ] Limpiar ramas obsoletas

### Mantenimiento Continuo
- [ ] Ejecutar health check semanalmente
- [ ] Limpiar ramas mergeadas cada viernes
- [ ] Revisar PRs abiertos cada 2 días
- [ ] Actualizar documentación según aprendizajes

---

## 📞 CONTACTO Y AYUDA

**Mantenedor**: Ing. Pedro Troncoso Willz
**Documentación**: `docs/BRANCHING_STRATEGY.md`, `docs/COMMIT_STRATEGY.md`
**Issues**: GitHub Issues del proyecto
**Slack**: Canal `#git-workflow` (si existe)

---

**Documento generado por**: Equipo EERGYGROUP
**Versión**: 1.0
**Fecha**: 9 de noviembre de 2025
**Próxima revisión**: 9 de febrero de 2026 (trimestral)
