# 📝 ESTRATEGIA DE COMMITS - Proyecto Odoo19 EERGYGROUP

**Versión**: 2.0  
**Última actualización**: 9 de noviembre de 2025  
**Estado**: ✅ ACTIVO - Aplicar en todos los commits

---

## 🎯 OBJETIVO

Mantener un historial de Git **profesional, trazable y semántico** que permita:

1. ✅ **Changelogs automáticos** (tools como `conventional-changelog`)
2. ✅ **Identificación rápida** del tipo de cambio (feature, bugfix, etc.)
3. ✅ **Trazabilidad completa** (hallazgos → commits → PRs)
4. ✅ **Rollback seguro** (commits atómicos y bien descritos)
5. ✅ **Comunicación clara** para el equipo y stakeholders

---

## 📜 CONVENCIÓN: CONVENTIONAL COMMITS

Seguimos la especificación **[Conventional Commits](https://www.conventionalcommits.org/)**:

### Formato General

```
<tipo>(<scope>)[!]: <descripción>

[cuerpo opcional - más detalles]

[footer opcional - referencias]
```

### Componentes

| Componente | Obligatorio | Descripción |
|------------|-------------|-------------|
| **tipo** | ✅ SÍ | Categoría del cambio (`feat`, `fix`, `docs`, etc.) |
| **scope** | ⚠️ Recomendado | Módulo/área afectada (`dte`, `payroll`, `ai`, etc.) |
| **!** | ❌ Opcional | Breaking change (cambio incompatible) |
| **descripción** | ✅ SÍ | Resumen corto (<72 caracteres) |
| **cuerpo** | ❌ Opcional | Explicación detallada del cambio |
| **footer** | ❌ Opcional | Referencias (issues, hallazgos, PRs) |

---

## 🏷️ TIPOS DE COMMIT

### Tipos Principales (Uso Frecuente)

| Tipo | Uso | Descripción | Ejemplo |
|------|-----|-------------|---------|
| **`feat`** | 🔵 Feature | Nueva funcionalidad para usuario final | `feat(dte): add support for DTE 39 Boleta` |
| **`fix`** | 🔴 Bugfix | Corrección de bug que afecta funcionalidad | `fix(sii): handle timeout in SOAP client` |
| **`docs`** | 📘 Docs | Solo documentación (README, guías, etc.) | `docs(payroll): update calculation examples` |
| **`test`** | 🧪 Testing | Agregar/modificar tests | `test(dte): add 23 XXE security tests` |
| **`i18n`** | 🌍 i18n | Traducciones (español, inglés) | `i18n(payroll): add es_CL and en_US translations` |

### Tipos Secundarios (Técnicos)

| Tipo | Uso | Descripción | Ejemplo |
|------|-----|-------------|---------|
| **`refactor`** | 🔧 Refactor | Mejora de código SIN cambiar funcionalidad | `refactor(libs): extract DTE validator to pure Python` |
| **`perf`** | ⚡ Performance | Optimización de rendimiento | `perf(quantum): add Redis caching for drill-down` |
| **`style`** | 💅 Style | Formato (black, PEP8, sin cambios lógicos) | `style(dte): format code with black` |
| **`chore`** | 🔨 Chore | Mantenimiento (dependencias, configs, etc.) | `chore(docker): update Odoo to 19.0.6` |
| **`build`** | 📦 Build | Cambios en build system (docker, CI/CD) | `build(ci): add GitHub Actions workflow` |
| **`ci`** | 🔄 CI/CD | Cambios en configuración CI/CD | `ci(github): add pytest coverage report` |
| **`revert`** | ↩️ Revert | Revertir commit previo | `revert: "feat(dte): add DTE 39 support"` |

---

## 🎯 SCOPES POR MÓDULO

### Módulos Odoo (l10n_cl_*)

| Scope | Módulo | Uso |
|-------|--------|-----|
| **`dte`** | `l10n_cl_dte` | DTEs 33,34,52,56,61 + SII |
| **`payroll`** | `l10n_cl_hr_payroll` | Nómina Chile (LRE, indicadores, AFP) |
| **`reports`** | `l10n_cl_financial_reports` | Reportes financieros Chile (F29, F22) |
| **`base`** | `l10n_cl_base` | Base localización (RUT, regiones) |

### Microservicios

| Scope | Servicio | Uso |
|-------|---------|-----|
| **`ai`** | `ai-service/` | Servicio AI (Claude, analytics) |
| **`dte-service`** | `dte-service/` | Servicio DTE (generación XML) |
| **`eergy`** | `eergy-services/` | Servicios EERGY |

### Infraestructura

| Scope | Área | Uso |
|-------|------|-----|
| **`docker`** | Docker Compose | Configuración contenedores |
| **`ci`** | CI/CD | GitHub Actions, GitLab CI |
| **`docs`** | Documentación | Documentos .md |
| **`tests`** | Testing | Framework de tests |
| **`libs`** | Libraries | Python libs puras (xml_signer, etc.) |

### Global

| Scope | Uso |
|-------|-----|
| **`*`** | Cambios que afectan TODO el proyecto |
| (vacío) | Cambios menores sin scope específico |

---

## 📋 EJEMPLOS REALES DEL PROYECTO

### ✅ EJEMPLOS EXCELENTES (De Commits Reales)

#### 1. Feature con Breaking Change
```
feat(payroll)!: use validity range for legal caps instead of year field

BREAKING CHANGE: Campo 'year' en l10n_cl.legal_caps eliminado.
Ahora se usa rango de vigencias (valid_from, valid_until).

Migración requerida:
- Actualizar queries que usen campo 'year'
- Usar dominio con valid_from/valid_until

Refs: H-007 (AUDITORIA_NOMINA_P0_P1_TABLA_EVIDENCIAS.md)
```

#### 2. Bugfix Crítico con Contexto
```
fix(dte): remove _name duplication in account.move.dte

Problema: Modelo account.move.dte tenía _name='account.move.dte'
duplicado, causando error en carga del módulo.

Solución: Eliminar _name duplicado, mantener solo uno.

Impact: P0 - Bloqueante de producción
Refs: B-024 (RATIFICACION_ESTADO_REAL_L10N_CL_DTE.md:756)
```

#### 3. Test Suite Completo
```
test(l10n_cl_dte): add comprehensive XXE security tests (23 tests)

Tests agregados:
- XXE entity expansion (5 tests)
- XXE external entity injection (6 tests)
- Billion laughs attack (3 tests)
- DTD validation bypass (4 tests)
- Integration tests (5 tests)

Coverage: 95%+ en xml_signer_unit.py
Refs: XXE_TEST_EXECUTION_SUMMARY.md
```

#### 4. i18n Completo
```
i18n(payroll): add es_CL and en_US translations

Archivos:
- i18n/es_CL.po (187 líneas)
- i18n/en_US.po (181 líneas)

Traducido:
- Wizard LRE (29 columnas)
- Legal Caps (5 códigos)
- Error messages
- Field labels & helps

Refs: H-003 (RESUMEN_EJECUTIVO_CIERRE_P0_P1_NOMINA.md)
```

#### 5. Feature con Acceso y Seguridad
```
feat(payroll): add access controls for LRE wizard

Permisos agregados:
- hr.lre.wizard.user: CRUD (sin unlink)
- hr.lre.wizard.manager: CRUD completo

Tests:
- test_lre_access_rights.py (4 tests)
- HR User, HR Manager, Basic User

Refs: H-002
```

#### 6. Chore con Higiene OCA
```
chore(l10n_cl_dte): OCA hygiene cleanup - remove .pyc and relocate migration scripts

Limpieza:
- Eliminados 15 archivos .pyc
- Movidos scripts migración a migrations/
- .gitignore actualizado

Cumplimiento: OCA Guidelines v14
Refs: SESION_AUDITORIA_OCA_2025-11-04.md
```

#### 7. Docs con Reporte Ejecutivo
```
docs(payroll): add P0/P1 gap closure report

Documentación agregada:
- RESUMEN_EJECUTIVO_CIERRE_P0_P1_NOMINA.md
- 4 gaps cerrados (H-007, H-001, H-002, H-003)
- Métricas: 1,191 LOC, 22 tests, 92% coverage

Audiencia: Stakeholders + equipo técnico
```

#### 8. Dashboard Feature Completo
```
feat(dashboard): Kanban drag&drop + Excel export inline

Funcionalidad:
- Drag&drop entre columnas Kanban
- Export Excel inline (sin wizard)
- Colores dinámicos por score

Archivos:
- l10n_cl_financial_reports/controllers/dashboard.py
- l10n_cl_financial_reports/static/src/js/dashboard.js

Refs: CIERRE_EXITOSO_DASHBOARD_FINAL_2025-11-04.md
```

---

## 🚫 ANTI-PATRONES (QUÉ NO HACER)

### ❌ Commits Genéricos

```
❌ git commit -m "fix"
❌ git commit -m "updates"
❌ git commit -m "cambios varios"
❌ git commit -m "wip"
❌ git commit -m "asdfasdf"
```

**Problema**: Imposible entender qué cambió sin revisar diff.

**✅ Correcto**:
```
fix(dte): handle timeout in SII SOAP client (30s → 60s)
```

---

### ❌ Commits Multi-Scope

```
❌ git commit -m "fix: payroll bug and add DTE 39 support and update docs"
```

**Problema**: Mezcla 3 cambios no relacionados.

**✅ Correcto** (3 commits atómicos):
```
fix(payroll): correct field name in allowance processing
feat(dte): add support for DTE 39 Boleta
docs(readme): update deployment instructions
```

---

### ❌ Sin Contexto Técnico

```
❌ git commit -m "fix(dte): arreglar bug"
```

**Problema**: No dice QUÉ bug ni CÓMO se arregló.

**✅ Correcto**:
```
fix(dte): validate RUT format before XML generation

Problema: RUTs sin formato (12345678-9) causaban rechazo SII.
Solución: Validar con stdnum.cl.rut antes de generar XML.

Refs: #42
```

---

### ❌ Commits Masivos (>500 LOC)

```
❌ git commit -m "feat(dte): implement complete DTE module"
     (3,000 líneas en 50 archivos)
```

**Problema**: Imposible de revisar, rollback arriesgado.

**✅ Correcto** (dividir en commits atómicos):
```
feat(dte): add base models (account.move.dte, dte.inbox)
feat(dte): add CAF management (wizard + validation)
feat(dte): add XML generator for DTE 33
feat(dte): add SII SOAP client
feat(dte): add DTE signature with xml_signer
test(dte): add comprehensive test suite
docs(dte): add configuration guide
```

---

## 🔧 HERRAMIENTAS Y AUTOMACIÓN

### 1. Git Message Template

**Archivo**: `.gitmessage`

```
# <tipo>(<scope>): <descripción corta (max 72 chars)>
# |<----  Preferiblemente usar hasta 50 caracteres  ---->|


# [cuerpo opcional - explicar QUÉ y POR QUÉ, no CÓMO]


# [footer opcional]
# Refs: #<issue>, <hallazgo-id>
# BREAKING CHANGE: <descripción>

# --- TIPOS ---
# feat:     Nueva funcionalidad
# fix:      Corrección de bug
# docs:     Solo documentación
# test:     Agregar/modificar tests
# i18n:     Traducciones
# refactor: Mejora de código (sin cambio funcionalidad)
# perf:     Optimización de performance
# style:    Formato (black, PEP8)
# chore:    Mantenimiento (deps, configs)
# build:    Cambios en build system
# ci:       Cambios en CI/CD
# revert:   Revertir commit previo
#
# --- SCOPES ---
# dte, payroll, reports, base, ai, docker, ci, docs, tests, libs
#
# --- BREAKING CHANGE ---
# Agregar '!' después del scope: feat(dte)!: ...
# O en footer: BREAKING CHANGE: descripción
```

**Configurar**:
```bash
git config commit.template /Users/pedro/Documents/odoo19/.gitmessage
```

---

### 2. Commitlint (Opcional - Futuro)

**Archivo**: `.commitlintrc.json`

```json
{
  "extends": ["@commitlint/config-conventional"],
  "rules": {
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "docs",
        "test",
        "i18n",
        "refactor",
        "perf",
        "style",
        "chore",
        "build",
        "ci",
        "revert"
      ]
    ],
    "scope-enum": [
      2,
      "always",
      [
        "dte",
        "payroll",
        "reports",
        "base",
        "ai",
        "dte-service",
        "eergy",
        "docker",
        "ci",
        "docs",
        "tests",
        "libs"
      ]
    ],
    "subject-max-length": [2, "always", 72],
    "body-max-line-length": [2, "always", 100]
  }
}
```

**Instalar**:
```bash
npm install --save-dev @commitlint/cli @commitlint/config-conventional
npx husky add .husky/commit-msg 'npx --no -- commitlint --edit "$1"'
```

---

### 3. Pre-commit Hooks (Validación Automática)

**Archivo**: `.pre-commit-config.yaml`

```yaml
repos:
  # Conventional Commits validation
  - repo: https://github.com/compilerla/conventional-pre-commit
    rev: v2.4.0
    hooks:
      - id: conventional-pre-commit
        stages: [commit-msg]
        args:
          - feat
          - fix
          - docs
          - test
          - i18n
          - refactor
          - perf
          - style
          - chore
          - build
          - ci
          - revert

  # Python formatting
  - repo: https://github.com/psf/black
    rev: 23.10.0
    hooks:
      - id: black
        language_version: python3.11

  # Flake8 linting
  - repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
      - id: flake8
        args: [--max-line-length=100]

  # Secrets detection
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
```

**Instalar**:
```bash
pip install pre-commit
pre-commit install
pre-commit install --hook-type commit-msg
```

---

## 📊 MÉTRICAS DE CALIDAD

### Indicadores de Commits Profesionales

| Métrica | Target | Descripción |
|---------|--------|-------------|
| **Convencionalidad** | 95%+ | % commits que siguen Conventional Commits |
| **Atomicidad** | 90%+ | % commits con 1 cambio lógico |
| **Trazabilidad** | 80%+ | % commits con referencias (Refs:) |
| **Descriptividad** | 100% | % commits con descripción clara |
| **Tamaño** | <300 LOC | Promedio de líneas por commit |

### Dashboard Calidad de Commits (Ejemplo)

```bash
# Analizar últimos 100 commits
git log --oneline -100 --pretty=format:"%s" | \
  grep -E "^(feat|fix|docs|test|i18n|refactor|perf|style|chore|build|ci|revert)\(" | \
  wc -l

# Resultado esperado: 95+ de 100 (95%+ convencionales)
```

---

## 🎓 GUÍA RÁPIDA: ¿QUÉ TIPO USAR?

### Diagrama de Decisión

```
¿Cambia funcionalidad para usuario final?
  ├─ SÍ → ¿Agrega algo nuevo?
  │         ├─ SÍ → feat
  │         └─ NO → fix
  │
  └─ NO → ¿Cambia código?
            ├─ SÍ → ¿Cambia lógica?
            │         ├─ SÍ → refactor
            │         └─ NO → style
            │
            └─ NO → ¿Es test?
                      ├─ SÍ → test
                      └─ NO → ¿Es documentación?
                                ├─ SÍ → docs
                                └─ NO → chore
```

---

## 📚 CASOS DE USO FRECUENTES

### Caso 1: Cerrar Hallazgo de Auditoría

```bash
# Hallazgo H-007: Campo year inexistente
git add addons/localization/l10n_cl_hr_payroll/models/hr_lre_wizard.py
git commit -m "fix(payroll): use validity range for legal caps instead of year field

Problema: Campo 'year' en l10n_cl.legal_caps no existe.
Solución: Usar dominio con valid_from/valid_until.

Impact: P0 - Bloqueante
Refs: H-007 (AUDITORIA_NOMINA_P0_P1_TABLA_EVIDENCIAS.md)"
```

---

### Caso 2: Agregar Test Suite

```bash
# Tests de seguridad XXE
git add addons/localization/l10n_cl_dte/tests/test_xxe_protection.py
git commit -m "test(l10n_cl_dte): add comprehensive XXE security tests (23 tests)

Coverage:
- XXE entity expansion (5 tests)
- External entity injection (6 tests)
- Billion laughs attack (3 tests)
- DTD validation bypass (4 tests)
- Integration tests (5 tests)

Coverage total: 95%+ en xml_signer
Refs: XXE_TEST_EXECUTION_SUMMARY.md"
```

---

### Caso 3: Actualizar Documentación

```bash
# Documentación de configuración
git add docs/guides/GUIA_CONFIGURACION_RECEPCION_DTE_EMAIL.md
git commit -m "docs(dte): add email reception configuration guide

Contenido:
- Setup servidor IMAP
- Configuración credenciales
- Reglas de filtrado
- Troubleshooting común

Audiencia: DevOps + Admin Odoo"
```

---

### Caso 4: Refactorizar Código Legacy

```bash
# Extraer lógica a librería pura
git add addons/localization/l10n_cl_dte/libs/xml_validator.py
git commit -m "refactor(libs): extract DTE XML validator to pure Python library

Beneficios:
- Testeable sin Odoo
- Reusable en microservicios
- Sin dependencias ORM

Cambios:
- Movido de models/ a libs/
- Eliminadas dependencias Odoo
- Agregados 10 unit tests

Performance: Sin cambios (100% compatible)"
```

---

### Caso 5: Breaking Change (Migración)

```bash
# Eliminar campo obsoleto
git add addons/localization/l10n_cl_dte/models/account_move_dte.py
git add addons/localization/l10n_cl_dte/migrations/19.0.7.0.0/
git commit -m "feat(dte)!: remove deprecated 'dte_xml_file' field

BREAKING CHANGE: Campo 'dte_xml_file' eliminado.
Ahora se usa attachment_ids estándar de Odoo.

Migración:
- Script: migrations/19.0.7.0.0/pre-migrate.py
- Convierte dte_xml_file → attachment_ids
- Backup automático pre-migración

Acción requerida:
- Actualizar módulo: -u l10n_cl_dte
- Verificar attachments post-migración

Refs: #156"
```

---

## 🔗 REFERENCIAS

### Especificaciones

- **Conventional Commits**: https://www.conventionalcommits.org/
- **Semantic Versioning**: https://semver.org/
- **Keep a Changelog**: https://keepachangelog.com/

### Herramientas

- **commitlint**: https://commitlint.js.org/
- **conventional-changelog**: https://github.com/conventional-changelog/conventional-changelog
- **semantic-release**: https://semantic-release.gitbook.io/

### Proyecto

- **CONTRIBUTING.md**: Guía completa de contribución
- **AGENTS.md**: Agentes AI y patrones de código
- **AI_AGENT_INSTRUCTIONS.md**: Instrucciones para agentes AI

---

## 📞 CONTACTO Y AYUDA

**¿Dudas sobre qué tipo de commit usar?**

1. Consulta el [Diagrama de Decisión](#diagrama-de-decisión)
2. Revisa los [Ejemplos Reales](#ejemplos-reales-del-proyecto)
3. Pregunta en canal `#git-commits` (Slack/Teams)

**¿Commit incorrecto?**

```bash
# Modificar último commit (NO pusheado)
git commit --amend

# Reescribir mensaje
git commit --amend -m "tipo(scope): descripción correcta"

# Si ya pusheaste: NO reescribir historial público
# En su lugar, crea un nuevo commit corrigiendo
```

---

## ✅ CHECKLIST PRE-COMMIT

Antes de cada commit, verifica:

- [ ] **Tipo correcto**: ¿Es `feat`, `fix`, `docs`, `test`, etc.?
- [ ] **Scope apropiado**: ¿`dte`, `payroll`, `ai`, etc.?
- [ ] **Descripción clara**: ¿Explica QUÉ cambió en <72 chars?
- [ ] **Atómico**: ¿Es 1 cambio lógico o debo dividir?
- [ ] **Referenciado**: ¿Incluye `Refs:` si aplica?
- [ ] **Breaking change**: ¿Agregué `!` o `BREAKING CHANGE:` si aplica?
- [ ] **Tests pasan**: ¿Ejecuté tests antes de commitear?
- [ ] **Sin secrets**: ¿No hay API keys, passwords, etc.?

---

## 🎯 CONCLUSIÓN

**Commits profesionales = Proyecto profesional**

Seguir esta estrategia garantiza:
- ✅ Historial legible y mantenible
- ✅ Changelogs automáticos
- ✅ Rollbacks seguros
- ✅ Colaboración eficiente
- ✅ Auditoría y compliance

**Recuerda**: Un buen commit hoy = Menos dolor mañana 🚀

---

**Documento generado por**: Equipo EERGYGROUP  
**Versión**: 2.0  
**Fecha**: 9 de noviembre de 2025  
**Mantenedor**: Ing. Pedro Troncoso Willz
