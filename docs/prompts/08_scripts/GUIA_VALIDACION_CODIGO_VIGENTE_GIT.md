# 🔍 GUÍA: Validación de Código Vigente en Git

**Autor:** Sistema de Prompts Odoo19  
**Fecha:** 2025-11-13  
**Versión:** 1.0  
**Compatibilidad:** Git 2.23+

---

## 🎯 Respuesta Rápida

**Pregunta:** ¿Cómo saber si estamos trabajando sobre código vigente?

**Respuesta:** Ejecuta estos 2 comandos:

```bash
git status
git pull origin develop
```

Si `git status` muestra:
- ✅ `Your branch is up to date with 'origin/develop'` → Estás al día
- ⚠️  `Your branch is behind 'origin/develop'` → Necesitas `git pull`

---

## 📊 Estado Actual del Repositorio (Ejemplo Real)

```bash
$ git status -s
 M .env                                    # Modificado localmente
 M ai-service/utils/redis_helper.py       # Modificado localmente
?? docs/prompts/06_outputs/2025-11/...   # Archivo nuevo (no trackeado)
```

**Interpretación:**
- `M` = Modificado (cambios locales pendientes)
- `??` = Archivo nuevo (no trackeado en Git)
- Si no aparece nada → Working tree clean ✅

---

## 🔍 Comandos de Validación

### 1. Ver Estado Git

```bash
git status
```

**Salida esperada:**
```
On branch develop
Your branch is up to date with 'origin/develop'.

Changes not staged for commit:
  modified:   .env
  modified:   ai-service/utils/redis_helper.py

Untracked files:
  docs/prompts/06_outputs/2025-11/...
```

### 2. Ver Branch Actual

```bash
git branch --show-current
```

**Salida:** `develop` ✅

### 3. Ver si Hay Commits Remotos Nuevos

```bash
git fetch origin
git status
```

Si dice `Your branch is up to date with 'origin/develop'` ✅

### 4. Ver Últimos Commits

```bash
git log --oneline -5
```

**Ejemplo:**
```
565df23c docs(audit): Add 360° audit report
3625b577 docs(p0): Add comprehensive P0 fixes summary
e96e002c test(integration): P0-4 - Add 17 integration tests
```

---

## ⚠️ Situaciones Comunes y Soluciones

### CASO 1: Branch Atrasado

**Síntoma:**
```
Your branch is behind 'origin/develop' by 3 commits
```

**Solución:**
```bash
git pull origin develop
```

**Importante:** Si tienes cambios locales sin commitear:
```bash
git stash              # Guarda cambios temporalmente
git pull origin develop
git stash pop          # Recupera tus cambios
```

### CASO 2: Descartar Cambios Locales

**Ver qué cambiaste:**
```bash
git diff archivo.py
```

**Descartar cambios:**
```bash
git restore archivo.py    # Git 2.23+
git checkout -- archivo.py  # Versión anterior
```

### CASO 3: Ver Versión Git vs Local

**Versión en Git (último commit):**
```bash
git show HEAD:ai-service/utils/redis_helper.py
```

**Diferencias:**
```bash
git diff ai-service/utils/redis_helper.py
```

### CASO 4: Ver Historial de un Archivo

```bash
git log --follow ai-service/utils/redis_helper.py
```

**Con cambios específicos:**
```bash
git log -p ai-service/utils/redis_helper.py
```

---

## ✅ Validación de Archivos Modificados

### Archivo: `.env`

| Propiedad | Valor |
|-----------|-------|
| **Status** | Modificado (M) |
| **Cambio** | ODOO_API_KEY actualizada |
| **¿Es correcto?** | SÍ ✅ (cambio intencional) |
| **¿Commitear?** | NO ❌ (.env nunca se commitea) |

### Archivo: `ai-service/utils/redis_helper.py`

| Propiedad | Valor |
|-----------|-------|
| **Status** | Modificado (M) |
| **Cambio** | Eliminados defaults hardcoded |
| **¿Es correcto?** | SÍ ✅ (fix P0-02) |
| **¿Commitear?** | SÍ ✅ (después de tests) |

---

## 🚨 Reglas de Oro

### ✅ ANTES de Hacer Cambios

```bash
git pull origin develop
git status  # Verificar que estás limpio
```

### ✅ DURANTE Cambios

- ✅ Trabaja sobre archivos con "M" (modificados)
- ✅ Si archivo tiene conflictos (`<<<<<<<`), resuélvelos primero
- ✅ Si un archivo "not found", verifica que existe en Git

### ✅ DESPUÉS de Cambios

```bash
git status    # Ver qué modificaste
git diff      # Ver cambios específicos
```

### ❌ NUNCA

- ❌ Modificar archivos de otro branch sin hacer `checkout`
- ❌ Hacer cambios sin verificar branch actual
- ❌ Commitear `.env` o archivos con secrets
- ❌ Hacer `git add .` sin revisar qué agregas

---

## 📝 Comandos Útiles de Verificación

### Ver Archivo Específico en Git (Sin Modificaciones Locales)

```bash
git show HEAD:ai-service/utils/redis_helper.py
```

### Comparar Tu Versión vs Git

```bash
git diff ai-service/utils/redis_helper.py
```

### Ver Quién Modificó Cada Línea (Blame)

```bash
git blame ai-service/utils/redis_helper.py
```

### Ver Diferencias Entre Commits

```bash
git diff HEAD~1 HEAD ai-service/utils/redis_helper.py
```

### Listar Archivos Trackeados en Git

```bash
git ls-files | grep redis_helper
```

**Interpretación:**
- Si devuelve resultado → Existe en Git ✅
- Si no devuelve nada → No está trackeado (archivo nuevo)

---

## 🎯 Situación Actual (2025-11-13)

| Aspecto | Estado | Comentario |
|---------|--------|------------|
| **Branch** | develop | ✅ Correcto |
| **Estado** | Up to date with origin | ✅ Al día |
| **Último commit** | 565df23c | ✅ Vigente |
| **Modificaciones locales** | 5 archivos | ✅ Intencionales (fixes P0) |

### Archivos Modificados Localmente (Intencionales)

1. ✅ `.env` (P0-01: API key segura)
2. ✅ `ai-service/utils/redis_helper.py` (P0-02: sin defaults)
3. ⚠️  `ai-service/config.py` (cambios menores)
4. ⚠️  `docker-compose.yml` (config updates)

### Conclusión

✅ **ESTÁS TRABAJANDO SOBRE CÓDIGO VIGENTE**  
✅ **LAS MODIFICACIONES SON INTENCIONALES (FIXES P0)**  
✅ **EL RESTO DEL CÓDIGO ESTÁ SINCRONIZADO CON GIT**

---

## 💡 Recomendación para Próximos Cambios

### 1. ANTES de Iniciar Trabajo

```bash
git status
git pull origin develop
```

### 2. DURANTE Trabajo

- Las herramientas (`search_replace`, `write`) trabajan sobre el **filesystem**
- El filesystem contiene: **Versión de Git + tus cambios locales**
- Es normal tener archivos con status "M" mientras trabajas

### 3. VALIDAR que Archivo Existe en Git

```bash
git ls-files | grep nombre_archivo
```

### 4. VER Versión Git vs Tu Versión

```bash
git diff nombre_archivo
```

---

## ✅ Respuesta Final

### ¿Qué Versión del Código Estás Editando?

Cuando trabajas con herramientas directamente sobre archivos:

1. **La versión de Git** (si el archivo está trackeado)
2. **MÁS** tus modificaciones locales pendientes (si las hay)

### ¿Cómo Saber si Estás en Código Vigente?

```bash
git status
git pull origin develop  # Si hay actualizaciones
```

### Tu Situación HOY

| Aspecto | Estado |
|---------|--------|
| **Código base** | ✅ Vigente (develop actualizado) |
| **Modificaciones** | ✅ Intencionales (fixes P0) |
| **Conflictos** | ✅ Sin conflictos |
| **Commits perdidos** | ✅ Ninguno |

**TODO OK ✅**

---

## 📚 Referencias

- **Git Documentation:** https://git-scm.com/doc
- **Git Basics:** https://git-scm.com/book/en/v2/Getting-Started-Git-Basics
- **AGENTS.md:** `/Users/pedro/Documents/odoo19/AGENTS.md` (línea 340-360)

---

## 🔗 Archivos Relacionados

- **Guía Docker + Odoo:** `.github/agents/knowledge/docker_odoo_command_reference.md`
- **Workflow Git:** `.github/workflows/ci.yml`
- **Configuración Git:** `.gitignore`, `.gitattributes`

---

**Última Actualización:** 2025-11-13  
**Mantenedor:** Pedro Troncoso Willz (@pwills85)  
**Licencia:** LGPL-3 (Odoo modules)

