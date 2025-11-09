# 🎯 MATRIZ DE DECISIONES - Guía Rápida

## Resumen en Tabla

| Item | Tamaño | Estado | Acción | Riesgo | Reversible | Prioridad |
|------|--------|--------|--------|--------|-----------|-----------|
| **--rm, --stop-after-init, -d, -name, -u, -o** | 43-102 B | ❌ Corrupto | Eliminar | ✅ Nulo | ✅ Git | 🔴 Inmediata |
| **0, Total, archivos, docker-compose (dup), echo, find, run** | 43-51 B | ❌ Corrupto | Eliminar | ✅ Nulo | ✅ Git | 🔴 Inmediata |
| **l10n_cl_dte, odoo, odoo19, *test.py, test*.py, test:** | 43-51 B | ❌ Corrupto | Eliminar | ✅ Nulo | ✅ Git | 🔴 Inmediata |
| **__pycache__ (ai-service)** | 380 KB | ⚠️ Cache | Eliminar | ✅ Nulo | ✅ Auto-regen | 🟡 Importante |
| **Documentos históricos (23 archivos)** | 340 KB | 📦 Archivado | Mover → docs/ARCHIVE | ⚠️ Bajo | ✅ Git | 🟢 Opcional |
| **Logs antiguos** | 90 KB | 📋 Histórico | Mover → backups/logs_archive | ✅ Nulo | ✅ Git | 🟢 Opcional |
| **addons/**, **ai-service/**, **config/** | 59+ MB | ✅ Activo | **NO TOCAR** | ❌ Alto | ❌ No | 🔵 Mantener |
| **README.md, START_HERE.md** | 58 KB | 📖 Crítico | **NO MOVER** | ❌ Alto | ✅ Git | 🔵 Mantener |

---

## 🚦 Flujo de Decisión

```
¿Necesitas limpiar el proyecto?
│
├─→ ¿Ejecuto TODO automático?
│   ├─→ SÍ (Recomendado)
│   │   └─→ ./cleanup.sh
│   │       ├─ 🟢 Fase 1: Elimina accidentales (SIN RIESGO)
│   │       ├─ 🟢 Fase 2: Limpia cachés (SIN RIESGO)
│   │       ├─ 🟡 Fase 3: Crea estructura backup
│   │       └─ 🟡 Fase 4: Archiva logs
│   │
│   └─→ NO (Manual selectivo)
│       ├─→ ¿Solo eliminar archivos accidentales?
│       │   └─→ rm -f --rm --stop-after-init -d ...
│       │
│       ├─→ ¿Solo limpiar cachés Python?
│       │   └─→ find ai-service -name __pycache__ -exec rm -rf {} +
│       │
│       └─→ ¿Solo archivar logs?
│           └─→ mkdir -p backups/logs_archive_DATE
│               mv logs/*.log backups/logs_archive_DATE/
│
└─→ ¿Necesito revisar antes?
    └─→ Leer: CLEANUP_VISUAL_GUIDE.md
```

---

## 🔍 ¿QUIÉN DEBE HACER QUÉ?

### 👨‍💼 Project Manager / DevOps Lead
**Tarea:** Revisar matriz y dar luz verde

- [ ] Leer `CLEANUP_SUMMARY.md` (5 min)
- [ ] Revisar impacto en `CLEANUP_VISUAL_GUIDE.md` (10 min)
- [ ] Confirmar archivos a mover en `CLEANUP_RECOMMENDATIONS.md`
- [ ] Aprobar ejecución de `cleanup.sh`

**Riesgo para el proyecto:** ✅ BAJO (0% impacto en funcionalidad)

---

### 👨‍💻 Developer / DevOps Engineer
**Tarea:** Ejecutar limpieza

```bash
# Paso 1: Verificación previa
cd /Users/pedro/Documents/odoo19
git status  # Confirmar rama y estado

# Paso 2: Ejecutar limpieza
./cleanup.sh

# Paso 3: Verificación post
git status  # Debe ser limpio
git diff --stat  # Ver cambios
ls -la | grep "^-" | wc -l  # Debe haber ~35 archivos (antes ~54)

# Paso 4: Commit
git add -A
git commit -m "chore: cleanup project structure - remove accidental files and cache"
```

**Tiempo total:** 5 minutos

---

### 🔐 Security/QA Lead
**Tarea:** Validar que la limpieza no afecte

- [ ] Verificar que `addons/` sigue íntegro
- [ ] Confirmar que `ai-service/` funciona sin caché
- [ ] Revisar que logs críticos no fueron eliminados
- [ ] Aprobar documentación archivada

**Validación:**
```bash
# Verificar integridad de módulos críticos
ls -la addons/ | grep "l10n_cl_dte"  # Debe existir
ls -la addons/ | grep "l10n_cl_hr"   # Debe existir

# Verificar que ai-service funciona
python ai-service/main.py --help 2>&1 | head -5  # Debe compilar

# Verificar estructura
find docs/ARCHIVE -name "*.md" | wc -l  # Documentos archivados
find backups/logs_archive* -name "*.log" 2>/dev/null | wc -l  # Logs archivados
```

---

## 📋 Checklist Pre-Ejecución

Antes de ejecutar `cleanup.sh`:

### Seguridad
- [ ] Backup realizado: `tar -czf ~/odoo19_backup_$(date +%Y%m%d).tar.gz /Users/pedro/Documents/odoo19`
- [ ] Rama correcta: `git branch` (debe ser feature/gap-closure-odoo19-production-ready)
- [ ] Sin cambios locales sin commit: `git status`
- [ ] Todos los procesos parados: No hay contenedores corriendo

### Verificación
- [ ] Leer: `CLEANUP_RECOMMENDATIONS.md`
- [ ] Revisar: `CLEANUP_VISUAL_GUIDE.md`
- [ ] Confirmar: Archivos a eliminar no son críticos
- [ ] Validar: Documentación archivada puede moverse

### Comunicación
- [ ] Team notificado de la limpieza
- [ ] Horario apropiado (sin trabajo en progreso)
- [ ] Acceso a soporte si hay problemas

---

## ✅ Checklist Post-Ejecución

Después de ejecutar `cleanup.sh`:

### Verificación Inmediata
- [ ] Script completó sin errores
- [ ] No hay archivos accidentales: `ls -l | grep "^-" | wc -l` (debe ser ~35)
- [ ] Cachés eliminados: `find ai-service -name __pycache__ | wc -l` (debe ser 0)
- [ ] Logs archivados: `ls -la backups/ | grep logs_archive`
- [ ] Git limpio: `git status` (nothing to commit)

### Validación Funcional
- [ ] Módulo l10n_cl_dte existe: `ls addons/l10n_cl_dte`
- [ ] Servicios IA íntegros: `python -c "import sys; sys.path.insert(0, 'ai-service'); from main import *"`
- [ ] Scripts disponibles: `ls scripts/` (debe tener contenido)
- [ ] Config accesible: `cat config/odoo.conf | head -5`

### Documentación
- [ ] Archivos históricos en archive: `ls docs/ARCHIVE | wc -l` (debe ser ~23)
- [ ] README aún en raíz: `ls README.md`
- [ ] START_HERE aún en raíz: `ls START_HERE.md`
- [ ] Estructura backup creada: `ls -la backups/logs_archive_*`

### Git
- [ ] Cambios visibles: `git log -1`
- [ ] Archivos eliminados registrados: `git log --name-status -1 | grep "^D"`
- [ ] Directorios creados registrados: `git log -p docs/ARCHIVE -1 | head -20`

---

## 🔄 Recuperación en Caso de Error

Si algo sale mal después de ejecutar:

```bash
# Opción 1: Revertir último commit
git revert HEAD

# Opción 2: Restaurar desde antes de los cambios
git restore .
git restore docs/
git restore backups/

# Opción 3: Recuperar desde backup
tar -xzf ~/odoo19_backup_*.tar.gz -C ~/

# Opción 4: Contactar soporte con logs
tail -100 ~/.bash_history | grep cleanup
```

---

## 📊 Resultados Esperados

```
ANTES:
├─ Archivos en raíz: 54 (corrupto, desorganizado)
├─ Tamaño raíz: ~465 KB (incluye caché)
├─ Carpetas raíz: 13 (mezcladas)
└─ Documentación: Dispersa

DESPUÉS:
├─ Archivos en raíz: ~35 (limpio, organizado)
├─ Tamaño raíz: ~116 KB (↓ 75%)
├─ Carpetas raíz: 13 (ordenadas, backup creadas)
├─ Documentación: Centralizada en docs/ + archive/
├─ Logs: Archivados en backups/
└─ Cachés: Eliminados (auto-regenerables)

BENEFICIOS:
✅ Espacio liberado: ~811 KB
✅ Organización mejorada: ⭐⭐⭐⭐⭐
✅ Raíz limpia y clara
✅ Mejor navegación del proyecto
✅ Menos confusión para nuevos desarrolladores
✅ Git history limpio
```

---

## ❓ Preguntas Frecuentes

**P: ¿Perdería datos si ejecuto cleanup.sh?**  
R: No. Todo está respaldado en Git y los cachés se regeneran. Pero haz backup por seguridad.

**P: ¿Cuánto tiempo toma?**  
R: 2-3 minutos máximo.

**P: ¿Qué pasa si olvido descomenta la Fase 2 de limpieza de docs?**  
R: Los documentos se quedan en raíz. Puedes moverlos después manualmente.

**P: ¿Necesito permisos especiales?**  
R: Solo permisos de lectura/escritura en la carpeta. No necesitas sudo.

**P: ¿Puedo ejecutarlo en producción?**  
R: No, solo en desarrollo. La limpieza es para organización.

**P: ¿Qué hace si los archivos están en Git?**  
R: Git los registra como "deleted" en el siguiente commit.

**P: ¿Se afecta el historial de Git?**  
R: No. El historial se mantiene. Los archivos pueden recuperarse con `git restore`.

---

## 🎓 Recomendaciones Futuras

Después de esta limpieza:

1. **Documentación:** 
   - Mantén README.md y START_HERE.md en raíz
   - Nuevo contenido en `docs/`
   - Histórico en `docs/ARCHIVE/`

2. **Cachés:**
   - Agrega a `.gitignore`: `__pycache__/`, `*.pyc`, `.pytest_cache/`
   - Ejecuta `git clean -fd` periódicamente

3. **Logs:**
   - Rota logs mensualmente
   - Archiva en `backups/logs_archive_YYYY-MM-DD/`
   - Mantén solo 3 meses de histórico

4. **Archivos Raíz:**
   - Mantén solo archivos críticos
   - Organiza por categoría (config, scripts, docs)
   - Revisa trimestralmente

5. **Git:**
   - Usa `.gitignore` agresivamente
   - Haz cleanup regularmente
   - Documenta cambios en PRs

---

**Última actualización:** 24 de octubre de 2025  
**Versión:** 1.0  
**Estado:** Listo para ejecutar ✅
