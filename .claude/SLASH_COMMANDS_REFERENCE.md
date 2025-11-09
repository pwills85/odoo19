# ⚡ Slash Commands - Quick Reference

**Ubicación:** `.claude/commands/`
**Total:** 6 comandos

---

## 🚀 Comandos Disponibles

### 1. /restart-odoo
**Descripción:** Reinicia el contenedor de Odoo y muestra logs

**Uso:**
```
/restart-odoo
```

**Output:**
- Reinicia el servicio Odoo
- Muestra las últimas 50 líneas de logs
- Útil después de cambios en código Python

---

### 2. /run-tests
**Descripción:** Ejecuta tests para un módulo específico

**Uso:**
```
/run-tests <module_name>
```

**Ejemplos:**
```
/run-tests l10n_cl_dte
/run-tests l10n_cl_hr_payroll
/run-tests l10n_cl_financial_reports
```

**Output:**
- Ejecuta suite completa de tests del módulo
- Muestra resultados en log-level=test
- Se detiene después de completar tests (--stop-after-init)

---

### 3. /update-module
**Descripción:** Actualiza un módulo en la base de datos de Odoo

**Uso:**
```
/update-module <module_name>
```

**Ejemplos:**
```
/update-module l10n_cl_dte
/update-module l10n_cl_financial_reports
```

**Output:**
- Actualiza esquema de base de datos
- Actualiza vistas y datos
- No ejecuta tests
- Recuerda reiniciar Odoo después

---

### 4. /compliance-check
**Descripción:** Ejecuta validación completa de compliance SII/DTE

**Uso:**
```
/compliance-check
```

**Validaciones:**
- ✅ Algoritmo de validación RUT
- ✅ Gestión de CAF (folios)
- ✅ Implementación de firma XML
- ✅ Endpoints de SII configurados
- ✅ Ejecuta validator enterprise

**Output:**
- Checklist de compliance
- Issues detectados
- Sugerencias para reporte detallado

---

### 5. /git-status
**Descripción:** Muestra status detallado del repositorio Git

**Uso:**
```
/git-status
```

**Output:**
- Branch actual
- Remote configurado
- Archivos modificados/agregados/eliminados
- Últimos 5 commits
- Resumen de cambios
- Comandos sugeridos

---

### 6. /docker-status
**Descripción:** Muestra status de servicios Docker y recursos

**Uso:**
```
/docker-status
```

**Output:**
- Contenedores corriendo
- Uso de recursos (CPU, memoria, red)
- Imágenes de Odoo/PostgreSQL
- Redes configuradas
- Comandos útiles sugeridos

---

## 💡 Tips de Uso

### Combinar comandos
```
# Workflow típico de desarrollo:
/git-status              # Ver cambios
/update-module l10n_cl_dte   # Actualizar módulo
/restart-odoo            # Reiniciar para ver cambios
/run-tests l10n_cl_dte   # Validar con tests
/compliance-check        # Verificar compliance
```

### Automatización con scripts
Los slash commands pueden ser invocados desde scripts bash:
```bash
# deploy.sh
/run-tests l10n_cl_dte && \
/compliance-check && \
/update-module l10n_cl_dte && \
/restart-odoo
```

### Crear tus propios comandos
```bash
# 1. Crea archivo en .claude/commands/
touch .claude/commands/mi-comando.md

# 2. Agrega frontmatter y lógica
---
description: Descripción de mi comando
---

# Comandos bash aquí
```

---

## 🔧 Troubleshooting

### Comando no reconocido
**Problema:** Claude no reconoce el slash command

**Solución:**
1. Verifica que el archivo existe: `ls .claude/commands/`
2. Verifica el formato del frontmatter (---description:---)
3. Reinicia Claude Code

### Permisos de ejecución
**Problema:** Error de permisos al ejecutar comando

**Solución:**
```bash
chmod +x .claude/commands/*.md
```

### Comando tarda mucho
**Problema:** El comando parece congelado

**Solución:**
- Comandos con Docker pueden tardar (especialmente /run-tests)
- Revisa logs: `docker-compose logs -f odoo`
- Considera timeout en settings.json

---

## 📚 Próximos Comandos (Roadmap)

**En consideración:**
- `/create-module` - Wrapper para skill odoo-module-scaffold
- `/deploy` - Deployment workflow completo
- `/backup-db` - Backup de base de datos
- `/migrate-module` - Asistente de migración
- `/cost-report` - Reporte de costos Claude API

**Sugerencias:** Abre issue o modifica directamente `.claude/commands/`

---

## 🎯 Comparación: Antes vs. Ahora

### Antes (Sin slash commands)
```
Tarea: Reiniciar Odoo y ver logs

Pasos:
1. Escribir: docker-compose restart odoo
2. Esperar
3. Escribir: docker-compose logs -f odoo --tail=50
4. Posibles errores tipográficos
5. Tiempo: ~60 segundos
```

### Ahora (Con slash commands)
```
Tarea: Reiniciar Odoo y ver logs

Pasos:
1. Escribir: /restart-odoo
2. Tiempo: ~5 segundos

Ahorro: 92% de tiempo
```

---

**Última actualización:** 2025-11-08
**Comandos totales:** 6
**Ahorro estimado:** 2 horas/semana
