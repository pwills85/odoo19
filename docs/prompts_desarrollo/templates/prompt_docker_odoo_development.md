# Prompt Docker/Odoo Development: Investigación y Desarrollo Profesional

**Versión:** 1.0.0  
**Nivel:** Enterprise Development (Investigación + Desarrollo + Testing + Debugging)  
**Target Output:** 600-900 palabras (±20% si justificas)  
**Tiempo estimado:** 5-8 minutos ejecución

---

## 📋 Objetivo

Proporcionar **comandos profesionales Docker + Odoo CLI** para investigación, desarrollo, testing y debugging en proyecto Odoo 19 CE chileno con arquitectura multi-servicio (Odoo + PostgreSQL + Redis + AI Service).

---

## 🎯 Contexto del Entorno (CRÍTICO)

### Stack Completo

```yaml
Arquitectura: Docker Compose (10 servicios)
  Core (siempre activos):
    - db: PostgreSQL 15-alpine
    - redis-master: Redis 7-alpine (sessions)
    - odoo: eergygroup/odoo19:chile-1.0.5 (CUSTOM)
    - ai-service: FastAPI microservice (CUSTOM)

Platform: linux/arm64 (Apple M3)
Host OS: macOS 15.1 Sequoia
Python Host: 3.14.0 (Homebrew + .venv aislado)
```

### Regla de Oro (CRÍTICA - NUNCA VIOLAR)

```bash
# ✅ CORRECTO - Comandos Odoo/Python EN CONTAINER
docker compose exec odoo odoo-bin [comando]
docker compose exec odoo pytest [tests]
docker compose exec odoo python [script]

# ❌ INCORRECTO - Comandos en host (FALLARÁN)
odoo-bin [comando]  # ❌ No existe en host
python [script]     # ❌ Usa Python host (sin acceso a DB Odoo)
pytest [tests]      # ❌ No tiene dependencias Odoo
```

### Scripts Host Permitidos (SOLO utilidades NO-Odoo)

```bash
# ✅ Scripts análisis estático (NO requieren Odoo runtime)
.venv/bin/python scripts/verify_production_readiness.py
.venv/bin/python scripts/compliance_check.py
.venv/bin/python scripts/validate_odoo19_standards.py

# ❌ Scripts que manipulan datos Odoo (REQUIEREN container)
python scripts/create_smoke_test_data.py  # ❌
# ✅ CORRECTO:
docker compose exec odoo odoo-bin shell -d odoo19_db < scripts/create_smoke_test_data.py
```

---

## 🔧 Comandos Docker + Odoo CLI Profesionales

### 1️⃣ GESTIÓN DE MÓDULOS

#### Instalar Módulo Específico

```bash
# Sintaxis: odoo-bin -i [módulo] -d [db] --stop-after-init
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --stop-after-init

# Instalar múltiples módulos
docker compose exec odoo odoo-bin -i l10n_cl_dte,l10n_cl_hr_payroll -d odoo19_db --stop-after-init

# Verificar instalación
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
module = env['ir.module.module'].search([('name', '=', 'l10n_cl_dte')])
print(f'Estado: {module.state}')  # Debe ser 'installed'
" --stop-after-init
```

#### Actualizar Módulo

```bash
# Actualizar módulo específico
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# Actualizar todos los módulos (CUIDADO - solo en dev)
docker compose exec odoo odoo-bin -u all -d odoo19_db --stop-after-init

# Actualizar con logging debug
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --log-level=debug --stop-after-init
```

---

### 2️⃣ TESTING PROFESIONAL

#### Tests con pytest (Recomendado)

```bash
# Ejecutar tests de módulo específico
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --tb=short

# Tests con coverage
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
  --cov=l10n_cl_dte \
  --cov-report=term-missing \
  --cov-report=html

# Tests específicos por archivo
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_validation.py \
  -v -s

# Tests con markers personalizados
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
  -m "not slow" \
  --maxfail=5

# Tests paralelos (faster)
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
  -n auto \
  -v
```

#### Tests con Odoo Test Framework

```bash
# Ejecutar tests Odoo nativos
docker compose exec odoo odoo-bin \
  --test-enable \
  -i l10n_cl_dte \
  --test-tags /l10n_cl_dte \
  --stop-after-init \
  -d odoo19_db

# Tests con tag específico
docker compose exec odoo odoo-bin \
  --test-enable \
  --test-tags l10n_cl_dte,post_install \
  --stop-after-init \
  -d odoo19_db
```

---

### 3️⃣ SHELL INTERACTIVO Y DEBUGGING

#### Shell Odoo (Investigación)

```bash
# Acceder a shell interactivo
docker compose exec odoo odoo-bin shell -d odoo19_db

# Dentro del shell:
>>> # Investigar modelo
>>> self.env['account.move'].search([('move_type', '=', 'out_invoice')], limit=1)
>>> invoice = _
>>> invoice.l10n_cl_dte_status
>>> invoice.l10n_cl_sii_barcode

# Ejecutar código Python en contexto Odoo
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
partners = env['res.partner'].search([('country_id.code', '=', 'CL')], limit=10)
for p in partners:
    print(f'{p.name}: {p.vat}')
" --stop-after-init
```

#### Shell con Debug Mode

```bash
# Shell con debugging habilitado
docker compose exec odoo odoo-bin shell \
  -d odoo19_db \
  --debug \
  --log-level=debug \
  --log-handler=odoo.addons.l10n_cl_dte:DEBUG

# Debug específico de módulo
docker compose exec odoo odoo-bin \
  --debug \
  --debug-py \
  --log-handler=odoo.addons.l10n_cl_dte:DEBUG \
  -u l10n_cl_dte \
  -d odoo19_db \
  --stop-after-init
```

---

### 4️⃣ GESTIÓN DE BASE DE DATOS

#### Backup y Restore

```bash
# Backup base de datos
docker compose exec db pg_dump \
  -U odoo \
  -h db \
  odoo19_db \
  > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore base de datos
docker compose exec -T db psql \
  -U odoo \
  -h db \
  odoo19_db \
  < backup_20251112_143000.sql

# Crear nueva base de datos limpia
docker compose exec odoo odoo-bin \
  --database test_db \
  --init base \
  --stop-after-init
```

#### Consultas Directas PostgreSQL

```bash
# Listar bases de datos
docker compose exec db psql -U odoo -h db -l

# Ejecutar query SQL
docker compose exec db psql -U odoo -h db odoo19_db -c "
SELECT id, name, state
FROM ir_module_module
WHERE name LIKE 'l10n_cl%'
ORDER BY name;
"

# Verificar estado módulo DTE
docker compose exec db psql -U odoo -h db odoo19_db -c "
SELECT name, state, latest_version
FROM ir_module_module
WHERE name = 'l10n_cl_dte';
"
```

---

### 5️⃣ OPERACIONES DE SERVIDOR

#### Configuración y Startup

```bash
# Verificar configuración sin iniciar
docker compose exec odoo odoo-bin \
  --config /etc/odoo/odoo.conf \
  --dry-run \
  --stop-after-init

# Iniciar servidor con configuración específica
docker compose exec odoo odoo-bin \
  --config /etc/odoo/odoo.conf \
  --http-port=8069 \
  --workers=2

# Iniciar con modo desarrollo (auto-reload)
docker compose exec odoo odoo-bin \
  --dev=all \
  --log-level=debug \
  --reload
```

#### Health Checks

```bash
# Verificar health check Odoo
docker compose exec odoo curl -f http://localhost:8069/web/health || echo "Odoo not responding"

# Verificar estado servicios
docker compose ps

# Logs en tiempo real
docker compose logs -f odoo

# Logs errores específicos
docker compose logs odoo | grep ERROR | tail -20
```

---

### 6️⃣ DESARROLLO Y SCAFFOLDING

#### Crear Estructura Módulo

```bash
# Scaffold módulo básico
docker compose exec odoo odoo-bin scaffold \
  my_custom_module \
  /mnt/extra-addons/custom

# Scaffold módulo website
docker compose exec odoo odoo-bin scaffold \
  --template=website \
  my_website_module \
  /mnt/extra-addons/custom
```

#### Verificar Dependencias

```bash
# Verificar dependencias módulo
docker compose exec odoo odoo-bin \
  --check-module-deps \
  -d odoo19_db \
  --stop-after-init

# Listar módulos disponibles
docker compose exec odoo odoo-bin \
  --list-available-modules | grep l10n_cl
```

---

### 7️⃣ TRADUCCIONES E INTERNACIONALIZACIÓN

```bash
# Extraer términos para traducción
docker compose exec odoo odoo-bin \
  -u l10n_cl_dte \
  --i18n-export /tmp/es.po \
  -l es \
  -d odoo19_db \
  --stop-after-init

# Importar traducciones
docker compose exec odoo odoo-bin \
  -u l10n_cl_dte \
  --i18n-import /tmp/es.po \
  -l es \
  -d odoo19_db \
  --stop-after-init

# Actualizar traducciones módulo
docker compose exec odoo odoo-bin \
  -u l10n_cl_dte \
  --i18n-overwrite \
  -d odoo19_db \
  --stop-after-init
```

---

### 8️⃣ MONITOREO Y LOGGING

```bash
# Ver logs en tiempo real (múltiples servicios)
docker compose logs -f odoo db redis-master

# Ver logs de errores específicos
docker compose logs odoo | grep -E "ERROR|CRITICAL" | tail -50

# Ver métricas de rendimiento
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
users = env['res.users'].search_count([])
partners = env['res.partner'].search_count([])
invoices = env['account.move'].search_count([('move_type', 'in', ['out_invoice', 'out_refund'])])
print(f'Users: {users}, Partners: {partners}, Invoices: {invoices}')
" --stop-after-init

# Health check avanzado
docker compose exec odoo bash -c "
timeout 10 curl -f http://localhost:8069/web/health 2>/dev/null && echo 'OK' || echo 'FAIL'
"
```

---

### 9️⃣ OPERACIONES DE MANTENIMIENTO

```bash
# Limpiar cache de archivos
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
attachments = env['ir.attachment'].search([('type', '=', 'binary')])
print(f'Total attachments: {len(attachments)}')
# attachments.unlink()  # Descomentar para ejecutar
" --stop-after-init

# Reindexar base de datos
docker compose exec db psql -U odoo -h db odoo19_db -c "REINDEX DATABASE odoo19_db;"

# Actualizar permisos archivos
docker compose exec odoo chown -R odoo:odoo /mnt/extra-addons

# Vacuum PostgreSQL (mantenimiento)
docker compose exec db psql -U odoo -h db odoo19_db -c "VACUUM ANALYZE;"
```

---

### 🔟 TROUBLESHOOTING COMÚN

#### Problema: Módulo no se instala

```bash
# 1. Verificar que el stack esté corriendo
docker compose ps

# 2. Verificar logs
docker compose logs odoo | tail -50

# 3. Verificar addons_path
docker compose exec odoo cat /etc/odoo/odoo.conf | grep addons_path

# 4. Verificar que el módulo existe
docker compose exec odoo ls -la /mnt/extra-addons/localization/l10n_cl_dte/

# 5. Verificar __manifest__.py existe
docker compose exec odoo ls -la /mnt/extra-addons/localization/l10n_cl_dte/__manifest__.py

# 6. Instalar con verbose logging
docker compose exec odoo odoo-bin \
  -i l10n_cl_dte \
  -d odoo19_db \
  --log-level=debug \
  --stop-after-init
```

#### Problema: Tests fallan en Docker

```bash
# 1. Ejecutar tests con verbose
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
  -v --tb=long

# 2. Ejecutar test específico con debugging
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_validation.py::TestDTEValidation::test_rut_validation \
  -v -s

# 3. Verificar configuración test database
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo.tests import common
print('Test framework loaded successfully')
" --stop-after-init

# 4. Tests sin paralelización (debugging)
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
  -v --tb=short -n0
```

#### Problema: Base de datos no accesible

```bash
# 1. Verificar PostgreSQL corriendo
docker compose ps db

# 2. Verificar conectividad
docker compose exec db psql -U odoo -h db -l

# 3. Crear base de datos si no existe
docker compose exec odoo odoo-bin \
  --database odoo19_db \
  --init base \
  --stop-after-init

# 4. Verificar configuración conexión
docker compose exec odoo cat /etc/odoo/odoo.conf | grep db_

# 5. Test conexión desde Odoo
docker compose exec odoo odoo-bin shell -d odoo19_db -c "print('Database connection OK')" --stop-after-init
```

---

## 📋 Checklist Flujo de Trabajo Típico

### Desarrollo Nueva Feature

```bash
# 1. Crear rama git
git checkout -b feature/nueva-feature

# 2. Modificar código
code addons/localization/l10n_cl_dte/models/account_move.py

# 3. Actualizar módulo
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# 4. Verificar en UI
# Abrir http://localhost:8069

# 5. Ejecutar tests
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v

# 6. Verificar coverage
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
  --cov=l10n_cl_dte \
  --cov-report=term-missing

# 7. Commit y push
git add .
git commit -m "feat: nueva feature"
git push origin feature/nueva-feature
```

### Debugging Issue Producción

```bash
# 1. Reproducir en dev
docker compose logs odoo | grep ERROR

# 2. Acceder a shell
docker compose exec odoo odoo-bin shell -d odoo19_db

# 3. Investigar issue
>>> invoice = self.env['account.move'].browse(1234)
>>> invoice.l10n_cl_dte_status
>>> invoice._validate_dte()

# 4. Fix código
code addons/localization/l10n_cl_dte/models/account_move.py

# 5. Actualizar y probar
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# 6. Ejecutar test específico
docker compose exec odoo pytest \
  /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_validation.py \
  -v -s
```

---

## 🎯 Best Practices

1. **SIEMPRE** usar `docker compose exec odoo` para comandos Odoo
2. **NUNCA** ejecutar comandos Odoo directamente en host
3. **USAR** `.venv/bin/python` para scripts análisis estático host
4. **VERIFICAR** logs después de cada operación crítica
5. **HACER BACKUP** base de datos antes de operaciones destructivas
6. **USAR** `--stop-after-init` para operaciones batch
7. **PROBAR** en database temporal antes de dev/staging
8. **DOCUMENTAR** cambios en CHANGELOG.md

---

## 📖 Referencias

- **Documentación Odoo CLI:** https://www.odoo.com/documentation/19.0/developer/reference/cli.html
- **Docker Compose:** `docker-compose.yml` (raíz proyecto)
- **Configuración Odoo:** `config/odoo.conf`
- **Contexto deployment:** `.github/agents/knowledge/deployment_environment.md`

---

**Versión:** 1.0.0  
**Última actualización:** 2025-11-12  
**Mantenedor:** Pedro Troncoso (@pwills85)  
**Compatibilidad:** Odoo 19 CE, Docker Compose, macOS ARM64
