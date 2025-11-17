# 🐳 DOCKER + ODOO CLI - REFERENCIA COMANDOS COMPLETA

**Versión:** 1.0.0
**Fecha:** 2025-11-12
**Para:** Agentes, Desarrolladores, DevOps
**Stack:** Docker Compose + Odoo 19 CE

---

## 🎯 Regla de Oro

**⚠️ NUNCA ejecutes comandos Odoo directamente en el host. SIEMPRE usa Docker Compose.**

```bash
# ❌ NUNCA (no funciona en este proyecto)
odoo-bin -u l10n_cl_dte -d odoo19_db

# ✅ SIEMPRE (correcto)
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init
```

**Razón:** Odoo corre dentro de un contenedor Docker. No está instalado en el host.

---

## 📋 ÍNDICE RÁPIDO

1. [Gestión Módulos](#gestión-módulos)
2. [Testing](#testing)
3. [Shell y Debugging](#shell-y-debugging)
4. [Base de Datos](#base-de-datos)
5. [Logs y Monitoring](#logs-y-monitoring)
6. [Docker Compose](#docker-compose)
7. [Troubleshooting](#troubleshooting)

---

## 1. GESTIÓN MÓDULOS

### Instalar Módulo

```bash
# Instalar módulo específico
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --stop-after-init

# Instalar múltiples módulos
docker compose exec odoo odoo-bin -i l10n_cl_dte,l10n_cl_hr_payroll -d odoo19_db --stop-after-init

# Instalar con log detallado
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --log-level=debug --stop-after-init
```

**Notas:**
- `-i`: install
- `-d odoo19_db`: database name
- `--stop-after-init`: detiene Odoo después de instalar (no queda corriendo)

---

### Actualizar Módulo

```bash
# Actualizar módulo específico
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# Actualizar múltiples módulos
docker compose exec odoo odoo-bin -u l10n_cl_dte,l10n_cl_hr_payroll -d odoo19_db --stop-after-init

# Actualizar todos los módulos (CUIDADO en producción)
docker compose exec odoo odoo-bin -u all -d odoo19_db --stop-after-init

# Actualizar con forzar recreación de vistas
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init --init=l10n_cl_dte
```

**Notas:**
- `-u`: update
- Usa `-u` después de modificar código Python/XML del módulo
- `--init` fuerza recreación completa (equivale a desinstalar + reinstalar)

---

### Desinstalar Módulo

```bash
# Desinstalar desde Odoo shell
docker compose exec odoo odoo-bin shell -d odoo19_db

# Dentro del shell:
>>> module = env['ir.module.module'].search([('name', '=', 'l10n_cl_dte')])
>>> module.button_immediate_uninstall()
>>> exit()
```

**Alternativa UI:** Apps → Buscar módulo → Desinstalar

---

### Listar Módulos Instalados

```bash
# Shell Odoo
docker compose exec odoo odoo-bin shell -d odoo19_db

>>> installed = env['ir.module.module'].search([('state', '=', 'installed')])
>>> for m in installed:
...     print(f"{m.name}: {m.shortdesc}")
>>> exit()
```

---

## 2. TESTING

### Tests con Pytest (Recomendado)

```bash
# Tests módulo completo
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v

# Test archivo específico
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_generation.py -v

# Test función específica
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_generation.py::TestDTEGeneration::test_factura_33 -v

# Con coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
    --cov=l10n_cl_dte \
    --cov-report=term-missing \
    --cov-report=html

# Con debug (verbose + stdout)
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -vv -s

# Solo tests marcados
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v -m "integration"

# Parallel execution (4 workers)
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v -n 4
```

---

### Tests con Odoo Framework

```bash
# Tests módulo completo (tag)
docker compose exec odoo odoo-bin --test-enable -i l10n_cl_dte \
    --test-tags /l10n_cl_dte -d odoo19_db --stop-after-init

# Tests archivo específico
docker compose exec odoo odoo-bin --test-enable -i l10n_cl_dte \
    --test-tags /l10n_cl_dte/tests/test_dte_generation -d odoo19_db --stop-after-init

# Tests con log detallado
docker compose exec odoo odoo-bin --test-enable -i l10n_cl_dte \
    --test-tags /l10n_cl_dte --log-level=test -d odoo19_db --stop-after-init

# Solo post-install tests
docker compose exec odoo odoo-bin --test-enable --test-tags /l10n_cl_dte/post_install \
    -d odoo19_db --stop-after-init
```

**Diferencias Pytest vs Odoo Tests:**
- **Pytest:** Más rápido, mejor reporting, coverage integrado, recomendado
- **Odoo Tests:** Necesario para tests que usan fixtures Odoo específicos

---

## 3. SHELL Y DEBUGGING

### Shell Odoo (ORM Access)

```bash
# Shell básico
docker compose exec odoo odoo-bin shell -d odoo19_db

# Shell con debug
docker compose exec odoo odoo-bin shell -d odoo19_db --debug --log-level=debug

# Shell con módulo pre-cargado
docker compose exec odoo odoo-bin shell -d odoo19_db -c "from odoo.addons.l10n_cl_dte import models"
```

**Dentro del shell:**

```python
# Environment disponible como 'env'
>>> env
<odoo.api.Environment object at 0x...>

# Buscar registros
>>> invoices = env['account.move'].search([('move_type', '=', 'out_invoice')])
>>> invoices
account.move(1, 2, 3, ...)

# Crear registro
>>> partner = env['res.partner'].create({'name': 'Test Partner', 'vat': '12345678-9'})

# Actualizar
>>> partner.write({'email': 'test@example.com'})

# Borrar
>>> partner.unlink()

# Ejecutar método
>>> invoice = env['account.move'].browse(1)
>>> invoice.action_post()

# SQL directo
>>> env.cr.execute("SELECT id, name FROM res_partner LIMIT 5")
>>> env.cr.fetchall()

# Commit cambios (CUIDADO - permanente)
>>> env.cr.commit()

# Rollback cambios
>>> env.cr.rollback()

# Salir
>>> exit()
```

---

### Ejecutar Script Python con Contexto Odoo

```bash
# Opción 1: Stdin
docker compose exec odoo odoo-bin shell -d odoo19_db < script.py

# Opción 2: Heredoc
docker compose exec odoo odoo-bin shell -d odoo19_db <<EOF
invoices = env['account.move'].search([('state', '=', 'draft')])
print(f"Draft invoices: {len(invoices)}")
EOF

# Opción 3: Archivo en container
docker compose exec odoo bash -c "cat > /tmp/script.py <<'EOF'
invoices = env['account.move'].search([('state', '=', 'draft')])
for inv in invoices:
    print(inv.name)
EOF
odoo-bin shell -d odoo19_db < /tmp/script.py"
```

---

### Debugging con pdb

```python
# En tu código Python (models/controllers)
import pdb; pdb.set_trace()

# Luego ejecutar Odoo en foreground
docker compose exec odoo odoo-bin -d odoo19_db --dev=all

# Debugger aparecerá en terminal
# Comandos pdb:
# n = next line
# s = step into
# c = continue
# p variable = print variable
# l = list code
# q = quit
```

---

## 4. BASE DE DATOS

### Backup

```bash
# Backup completo (formato custom compress)
docker compose exec db pg_dump -U odoo -Fc odoo19_db > backup_$(date +%Y%m%d_%H%M%S).dump

# Backup SQL plano
docker compose exec db pg_dump -U odoo odoo19_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Backup solo schema (sin datos)
docker compose exec db pg_dump -U odoo -s odoo19_db > schema_$(date +%Y%m%d_%H%M%S).sql

# Backup solo datos (sin schema)
docker compose exec db pg_dump -U odoo -a odoo19_db > data_$(date +%Y%m%d_%H%M%S).sql

# Backup tabla específica
docker compose exec db pg_dump -U odoo -t account_move odoo19_db > account_move_backup.sql
```

---

### Restore

```bash
# Restore desde dump custom
docker compose exec db pg_restore -U odoo -d odoo19_db_restored backup.dump

# Restore desde SQL
docker compose exec db psql -U odoo -d odoo19_db < backup.sql

# Drop y recrear DB antes de restore
docker compose exec db psql -U odoo <<EOF
DROP DATABASE IF EXISTS odoo19_db_restored;
CREATE DATABASE odoo19_db_restored OWNER odoo;
EOF

docker compose exec db pg_restore -U odoo -d odoo19_db_restored backup.dump
```

---

### Operaciones DB

```bash
# Listar databases
docker compose exec db psql -U odoo -l

# Crear database
docker compose exec db createdb -U odoo odoo19_db_test

# Drop database
docker compose exec db dropdb -U odoo odoo19_db_test

# Conectar a DB
docker compose exec db psql -U odoo -d odoo19_db

# Dentro de psql:
# \dt - listar tablas
# \d table_name - describe tabla
# \q - salir

# Query SQL
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT id, name FROM res_partner LIMIT 5;"

# Vacuum DB (liberar espacio)
docker compose exec db vacuumdb -U odoo -d odoo19_db -v

# Vacuum analyze (optimizar + estadísticas)
docker compose exec db vacuumdb -U odoo -d odoo19_db -v -z

# Reindex DB
docker compose exec db reindexdb -U odoo -d odoo19_db -v
```

---

## 5. LOGS Y MONITORING

### Ver Logs

```bash
# Logs todos servicios
docker compose logs

# Logs solo Odoo
docker compose logs odoo

# Logs en tiempo real (follow)
docker compose logs -f odoo

# Últimas 100 líneas
docker compose logs --tail=100 odoo

# Logs con timestamps
docker compose logs -f --timestamps odoo

# Logs desde fecha específica
docker compose logs --since="2025-11-12T10:00:00" odoo

# Logs hasta fecha específica
docker compose logs --until="2025-11-12T12:00:00" odoo

# Logs todos servicios en paralelo
docker compose logs -f odoo db redis
```

---

### Filtrar Logs

```bash
# Solo errores
docker compose logs odoo | grep ERROR

# Errores y warnings
docker compose logs odoo | grep -E "ERROR|WARNING"

# Excluir cierto patrón
docker compose logs odoo | grep -v "DEBUG"

# SQL queries (si log_level=debug_sql)
docker compose logs odoo | grep "SELECT\|INSERT\|UPDATE\|DELETE"

# Logs de módulo específico
docker compose logs odoo | grep l10n_cl_dte
```

---

### Monitoring Recursos

```bash
# Uso CPU/Memoria en tiempo real
docker stats

# Uso recursos contenedor específico
docker stats odoo

# Uso recursos sin stream (snapshot)
docker stats --no-stream

# Uso con formato personalizado
docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

---

### Health Checks

```bash
# Ver estado containers
docker compose ps

# Health check específico
docker inspect odoo | jq '.[0].State.Health'

# Logs health check
docker inspect odoo | jq '.[0].State.Health.Log'
```

---

## 6. DOCKER COMPOSE

### Gestión Servicios

```bash
# Iniciar todos los servicios
docker compose up -d

# Iniciar servicio específico
docker compose up -d odoo

# Detener todos los servicios
docker compose stop

# Detener servicio específico
docker compose stop odoo

# Reiniciar servicios
docker compose restart

# Reiniciar servicio específico
docker compose restart odoo

# Detener y eliminar containers (mantiene volumes)
docker compose down

# Detener y eliminar TODO (incluyendo volumes - CUIDADO)
docker compose down -v

# Ver logs durante startup
docker compose up

# Rebuild images (si cambió Dockerfile)
docker compose build
docker compose up -d --build
```

---

### Ejecución Comandos

```bash
# Ejecutar comando en container corriendo
docker compose exec odoo <comando>

# Ejecutar comando en container nuevo (one-off)
docker compose run --rm odoo <comando>

# Ejecutar como root
docker compose exec -u root odoo bash

# Ejecutar con variables entorno
docker compose exec -e VAR=value odoo <comando>

# Ejecutar sin TTY (para scripts)
docker compose exec -T odoo <comando>
```

---

### Inspección

```bash
# Ver configuración final
docker compose config

# Ver solo servicio específico
docker compose config odoo

# Listar containers
docker compose ps

# Listar containers todos (incluido stopped)
docker compose ps -a

# Ver procesos corriendo
docker compose top

# Ver procesos servicio específico
docker compose top odoo
```

---

## 7. TROUBLESHOOTING

### Odoo No Inicia

```bash
# 1. Ver logs
docker compose logs odoo --tail=100

# 2. Verificar healthcheck
docker compose ps

# 3. Verificar DB disponible
docker compose exec db psql -U odoo -l

# 4. Verificar permisos
docker compose exec odoo ls -la /var/lib/odoo

# 5. Reiniciar limpio
docker compose down
docker compose up -d

# 6. Modo debug
docker compose exec odoo odoo-bin -d odoo19_db --dev=all --log-level=debug
```

---

### Módulo No Se Instala/Actualiza

```bash
# 1. Verificar módulo en path
docker compose exec odoo ls /mnt/extra-addons/localization/l10n_cl_dte

# 2. Actualizar lista módulos (desde shell)
docker compose exec odoo odoo-bin shell -d odoo19_db
>>> env['ir.module.module'].update_list()
>>> exit()

# 3. Reinstalar forzado
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --stop-after-init --init=l10n_cl_dte

# 4. Verificar dependencias
docker compose exec odoo grep "depends" /mnt/extra-addons/localization/l10n_cl_dte/__manifest__.py

# 5. Ver estado módulo
docker compose exec odoo odoo-bin shell -d odoo19_db
>>> module = env['ir.module.module'].search([('name', '=', 'l10n_cl_dte')])
>>> print(f"State: {module.state}, Dependencies: {module.dependencies_id}")
>>> exit()
```

---

### Performance Issues

```bash
# 1. Queries lentas (habilitar log SQL)
docker compose exec odoo odoo-bin -d odoo19_db --dev=all --log-level=debug_sql

# 2. Profiling
docker compose exec odoo odoo-bin -d odoo19_db --dev=all --log-level=debug --profile

# 3. Ver queries activas (PostgreSQL)
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT pid, query_start, state, query FROM pg_stat_activity WHERE state != 'idle' ORDER BY query_start;"

# 4. Matar query lenta
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT pg_terminate_backend(<pid>);"

# 5. Vacuum DB
docker compose exec db vacuumdb -U odoo -d odoo19_db -v -z

# 6. Verificar indexes faltantes
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT schemaname, tablename, seq_scan, idx_scan FROM pg_stat_user_tables WHERE seq_scan > 0 ORDER BY seq_scan DESC LIMIT 20;"
```

---

### DB Connection Issues

```bash
# 1. Verificar DB corriendo
docker compose ps db

# 2. Verificar conectividad
docker compose exec odoo pg_isready -h db -U odoo

# 3. Verificar credenciales
docker compose exec odoo env | grep POSTGRES

# 4. Test conexión manual
docker compose exec odoo psql -h db -U odoo -d odoo19_db -c "SELECT 1;"

# 5. Ver max_connections
docker compose exec db psql -U odoo -d odoo19_db -c "SHOW max_connections;"

# 6. Ver conexiones actuales
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT count(*) FROM pg_stat_activity;"
```

---

### Espacio en Disco

```bash
# 1. Ver espacio volumes
docker system df -v

# 2. Limpiar images no usadas
docker image prune -a

# 3. Limpiar containers stopped
docker container prune

# 4. Limpiar volumes no usados
docker volume prune

# 5. Limpiar todo (CUIDADO)
docker system prune -a --volumes

# 6. Ver tamaño DB
docker compose exec db psql -U odoo -d odoo19_db -c "SELECT pg_size_pretty(pg_database_size('odoo19_db'));"

# 7. Vacuum full (libera espacio físico - bloquea tablas)
docker compose exec db vacuumdb -U odoo -d odoo19_db --full -v
```

---

## 📚 REFERENCIAS

### Documentación Oficial

- **Odoo CLI:** https://www.odoo.com/documentation/19.0/developer/reference/cli.html
- **Docker Compose:** https://docs.docker.com/compose/
- **PostgreSQL:** https://www.postgresql.org/docs/15/

### Documentación Proyecto

- **Stack Info:** `00_knowledge_base/deployment_environment.md`
- **Patrones Odoo 19:** `00_knowledge_base/odoo19_patterns.md`
- **Troubleshooting:** `README.md` sección Docker

---

## 🎯 CHEAT SHEET

```bash
# Desarrollo día a día
docker compose up -d                           # Iniciar stack
docker compose logs -f odoo                    # Ver logs
docker compose exec odoo odoo-bin shell -d odoo19_db  # Shell ORM
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v  # Tests

# Gestión módulos
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init  # Update
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --stop-after-init  # Install

# Debugging
docker compose exec odoo odoo-bin -d odoo19_db --dev=all --log-level=debug  # Debug mode
docker compose exec db psql -U odoo -d odoo19_db  # DB access

# Backup
docker compose exec db pg_dump -U odoo -Fc odoo19_db > backup.dump  # Backup DB

# Monitoring
docker stats                                   # Recursos
docker compose ps                             # Estado servicios
```

---

**Versión:** 1.0.0
**Última actualización:** 2025-11-12
**Mantenedor:** Pedro Troncoso (@pwills85)
