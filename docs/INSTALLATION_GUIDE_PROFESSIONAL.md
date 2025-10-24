# 📦 GUÍA DE INSTALACIÓN PROFESIONAL - l10n_cl_dte

**Módulo:** Facturación Electrónica Chilena (l10n_cl_dte)
**Versión:** 19.0.1.0.0
**Fecha:** 2025-10-24
**Autor:** EERGYGROUP - Ing. Pedro Troncoso Willz

---

## 🎯 ANÁLISIS PREVIO

### ¿Necesito Reconstruir la Imagen Docker?

**RESPUESTA: NO** ❌

**Razón:**
Las nuevas funcionalidades agregadas (Phase 2) utilizan librerías que **YA ESTÁN instaladas** en la imagen Docker:

- ✅ `cryptography>=3.4.8` - Ya incluida (usada para Fernet encryption)
- ✅ `lxml>=4.9.0` - Ya incluida
- ✅ `requests>=2.28.0` - Ya incluida
- ✅ Todas las dependencias Python están satisfechas

**Nuevos Archivos Añadidos (Phase 2):**
- `tools/encryption_helper.py` - Usa `cryptography.fernet` (ya instalada)
- `models/ai_agent_selector.py` - Usa solo librerías Odoo nativas
- `wizards/ai_chat_universal_wizard.py` - Usa `requests` (ya instalada)
- `ai-service/plugins/account/plugin.py` - AI Service (separate container)

**Conclusión:** ✅ Proceder directo a instalación. No rebuild necesario.

---

## 📋 PREREQUISITES

### Sistema Operativo
- ✅ macOS 11+ / Linux (Ubuntu 20.04+) / Windows 10+ con WSL2
- ✅ Docker Desktop 4.0+ instalado y corriendo
- ✅ Docker Compose v2.0+

### Recursos Mínimos
- **CPU:** 2 cores (4 recomendado)
- **RAM:** 4GB (8GB recomendado)
- **Disk:** 10GB libre

### Servicios Requeridos
- ✅ PostgreSQL 15+ (container)
- ✅ Redis 7+ (container)
- ✅ Odoo 19 CE (container)
- ✅ AI Service (container - FastAPI)

### Verificación Prerequisites

```bash
# 1. Verificar Docker
docker --version
docker-compose --version

# 2. Verificar containers corriendo
docker ps

# Deberías ver:
# - postgres (PostgreSQL 15)
# - redis (Redis 7)
# - odoo (Odoo 19 CE)
# - ai-service (FastAPI)

# 3. Verificar database existe
docker exec odoo psql -U odoo -d postgres -c "\l" | grep odoo

# 4. Verificar módulo files existen
ls -la addons/localization/l10n_cl_dte
```

---

## 🚀 INSTALACIÓN MÉTODO 1: Script Automático (Recomendado)

### Paso 1: Verificar Script

```bash
cd /Users/pedro/Documents/odoo19
ls -lh scripts/install_l10n_cl_dte_professional.sh

# Deberías ver:
# -rwxr-xr-x  16K install_l10n_cl_dte_professional.sh
```

### Paso 2: Ejecutar Script

```bash
./scripts/install_l10n_cl_dte_professional.sh
```

**El script automáticamente:**
1. ✅ Verifica prerequisites
2. ✅ Valida sintaxis Python/XML
3. ✅ Actualiza lista módulos
4. ✅ Instala dependencias
5. ✅ Instala l10n_cl_dte
6. ✅ Verifica instalación
7. ✅ Reinicia Odoo
8. ✅ Genera reporte

### Paso 3: Verificar Instalación

El script genera un reporte en `/tmp/odoo_install_l10n_cl_dte_report_*.txt`

```bash
# Ver último reporte
cat /tmp/odoo_install_l10n_cl_dte_report_* | tail -1
```

**Output esperado:**
```
╔═══════════════════════════════════════════════════════════════╗
║  ✅ Module l10n_cl_dte successfully installed                 ║
║  📊 Statistics:                                               ║
║     - Models: 50+                                             ║
║     - Views: 80+                                              ║
║     - Menus: 15+                                              ║
║     - Errors: 0                                               ║
║     - Warnings: 0                                             ║
║  🎉 Ready to use!                                             ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## 🔧 INSTALACIÓN MÉTODO 2: Manual (Avanzado)

### Paso 1: Verificar Sintaxis

```bash
cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte

# Verificar Python
python3 -m compileall -q .

# Verificar XML
find . -name "*.xml" -exec xmllint --noout {} \;
```

### Paso 2: Update Module List

```bash
docker-compose exec odoo odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    --stop-after-init \
    --update=base
```

### Paso 3: Instalar Dependencias

```bash
# Dependencias base
DEPS="base account l10n_latam_base l10n_latam_invoice_document l10n_cl purchase stock web"

for dep in $DEPS; do
    echo "Installing $dep..."
    docker-compose exec odoo odoo \
        -c /etc/odoo/odoo.conf \
        -d odoo \
        --stop-after-init \
        -i $dep
done
```

### Paso 4: Instalar Módulo

```bash
docker-compose exec odoo odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    --stop-after-init \
    -i l10n_cl_dte
```

### Paso 5: Verificar Instalación

```bash
# Check module state
docker exec odoo psql -U odoo -d odoo -c "
    SELECT name, state, latest_version
    FROM ir_module_module
    WHERE name='l10n_cl_dte';
"

# Expected output:
#     name      | state     | latest_version
# --------------+-----------+----------------
#  l10n_cl_dte | installed | 19.0.1.0.0
```

### Paso 6: Restart Odoo

```bash
docker-compose restart odoo

# Wait for Odoo to start
sleep 30

# Check health
docker exec odoo curl -s http://localhost:8069/web/health
```

---

## ✅ VERIFICACIÓN POST-INSTALACIÓN

### 1. Verificar Módulo Instalado

```bash
docker exec odoo psql -U odoo -d odoo -tAc "
    SELECT state FROM ir_module_module WHERE name='l10n_cl_dte'
"

# Expected: installed
```

### 2. Verificar Models Creados

```bash
docker exec odoo psql -U odoo -d odoo -c "
    SELECT model, name
    FROM ir_model
    WHERE model LIKE '%dte%' OR model LIKE '%l10n_cl%'
    ORDER BY model
    LIMIT 10;
"
```

### 3. Verificar Views Creadas

```bash
docker exec odoo psql -U odoo -d odoo -c "
    SELECT name, type
    FROM ir_ui_view
    WHERE name LIKE '%dte%' OR name LIKE '%l10n_cl%'
    LIMIT 10;
"
```

### 4. Verificar Menus Creados

```bash
docker exec odoo psql -U odoo -d odoo -c "
    SELECT name, parent_id
    FROM ir_ui_menu
    WHERE name LIKE '%DTE%' OR name LIKE '%Facturación%';
"
```

### 5. Verificar Security Groups

```bash
docker exec odoo psql -U odoo -d odoo -c "
    SELECT name, category_id
    FROM res_groups
    WHERE name LIKE '%DTE%';
"
```

### 6. Verificar Cron Jobs

```bash
docker exec odoo psql -U odoo -d odoo -c "
    SELECT name, model_id, interval_number, interval_type, active
    FROM ir_cron
    WHERE name LIKE '%DTE%';
"
```

---

## 🌐 ACCESO A ODOO

### Web Interface

**URL:** http://localhost:8069

**Login:**
- **Email:** admin
- **Password:** admin (cambiar en producción)
- **Database:** odoo

### Navegación al Módulo

1. Login to Odoo
2. Apps → Update Apps List
3. Search "Facturación Electrónica Chilena"
4. Verify "Installed" badge
5. Facturación Electrónica → Panel DTE

---

## 🧪 TEST BÁSICO DE FUNCIONALIDAD

### Test 1: Crear Certificado Digital

```
1. Go to: Facturación Electrónica → Configuración → Certificados Digitales
2. Click: Crear
3. Fill:
   - Nombre: Certificado Test
   - Archivo .pfx: Upload test certificate
   - Password: ********
4. Click: Guardar
5. Click: Validar
6. Expected: ✅ Certificado validado correctamente
```

### Test 2: Universal AI Chat

```
1. Go to: Facturación Electrónica → Asistente IA
2. Verify:
   - Módulo activo: detected correctly
   - Plugins disponibles: listed
   - AI Service available: ✅
3. Type: "¿Cómo crear una factura electrónica?"
4. Click: Enviar
5. Expected: Response from AI with instructions
```

### Test 3: Verificar Encryption

```bash
# Verify password is encrypted in database
docker exec odoo psql -U odoo -d odoo -c "
    SELECT name, _cert_password_encrypted
    FROM dte_certificate
    LIMIT 1;
"

# Expected: _cert_password_encrypted starts with 'gA' (Fernet encrypted)
```

---

## ⚠️ TROUBLESHOOTING

### Error: "Module not found"

**Causa:** Módulo no está en addons path

**Solución:**
```bash
# Verify module path
docker exec odoo ls -la /mnt/extra-addons/addons/localization/l10n_cl_dte

# Update addons path in odoo.conf if needed
```

### Error: "Access denied" al validar certificado

**Causa:** Usuario no tiene permisos

**Solución:**
```
1. Settings → Users & Companies → Users
2. Select user
3. Add groups: Contabilidad / Facturación
```

### Error: "AI Service not available"

**Causa:** AI Service container no corriendo

**Solución:**
```bash
# Start AI Service
docker-compose up -d ai-service

# Check logs
docker-compose logs ai-service

# Verify health
curl http://localhost:8002/health
```

### Warning: "Fernet key not found"

**Causa:** Primera vez usando encryption

**Solución:**
- ✅ **Normal:** Key se genera automáticamente en primer uso
- Check: Settings → Technical → System Parameters → `l10n_cl_dte.encryption_key`

---

## 📊 UPGRADE FROM PREVIOUS VERSION

### Si ya tienes l10n_cl_dte instalado:

```bash
# Method 1: Using script
./scripts/install_l10n_cl_dte_professional.sh
# Choose "yes" when asked to upgrade

# Method 2: Manual
docker-compose exec odoo odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    --stop-after-init \
    -u l10n_cl_dte
```

### Migration Notes:

**Phase 2 Changes:**
- ✅ Password encryption añadido (auto-migrates on first read)
- ✅ AI Agent Selector añadido (nuevo AbstractModel)
- ✅ Universal AI Chat añadido (nuevo wizard)
- ✅ Account AI Plugin añadido (AI Service)

**No Breaking Changes:** Upgrade es seguro, no requiere migración de datos.

---

## 🔒 SECURITY CHECKLIST

Antes de producción, verifica:

- [ ] Cambiar password admin de Odoo
- [ ] Configurar `l10n_cl_dte.ai_service_api_key` (no usar default)
- [ ] Encryption key generada y guardada en backup
- [ ] Certificados digitales con passwords encriptados
- [ ] Firewall configurado (solo puertos necesarios)
- [ ] SSL/TLS habilitado (nginx reverse proxy)
- [ ] Backups automáticos configurados
- [ ] Access logs habilitados

---

## 📚 DOCUMENTACIÓN ADICIONAL

- **Architecture:** `/docs/AI_INTEGRATION_ARCHITECTURE.md`
- **Executive Summary:** `/docs/RESUMEN_EJECUTIVO_FASE_2.md`
- **Audit Report:** `/docs/CIERRE_MIGRACION_DTE_NATIVO.md`
- **Module README:** `/addons/localization/l10n_cl_dte/README.md`

---

## 🆘 SOPORTE

**Desarrollado por:** EERGYGROUP
**Contacto:** contacto@eergygroup.cl
**Website:** https://www.eergygroup.com

**Stack tecnológico:**
- Odoo 19 CE (UI/UX + Business Logic)
- FastAPI (AI Service)
- Claude 3.5 Sonnet (AI)
- Docker + PostgreSQL + Redis

---

## ✅ CHECKLIST FINAL

Antes de dar por terminada la instalación:

- [ ] Script ejecutado sin errores
- [ ] Reporte generado muestra 0 errores, 0 warnings
- [ ] Módulo state="installed" en database
- [ ] Web interface accesible (http://localhost:8069)
- [ ] Menu "Facturación Electrónica" visible
- [ ] Test básico certificado OK
- [ ] Test AI Chat OK
- [ ] Passwords encriptados verificados
- [ ] Cron jobs activos verificados
- [ ] AI Service responding OK

---

**¡Instalación Completa!** 🎉

Tu sistema Odoo 19 CE + AI Service está listo para **superar a SAP, Oracle y NetSuite**.
