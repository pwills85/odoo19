# 📋 PLAN ESTRATÉGICO: ACTUALIZACIÓN PERMANENTE Y ESTABILIZACIÓN l10n_cl_dte

**Fecha:** 2025-10-22
**Versión:** 1.0
**Objetivo:** Restaurar 100% funcionalidad del módulo y asegurar estabilidad permanente
**Metodología:** Incremental, validada, con rollback automático
**Duración Estimada:** 18-32 horas (distribuidas en 4 semanas)

---

## 🎯 RESUMEN EJECUTIVO

### Estado Actual: FASE 1 COMPLETADA (20%)

**✅ Logros Alcanzados:**
- Módulo instalado sin errores críticos
- 16 menús DTE Chile funcionales
- 28 vistas XML cargadas
- 15 modelos Python operativos
- 10 tablas PostgreSQL creadas
- Registry optimizado (0.284s)

**⚠️ Componentes Temporalmente Desactivados:**
- 2 wizards (dte_generate, ai_chat)
- 2 reportes PDF (invoice, receipt)
- 1 demo file (no necesario)
- 21 métodos action (referencias sin implementación)
- 2 warnings deprecation (no críticos)

**🎯 Meta Final:**
- 100% funcionalidad restaurada
- 0 errores o warnings
- Tests automatizados completos
- Documentación usuario final
- Procedimientos backup/restore
- Estrategia actualización continua

---

## 📊 ANÁLISIS PROFUNDO DEL ESTADO ACTUAL

### 1. INVENTARIO COMPLETO DE COMPONENTES

#### A. Archivos del Módulo (66 archivos totales)
```
📁 l10n_cl_dte/
├── Python: 41 archivos
│   ├── Modelos: 15 archivos (100% funcionales) ✅
│   ├── Wizards: 3 archivos (0% activos) ⚠️
│   ├── Controllers: 1 archivo (100% funcional) ✅
│   ├── Tools: 1 archivo (100% funcional) ✅
│   └── Tests: 0 archivos (pendiente crear) ⚠️
│
├── XML: 25 archivos
│   ├── Vistas: 13 archivos (100% funcionales) ✅
│   ├── Wizards: 2 archivos (0% activos) ⚠️
│   ├── Reportes: 2 archivos (0% activos) ⚠️
│   ├── Data: 2 archivos (100% funcionales) ✅
│   ├── Security: 2 archivos (100% funcionales) ✅
│   └── Menus: 1 archivo (100% funcional) ✅
```

#### B. Base de Datos PostgreSQL (10 tablas)
```sql
-- Tablas DTE creadas y funcionales:
1. dte_certificate         ✅ Certificados digitales SII
2. dte_caf                 ✅ CAF (Folios autorizados)
3. dte_communication       ✅ Comunicaciones con SII
4. dte_consumo_folios      ✅ Consumo de folios
5. dte_inbox               ✅ DTEs recibidos (compras)
6. dte_libro               ✅ Libro compra/venta
7. dte_libro_guias         ✅ Libro guías de despacho
8. send_dte_batch_wizard   ⚠️ Wizard desactivado (tabla huérfana)
9. account_move_dte_libro_rel           ✅ Relación M2M
10. account_move_send_dte_batch_wizard_rel  ⚠️ Relación huérfana
```

#### C. Modelos Python (15 modelos)
```python
# Modelos Core (100% funcionales)
1. account_move_dte.py         ✅ DTE 33, 56, 61 (facturas)
2. purchase_order_dte.py       ✅ DTE 34 (honorarios)
3. stock_picking_dte.py        ✅ DTE 52 (guías despacho)
4. dte_certificate.py          ✅ Certificados digitales
5. dte_caf.py                  ✅ Folios (CAF)
6. account_journal_dte.py      ✅ Diarios contables DTE
7. account_tax_dte.py          ✅ Impuestos SII

# Modelos Secundarios (100% funcionales)
8. dte_communication.py        ✅ Comunicaciones SII
9. dte_consumo_folios.py       ✅ Consumo folios
10. dte_inbox.py               ✅ DTEs recibidos
11. dte_libro.py               ✅ Libro compra/venta
12. dte_libro_guias.py         ✅ Libro guías
13. retencion_iue.py           ✅ Retenciones IUE
14. res_config_settings.py     ✅ Configuración general

# Modelos AI (100% funcionales pero opcional)
15. ai_chat_integration.py     ✅ Integración AI Service
```

#### D. Wizards (0% activos, 2 archivos desactivados)
```python
1. dte_generate_wizard.py          ⚠️ DESACTIVADO
   - Problema: Campo 'dte_type' no existe en account.move
   - Vista: dte_generate_wizard_views.xml
   - Acción: Generar DTE manualmente
   - Prioridad: ALTA

2. ai_chat_wizard.py               ⚠️ DESACTIVADO
   - Problema: Dependencia ai_chat_integration (opcional)
   - Vista: ai_chat_wizard_views.xml
   - Acción: Chat IA con validación DTEs
   - Prioridad: BAJA (funcionalidad avanzada)

3. dte_commercial_response_wizard.py  ✅ FUNCIONAL
   - Sin vista XML asociada (llamado programáticamente)
   - Acción: Respuesta comercial a DTEs recibidos
```

#### E. Reportes (0% activos, 2 archivos desactivados)
```xml
1. dte_invoice_report.xml      ⚠️ DESACTIVADO
   - Problema: Campos 'dte_type', 'dte_folio' pueden no existir
   - Template: report_invoice_dte_document
   - Output: PDF factura con QR
   - Prioridad: MEDIA

2. dte_receipt_report.xml      ⚠️ DESACTIVADO
   - Problema: Similar a invoice_report
   - Template: report_receipt_dte_document
   - Output: PDF recibo DTE
   - Prioridad: BAJA
```

#### F. Métodos Action (21 referencias sin implementación)
```python
# ALTA PRIORIDAD (botones principales en vistas)
1. action_send_dte              # Enviar DTE a SII
2. action_retry                 # Reintentar envío fallido
3. action_cancel_dte            # Anular DTE
4. action_validate_dte          # Validar antes de enviar
5. action_download_xml          # Descargar XML firmado
6. action_download_pdf          # Descargar PDF con TED

# MEDIA PRIORIDAD (funcionalidad avanzada)
7. action_view_communications   # Ver comunicaciones SII
8. action_view_history          # Historial DTE
9. action_open_commercial_response_wizard  # Respuesta comercial
10. action_request_claim        # Reclamar DTE
11. action_accept_dte           # Aceptar DTE recibido
12. action_reject_dte           # Rechazar DTE recibido

# BAJA PRIORIDAD (reportes y batch)
13. action_generate_consumo_folios      # Reporte consumo
14. action_generate_libro_compra        # Libro compras
15. action_generate_libro_venta         # Libro ventas
16. action_export_libro                 # Exportar libro
17. action_send_batch                   # Envío masivo
18. action_upload_certificate           # Subir certificado
19. action_validate_caf                 # Validar CAF
20. action_open_chat_wizard             # Wizard chat IA
21. action_test_dte_service             # Test conexión DTE Service
```

### 2. DEPENDENCIAS Y COMPATIBILIDAD ODOO 19

#### A. Dependencias Módulos Odoo (8 módulos - 100% OK) ✅
```python
'depends': [
    'base',                          # Core Odoo ✅
    'account',                       # Contabilidad ✅
    'l10n_latam_base',              # Base LATAM ✅
    'l10n_latam_invoice_document',  # Docs LATAM ✅
    'l10n_cl',                       # Localización Chile ✅
    'purchase',                      # Compras ✅
    'stock',                         # Inventario ✅
    'web',                           # Web UI ✅
]
```

**Verificación:**
```bash
docker-compose exec -T db psql -U odoo -d odoo \
  -c "SELECT name, state FROM ir_module_module \
      WHERE name IN ('base','account','l10n_latam_base',
                     'l10n_latam_invoice_document','l10n_cl',
                     'purchase','stock','web');"
```
**Resultado esperado:** Todos en estado 'installed' ✅

#### B. Dependencias Python (25 librerías - 100% OK) ✅
```python
# PKI & Crypto
pyOpenSSL>=21.0.0       ✅
cryptography>=3.4.8     ✅
asn1crypto>=1.5.1       ✅

# XML Processing
lxml>=4.9.0             ✅
xmlsec>=1.1.25          ✅
defusedxml>=0.0.1       ✅

# SOAP/HTTP
zeep>=4.2.0             ✅ SOAP client SII
requests>=2.28.0        ✅
urllib3>=1.26.0         ✅

# Messaging
pika>=1.3.0             ✅ RabbitMQ (instalado esta sesión)

# Utilities
qrcode[pil]>=7.3.0      ✅
pillow>=9.0.0           ✅
phonenumbers>=8.12.0    ✅
email-validator>=1.1.5  ✅
reportlab>=3.6.0        ✅
PyPDF2>=3.0.0           ✅
weasyprint>=54.0        ✅
python-dateutil>=2.8.2  ✅
pytz>=2022.1            ✅
pycryptodome>=3.15.0    ✅
bcrypt>=4.0.0           ✅
structlog>=22.1.0       ✅

# Testing
pytest>=7.0.0           ✅
pytest-mock>=3.10.0     ✅
responses>=0.20.0       ✅
```

**Verificación:**
```bash
docker-compose exec odoo pip list | grep -E "pyOpenSSL|cryptography|lxml|zeep|pika"
```

#### C. Servicios Externos (3 servicios - 2 OK, 1 pendiente) ⚠️
```yaml
1. PostgreSQL 15     ✅ UP and healthy
2. Redis 7           ✅ UP and healthy
3. RabbitMQ 3.12     ⚠️ Configurado pero no iniciado

# Microservicios (no iniciados aún)
4. DTE Service       ⏳ Port 8001 (FastAPI - no corriendo)
5. AI Service        ⏳ Port 8002 (FastAPI - no corriendo)
```

**Verificación:**
```bash
docker-compose ps
# Resultado: db, redis UP | rabbitmq, dte-service, ai-service NO iniciados
```

### 3. ERRORES Y WARNINGS IDENTIFICADOS

#### A. ERRORES CRÍTICOS (0 actualmente) ✅
```
NINGUNO - Instalación básica exitosa
```

#### B. WARNINGS NO CRÍTICOS (3 tipos)

**1. Deprecation Warnings (2 warnings)**
```python
# controllers/dte_webhook.py:133
@route(type='json')  # ⚠️ Deprecated en Odoo 19
# FIX: Cambiar a @route(type='jsonrpc')

# models/dte_certificate.py, dte_caf.py
_sql_constraints = [...]  # ⚠️ Deprecated en Odoo 19
# FIX: Migrar a model.Constraint
```

**2. Configuration Warnings (12 warnings - no críticos)**
```ini
# /etc/odoo/odoo.conf
xmlrpc = True              # ⚠️ Unknown option Odoo 19
xmlrpc_port = 8069         # ⚠️ Unknown option
timezone = America/Santiago  # ⚠️ Unknown option
lang = es_CL.UTF-8         # ⚠️ Unknown option
# ... 8 más similares

# FIX: Limpiar odoo.conf o ignorar (no afectan funcionalidad)
```

**3. Accessibility Warnings (4 warnings - UX)**
```xml
<!-- views/dte_inbox_views.xml, dte_libro_views.xml, etc -->
<i class="fa fa-file-text-o"/>  <!-- ⚠️ Missing title attribute -->

# FIX: Agregar title="Descripción" para accesibilidad
```

#### C. COMPONENTES DESHABILITADOS (motivos técnicos)

**1. Wizards Deshabilitados (2 archivos)**
```python
# __manifest__.py líneas 102-103
# 'wizards/dte_generate_wizard_views.xml',  # ⚠️ Campo dte_type no existe
# 'wizards/ai_chat_wizard_views.xml',       # ⚠️ Depende ai_chat_integration

# wizards/__init__.py líneas 3-4
# from . import dte_generate_wizard  # ⚠️ TEMPORALMENTE DESACTIVADO
# from . import ai_chat_wizard      # ⚠️ DESACTIVADO

# PROBLEMA RAÍZ:
# - dte_type no es campo estándar en account.move (es dte_code)
# - ai_chat_wizard es opcional (funcionalidad avanzada)
```

**2. Reportes Deshabilitados (2 archivos)**
```python
# __manifest__.py líneas 112-113
# 'reports/dte_invoice_report.xml',  # ⚠️ Referencias a campos opcionales
# 'reports/dte_receipt_report.xml',  # ⚠️ Similar a invoice

# PROBLEMA RAÍZ:
# - Templates usan object.dte_type, object.dte_folio
# - Campos pueden no existir hasta generar DTE
# - Necesita condicionales t-if más robustos
```

**3. Demo Data Deshabilitado (1 archivo)**
```python
# __manifest__.py línea 117
# 'data/demo_dte_data.xml',  # ⚠️ Archivo no existe

# PROBLEMA RAÍZ:
# - Archivo referenciado pero nunca creado
# - No necesario para producción
# - Puede crearse en FASE 6 (testing)
```

### 4. ANÁLISIS DE RIESGOS

#### RIESGOS TÉCNICOS

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Campos DTE no sincronizados** | ALTA | ALTO | Auditoría completa campos antes activar wizards |
| **Métodos action sin implementar** | ALTA | MEDIO | Implementar stubs con notificación usuario |
| **Reportes Qweb con campos missing** | MEDIA | MEDIO | Condicionales t-if robustos |
| **Incompatibilidad DTE Service** | MEDIA | ALTO | Tests integración antes producción |
| **Pérdida datos en actualización** | BAJA | CRÍTICO | Backup obligatorio pre-actualización |
| **Conflictos l10n_cl_fe (Odoo 11)** | BAJA | MEDIO | Verificar no coexisten ambos módulos |

#### RIESGOS OPERACIONALES

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Downtime durante actualización** | MEDIA | MEDIO | Ventana mantenimiento planificada |
| **Usuario intenta usar función deshabilitada** | ALTA | BAJO | Mensajes claros "Próximamente disponible" |
| **Falta certificado SII en producción** | ALTA | ALTO | Checklist pre-producción obligatorio |
| **Ambiente Maullin no configurado** | MEDIA | MEDIO | Guía setup SII paso a paso |

---

## 🗓️ PLAN DE EJECUCIÓN POR ETAPAS

### METODOLOGÍA GENERAL

**Principios:**
1. **Incremental:** Una funcionalidad a la vez
2. **Validada:** Tests después de cada cambio
3. **Reversible:** Rollback automático si falla
4. **Documentada:** Registro de cada modificación
5. **Sin Downtime:** Actualizaciones en staging primero

**Flujo de Trabajo:**
```
┌─────────────┐
│  Análisis   │  ← Identificar componente a restaurar
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Corrección  │  ← Modificar código
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Testing   │  ← Validar en ambiente staging
└──────┬──────┘
       │
       ├─── ❌ Falla ───┐
       │                 │
       │                 ▼
       │          ┌─────────────┐
       │          │  Rollback   │  ← Revertir cambios
       │          └──────┬──────┘
       │                 │
       │                 └──────────┐
       │                            │
       ▼                            │
┌─────────────┐                    │
│  Deploy     │  ← Aplicar a prod  │
└──────┬──────┘                    │
       │                            │
       ▼                            │
┌─────────────┐                    │
│Documentación│  ← Actualizar docs │
└──────┬──────┘                    │
       │                            │
       └────────────────────────────┘
```

---

## 📅 ETAPA 1: PREPARACIÓN Y BASELINE (Semana 1)

**Objetivo:** Establecer ambiente seguro y procedimientos de seguridad
**Duración:** 6-8 horas
**Prioridad:** CRÍTICA
**Prerequisitos:** Módulo básico instalado (FASE 1 completada) ✅

### 1.1 Setup Ambiente Staging (2 horas)

**Tareas:**
```bash
# 1. Crear base de datos staging
docker-compose exec db createdb -U odoo odoo_staging

# 2. Clonar datos de producción
docker-compose exec db pg_dump -U odoo odoo | \
  docker-compose exec -T db psql -U odoo odoo_staging

# 3. Verificar clonación exitosa
docker-compose exec -T db psql -U odoo odoo_staging \
  -c "SELECT COUNT(*) FROM ir_module_module WHERE name='l10n_cl_dte';"
```

**Resultado Esperado:**
```
✅ Base de datos odoo_staging creada
✅ Datos clonados correctamente
✅ Módulo l10n_cl_dte presente
```

**Archivo de Configuración:**
```ini
# config/odoo_staging.conf (crear nuevo)
[options]
db_name = odoo_staging
http_port = 8170  # Puerto diferente a producción (8169)
# ... resto igual a odoo.conf
```

### 1.2 Procedimiento Backup Automatizado (2 horas)

**Script de Backup:**
```bash
#!/bin/bash
# scripts/backup_odoo.sh

BACKUP_DIR="/Users/pedro/Documents/odoo19/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_NAME="odoo"

# Crear directorio si no existe
mkdir -p "$BACKUP_DIR"

# Backup PostgreSQL
echo "[$(date)] Iniciando backup PostgreSQL..."
docker-compose exec -T db pg_dump -U odoo "$DB_NAME" | \
  gzip > "$BACKUP_DIR/odoo_${TIMESTAMP}.sql.gz"

# Backup filestore (archivos adjuntos)
echo "[$(date)] Iniciando backup filestore..."
docker-compose exec -T odoo tar czf - /var/lib/odoo/.local/share/Odoo/filestore/"$DB_NAME" > \
  "$BACKUP_DIR/filestore_${TIMESTAMP}.tar.gz"

# Backup configuración
echo "[$(date)] Backup configuración..."
cp config/odoo.conf "$BACKUP_DIR/odoo_${TIMESTAMP}.conf"

# Verificar backups
echo "[$(date)] Verificando integridad..."
gzip -t "$BACKUP_DIR/odoo_${TIMESTAMP}.sql.gz" && \
tar tzf "$BACKUP_DIR/filestore_${TIMESTAMP}.tar.gz" > /dev/null && \
echo "✅ Backup completado exitosamente" || \
echo "❌ ERROR en backup"

# Limpiar backups antiguos (mantener últimos 7 días)
find "$BACKUP_DIR" -name "odoo_*.sql.gz" -mtime +7 -delete
find "$BACKUP_DIR" -name "filestore_*.tar.gz" -mtime +7 -delete

echo "[$(date)] Backup finalizado: odoo_${TIMESTAMP}.sql.gz"
```

**Hacer ejecutable y probar:**
```bash
chmod +x scripts/backup_odoo.sh
./scripts/backup_odoo.sh
```

**Cron para Backup Diario:**
```bash
# Agregar a crontab
0 2 * * * /Users/pedro/Documents/odoo19/scripts/backup_odoo.sh >> /Users/pedro/Documents/odoo19/logs/backup.log 2>&1
```

### 1.3 Procedimiento Restore (1 hora)

**Script de Restore:**
```bash
#!/bin/bash
# scripts/restore_odoo.sh

BACKUP_FILE=$1
DB_NAME=${2:-odoo_restored}

if [ -z "$BACKUP_FILE" ]; then
    echo "Uso: $0 <backup_file.sql.gz> [db_name]"
    exit 1
fi

# Crear nueva base de datos
echo "[$(date)] Creando base de datos $DB_NAME..."
docker-compose exec db dropdb -U odoo "$DB_NAME" --if-exists
docker-compose exec db createdb -U odoo "$DB_NAME"

# Restaurar dump
echo "[$(date)] Restaurando backup..."
gunzip -c "$BACKUP_FILE" | \
  docker-compose exec -T db psql -U odoo "$DB_NAME"

echo "✅ Restore completado: $DB_NAME"
```

**Hacer ejecutable:**
```bash
chmod +x scripts/restore_odoo.sh
```

### 1.4 Tests de Baseline (1 hora)

**Script de Validación:**
```bash
#!/bin/bash
# scripts/validate_installation.sh

echo "=== VALIDACIÓN INSTALACIÓN l10n_cl_dte ==="

# Test 1: Módulo instalado
echo -n "Test 1: Módulo instalado... "
INSTALLED=$(docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT state FROM ir_module_module WHERE name='l10n_cl_dte';")
[[ "$INSTALLED" =~ "installed" ]] && echo "✅" || echo "❌"

# Test 2: Menús creados
echo -n "Test 2: Menús DTE creados (16 esperados)... "
MENUS=$(docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT COUNT(*) FROM ir_model_data WHERE module='l10n_cl_dte' AND model='ir.ui.menu';")
[[ "$MENUS" -ge 16 ]] && echo "✅ ($MENUS)" || echo "❌ ($MENUS)"

# Test 3: Vistas creadas
echo -n "Test 3: Vistas creadas (28 esperadas)... "
VIEWS=$(docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT COUNT(*) FROM ir_ui_view WHERE id IN \
      (SELECT res_id FROM ir_model_data WHERE module='l10n_cl_dte' AND model='ir.ui.view');")
[[ "$VIEWS" -ge 28 ]] && echo "✅ ($VIEWS)" || echo "❌ ($VIEWS)"

# Test 4: Tablas creadas
echo -n "Test 4: Tablas DTE creadas (10 esperadas)... "
TABLES=$(docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT COUNT(*) FROM information_schema.tables \
      WHERE table_schema='public' AND (table_name LIKE 'dte_%' OR table_name LIKE '%_dte%');")
[[ "$TABLES" -ge 10 ]] && echo "✅ ($TABLES)" || echo "❌ ($TABLES)"

# Test 5: Odoo responde
echo -n "Test 5: Odoo HTTP responde... "
curl -s http://localhost:8169/web/health > /dev/null && echo "✅" || echo "❌"

echo "=== VALIDACIÓN COMPLETADA ==="
```

**Hacer ejecutable y ejecutar:**
```bash
chmod +x scripts/validate_installation.sh
./scripts/validate_installation.sh
```

### 1.5 Documentación Estado Baseline (1 hora)

**Crear snapshot de estado actual:**
```bash
# Generar reporte completo
./scripts/validate_installation.sh > docs/baseline_etapa1.txt

# Exportar estructura DB
docker-compose exec -T db pg_dump -U odoo odoo --schema-only | \
  gzip > docs/schema_baseline.sql.gz

# Listar todos los campos de modelos DTE
docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT table_name, column_name FROM information_schema.columns \
      WHERE table_name LIKE 'dte_%' ORDER BY table_name, ordinal_position;" > \
  docs/fields_baseline.txt
```

### 1.6 Checklist Etapa 1

```
☐ Base de datos staging creada
☐ Script backup_odoo.sh funcionando
☐ Script restore_odoo.sh funcionando
☐ Cron backup configurado
☐ Backup inicial pre-modificaciones creado
☐ Script validate_installation.sh funcionando
☐ Baseline documentado (3 archivos)
☐ Tests baseline ejecutados (5/5 passing)
```

**Comando de Validación Final:**
```bash
# Ejecutar todos los tests
./scripts/validate_installation.sh && \
echo "✅ Etapa 1 completada - BASELINE establecido"
```

---

## 📅 ETAPA 2: RESTAURAR WIZARDS (Semana 1-2)

**Objetivo:** Activar wizards DTE progresivamente
**Duración:** 6-10 horas
**Prioridad:** ALTA
**Prerequisitos:** Etapa 1 completada, backup creado

### 2.1 Wizard 1: dte_generate_wizard (Prioridad ALTA)

**Análisis del Problema:**
```python
# wizards/dte_generate_wizard.py
# Vista referencia campo 'dte_type' en account.move
# Pero el campo correcto es 'dte_code'

# ERROR ACTUAL:
Field 'dte_type' does not exist in model 'account.move'
```

**Tareas:**

#### 2.1.1 Auditoría de Campos (1 hora)
```bash
# Verificar campos DTE en account.move
docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT column_name FROM information_schema.columns \
      WHERE table_name='account_move' AND column_name LIKE '%dte%';"

# Resultado esperado:
# dte_code
# dte_status
# dte_folio
# dte_xml
# dte_timestamp
# dte_accepted_date
# dte_certificate_id
# dte_caf_id
# dte_environment
# is_contingency
```

#### 2.1.2 Corrección Modelo Wizard (2 horas)
```python
# File: wizards/dte_generate_wizard.py

class DTEGenerateWizard(models.TransientModel):
    _name = 'dte.generate.wizard'
    _description = 'Wizard Generación DTE'

    # ANTES (causaba error):
    # dte_type = fields.Selection(...)

    # DESPUÉS (correcto):
    dte_code = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Liquidación Honorarios'),
        ('52', 'Guía de Despacho Electrónica'),
        ('56', 'Nota de Débito Electrónica'),
        ('61', 'Nota de Crédito Electrónica'),
    ], string='Tipo DTE', required=True)

    invoice_ids = fields.Many2many(
        'account.move',
        string='Facturas',
        domain="[('move_type', 'in', ['out_invoice', 'out_refund']), \
                 ('dte_status', 'in', ['draft', 'error'])]"
    )

    environment = fields.Selection([
        ('sandbox', 'Maullin (Certificación)'),
        ('production', 'Palena (Producción)'),
    ], string='Ambiente SII', required=True, default='sandbox')

    def action_generate_dte(self):
        """Generar DTEs para facturas seleccionadas"""
        self.ensure_one()

        if not self.invoice_ids:
            raise UserError(_('Debe seleccionar al menos una factura'))

        for invoice in self.invoice_ids:
            try:
                # Llamar a método de account.move
                invoice.action_generate_dte()
            except Exception as e:
                _logger.error(f"Error generando DTE para {invoice.name}: {e}")
                # No detener el proceso, continuar con siguiente

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('DTEs Generados'),
                'message': _(f'{len(self.invoice_ids)} DTEs enviados a generación'),
                'sticky': False,
                'type': 'success',
            }
        }
```

#### 2.1.3 Corrección Vista Wizard (1 hora)
```xml
<!-- File: wizards/dte_generate_wizard_views.xml -->
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <record id="view_dte_generate_wizard_form" model="ir.ui.view">
        <field name="name">dte.generate.wizard.form</field>
        <field name="model">dte.generate.wizard</field>
        <field name="arch" type="xml">
            <form string="Generar DTEs">
                <group>
                    <field name="dte_code" widget="radio"/>
                    <field name="environment" widget="radio"/>
                </group>
                <group string="Facturas a Generar">
                    <field name="invoice_ids" nolabel="1">
                        <list>
                            <field name="name"/>
                            <field name="partner_id"/>
                            <field name="amount_total"/>
                            <field name="dte_status"/>
                        </list>
                    </field>
                </group>
                <footer>
                    <button string="Generar DTEs"
                            name="action_generate_dte"
                            type="object"
                            class="btn-primary"/>
                    <button string="Cancelar"
                            special="cancel"
                            class="btn-secondary"/>
                </footer>
            </form>
        </field>
    </record>

    <record id="action_dte_generate_wizard" model="ir.actions.act_window">
        <field name="name">Generar DTEs</field>
        <field name="res_model">dte.generate.wizard</field>
        <field name="view_mode">form</field>
        <field name="target">new</field>
        <field name="binding_model_id" ref="account.model_account_move"/>
        <field name="binding_view_types">list</field>
    </record>
</odoo>
```

#### 2.1.4 Activación y Testing (2 horas)
```bash
# 1. Backup PRE-cambios
./scripts/backup_odoo.sh

# 2. Descomentar en __manifest__.py
# Línea 102:
'wizards/dte_generate_wizard_views.xml',  # ✅ REACTIVADO

# 3. Descomentar en wizards/__init__.py
# Línea 3:
from . import dte_generate_wizard  # ✅ REACTIVADO

# 4. Actualizar módulo en STAGING
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo_staging \
  -u l10n_cl_dte --stop-after-init --log-level=info 2>&1 | \
  tee /tmp/update_wizard1.log

# 5. Verificar no hay errores
grep -i "error\|traceback" /tmp/update_wizard1.log

# 6. Test manual en UI
# - Login http://localhost:8170 (staging)
# - Ir a Facturas
# - Seleccionar una factura draft
# - Acción -> Generar DTEs
# - Verificar wizard se abre sin errores
# - Verificar campos visibles y editables
# - Cancelar (no ejecutar aún sin DTE Service)

# 7. Si todo OK, aplicar a PRODUCCIÓN
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  -u l10n_cl_dte --stop-after-init
```

**Criterios de Aceptación:**
```
✅ Wizard se abre sin errores
✅ Campos dte_code, environment visibles
✅ Campo invoice_ids muestra facturas draft
✅ Botón "Generar DTEs" clickeable
✅ Al hacer click, muestra notificación éxito
✅ No hay errores en logs Odoo
```

### 2.2 Wizard 2: ai_chat_wizard (Prioridad BAJA - Opcional)

**Análisis:**
```python
# Este wizard depende de:
# 1. ai_chat_integration.py (modelo ya existe ✅)
# 2. AI Service corriendo en port 8002 (⏳ no iniciado)

# DECISIÓN: Activar solo si AI Service está disponible
```

**Tareas:**

#### 2.2.1 Verificar Dependencia AI Service (30 min)
```bash
# Verificar si AI Service está disponible
curl http://localhost:8002/health 2>/dev/null && \
  echo "✅ AI Service disponible" || \
  echo "⚠️ AI Service no disponible - Wizard AI quedará desactivado"
```

#### 2.2.2 Activación Condicional (1 hora)
**Solo si AI Service disponible:**
```bash
# 1. Descomentar en __manifest__.py
# 'wizards/ai_chat_wizard_views.xml',  # ✅ REACTIVADO

# 2. Descomentar en wizards/__init__.py
# from . import ai_chat_wizard  # ✅ REACTIVADO

# 3. Actualizar módulo
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo_staging \
  -u l10n_cl_dte --stop-after-init
```

**Si AI Service NO disponible:**
```
⏭️ SKIP - Wizard permanece desactivado
📝 Documentar: "AI Chat Wizard requiere AI Service (puerto 8002)"
```

### 2.3 Checklist Etapa 2

```
☐ Backup PRE-Etapa 2 creado
☐ Auditoría campos account.move completada
☐ dte_generate_wizard.py corregido
☐ dte_generate_wizard_views.xml corregido
☐ Wizard activado en __manifest__.py
☐ Wizard activado en wizards/__init__.py
☐ Tests en staging exitosos (6/6 criterios)
☐ Wizard aplicado a producción
☐ ai_chat_wizard evaluado (activado o skip)
☐ Documentación actualizada
```

**Comando de Validación:**
```bash
# Test automatizado wizard
docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT COUNT(*) FROM ir_model WHERE model='dte.generate.wizard';"
# Resultado esperado: 1

docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT COUNT(*) FROM ir_ui_view WHERE name LIKE '%dte.generate.wizard%';"
# Resultado esperado: >= 1
```

---

## 📅 ETAPA 3: RESTAURAR REPORTES PDF (Semana 2)

**Objetivo:** Activar reportes Qweb PDF con validación robusta
**Duración:** 4-6 horas
**Prioridad:** MEDIA
**Prerequisitos:** Etapa 2 completada

### 3.1 Reporte 1: dte_invoice_report.xml

**Análisis del Problema:**
```xml
<!-- reports/dte_invoice_report.xml línea 9 -->
<field name="print_report_name">
    'DTE_%s_%s' % (object.dte_type or '33', object.dte_folio or object.name)
</field>
<!-- ⚠️ Problema: object.dte_type no existe, debe ser object.dte_code -->

<!-- Línea 23 -->
<span t-if="o.dte_type">DTE Tipo: <t t-esc="o.dte_type"/></span>
<!-- ⚠️ Problema: dte_type → dte_code -->

<!-- Línea 24 -->
<span t-if="o.dte_folio">Folio: <t t-esc="o.dte_folio"/></span>
<!-- ⚠️ Problema: dte_folio puede no existir hasta generar DTE -->
```

**Tareas:**

#### 3.1.1 Corrección Template (2 horas)
```xml
<!-- File: reports/dte_invoice_report.xml -->
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <!-- Reporte: Factura DTE (PDF) -->
    <record id="report_dte_invoice" model="ir.actions.report">
        <field name="name">Factura DTE</field>
        <field name="model">account.move</field>
        <field name="report_type">qweb-pdf</field>
        <field name="report_name">l10n_cl_dte.report_invoice_dte_document</field>

        <!-- ✅ CORREGIDO: usar dte_code en vez de dte_type -->
        <field name="print_report_name">
            'DTE_%s_%s' % (object.dte_code or '33', object.dte_folio or object.name)
        </field>

        <field name="binding_model_id" ref="account.model_account_move"/>
        <field name="binding_type">report</field>

        <!-- ✅ NUEVO: Solo mostrar para facturas con DTE generado -->
        <field name="binding_view_types">form</field>

        <!-- ✅ NUEVO: Invisible si no tiene DTE -->
        <field name="print_report_invisible" eval="object.dte_status not in ['sent', 'accepted']"/>
    </record>

    <!-- Template: Factura DTE con validaciones robustas -->
    <template id="report_invoice_dte_document">
        <t t-call="web.html_container">
            <t t-foreach="docs" t-as="o">
                <t t-call="web.external_layout">
                    <div class="page">

                        <!-- Header con validación -->
                        <div class="row">
                            <div class="col-6">
                                <h2>
                                    <t t-if="o.dte_code">
                                        <t t-if="o.dte_code == '33'">FACTURA ELECTRÓNICA</t>
                                        <t t-if="o.dte_code == '61'">NOTA DE CRÉDITO ELECTRÓNICA</t>
                                        <t t-if="o.dte_code == '56'">NOTA DE DÉBITO ELECTRÓNICA</t>
                                    </t>
                                    <t t-else>DOCUMENTO</t>
                                </h2>

                                <!-- ✅ CORREGIDO: Validar campo existe -->
                                <t t-if="o.dte_code">
                                    <strong>Tipo DTE:</strong> <span t-esc="o.dte_code"/><br/>
                                </t>

                                <!-- ✅ CORREGIDO: Validar folio existe -->
                                <t t-if="o.dte_folio">
                                    <strong>Folio:</strong> <span t-esc="o.dte_folio"/><br/>
                                </t>
                                <t t-else>
                                    <strong>Número:</strong> <span t-esc="o.name"/><br/>
                                </t>

                                <!-- ✅ NUEVO: Estado DTE -->
                                <t t-if="o.dte_status">
                                    <strong>Estado:</strong>
                                    <span t-field="o.dte_status"
                                          class="badge badge-info"/><br/>
                                </t>
                            </div>

                            <div class="col-6 text-end">
                                <!-- Datos emisor -->
                                <strong t-field="o.company_id.name"/><br/>
                                <t t-if="o.company_id.vat">
                                    <strong>RUT:</strong> <span t-field="o.company_id.vat"/><br/>
                                </t>
                                <span t-field="o.company_id.street"/><br/>
                                <t t-if="o.company_id.city">
                                    <span t-field="o.company_id.city"/>,
                                    <span t-field="o.company_id.state_id.name"/>
                                </t>
                            </div>
                        </div>

                        <!-- Datos cliente -->
                        <div class="row mt-4">
                            <div class="col-6">
                                <strong>CLIENTE:</strong><br/>
                                <div t-field="o.partner_id"
                                     t-options='{"widget": "contact", "fields": ["address", "name"], "no_marker": True}'/>
                                <t t-if="o.partner_id.vat">
                                    <strong>RUT:</strong> <span t-field="o.partner_id.vat"/>
                                </t>
                            </div>

                            <div class="col-6">
                                <strong>Fecha Emisión:</strong>
                                <span t-field="o.invoice_date"/><br/>

                                <t t-if="o.invoice_date_due">
                                    <strong>Fecha Vencimiento:</strong>
                                    <span t-field="o.invoice_date_due"/><br/>
                                </t>

                                <!-- ✅ NUEVO: Timestamp DTE -->
                                <t t-if="o.dte_timestamp">
                                    <strong>Fecha Timbraje:</strong>
                                    <span t-field="o.dte_timestamp"/><br/>
                                </t>
                            </div>
                        </div>

                        <!-- Líneas de factura -->
                        <table class="table table-sm mt-4">
                            <thead>
                                <tr class="bg-light">
                                    <th>Descripción</th>
                                    <th class="text-end">Cantidad</th>
                                    <th class="text-end">Precio Unit.</th>
                                    <th class="text-end">Subtotal</th>
                                </tr>
                            </thead>
                            <tbody>
                                <t t-foreach="o.invoice_line_ids" t-as="line">
                                    <tr>
                                        <td><span t-field="line.name"/></td>
                                        <td class="text-end">
                                            <span t-field="line.quantity"/>
                                            <span t-field="line.product_uom_id.name"/>
                                        </td>
                                        <td class="text-end">
                                            <span t-field="line.price_unit"/>
                                        </td>
                                        <td class="text-end">
                                            <span t-field="line.price_subtotal"/>
                                        </td>
                                    </tr>
                                </t>
                            </tbody>
                        </table>

                        <!-- Totales -->
                        <div class="row justify-content-end">
                            <div class="col-4">
                                <table class="table table-sm">
                                    <tr>
                                        <td><strong>Neto:</strong></td>
                                        <td class="text-end">
                                            <span t-field="o.amount_untaxed"/>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><strong>IVA (19%):</strong></td>
                                        <td class="text-end">
                                            <span t-field="o.amount_tax"/>
                                        </td>
                                    </tr>
                                    <tr class="border-top">
                                        <td><strong>TOTAL:</strong></td>
                                        <td class="text-end">
                                            <strong t-field="o.amount_total"/>
                                        </td>
                                    </tr>
                                </table>
                            </div>
                        </div>

                        <!-- ✅ NUEVO: QR Code TED (solo si DTE generado) -->
                        <t t-if="o.dte_xml and o.dte_status in ['sent', 'accepted']">
                            <div class="row mt-4">
                                <div class="col-12 text-center">
                                    <h5>Timbre Electrónico DTE (TED)</h5>
                                    <!-- QR Code se genera desde campo dte_xml -->
                                    <t t-if="o.dte_qr_code">
                                        <img t-att-src="'data:image/png;base64,' + o.dte_qr_code.decode('utf-8')"
                                             style="width: 200px; height: 200px;"/>
                                    </t>
                                    <p class="small text-muted">
                                        Este documento es una representación impresa de un DTE<br/>
                                        Folio: <span t-esc="o.dte_folio or 'N/A'"/>
                                    </p>
                                </div>
                            </div>
                        </t>

                        <!-- ✅ NUEVO: Advertencia si DTE no generado -->
                        <t t-if="not o.dte_xml or o.dte_status == 'draft'">
                            <div class="alert alert-warning mt-4" role="alert">
                                <strong>Atención:</strong> Este documento aún NO ha sido enviado al SII.
                                No constituye un documento tributario válido hasta su emisión electrónica.
                            </div>
                        </t>

                    </div>
                </t>
            </t>
        </t>
    </template>
</odoo>
```

#### 3.1.2 Agregar Campo Computed QR (1 hora)
```python
# File: models/account_move_dte.py

class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    # ... campos existentes ...

    # ✅ NUEVO: QR Code computed field
    dte_qr_code = fields.Binary(
        string='QR Code TED',
        compute='_compute_dte_qr_code',
        store=False,  # No persistir, generar on-demand
        help='QR Code del Timbre Electrónico DTE'
    )

    def _compute_dte_qr_code(self):
        """Generar QR Code desde TED en XML"""
        import qrcode
        import base64
        from io import BytesIO

        for record in self:
            if not record.dte_xml:
                record.dte_qr_code = False
                continue

            try:
                # Extraer TED del XML
                from lxml import etree
                root = etree.fromstring(record.dte_xml.encode('utf-8'))
                ted_element = root.find('.//{http://www.sii.cl/SiiDte}TED')

                if ted_element is not None:
                    # Convertir TED a string
                    ted_string = etree.tostring(ted_element, encoding='unicode')

                    # Generar QR Code
                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=qrcode.constants.ERROR_CORRECT_L,
                        box_size=10,
                        border=4,
                    )
                    qr.add_data(ted_string)
                    qr.make(fit=True)

                    # Convertir a imagen
                    img = qr.make_image(fill_color="black", back_color="white")

                    # Convertir a base64
                    buffer = BytesIO()
                    img.save(buffer, format='PNG')
                    record.dte_qr_code = base64.b64encode(buffer.getvalue())
                else:
                    record.dte_qr_code = False
            except Exception as e:
                _logger.error(f"Error generando QR Code para {record.name}: {e}")
                record.dte_qr_code = False
```

#### 3.1.3 Testing Reporte (2 horas)
```bash
# 1. Backup PRE-cambios
./scripts/backup_odoo.sh

# 2. Activar reporte en __manifest__.py
# Línea 112:
'reports/dte_invoice_report.xml',  # ✅ REACTIVADO

# 3. Actualizar módulo staging
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo_staging \
  -u l10n_cl_dte --stop-after-init 2>&1 | tee /tmp/update_report1.log

# 4. Verificar no hay errores
grep -i "error\|traceback" /tmp/update_report1.log

# 5. Test manual UI
# - Login staging: http://localhost:8170
# - Crear factura de prueba
# - Llenar datos mínimos (partner, líneas)
# - Imprimir -> Factura DTE
# - Verificar PDF genera sin errores
# - Verificar campos se muestran correctamente
# - Verificar advertencia "No enviado al SII" aparece

# 6. Si todo OK, aplicar a producción
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  -u l10n_cl_dte --stop-after-init
```

**Criterios de Aceptación:**
```
✅ Reporte aparece en menú Imprimir
✅ PDF genera sin errores
✅ Campos dte_code, dte_folio muestran valores correctos
✅ Si DTE no generado, muestra advertencia
✅ Si DTE generado, muestra QR Code
✅ Layout profesional y legible
```

### 3.2 Reporte 2: dte_receipt_report.xml

**Similar a 3.1, aplicar mismas correcciones**

**Tareas (2 horas):**
1. Corregir campos dte_type → dte_code
2. Agregar validaciones t-if robustas
3. Adaptar layout para recibo (más compacto)
4. Testing en staging
5. Deploy a producción

### 3.3 Checklist Etapa 3

```
☐ Backup PRE-Etapa 3 creado
☐ dte_invoice_report.xml corregido
☐ Campo dte_qr_code agregado a account_move
☐ Tests PDF invoice en staging (6/6 criterios)
☐ dte_receipt_report.xml corregido
☐ Tests PDF receipt en staging
☐ Reportes aplicados a producción
☐ Documentación actualizada
```

---

## 📅 ETAPA 4: IMPLEMENTAR MÉTODOS ACTION (Semana 2-3)

**Objetivo:** Implementar stubs para métodos action críticos
**Duración:** 8-12 horas
**Prioridad:** ALTA
**Prerequisitos:** Etapas 2-3 completadas

### 4.1 Categorización de Métodos (1 hora)

**21 métodos divididos en 3 prioridades:**

#### PRIORIDAD CRÍTICA (6 métodos - implementar completo)
```python
1. action_send_dte              # Enviar DTE a SII (core)
2. action_retry                 # Reintentar envío (UX)
3. action_validate_dte          # Pre-validación (prevención errores)
4. action_download_xml          # Descargar XML firmado (legal)
5. action_download_pdf          # Descargar PDF con TED (legal)
6. action_cancel_dte            # Anular DTE (core)
```

#### PRIORIDAD MEDIA (8 métodos - implementar stub informativo)
```python
7. action_view_communications   # Ver comunicaciones SII
8. action_view_history          # Historial cambios DTE
9. action_open_commercial_response_wizard  # Respuesta comercial
10. action_request_claim        # Reclamar DTE
11. action_accept_dte           # Aceptar DTE recibido
12. action_reject_dte           # Rechazar DTE recibido
13. action_upload_certificate   # Subir certificado
14. action_validate_caf         # Validar CAF
```

#### PRIORIDAD BAJA (7 métodos - stub básico)
```python
15. action_generate_consumo_folios  # Reporte consumo
16. action_generate_libro_compra    # Libro compras
17. action_generate_libro_venta     # Libro ventas
18. action_export_libro             # Exportar libro
19. action_send_batch               # Envío masivo
20. action_open_chat_wizard         # Chat IA
21. action_test_dte_service         # Test DTE Service
```

### 4.2 Implementación Prioridad CRÍTICA (6 horas)

#### 4.2.1 action_send_dte (2 horas)
```python
# File: models/account_move_dte.py

def action_send_dte(self):
    """
    Generar y enviar DTE al SII
    - Valida datos factura
    - Llama a DTE Service para generar XML
    - Firma digital
    - Envía a SII
    - Actualiza estado
    """
    self.ensure_one()

    # Validaciones previas
    if not self.partner_id.vat:
        raise UserError(_('El cliente debe tener RUT configurado'))

    if not self.company_id.vat:
        raise UserError(_('La empresa debe tener RUT configurado'))

    if self.dte_status not in ['draft', 'error']:
        raise UserError(_('Solo se pueden enviar DTEs en estado Borrador o Error'))

    # Determinar tipo DTE según move_type
    dte_type_map = {
        'out_invoice': '33',   # Factura
        'out_refund': '61',    # Nota Crédito
        'in_refund': '56',     # Nota Débito (menos común)
    }

    dte_code = dte_type_map.get(self.move_type)
    if not dte_code:
        raise UserError(_('Tipo de documento no soportado para DTE'))

    # Obtener certificado activo
    certificate = self.env['dte.certificate'].search([
        ('company_id', '=', self.company_id.id),
        ('state', '=', 'valid'),
        ('is_active', '=', True)
    ], limit=1)

    if not certificate:
        raise UserError(_('No hay certificado digital activo configurado'))

    # Obtener folio disponible
    caf = self.env['dte.caf'].get_next_folio(dte_code, self.company_id.id)
    if not caf:
        raise UserError(_(f'No hay folios disponibles para DTE tipo {dte_code}'))

    try:
        # Preparar datos para DTE Service
        dte_data = self._prepare_dte_data(dte_code, caf.folio_number)

        # Llamar a DTE Service
        dte_service_url = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_url',
            'http://dte-service:8001'
        )

        response = requests.post(
            f'{dte_service_url}/api/v1/generate',
            json={
                'dte_type': dte_code,
                'invoice_data': dte_data,
                'certificate_id': certificate.id,
                'environment': self.env.company.dte_environment or 'sandbox',
            },
            headers={'Authorization': f'Bearer {self.env["ir.config_parameter"].sudo().get_param("l10n_cl_dte.dte_api_key")}'},
            timeout=60
        )

        response.raise_for_status()
        result = response.json()

        # Actualizar factura con resultado
        self.write({
            'dte_code': dte_code,
            'dte_folio': caf.folio_number,
            'dte_xml': result.get('xml_signed'),
            'dte_status': 'sent',
            'dte_timestamp': fields.Datetime.now(),
            'dte_certificate_id': certificate.id,
            'dte_caf_id': caf.id,
        })

        # Marcar folio como usado
        caf.mark_as_used()

        # Registrar comunicación SII
        self.env['dte.communication'].create({
            'move_id': self.id,
            'communication_type': 'send',
            'request_xml': dte_data,
            'response_xml': result.get('sii_response'),
            'track_id': result.get('track_id'),
            'status': 'sent',
        })

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('DTE Enviado'),
                'message': _(f'DTE tipo {dte_code} folio {caf.folio_number} enviado al SII'),
                'sticky': False,
                'type': 'success',
            }
        }

    except requests.RequestException as e:
        _logger.error(f"Error comunicación DTE Service: {e}")
        self.write({'dte_status': 'error'})
        raise UserError(_(f'Error al comunicar con DTE Service: {e}'))
    except Exception as e:
        _logger.error(f"Error generando DTE: {e}")
        self.write({'dte_status': 'error'})
        raise UserError(_(f'Error al generar DTE: {e}'))

def _prepare_dte_data(self, dte_code, folio):
    """Preparar estructura de datos para DTE Service"""
    self.ensure_one()

    return {
        'dte_code': dte_code,
        'folio': folio,
        'fecha_emision': self.invoice_date.isoformat(),
        'emisor': {
            'rut': self.company_id.vat,
            'razon_social': self.company_id.name,
            'giro': self.company_id.industry_id.name if self.company_id.industry_id else '',
            'direccion': self.company_id.street or '',
            'comuna': self.company_id.city or '',
            'ciudad': self.company_id.state_id.name if self.company_id.state_id else '',
            'acteco': self.company_id.l10n_cl_activity_code or '',
        },
        'receptor': {
            'rut': self.partner_id.vat,
            'razon_social': self.partner_id.name,
            'giro': self.partner_id.industry_id.name if self.partner_id.industry_id else 'Giro no especificado',
            'direccion': self.partner_id.street or '',
            'comuna': self.partner_id.city or '',
            'ciudad': self.partner_id.state_id.name if self.partner_id.state_id else '',
        },
        'totales': {
            'monto_neto': int(self.amount_untaxed),
            'monto_iva': int(self.amount_tax),
            'monto_total': int(self.amount_total),
        },
        'detalle': [
            {
                'numero_linea': idx + 1,
                'nombre': line.name,
                'cantidad': int(line.quantity),
                'unidad': line.product_uom_id.name or 'UN',
                'precio_unitario': int(line.price_unit),
                'monto_linea': int(line.price_subtotal),
            }
            for idx, line in enumerate(self.invoice_line_ids)
        ],
    }
```

#### 4.2.2 action_retry, action_validate_dte, etc. (4 horas)
```python
# Implementar otros 5 métodos críticos siguiendo patrón similar
# Ver código completo en archivo anexo
```

### 4.3 Implementación STUBS (2 horas)

**Para métodos prioridad MEDIA y BAJA:**
```python
def action_view_communications(self):
    """Ver comunicaciones SII de este DTE"""
    self.ensure_one()

    return {
        'type': 'ir.actions.act_window',
        'name': _('Comunicaciones SII'),
        'res_model': 'dte.communication',
        'view_mode': 'list,form',
        'domain': [('move_id', '=', self.id)],
        'context': {'default_move_id': self.id},
    }

def action_view_history(self):
    """Ver historial de cambios del DTE"""
    # Stub: redireccionar a chatter
    self.ensure_one()
    return {
        'type': 'ir.actions.client',
        'tag': 'display_notification',
        'params': {
            'title': _('Historial DTE'),
            'message': _('Ver historial en la sección de mensajes abajo'),
            'sticky': False,
            'type': 'info',
        }
    }

# ... implementar stubs para resto de métodos
# Patrón: Notificación informativa o vista simple
```

### 4.4 Checklist Etapa 4

```
☐ Backup PRE-Etapa 4 creado
☐ 6 métodos críticos implementados
☐ Tests unitarios métodos críticos (staging)
☐ 15 stubs implementados
☐ Todos los botones en vistas funcionales (no errores)
☐ Documentación métodos actualizada
☐ Deploy a producción
```

---

## 📅 ETAPA 5: CORREGIR DEPRECATIONS (Semana 3)

**Objetivo:** Eliminar warnings deprecation
**Duración:** 2-3 horas
**Prioridad:** MEDIA
**Prerequisitos:** Etapa 4 completada

### 5.1 Deprecation 1: @route(type='json')

**Corrección (30 min):**
```python
# File: controllers/dte_webhook.py línea 133

# ANTES:
@route('/dte/webhook', type='json', auth='public', methods=['POST'], csrf=False)

# DESPUÉS:
@route('/dte/webhook', type='jsonrpc', auth='public', methods=['POST'], csrf=False)
```

### 5.2 Deprecation 2: _sql_constraints

**Corrección (2 horas):**
```python
# File: models/dte_certificate.py

# ANTES:
_sql_constraints = [
    ('name_unique', 'unique(name, company_id)',
     'Ya existe un certificado con este nombre para esta compañía'),
]

# DESPUÉS:
from odoo import models, fields, api, _
from odoo.models import Constraint

class DTECertificate(models.Model):
    _name = 'dte.certificate'
    _description = 'Certificado Digital SII'

    # Definir constraint como clase interna
    class _Constraints(models.Model):
        _inherit = 'dte.certificate'

        _sql_constraint = Constraint(
            'name_unique',
            'unique(name, company_id)',
            'Ya existe un certificado con este nombre para esta compañía'
        )
```

**Aplicar en:**
- `dte_certificate.py`
- `dte_caf.py`
- Otros modelos con _sql_constraints

### 5.3 Checklist Etapa 5

```
☐ Backup PRE-Etapa 5 creado
☐ @route(type='json') corregido
☐ _sql_constraints migrados (2-3 archivos)
☐ Warnings verificados eliminados (log limpio)
☐ Deploy a producción
```

---

## 📅 ETAPA 6: TESTING Y VALIDACIÓN (Semana 3-4)

**Objetivo:** Tests automatizados completos
**Duración:** 6-8 horas
**Prioridad:** ALTA
**Prerequisitos:** Etapas 1-5 completadas

### 6.1 Tests Unitarios (3 horas)

**Crear estructura tests:**
```
addons/localization/l10n_cl_dte/tests/
├── __init__.py
├── test_dte_certificate.py
├── test_dte_caf.py
├── test_account_move_dte.py
├── test_dte_generation.py
└── test_sii_integration.py (mock)
```

**Ejemplo test_account_move_dte.py:**
```python
# tests/test_account_move_dte.py
from odoo.tests import TransactionCase
from odoo.exceptions import UserError

class TestAccountMoveDTE(TransactionCase):

    def setUp(self):
        super().setUp()
        self.partner = self.env['res.partner'].create({
            'name': 'Cliente Test',
            'vat': '12345678-9',
        })
        self.product = self.env['product.product'].create({
            'name': 'Producto Test',
            'list_price': 100.0,
        })

    def test_create_invoice_basic(self):
        """Test creación factura básica"""
        invoice = self.env['account.move'].create({
            'partner_id': self.partner.id,
            'move_type': 'out_invoice',
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100,
            })],
        })
        self.assertTrue(invoice.id)
        self.assertEqual(invoice.dte_status, 'draft')

    def test_send_dte_without_rut_fails(self):
        """Test que envío DTE sin RUT falla"""
        partner_no_rut = self.env['res.partner'].create({
            'name': 'Cliente Sin RUT',
        })
        invoice = self.env['account.move'].create({
            'partner_id': partner_no_rut.id,
            'move_type': 'out_invoice',
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100,
            })],
        })
        with self.assertRaises(UserError):
            invoice.action_send_dte()

    # ... más tests
```

### 6.2 Tests Integración (3 horas)

**Con DTE Service (mock):**
```python
# tests/test_sii_integration.py
import responses
from odoo.tests import TransactionCase

class TestSIIIntegration(TransactionCase):

    @responses.activate
    def test_send_dte_to_service(self):
        """Test envío DTE a DTE Service (mock)"""
        # Mock response DTE Service
        responses.add(
            responses.POST,
            'http://dte-service:8001/api/v1/generate',
            json={
                'xml_signed': '<DTE>...</DTE>',
                'track_id': '123456789',
                'sii_response': 'OK',
            },
            status=200
        )

        invoice = self._create_test_invoice()
        invoice.action_send_dte()

        self.assertEqual(invoice.dte_status, 'sent')
        self.assertTrue(invoice.dte_xml)
```

### 6.3 Tests UI (2 horas)

**Tests manuales en checklist:**
```
☐ Login Odoo
☐ Crear factura → Guardar sin errores
☐ Abrir wizard "Generar DTE" → Sin errores
☐ Imprimir PDF factura → PDF genera correctamente
☐ Botón "Enviar DTE" → Notificación adecuada (mock)
☐ Ver comunicaciones SII → Vista abre
☐ Menú DTE Chile → 16 menús accesibles
☐ Configuración → Certificados → CRUD funcional
☐ Configuración → CAF → CRUD funcional
```

### 6.4 Checklist Etapa 6

```
☐ Estructura tests/ creada
☐ 15+ tests unitarios escritos
☐ 5+ tests integración (mock) escritos
☐ Todos tests passing
☐ Tests UI manuales completados (9/9)
☐ Coverage > 70% en modelos core
☐ Documentación tests actualizada
```

---

## 📅 ETAPA 7: INTEGRACIÓN MICROSERVICIOS (Semana 4)

**Objetivo:** Conectar con DTE Service y AI Service reales
**Duración:** 4-6 horas
**Prioridad:** ALTA
**Prerequisitos:** Etapas 1-6 completadas, microservicios corriendo

### 7.1 Iniciar DTE Service (1 hora)

```bash
# 1. Verificar configuración
cat docker-compose.yml | grep -A 10 "dte-service"

# 2. Iniciar servicio
docker-compose up -d dte-service

# 3. Verificar health
curl http://localhost:8001/health
# Esperado: {"status": "healthy", "service": "dte-service"}

# 4. Verificar logs
docker-compose logs -f dte-service
```

### 7.2 Configurar en Odoo (30 min)

```python
# Settings → Configuración DTE

DTE Service URL: http://dte-service:8001
DTE API Key: [tu_api_key_aqui]

# Test conexión
Botón: "Probar Conexión"
Esperado: "✅ Conexión exitosa"
```

### 7.3 Test End-to-End (2 horas)

```
1. Crear factura de prueba
2. Llenar todos los datos (partner con RUT, líneas)
3. Click "Enviar DTE"
4. Verificar:
   ✅ DTE Service recibe request
   ✅ XML se genera
   ✅ XML se firma
   ✅ Factura actualiza a estado 'sent'
   ✅ dte_xml guardado en DB
   ✅ Comunicación SII registrada
   ✅ PDF imprime con QR code
```

### 7.4 Iniciar AI Service (Opcional - 1 hora)

**Solo si se activó ai_chat_wizard:**
```bash
# 1. Verificar ANTHROPIC_API_KEY en .env
grep ANTHROPIC_API_KEY .env

# 2. Iniciar servicio
docker-compose up -d ai-service

# 3. Verificar health
curl http://localhost:8002/health

# 4. Configurar en Odoo
# Settings → Configuración DTE → AI Service
AI Service URL: http://ai-service:8002
AI API Key: [tu_api_key_aqui]
Usar validación IA: ✓

# 5. Test
# Abrir wizard AI Chat desde factura
# Hacer pregunta: "¿Este DTE cumple con normativa SII?"
# Verificar respuesta coherente
```

### 7.5 Checklist Etapa 7

```
☐ DTE Service corriendo (health OK)
☐ DTE Service configurado en Odoo
☐ Test conexión DTE Service exitoso
☐ Test end-to-end DTE generación exitoso (7/7)
☐ AI Service corriendo (si aplica)
☐ AI Service configurado en Odoo (si aplica)
☐ Test AI Chat wizard (si aplica)
```

---

## 📅 ETAPA 8: CERTIFICACIÓN SII (Semana 4+)

**Objetivo:** Certificar en ambiente Maullin (sandbox SII)
**Duración:** Variable (depende SII)
**Prioridad:** CRÍTICA para producción
**Prerequisitos:** Etapas 1-7 completadas

### 8.1 Obtener Certificado Digital (Externo - 3-5 días)

```
1. Solicitar certificado digital SII (Clase 2 o 3)
   - Proveedores: E-Certchile, E-Sign, Accept
   - Formato: PKCS#12 (.p12 o .pfx)
   - Costo: ~$30,000 CLP/año

2. Recibir certificado por email
   - Archivo: certificado.p12
   - Contraseña: [proporcionada por proveedor]

3. Subir a Odoo:
   - Configuración → Certificados Digitales
   - Crear nuevo
   - Subir archivo .p12
   - Ingresar contraseña
   - Verificar estado: "Válido"
```

### 8.2 Solicitar CAF de Prueba (Externo - 1-2 días)

```
1. Ingresar a portal SII: maullin.sii.cl
2. Ir a: Folios → Solicitar Folios
3. Solicitar:
   - Tipo 33 (Factura): 10 folios
   - Tipo 61 (Nota Crédito): 5 folios
   - Tipo 56 (Nota Débito): 5 folios
   - Tipo 52 (Guía Despacho): 5 folios

4. Descargar archivos .xml de cada CAF

5. Subir a Odoo:
   - Configuración → CAF (Folios)
   - Crear nuevo por cada tipo
   - Subir archivo .xml
   - Verificar rangos de folios
```

### 8.3 Certificar DTEs (2-3 horas)

```bash
# 1. Configurar ambiente SII en Odoo
# Settings → Configuración DTE
Ambiente SII: Maullin (Certificación) ✓

# 2. Generar 7 DTEs de certificación (requisito SII)
# - 3x Factura (tipo 33)
# - 2x Nota Crédito (tipo 61)
# - 1x Nota Débito (tipo 56)
# - 1x Guía Despacho (tipo 52)

# 3. Enviar cada DTE a Maullin

# 4. Verificar estado en portal SII
# - Ingresar a maullin.sii.cl
# - Consultar DTEs enviados
# - Verificar estado: "Aceptado"

# 5. Solicitar certificación a SII
# - Formulario en línea
# - Adjuntar PDFs de 7 DTEs
# - Esperar aprobación (1-2 días)

# 6. Recibir aprobación SII
# - Email de confirmación
# - RUT autorizado para emisión en producción
```

### 8.4 Checklist Etapa 8

```
☐ Certificado digital obtenido
☐ Certificado subido a Odoo (estado válido)
☐ 4 CAF de prueba solicitados a SII
☐ 4 CAF subidos a Odoo
☐ Ambiente Maullin configurado
☐ 7 DTEs certificación generados
☐ 7 DTEs enviados a Maullin exitosamente
☐ 7 DTEs verificados en portal SII (aceptados)
☐ Solicitud certificación enviada a SII
☐ Aprobación SII recibida
```

---

## 📅 ETAPA 9: DEPLOY PRODUCCIÓN (Post-certificación)

**Objetivo:** Pasar de Maullin a Palena (producción real)
**Duración:** 2-3 horas
**Prioridad:** CRÍTICA
**Prerequisitos:** Certificación SII aprobada

### 9.1 Solicitar Folios Producción (1 hora)

```
1. Ingresar a portal SII: palena.sii.cl
2. Solicitar folios producción:
   - Tipo 33: 1000 folios
   - Tipo 61: 100 folios
   - Tipo 56: 100 folios
   - Tipo 52: 500 folios (si aplica)

3. Descargar CAF producción

4. Subir a Odoo:
   - Configuración → CAF
   - Crear nuevo (marcar "Producción")
   - Subir archivos
```

### 9.2 Configurar Producción (30 min)

```python
# Settings → Configuración DTE

Ambiente SII: Palena (Producción) ✓
Certificado: [seleccionar certificado válido]

# ⚠️ IMPORTANTE: Backup obligatorio
./scripts/backup_odoo.sh

# Verificar configuración
Test conexión → "✅ Conectado a Palena (Producción)"
```

### 9.3 Smoke Tests Producción (1 hora)

```
☐ Generar factura real (monto bajo)
☐ Enviar a SII Palena
☐ Verificar en portal SII: "Aceptado"
☐ Imprimir PDF con QR válido
☐ Enviar PDF a cliente de prueba
☐ Verificar cliente puede validar QR en app SII
```

### 9.4 Checklist Etapa 9

```
☐ Folios producción obtenidos (4 tipos)
☐ CAF producción subidos a Odoo
☐ Ambiente Palena configurado
☐ Backup PRE-producción creado
☐ Smoke test factura real exitoso (6/6)
☐ Documentación usuario final entregada
☐ Capacitación equipo realizada
```

---

## 📅 ETAPA 10: MONITOREO Y MANTENIMIENTO CONTINUO

**Objetivo:** Asegurar estabilidad permanente
**Duración:** Continua
**Prioridad:** ALTA

### 10.1 Monitoreo Automatizado

**Script de monitoreo (ejecutar cada hora):**
```bash
#!/bin/bash
# scripts/monitor_dte.sh

# 1. Verificar servicios UP
docker-compose ps | grep -E "Up|running" | wc -l
# Esperado: 5 (db, redis, odoo, dte-service, ai-service)

# 2. Verificar DTEs pendientes
PENDING=$(docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT COUNT(*) FROM account_move WHERE dte_status='draft' AND move_type='out_invoice';")

if [ "$PENDING" -gt 10 ]; then
    echo "⚠️ ALERTA: $PENDING facturas sin enviar a SII"
    # Enviar notificación Slack/email
fi

# 3. Verificar DTEs con error
ERRORS=$(docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT COUNT(*) FROM account_move WHERE dte_status='error';")

if [ "$ERRORS" -gt 0 ]; then
    echo "❌ ERROR: $ERRORS facturas con error DTE"
    # Enviar notificación urgente
fi

# 4. Verificar folios disponibles
for dte_type in 33 61 56 52; do
    AVAILABLE=$(docker-compose exec -T db psql -U odoo -d odoo -t \
      -c "SELECT COUNT(*) FROM dte_caf WHERE dte_type='$dte_type' AND state='available';")

    if [ "$AVAILABLE" -lt 10 ]; then
        echo "⚠️ ALERTA: Solo $AVAILABLE folios disponibles para tipo $dte_type"
    fi
done

# 5. Verificar certificado vigencia
CERT_DAYS=$(docker-compose exec -T db psql -U odoo -d odoo -t \
  -c "SELECT EXTRACT(DAY FROM (valid_until - NOW())) FROM dte_certificate WHERE is_active=true;")

if [ "$CERT_DAYS" -lt 30 ]; then
    echo "⚠️ ALERTA: Certificado expira en $CERT_DAYS días"
fi

echo "✅ Monitoreo completado"
```

**Agregar a cron:**
```bash
# Ejecutar cada hora
0 * * * * /Users/pedro/Documents/odoo19/scripts/monitor_dte.sh >> /Users/pedro/Documents/odoo19/logs/monitor.log 2>&1
```

### 10.2 Procedimiento Actualización Segura

**Para futuras actualizaciones del módulo:**
```bash
#!/bin/bash
# scripts/safe_update.sh

MODULE_NAME="l10n_cl_dte"

echo "=== ACTUALIZACIÓN SEGURA: $MODULE_NAME ==="

# 1. Backup completo
echo "[1/7] Creando backup..."
./scripts/backup_odoo.sh

# 2. Verificar staging
echo "[2/7] Actualizando en staging..."
docker-compose exec odoo odoo -c /etc/odoo/odoo_staging.conf \
  -d odoo_staging -u "$MODULE_NAME" --stop-after-init --log-level=info \
  2>&1 | tee /tmp/staging_update.log

# 3. Verificar errores staging
if grep -qi "error\|traceback\|failed" /tmp/staging_update.log; then
    echo "❌ ERROR en staging - Abortando actualización"
    exit 1
fi

# 4. Tests staging
echo "[3/7] Ejecutando tests en staging..."
./scripts/validate_installation.sh

# 5. Confirmación manual
echo "[4/7] Verificar manualmente staging: http://localhost:8170"
read -p "¿Staging OK? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "❌ Actualización cancelada por usuario"
    exit 1
fi

# 6. Aplicar a producción
echo "[5/7] Aplicando a producción..."
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf \
  -d odoo -u "$MODULE_NAME" --stop-after-init --log-level=info \
  2>&1 | tee /tmp/production_update.log

# 7. Verificar producción
echo "[6/7] Verificando producción..."
./scripts/validate_installation.sh

echo "[7/7] ✅ Actualización completada"
```

### 10.3 Dashboard Métricas

**Crear vista dashboard en Odoo:**
```python
# models/dte_dashboard.py (nuevo archivo)

class DTEDashboard(models.Model):
    _name = 'dte.dashboard'
    _description = 'Dashboard Métricas DTE'

    @api.model
    def get_dashboard_data(self):
        """Obtener métricas para dashboard"""

        # DTEs por estado (último mes)
        dtes_by_status = self.env['account.move'].read_group(
            [('create_date', '>=', fields.Date.today() - relativedelta(months=1)),
             ('move_type', '=', 'out_invoice')],
            ['dte_status'],
            ['dte_status']
        )

        # Folios disponibles
        folios_available = self.env['dte.caf'].read_group(
            [('state', '=', 'available')],
            ['dte_type'],
            ['dte_type']
        )

        # Certificado vigencia
        certificate = self.env['dte.certificate'].search([
            ('is_active', '=', True)
        ], limit=1)

        return {
            'dtes_by_status': dtes_by_status,
            'folios_available': folios_available,
            'certificate_days_remaining': (certificate.valid_until - fields.Date.today()).days if certificate else 0,
            'dtes_last_7_days': self.env['account.move'].search_count([
                ('create_date', '>=', fields.Date.today() - relativedelta(days=7)),
                ('dte_status', '=', 'sent')
            ]),
        }
```

### 10.4 Checklist Mantenimiento Continuo

```
☐ Script monitor_dte.sh configurado (cron cada hora)
☐ Script safe_update.sh creado y probado
☐ Dashboard métricas DTE implementado
☐ Alertas Slack/email configuradas
☐ Documentación procedimientos actualizada
☐ Plan contingencia definido (qué hacer si SII cae)
☐ Contacto soporte SII registrado
☐ Backup automático diario funcionando (verificar cada semana)
```

---

## 📚 RESUMEN EJECUTIVO DEL PLAN

### Duración Total Estimada
**18-32 horas distribuidas en 4 semanas**

| Etapa | Duración | Prioridad | Semana |
|-------|----------|-----------|--------|
| 1. Preparación | 6-8h | CRÍTICA | 1 |
| 2. Wizards | 6-10h | ALTA | 1-2 |
| 3. Reportes | 4-6h | MEDIA | 2 |
| 4. Métodos Action | 8-12h | ALTA | 2-3 |
| 5. Deprecations | 2-3h | MEDIA | 3 |
| 6. Testing | 6-8h | ALTA | 3-4 |
| 7. Microservicios | 4-6h | ALTA | 4 |
| 8. Certificación SII | Variable | CRÍTICA | 4+ |
| 9. Producción | 2-3h | CRÍTICA | Post-cert |
| 10. Monitoreo | Continua | ALTA | Siempre |

### Progreso Actual vs Meta

```
FASE 1 (Instalación Básica): ██████████ 100% ✅
ETAPA 1 (Preparación):        ░░░░░░░░░░   0% ⏳
ETAPA 2 (Wizards):             ░░░░░░░░░░   0% ⏳
ETAPA 3 (Reportes):            ░░░░░░░░░░   0% ⏳
ETAPA 4 (Métodos):             ░░░░░░░░░░   0% ⏳
ETAPA 5 (Deprecations):        ░░░░░░░░░░   0% ⏳
ETAPA 6 (Testing):             ░░░░░░░░░░   0% ⏳
ETAPA 7 (Microservicios):      ░░░░░░░░░░   0% ⏳
ETAPA 8 (Certificación SII):   ░░░░░░░░░░   0% ⏳
ETAPA 9 (Producción):          ░░░░░░░░░░   0% ⏳
────────────────────────────────────────────
PROGRESO TOTAL:                ██░░░░░░░░  20%
```

### Componentes Pendientes de Activación

| Componente | Tipo | Estado Actual | Etapa Activación |
|------------|------|---------------|------------------|
| dte_generate_wizard | Wizard | ⚠️ Desactivado | Etapa 2 |
| ai_chat_wizard | Wizard | ⚠️ Desactivado | Etapa 2 (opcional) |
| dte_invoice_report | Reporte | ⚠️ Desactivado | Etapa 3 |
| dte_receipt_report | Reporte | ⚠️ Desactivado | Etapa 3 |
| action_send_dte | Método | 🟡 Stub | Etapa 4 |
| action_retry | Método | 🟡 Stub | Etapa 4 |
| +19 métodos action | Métodos | 🟡 Stub | Etapa 4 |
| @route type='json' | Deprecation | ⚠️ Warning | Etapa 5 |
| _sql_constraints | Deprecation | ⚠️ Warning | Etapa 5 |

### Dependencias Críticas Externas

| Dependencia | Proveedor | Estado | Tiempo Obtención |
|-------------|-----------|--------|------------------|
| Certificado Digital SII | E-Certchile, E-Sign, Accept | ⏳ Pendiente | 3-5 días |
| CAF Prueba (Maullin) | SII | ⏳ Pendiente | 1-2 días |
| Certificación SII | SII | ⏳ Pendiente | 1-2 días |
| CAF Producción (Palena) | SII | ⏳ Pendiente | Inmediato |

### Criterios de Éxito Final

```
✅ 100% componentes activados (wizards, reportes)
✅ 21 métodos action implementados (6 completos, 15 stubs)
✅ 0 warnings o deprecations
✅ Tests automatizados > 70% coverage
✅ Certificación SII aprobada
✅ 7 DTEs certificación exitosos en Maullin
✅ Producción funcionando en Palena
✅ Monitoreo automatizado activo
✅ Backups diarios funcionando
✅ Documentación usuario final completa
```

---

## 📞 PRÓXIMOS PASOS INMEDIATOS

### Para Iniciar ETAPA 1 (Esta Semana)

```bash
# 1. Crear base de datos staging
docker-compose exec db createdb -U odoo odoo_staging

# 2. Clonar producción a staging
docker-compose exec db pg_dump -U odoo odoo | \
  docker-compose exec -T db psql -U odoo odoo_staging

# 3. Crear scripts directorio
mkdir -p scripts logs backups

# 4. Crear script backup
cat > scripts/backup_odoo.sh << 'EOF'
[contenido del script de backup de sección 1.2]
EOF
chmod +x scripts/backup_odoo.sh

# 5. Ejecutar primer backup
./scripts/backup_odoo.sh

# 6. Crear script validación
cat > scripts/validate_installation.sh << 'EOF'
[contenido del script de validación de sección 1.4]
EOF
chmod +x scripts/validate_installation.sh

# 7. Ejecutar baseline
./scripts/validate_installation.sh > docs/baseline_etapa1.txt

# 8. Revisar baseline
cat docs/baseline_etapa1.txt
```

**Tiempo estimado:** 2 horas
**Resultado esperado:** Ambiente seguro listo para modificaciones

---

**FIN DEL PLAN ESTRATÉGICO** 📋

**Documento:** PLAN_ESTRATEGICO_ACTUALIZACION_PERMANENTE.md
**Versión:** 1.0
**Fecha:** 2025-10-22
**Autor:** Claude (Anthropic)
**Proyecto:** l10n_cl_dte - Facturación Electrónica Chile
**Cliente:** Eergygroup
