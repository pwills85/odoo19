# 🚀 PLAN DE EJECUCIÓN: OPCIÓN B - PARIDAD ODOO 11

**Fecha Inicio:** 2025-10-23 11:15 UTC
**Timeline:** 6 semanas (30 días hábiles)
**Inversión:** $7,500 USD
**Objetivo:** 78% → 98% (Paridad funcional Oracle + Certificación SII)

---

## ✅ PREPARACIÓN COMPLETADA (2025-10-23)

### Estado Stack Validado

```bash
✅ odoo19_app: Up 31 minutes (healthy)
✅ odoo19_db: Up 33 minutes (healthy)
✅ odoo19_redis: Up 33 minutes (healthy)
✅ odoo19_dte_service: Up 33 minutes (healthy)
✅ odoo19_ai_service: Up 33 minutes (healthy)
✅ odoo19_rabbitmq: Up 33 minutes (healthy)
```

### Módulo Actualizado

```bash
✅ Módulo l10n_cl_dte loaded in 0.53s, 932 queries
✅ Report action registrado (ID: 567)
✅ Archivos report/ creados:
   - __init__.py (138 bytes)
   - account_move_dte_report.py (9.3K)
   - report_invoice_dte_document.xml (16K)
```

### Backup Creado

```bash
✅ Backup: backups/backup_opcion_b_20251023.sql.gz (1.5MB)
✅ Comando restore si necesario:
   gunzip < backups/backup_opcion_b_20251023.sql.gz | \
   docker-compose exec -T db psql -U odoo odoo
```

---

## 📅 CRONOGRAMA DETALLADO (6 Semanas)

### 🔴 FASE 1: BRECHAS P0 (Semanas 1-3) - CRÍTICO

#### **SEMANA 1: P0-1 PDF Reports (COMPLETADO) + P0-2 Inicio**

**Días 1-2:** ✅ **COMPLETADO 2025-10-23**
- [x] PDF Reports con TED (PDF417/QR)
- [x] Python helper module (254 líneas)
- [x] QWeb template (280 líneas)
- [x] Report action registrado
- [x] Testing dependencias (qrcode, reportlab, Pillow)
- [x] Módulo actualizado en Odoo
- [x] Documentación generada (3 docs)

**Progreso:** 78% → 80% (+2%)

**Días 3-5:** ⏳ **P0-2 Recepción DTEs UI (50%)**

**Día 3: Modelo `dte.inbox` (Backend)**
```python
# addons/localization/l10n_cl_dte/models/dte_inbox.py
# Tareas:
- [ ] Crear archivo modelo (250 líneas)
- [ ] Campos core (dte_xml, partner_id, dte_type, folio, etc.)
- [ ] Estado workflow (received, validated, accepted, rejected, claimed)
- [ ] Inherit mail.thread + mail.activity.mixin
- [ ] Método action_validate_xml() - Llama ai-service parser
- [ ] Método action_accept() - Genera respuesta comercial
- [ ] Método action_reject() - Genera respuesta comercial
- [ ] Método action_claim() - Genera reclamo SII
- [ ] Método _cron_fetch_dte_emails() - IMAP integration
- [ ] Tests unitarios (10 tests)
```

**Día 4: Views + Security**
```xml
# addons/localization/l10n_cl_dte/views/dte_inbox_views.xml
# Tareas:
- [ ] View tree con decoration (success/danger)
- [ ] View form con header + statusbar
- [ ] View search con filters
- [ ] View kanban (opcional)
- [ ] Menú "Recepción DTEs" en menus.xml
- [ ] Access rights en ir.model.access.csv
```

**Día 5: Cron Job + Integration Testing**
```xml
# addons/localization/l10n_cl_dte/data/ir_cron_data.xml
# Tareas:
- [ ] Cron job fetch emails cada 15 min
- [ ] Integration test con ai-service IMAP client
- [ ] Test workflow Accept/Reject/Claim
- [ ] Test creación factura proveedor desde DTE
- [ ] Visual QA UI
- [ ] Documentación usuario
```

**Entregables Semana 1:**
- ✅ P0-1 PDF Reports (COMPLETADO)
- ⏳ P0-2 Recepción DTEs UI (70% esperado)

---

#### **SEMANA 2: P0-2 Completar + P0-3 Inicio**

**Días 6-7: P0-2 Completar (30% restante)**

**Día 6: Polish + Edge Cases**
```python
# Tareas:
- [ ] Handle XML malformado (try/except robusto)
- [ ] Validación RUT proveedor vs partner
- [ ] Monto DTE vs PO validation
- [ ] Duplicate detection (mismo folio)
- [ ] Error messages user-friendly
- [ ] Logging estructurado
```

**Día 7: Testing Final P0-2**
```bash
# Tareas:
- [ ] E2E test: Email → Inbox → Accept → Invoice
- [ ] E2E test: Email → Inbox → Reject → Notification
- [ ] Performance test (100 DTEs simultáneos)
- [ ] Manual QA checklist (20 items)
- [ ] Documentation: user guide + admin guide
```

**Días 8-10: P0-3 Libro Honorarios**

**Día 8: Generator DTE Service**
```python
# dte-service/generators/libro_honorarios_generator.py
# Tareas:
- [ ] Clase LibroHonorariosGenerator (300 líneas)
- [ ] Método generate(period, company, honorarios)
- [ ] _build_caratula() - Header info
- [ ] _build_resumen() - Totales período
- [ ] _build_detalle() - Lista DTEs 34
- [ ] Validación XSD LibroHonorarios_v10.xsd
- [ ] Sign XML con certificado
- [ ] Tests unitarios (8 tests)
```

**Día 9: Integración Odoo**
```python
# addons/localization/l10n_cl_dte/models/dte_libro.py
# Tareas:
- [ ] Extend selection book_type += 'honorarios'
- [ ] Método action_generate_libro_honorarios()
- [ ] Filtrar DTEs tipo 34 del período
- [ ] API call a dte-service
- [ ] Handle response y storage XML
- [ ] Tests integration (5 tests)
```

**Día 10: Testing + Deploy Staging**
```bash
# Tareas:
- [ ] Test generación libro con datos Odoo 11 real
- [ ] Validar estructura XML vs spec SII
- [ ] Test envío Maullin (sandbox)
- [ ] Verificar respuesta SII
- [ ] Documentation: admin guide
```

**Entregables Semana 2:**
- ✅ P0-2 Recepción DTEs UI (100%)
- ✅ P0-3 Libro Honorarios (100%)

**Progreso:** 80% → 85% (+5%)

---

#### **SEMANA 3: Buffer + Refinement P0**

**Días 11-12: Bug Fixes + Polish**
```bash
# Tareas:
- [ ] Revisar todos los logs (errors, warnings)
- [ ] Fix bugs P0-2 y P0-3
- [ ] Refactoring código duplicado
- [ ] Improve error messages
- [ ] Add logging faltante
- [ ] Update documentation
```

**Días 13-15: Testing Integration Stack Completo**
```bash
# Tareas:
- [ ] E2E test: Crear factura → Generar DTE → Imprimir PDF
- [ ] E2E test: Recibir DTE → Aceptar → Crear factura
- [ ] E2E test: Generar libro honorarios → Enviar SII
- [ ] Performance testing (500 DTEs/hora target)
- [ ] Stress testing (10 usuarios concurrentes)
- [ ] Security audit (OAuth2 + RBAC)
- [ ] Documentation: deployment guide
```

**Entregables Semana 3:**
- ✅ 3 Brechas P0 cerradas (100%)
- ✅ 35+ tests nuevos pasando
- ✅ Stack estable y probado
- ✅ Documentation completa

**Progreso:** 85% → 85% (consolidación)

---

### 🟡 FASE 2: BRECHAS P1 (Semanas 4-6) - IMPORTANTE

#### **SEMANA 4: P1-1 Referencias + P1-2 Desc/Rec Globales**

**Días 16-17: P1-1 Referencias DTE**

```python
# addons/localization/l10n_cl_dte/models/account_move_referencias.py
# Tareas:
- [ ] Model One2many con account.move
- [ ] Campos: reference_doc_type, reference_folio, reference_date, reference_reason
- [ ] View form en account_move (notebook page)
- [ ] Integración con generators NC/ND (33, 56, 61)
- [ ] XML: tag <Referencia> según spec SII
- [ ] Tests (5 tests)
```

**Días 18-19: P1-2 Descuentos/Recargos Globales**

```python
# addons/localization/l10n_cl_dte/models/account_move_gdr.py
# Tareas:
- [ ] Model One2many con account.move
- [ ] Campos: type (D/R), value_type (%/$), value, reason
- [ ] Compute fields para totales
- [ ] View form en account_move (notebook page)
- [ ] Integración con generators (todos los DTEs)
- [ ] XML: tag <DscRcgGlobal> según spec SII
- [ ] Tests (5 tests)
```

**Día 20: Testing + Documentation**

```bash
# Tareas:
- [ ] E2E: NC con referencias a factura original
- [ ] E2E: Factura con descuento global 10%
- [ ] E2E: Factura con recargo flete $5,000
- [ ] Documentation: user guide referencias/gdr
```

**Entregables Semana 4:**
- ✅ P1-1 Referencias DTE (100%)
- ✅ P1-2 Desc/Rec Globales (100%)

**Progreso:** 85% → 88% (+3%)

---

#### **SEMANA 5: P1-3 Wizards Avanzados**

**Días 21-22: Wizard Envío Masivo**

```python
# addons/localization/l10n_cl_dte/wizards/masive_send_wizard.py
# Tareas:
- [ ] TransientModel con Many2many invoices
- [ ] Progress bar (Float field 0-100%)
- [ ] Async processing via RabbitMQ
- [ ] Redis tracking status
- [ ] View wizard con progress indicator
- [ ] Action en vista tree facturas (multi-select)
- [ ] Tests (8 tests)
```

**Días 23-24: Wizard Upload XML + Validación**

```python
# addons/localization/l10n_cl_dte/wizards/upload_xml_wizard.py
# Tareas:
- [ ] Upload campo Binary
- [ ] Parse XML (ai-service)
- [ ] Validación XSD
- [ ] Preview datos extraídos
- [ ] Crear dte.inbox record
- [ ] Tests (5 tests)

# addons/localization/l10n_cl_dte/wizards/validate_wizard.py
# Tareas:
- [ ] Pre-validación antes envío SII
- [ ] Checks: RUT, montos, fechas, folios
- [ ] AI validation (Claude)
- [ ] Show warnings/errors
- [ ] Allow force send
- [ ] Tests (5 tests)
```

**Día 25: Integration Testing Wizards**

```bash
# Tareas:
- [ ] E2E: Envío masivo 50 facturas
- [ ] E2E: Upload XML proveedor
- [ ] E2E: Validación pre-envío con warnings
- [ ] Performance: 100 facturas batch
- [ ] Documentation: wizards user guide
```

**Entregables Semana 5:**
- ✅ P1-3 Wizards Avanzados (100%)
- ✅ 18+ tests nuevos

**Progreso:** 88% → 91% (+3%)

---

#### **SEMANA 6: P1-4 Boletas + P1-5 Libro Boletas**

**Días 26-27: P1-4 Boletas Electrónicas (39, 41)**

```python
# dte-service/generators/dte_generator_39.py (Boleta)
# dte-service/generators/dte_generator_41.py (Boleta Exenta)
# Tareas:
- [ ] Clase DTEGenerator39 (similar a 33)
- [ ] Clase DTEGenerator41 (similar a 34)
- [ ] Reglas específicas boletas (sin RUT receptor retail)
- [ ] Montos menores (< 1 UF típicamente)
- [ ] XSD validation BolDTE_v11.xsd
- [ ] Tests generators (10 tests)
```

**Integración Odoo:**
```python
# addons/localization/l10n_cl_dte/models/pos_order_dte.py
# Tareas:
- [ ] Extend pos.order (opcional, si usan POS)
- [ ] O extend account.move con flag is_boleta
- [ ] Selection dte_type += ('39', '41')
- [ ] Wizard generación boleta desde POS
- [ ] Tests (5 tests)
```

**Días 28-29: P1-5 Libro Boletas**

```python
# dte-service/generators/libro_boletas_generator.py
# Tareas:
- [ ] Clase LibroBoletasGenerator (250 líneas)
- [ ] Similar estructura libro_generator.py
- [ ] Filtrar DTEs 39/41 del período
- [ ] Resumen: cantidad boletas, montos
- [ ] XSD validation LibroGuia_v10.xsd (similar)
- [ ] Tests (8 tests)
```

**Integración Odoo:**
```python
# addons/localization/l10n_cl_dte/models/dte_libro.py
# Tareas:
- [ ] Extend selection book_type += 'boletas'
- [ ] Método action_generate_libro_boletas()
- [ ] Tests integration (5 tests)
```

**Día 30: Testing Final FASE 2 + Deploy Staging**

```bash
# Tareas:
- [ ] E2E: Boleta retail → Imprimir
- [ ] E2E: Libro boletas mensual → Enviar SII
- [ ] Regression testing (todos los P0+P1)
- [ ] Performance testing stack completo
- [ ] Security audit final
- [ ] Documentation: deployment checklist
- [ ] Deploy staging environment
- [ ] Smoke tests staging
```

**Entregables Semana 6:**
- ✅ P1-4 Boletas 39/41 (100%)
- ✅ P1-5 Libro Boletas (100%)
- ✅ 5 Brechas P1 cerradas
- ✅ Deploy staging validado

**Progreso:** 91% → 98% (+7%)

---

## 🟢 FASE 3: CERTIFICACIÓN SII (Semana 7) - OPCIONAL

**Esta fase es OPCIONAL pero ALTAMENTE RECOMENDADA**

### Objetivo: Certificar sistema en Maullin (sandbox SII)

**Días 31-32: Obtener Credenciales**
```bash
# Tareas:
- [ ] Solicitar certificado digital SII (Clase 2 o 3)
- [ ] Obtener CAF prueba (5 tipos: 33, 34, 52, 56, 61)
- [ ] Configurar certificado en Odoo (modelo dte.certificate)
- [ ] Importar CAF files (modelo dte.caf)
- [ ] Verificar conexión Maullin
```

**Días 33-34: Testing Maullin**
```bash
# Tareas:
- [ ] Enviar DTE 33 (Factura) → Verificar aceptado
- [ ] Enviar DTE 34 (Honorarios) → Verificar aceptado
- [ ] Enviar DTE 52 (Guía) → Verificar aceptado
- [ ] Enviar DTE 56 (ND) → Verificar aceptado
- [ ] Enviar DTE 61 (NC) → Verificar aceptado
- [ ] Validar folios consumidos
- [ ] Corregir errores SII
```

**Día 35: Documentación + Checklist**
```bash
# Tareas:
- [ ] Checklist certificación SII (30 items)
- [ ] Screenshots proceso certificación
- [ ] Documentar errores encontrados + soluciones
- [ ] Guide: migración sandbox → producción
```

**Entregables FASE 3:**
- ✅ Certificado SII configurado
- ✅ 5 CAF prueba importados
- ✅ 5 DTEs certificados en Maullin
- ✅ Checklist certificación completo
- ✅ Sistema production-ready

---

## 📊 MÉTRICAS DE ÉXITO POR FASE

### FASE 1 (P0 - Semanas 1-3)
```
✅ 3 brechas P0 cerradas
✅ 35+ tests nuevos pasando
✅ 0 regresiones tests existentes
✅ Coverage mantiene 80%+
✅ Progreso: 78% → 85%
```

### FASE 2 (P1 - Semanas 4-6)
```
✅ 5 brechas P1 cerradas
✅ 35+ tests nuevos pasando
✅ Wizards UX validados
✅ Deploy staging OK
✅ Progreso: 85% → 98%
```

### FASE 3 (Certificación - Semana 7)
```
✅ 5 DTEs certificados Maullin
✅ 0 errores SII
✅ Folios OK
✅ Production-ready
✅ Progreso: 98% → 100%
```

---

## 🔧 COMANDOS ÚTILES DESARROLLO

### Actualizar Módulo (Después de cambios)
```bash
# Opción 1: Update rápido (si Odoo corriendo)
docker-compose restart odoo

# Opción 2: Update completo (si cambios modelos)
docker-compose stop odoo
docker-compose run --rm odoo odoo -c /etc/odoo/odoo.conf -d odoo -u l10n_cl_dte --stop-after-init
docker-compose up -d odoo
```

### Ver Logs en Tiempo Real
```bash
# Odoo logs
docker-compose logs -f odoo | grep -E "(error|ERROR|warning|WARNING)"

# DTE Service logs
docker-compose logs -f dte-service | grep -E "(error|ERROR)"

# AI Service logs
docker-compose logs -f ai-service | grep -E "(error|ERROR)"
```

### Ejecutar Tests
```bash
# Tests Odoo module
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-enable --test-tags /l10n_cl_dte --stop-after-init

# Tests DTE Service
cd dte-service && pytest --cov=. --cov-report=term

# Tests AI Service
cd ai-service && pytest tests/ -v
```

### Backup/Restore Database
```bash
# Backup
docker-compose exec -T db pg_dump -U odoo odoo | \
  gzip > backups/backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Restore
gunzip < backups/backup_YYYYMMDD_HHMMSS.sql.gz | \
  docker-compose exec -T db psql -U odoo odoo
```

### Verificar Estado Stack
```bash
# Health check todos los servicios
docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Health}}"

# Verificar conectividad microservicios
docker-compose exec odoo curl http://dte-service:8001/health
docker-compose exec odoo curl http://ai-service:8002/health
```

---

## 📋 CHECKLIST PRE-INICIO CADA SEMANA

**Lunes (inicio semana):**
- [ ] Crear branch `feature/week-N-pX-Y` desde main
- [ ] Backup DB del domingo
- [ ] Verificar stack healthy (6/6 servicios)
- [ ] Run tests existentes (baseline)
- [ ] Revisar plan semana

**Viernes (fin semana):**
- [ ] Run tests completos (nuevo + existentes)
- [ ] Verificar coverage >= 80%
- [ ] Code review cambios semana
- [ ] Merge branch a main (si todo OK)
- [ ] Tag release `v0.X.0`
- [ ] Deploy staging (validar)
- [ ] Actualizar documentación
- [ ] Preparar retrospectiva

---

## 🎯 CRITERIOS DE ACEPTACIÓN

### Brecha P0-1: PDF Reports ✅
- [x] PDF se genera sin errores
- [x] TED barcode visible (PDF417 o QR)
- [x] Layout SII-compliant
- [x] Logo empresa configurable
- [x] Totales correctos
- [x] Multi-idioma (es_CL)
- [x] Tests unitarios (5+)

### Brecha P0-2: Recepción DTEs UI ⏳
- [ ] Modelo dte.inbox creado
- [ ] Views tree/form/search funcionales
- [ ] Workflow Accept/Reject/Claim OK
- [ ] Cron job fetch emails cada 15 min
- [ ] Integration ai-service IMAP OK
- [ ] Tests unitarios (10+)
- [ ] Documentation user guide

### Brecha P0-3: Libro Honorarios ⏳
- [ ] Generator libro_honorarios_generator.py creado
- [ ] Extend modelo dte.libro (book_type += honorarios)
- [ ] XSD validation LibroHonorarios_v10.xsd
- [ ] Envío SII Maullin exitoso
- [ ] Tests unitarios (8+)
- [ ] Documentation admin guide

### Brecha P1-1 a P1-5 ⏳
- [ ] (Similar criterios cada brecha)
- [ ] Total 18+ tests nuevos P1
- [ ] Deploy staging validado

---

## 📞 CONTACTO Y ESCALAMIENTO

**Para aprobar avances:**
- **Semanalmente:** Demo viernes (30 min)
- **Issues bloqueantes:** Slack inmediato
- **Cambios scope:** Reunión 1:1

**Métricas reportadas:**
- Tests passing/failing
- Coverage %
- Progreso % (actualizado cada viernes)
- Bugs abiertos/cerrados
- Velocity (story points/semana)

---

## ✅ CONCLUSIÓN

### Estado Actual (2025-10-23 11:15 UTC)

**Completado Hoy:**
- ✅ Stack validado (6/6 servicios healthy)
- ✅ Backup creado (1.5MB)
- ✅ Módulo actualizado (932 queries)
- ✅ P0-1 PDF Reports (100%)

**Próximo Paso Inmediato:**
⏳ **Implementar P0-2 Recepción DTEs UI (Días 3-5, Semana 1)**

**Timeline Total:**
- **Semanas 1-3:** FASE 1 (P0) - 78% → 85%
- **Semanas 4-6:** FASE 2 (P1) - 85% → 98%
- **Semana 7:** FASE 3 (Certificación SII) - 98% → 100% [OPCIONAL]

**Inversión:** $7,500 USD
**ROI:** $385K ahorro vs SAP (3 años)
**Break-even:** 2 meses

---

**Documento:** `PLAN_EJECUCION_OPCION_B.md`
**Versión:** 1.0
**Fecha:** 2025-10-23
**Status:** ✅ **LISTO PARA EJECUTAR**
**Próximo:** Implementar P0-2 Recepción DTEs UI (Día 3)

---

**¿Listo para comenzar Semana 1, Día 3: P0-2 Recepción DTEs UI?** 🚀

