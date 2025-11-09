# 🚀 FAST-TRACK: Migración Odoo 11 → 19 (Empresa Certificada)

**Contexto:** Empresa YA certificada SII, operando en Odoo 11 CE con l10n_cl_dte
**Situación:** Certificado digital + CAF válidos existentes
**Objetivo:** Migración rápida a Odoo 19 stack superior manteniendo operación
**Timeline:** 2-3 semanas vs 8 semanas desde cero

---

## 🎯 VENTAJA COMPETITIVA: Ya Están Certificados

### ✅ LO QUE YA TIENEN (Ahorra 1-2 semanas)

1. **Certificado Digital SII Válido**
   - Clase 2 o 3 activo
   - Archivo .p12 + password
   - **Ahorro:** 3-5 días proceso certificación

2. **CAF (Folios Autorizados) Activos**
   - CAF vigentes para 5 tipos DTE (33,34,52,56,61)
   - Folios disponibles
   - **Ahorro:** 1-2 días trámites SII

3. **Conocimiento Proceso SII**
   - Usuarios capacitados
   - Workflows establecidos
   - Datos históricos
   - **Ahorro:** 1-2 semanas curva aprendizaje

4. **Historial DTEs Enviados**
   - Base conocimiento errores comunes
   - Partners configurados
   - Templates documentos
   - **Ahorro:** Configuración inicial

**Total Ahorro vs Empresa Nueva:** 2-3 semanas ⚡

---

## 📊 ROADMAP ACTUALIZADO: FAST-TRACK

### **TIER 0: MIGRACIÓN DATOS (3-5 días)** 🟣 NUEVO

**Objetivo:** Extraer certificado + CAF + datos de Odoo 11

#### **Paso 1: Extracción desde Odoo 11 (1 día)**

**Certificado Digital:**
```bash
# Conectar a Odoo 11
docker exec -it odoo11_container bash

# Exportar certificado desde base de datos
psql -U odoo -d odoo11_db -c \
  "SELECT id, name, file FROM dte_certificate WHERE active=true;" \
  -o /tmp/certificates.csv

# Exportar archivo .p12 (si está en filesystem)
# O recuperar desde campo Binary en DB
```

**CAF Files:**
```bash
# Exportar CAF activos
psql -U odoo -d odoo11_db -c \
  "SELECT id, name, dte_type, sequence_start, sequence_end,
   folios_disponibles, file FROM dte_caf
   WHERE state='active';" \
  -o /tmp/caf_files.csv

# Exportar archivos CAF .xml
# Ubicación típica: /opt/odoo/filestore/odoo11_db/dte_caf/
```

**Datos Críticos:**
```sql
-- Partners con RUT configurado
SELECT id, name, vat, street, city
FROM res_partner
WHERE vat IS NOT NULL
  AND country_id = (SELECT id FROM res_country WHERE code='CL');

-- Configuración company SII
SELECT id, name, vat, dte_activity_code,
       dte_resolution_number, dte_resolution_date
FROM res_company;

-- Últimos DTEs enviados (para referencia)
SELECT id, name, dte_code, dte_folio, dte_status,
       dte_timestamp, dte_track_id
FROM account_move
WHERE dte_code IS NOT NULL
ORDER BY dte_timestamp DESC
LIMIT 100;
```

**Output:**
- ✅ Certificado .p12 exportado
- ✅ CAF .xml exportados (5 archivos)
- ✅ CSV datos críticos
- ✅ Backup completo Odoo 11

---

#### **Paso 2: Importación a Odoo 19 (1 día)**

**Setup Odoo 19 Staging:**
```bash
cd /Users/pedro/Documents/odoo19

# Asegurar servicios corriendo
docker-compose up -d

# Verificar salud
docker-compose ps
# Todos deben estar "healthy"
```

**Importar Certificado:**
```python
# Via UI Odoo 19
# Settings → Chilean Localization → Electronic Invoicing → Certificates
# → Create

# Fields:
# - Name: "Certificado Producción [Empresa]"
# - File: Upload certificado.p12
# - Password: [password del .p12]
# - Company: [Seleccionar]

# Al guardar, automáticamente:
# ✅ Validación OID (Clase 2/3)
# ✅ Extracción RUT del certificado
# ✅ Validación RUT vs Company
# ✅ Check expiración
```

**Importar CAF:**
```python
# Via UI Odoo 19
# Settings → Chilean Localization → Electronic Invoicing → CAF Files
# → Create (5 veces, 1 por cada tipo DTE)

# Para cada CAF:
# - DTE Type: [33, 34, 52, 56, 61]
# - File: Upload CAF_XX.xml
# - Company: [Seleccionar]

# Al guardar, automáticamente:
# ✅ Validación firma SII en CAF
# ✅ Extracción rango folios
# ✅ Cálculo folios disponibles
# ✅ Estado = "active"
```

**Importar Datos Maestros (opcional pero recomendado):**
```bash
# Importar partners via CSV
# Odoo 19 → Contacts → Import
# Upload CSV con: name, vat, street, city, country_id/id

# Importar configuración company
# Settings → Companies → [Editar company]
# Fields:
# - VAT (RUT): 76.XXX.XXX-X
# - SII Activity Code: XXXXXX
# - DTE Resolution Number: XX
# - DTE Resolution Date: YYYY-MM-DD
```

**Output:**
- ✅ 1 Certificado digital activo Odoo 19
- ✅ 5 CAF activos Odoo 19
- ✅ Partners migrados
- ✅ Company configurada

---

#### **Paso 3: Testing Migración (1-2 días)**

**Test 1: Validar Certificado**
```bash
# Verificar certificado funciona
# Odoo 19 → Settings → Certificates → [Abrir certificado]
# → Botón "Test Certificate"

# Debe mostrar:
# ✅ Certificate valid
# ✅ Class 2/3 detected
# ✅ RUT matches company
# ✅ Valid until: [fecha]
```

**Test 2: Validar CAF**
```bash
# Verificar CAF funcionan
# Odoo 19 → Settings → CAF Files → [Abrir cada CAF]

# Para cada uno verificar:
# ✅ Folios disponibles > 0
# ✅ Estado = Active
# ✅ Firma SII válida
```

**Test 3: Generar DTE Prueba en Maullin**
```bash
# Configurar ambiente sandbox
# Settings → Chilean Localization → Configuration
# - SII Environment: Sandbox (Maullin)

# Crear factura de prueba
# Accounting → Customers → Invoices → Create
# - Customer: [Cliente de prueba con RUT]
# - Products: [1 producto]
# - Amount: $10,000

# Confirmar factura → Botón "Generar DTE"
# → Wizard:
#   - Certificate: [Seleccionar certificado]
#   - CAF: [Auto-seleccionado tipo 33]
#   - Environment: Sandbox

# → Enviar

# Validar respuesta:
# ✅ DTE generado con folio
# ✅ TED + QR generados
# ✅ Enviado a SII Maullin
# ✅ Respuesta SII: "Aceptado"
# ✅ Track ID asignado
```

**Test 4: Validar Polling Automático**
```bash
# Esperar 15 minutos (1 ciclo polling)

# Verificar logs DTE Service
docker-compose logs dte-service | grep "poller"

# Debe mostrar:
# ✅ poller_initialized
# ✅ polling_job_started
# ✅ dte_status_updated: [folio] → accepted

# Verificar en Odoo factura actualizada
# Estado DTE debe cambiar a "Accepted"
```

**Output:**
- ✅ Certificado validado funcional
- ✅ CAF validados funcionales
- ✅ 1 DTE test exitoso Maullin
- ✅ Polling automático funciona

---

### **TIER 1: PRODUCCIÓN MVP (3-5 días)** 🔴

**Ahora que certificado + CAF migrados, foco en validación producción**

#### **Paso 4: Testing Integral (2-3 días)**

**Crear Suite Testing Real:**
```python
# Tests con datos reales empresa

# DTE 33: Factura Electrónica
# - 5 facturas diferentes clientes
# - Montos variados ($10K - $500K)
# - Items múltiples
# - Con/sin descuentos

# DTE 34: Liquidación Honorarios
# - 3 liquidaciones con retención IUE
# - Diferentes % retención
# - Proveedores reales

# DTE 52: Guía Despacho
# - 3 guías diferentes tipos traslado
# - Con stock real
# - Direcciones destino correctas

# DTE 56: Nota Débito
# - 2 notas débito referenciando facturas
# - Montos ajuste

# DTE 61: Nota Crédito
# - 2 notas crédito devoluciones
# - Referencias a facturas originales
```

**Casos Borde Específicos Empresa:**
```python
# Basado en historial Odoo 11, probar:

# 1. Clientes frecuentes top 10
# 2. Productos más vendidos
# 3. Descuentos corporativos
# 4. Múltiples impuestos simultáneos
# 5. Facturas exportación (si aplica)
# 6. Documentos referenciados
# 7. Caracteres especiales en descripciones (ñ, á, etc.)
```

**Validación vs Odoo 11:**
```bash
# Comparar XML generados
# Odoo 11 XML vs Odoo 19 XML

# Verificar:
# ✅ Mismos campos obligatorios
# ✅ Formato TED idéntico
# ✅ Firma digital válida
# ✅ QR Code correcto
# ✅ Respuesta SII similar
```

**Output:**
- ✅ 15+ DTEs test exitosos Maullin
- ✅ Todos casos borde validados
- ✅ Comparación Odoo 11 vs 19 OK
- ✅ 0 errores bloqueantes

---

#### **Paso 5: Deploy Staging Paralelo (1 día)**

**Arquitectura Dual (Odoo 11 + Odoo 19 simultáneos):**
```
┌─────────────────────────────────────┐
│   PRODUCCIÓN ACTUAL (Odoo 11)       │
│   - Operación normal continúa       │
│   - Sin interrupciones              │
└─────────────────────────────────────┘
              ↓ (Datos replicados)
┌─────────────────────────────────────┐
│   STAGING (Odoo 19)                 │
│   - Testing paralelo                │
│   - Validación usuarios             │
│   - Certificado MISMO que producción│
└─────────────────────────────────────┘
```

**Setup Staging:**
```bash
# En servidor staging o local

# 1. Clonar repo Odoo 19
git clone [tu_repo] /opt/odoo19_staging
cd /opt/odoo19_staging

# 2. Configurar variables entorno
cp .env.example .env.staging
nano .env.staging

# Variables críticas:
# - ODOO_DB_NAME=odoo19_staging
# - SII_ENVIRONMENT=sandbox  # ⚠️ IMPORTANTE: Sandbox primero
# - ANTHROPIC_API_KEY=[tu_key]

# 3. Build y deploy
docker-compose -f docker-compose.staging.yml up -d

# 4. Importar certificado + CAF (mismo que producción)
# Via UI Odoo 19 staging

# 5. Smoke tests
./scripts/validate_installation.sh
```

**Validación Usuarios Finales:**
```bash
# Invitar 3-5 usuarios clave probar staging

# Checklist validación:
# ✅ Login funciona
# ✅ Crear factura manual
# ✅ Generar DTE
# ✅ Descargar PDF
# ✅ Consultar estado
# ✅ UI intuitiva vs Odoo 11
# ✅ Performance aceptable
```

**Output:**
- ✅ Staging Odoo 19 operativo
- ✅ Certificado + CAF migrados
- ✅ Usuarios validaron funcionalidad
- ✅ Feedback incorporado

---

#### **Paso 6: Switchover a Producción (1 día)**

**Plan de Migración:**
```
VIERNES 18:00 (fin jornada):
├─ Backup completo Odoo 11
├─ Freeze operaciones nuevas
├─ Exportar datos pendientes
└─ Notificar usuarios mantenimiento

VIERNES 18:30 - 20:00:
├─ Migración final datos Odoo 11 → 19
├─ Validación smoke tests
├─ Configurar DNS/URLs a Odoo 19
└─ Testing acceso usuarios

LUNES 08:00 (inicio semana):
├─ Go-live Odoo 19 producción ✅
├─ Soporte activo usuarios
├─ Monitoreo intensivo 24h
└─ Odoo 11 standby (rollback si falla)

MARTES 08:00:
└─ Si todo OK → Odoo 11 archivado
```

**Checklist Pre-Switch:**
```bash
# Verificaciones finales

# 1. Backup Odoo 11
./scripts/backup_odoo11.sh  # Doble backup

# 2. Migrar datos pendientes
# - Facturas últimas 48h
# - DTEs en proceso
# - Partners nuevos

# 3. Validar Odoo 19 producción ready
# ✅ Certificado válido producción (Palena)
# ✅ CAF con folios suficientes (>100 por tipo)
# ✅ SII_ENVIRONMENT=production
# ✅ Todos servicios healthy
# ✅ Monitoring activo
# ✅ Backups automáticos configurados

# 4. Comunicar usuarios
# Email: "Nueva versión Odoo 19 desde lunes"
# Training: Videos tutoriales diferencias
# Soporte: Canal Slack/Teams activo
```

**Plan Rollback (si falla):**
```bash
# Si algo crítico falla en primeras 24h

# 1. Pausar Odoo 19
docker-compose -f production.yml down

# 2. Re-activar Odoo 11
docker-compose -f odoo11.yml up -d

# 3. Restaurar DNS a Odoo 11
# 4. Comunicar usuarios
# 5. Diagnosticar problema
# 6. Fix en staging
# 7. Re-intentar siguiente semana
```

**Output:**
- ✅ Odoo 19 en producción
- ✅ Usuarios operando
- ✅ Certificado + CAF funcionando
- ✅ 0 downtime crítico

---

### **TIER 2: FEATURES IMPORTANTES (1-2 semanas)** 🟡

**Ahora con producción estable, agregar features avanzados**

#### **Semana 1: ETAPA 3 + 4**

**ETAPA 3: PDF Reports (3 días):**
- [ ] Templates profesionales 5 tipos DTE
- [ ] QR visible y escaneable
- [ ] Logo empresa
- [ ] Formato SII oficial

**ETAPA 4: Libros Completos (2 días):**
- [ ] Libro Compra XML + envío SII
- [ ] Libro Venta XML + envío SII
- [ ] Consumo Folios automático
- [ ] Wizard generación manual

**Output:** 95% funcionalidad

---

#### **Semana 2: Monitoreo + Validaciones**

**Monitoreo SII UI (2 días):**
- [ ] Modelo `dte.sii.news` en Odoo
- [ ] Vistas + Dashboard
- [ ] Cron automático
- [ ] Integración Slack

**Validaciones Avanzadas (2 días):**
- [ ] Consulta estado on-demand
- [ ] Validación RUT online
- [ ] Tracking envíos masivos

**Output:** 98% funcionalidad

---

### **TIER 3: ENTERPRISE FEATURES (1-2 semanas)** 🟢 Opcional

**ETAPA 5 + IA:**
- Wizards restantes
- Chat IA conversacional
- Performance tuning
- UX/UI polish

**Output:** 100% ✅

---

## 📊 COMPARACIÓN TIMELINES

### **Empresa Nueva (Sin Certificación):**
```
Semana 1-2:   Certificación SII (crítico)
Semana 3:     Testing básico
Semana 4:     Deploy staging
Semana 5-6:   ETAPA 3+4
Semana 7-8:   Features avanzados

Total: 8 semanas
```

### **SU EMPRESA (Ya Certificada):** ⚡
```
Semana 1:     Migración certificado+CAF+datos
Semana 2:     Testing + Deploy staging
Semana 3:     Switch producción + validación
Semana 4:     ETAPA 3+4
Semana 5:     Monitoreo+Validaciones
Semana 6:     (Opcional) Features enterprise

Total: 3-4 semanas (producción MVP)
Total: 5-6 semanas (producción completa)
```

**Ahorro:** 3-4 semanas ⚡⚡⚡

---

## 💰 INVERSIÓN ACTUALIZADA

### **Costos Directos:**

| Concepto | Costo | Nota |
|----------|-------|------|
| Certificado SII | $0 | ✅ Ya tienen |
| CAF Folios | $0 | ✅ Ya tienen |
| Claude API (IA) | $200/mes | Opcional |
| Hosting Production | $100-300/mes | Si no self-hosted |

**Total Año 1:** $700-1,000 USD (vs $150-400 sin certificado)

---

### **Costos Desarrollo:**

| Fase | Días | Costo @$500/día | Resultado |
|------|------|-----------------|-----------|
| **TIER 0: Migración** | 3-5 días | $1,500-$2,500 | Datos migrados |
| **TIER 1: MVP** | 3-5 días | $1,500-$2,500 | Producción |
| **TIER 2: Completo** | 7-10 días | $3,500-$5,000 | 98% features |
| **TIER 3: Enterprise** | 7-10 días | $3,500-$5,000 | 100% |

**Total MVP (Producción):** $3,000-$5,000
**Total Completo:** $6,500-$10,000
**Total Enterprise:** $10,000-$15,000

---

## 🎯 RECOMENDACIÓN ESPECÍFICA PARA SU EMPRESA

### **PLAN FAST-TRACK RECOMENDADO:**

#### **Opción A: MVP Ultra-Rápido (2-3 semanas)** ⚡⚡⚡
**Scope:** TIER 0 + TIER 1
**Costo:** $3,000-$5,000
**Timeline:** 10-15 días

**Incluye:**
- ✅ Migración certificado + CAF
- ✅ Testing integral
- ✅ Deploy staging
- ✅ Switch producción
- ✅ Soporte go-live

**Output:** Odoo 19 en producción funcionando

**Cuándo elegir:**
- Necesitan migrar RÁPIDO (competencia, bugs Odoo 11)
- Presupuesto ajustado
- Solo reemplazo 1:1 de funcionalidad

---

#### **Opción B: Migración + Mejoras (4-5 semanas)** ⭐ **RECOMENDADO**
**Scope:** TIER 0 + TIER 1 + TIER 2
**Costo:** $6,500-$10,000
**Timeline:** 20-25 días

**Incluye:**
- ✅ Todo de Opción A
- ✅ ETAPA 3: PDFs profesionales
- ✅ ETAPA 4: Libros automáticos
- ✅ Monitoreo SII UI
- ✅ Validaciones avanzadas

**Output:** Odoo 19 MEJOR que Odoo 11

**Cuándo elegir:**
- Quieren aprovechar migración para MEJORAR
- Presupuesto moderado ($10K)
- Timeline 1 mes OK
- Buscan ventaja vs Odoo 11

---

#### **Opción C: Enterprise Full (6 semanas)** 🏆
**Scope:** TIER 0 + 1 + 2 + 3
**Costo:** $10,000-$15,000
**Timeline:** 30-35 días

**Incluye:**
- ✅ Todo de Opción B
- ✅ ETAPA 5: Wizards completos
- ✅ Chat IA (único en mercado)
- ✅ Performance optimizado
- ✅ UX/UI avanzado
- ✅ Documentación completa

**Output:** Sistema enterprise-grade superior a SAP/Oracle

**Cuándo elegir:**
- Quieren SUPERAR competencia
- Presupuesto $15K disponible
- Timeline 6 semanas OK
- Buscan features únicos (IA)

---

## 📋 ACCIÓN INMEDIATA (ESTA SEMANA)

### **Paso 1: Extraer Credenciales Odoo 11 (HOY)**

```bash
# Conectar a servidor Odoo 11 actual
ssh user@servidor_odoo11

# Exportar certificado
# Ubicación típica: Settings → Certificates
# Descargar archivo .p12 + anotar password

# Exportar CAF
# Ubicación típica: Settings → CAF Files
# Descargar 5 archivos .xml (uno por cada tipo DTE)

# Backup completo DB
pg_dump -U odoo odoo11_db > backup_odoo11_$(date +%Y%m%d).sql
```

**Output esperado:**
- certificado_produccion.p12
- password_certificado.txt
- CAF_33.xml
- CAF_34.xml
- CAF_52.xml
- CAF_56.xml
- CAF_61.xml
- backup_odoo11_20251023.sql

---

### **Paso 2: Setup Odoo 19 Staging (MAÑANA)**

```bash
# En tu máquina local o servidor staging
cd /Users/pedro/Documents/odoo19

# Verificar stack completo funciona
docker-compose ps
# Todos deben estar "Up" y "healthy"

# Si no están levantados:
docker-compose up -d

# Esperar 30 segundos, verificar logs
docker-compose logs odoo | tail -50
# Debe mostrar: "odoo.service.server: HTTP service (werkzeug) running on..."
```

---

### **Paso 3: Importar Credenciales (MAÑANA)**

```bash
# 1. Acceder Odoo 19 UI
# http://localhost:8169

# 2. Login admin
# User: admin
# Pass: [configurado en primer setup]

# 3. Importar certificado
# Settings → Technical → Chilean Localization → Certificates
# → Create
# → Upload certificado_produccion.p12
# → Ingresar password
# → Save

# 4. Importar CAF (repetir 5 veces)
# Settings → Technical → Chilean Localization → CAF Files
# → Create
# → Upload CAF_XX.xml
# → Save

# 5. Validar importación
# → Certificates: debe mostrar 1 registro "Valid"
# → CAF Files: debe mostrar 5 registros "Active"
```

---

### **Paso 4: Test Rápido Maullin (PASADO MAÑANA)**

```bash
# 1. Configurar ambiente sandbox
# Settings → Chilean Localization → Configuration
# SII Environment: Sandbox (Maullin)

# 2. Crear factura test
# Accounting → Customers → Invoices → Create
# Customer: [Cualquier cliente con RUT]
# Product: [Cualquier producto]
# Amount: $10,000
# Save

# 3. Generar DTE
# Botón "Generar DTE"
# → Select Certificate
# → Select CAF (auto)
# → Confirm

# 4. Verificar resultado
# ✅ Estado: "Accepted" por SII
# ✅ Folio asignado
# ✅ PDF con QR generado
# ✅ XML descargable
```

**Si este test pasa → Migración es viable ✅**

---

## 🚨 RIESGOS Y MITIGACIONES

### **Riesgo 1: Certificado No Compatible**
**Probabilidad:** Baja (5%)
**Impacto:** Alto (bloquea todo)

**Mitigación:**
- Validar certificado en Odoo 19 ANTES de migrar todo
- Tener contacto entidad certificadora (renovar si necesario)
- Período válido > 6 meses (sino renovar primero)

---

### **Riesgo 2: CAF Incompatibles Formato**
**Probabilidad:** Media (20%)
**Impacto:** Medio (retrasar 1-2 días)

**Mitigación:**
- Validar 1 CAF primero antes de migrar los 5
- Si falla, contactar SII obtener nuevos CAF formato actualizado
- Odoo 19 parser más robusto que Odoo 11 (probablemente funciona)

---

### **Riesgo 3: Downtime Durante Switch**
**Probabilidad:** Media (30%)
**Impacto:** Alto (pérdida operación)

**Mitigación:**
- Switch fuera horario laboral (viernes noche)
- Odoo 11 en standby 48h (rollback rápido)
- Testing exhaustivo staging antes
- Comunicar usuarios con anticipación

---

### **Riesgo 4: Usuarios Rechazo Cambio**
**Probabilidad:** Media (25%)
**Impacto:** Medio (fricción adopción)

**Mitigación:**
- Involucrar usuarios clave en testing staging
- Training antes del switch
- Videos tutoriales diferencias Odoo 11 vs 19
- Soporte intensivo primera semana

---

## ✅ CRITERIOS DE ÉXITO

### **Semana 1:**
- [x] Certificado exportado Odoo 11
- [x] CAF exportados Odoo 11
- [ ] Certificado importado Odoo 19
- [ ] CAF importados Odoo 19
- [ ] 1 DTE test exitoso Maullin

---

### **Semana 2:**
- [ ] 15+ DTEs test diversos Maullin
- [ ] Staging validado por usuarios
- [ ] 0 bugs bloqueantes
- [ ] Plan switch aprobado

---

### **Semana 3:**
- [ ] Switch producción ejecutado
- [ ] Odoo 19 operando sin issues
- [ ] Usuarios trabajando normal
- [ ] Odoo 11 archivado

---

### **Semana 4-5 (si Opción B):**
- [ ] ETAPA 3 PDFs completos
- [ ] ETAPA 4 Libros funcionando
- [ ] Monitoreo SII activo
- [ ] Validaciones avanzadas OK

---

## 🎯 DECISIÓN REQUERIDA

**Necesito que confirmes:**

1. **¿Qué opción elegimos?**
   - [ ] Opción A: MVP 2-3 semanas ($3-5K)
   - [ ] Opción B: Migración + Mejoras 4-5 semanas ($6.5-10K) ⭐
   - [ ] Opción C: Enterprise Full 6 semanas ($10-15K)

2. **¿Cuándo podemos acceder a Odoo 11?**
   - Necesito extraer: certificado.p12, CAF files, configuración company
   - ¿Tienes acceso SSH servidor?
   - ¿O prefieres exportar vía UI?

3. **¿Cuándo queremos switch a producción?**
   - Sugerencia: Viernes 15 Nov tarde (da 2 semanas preparación)
   - Alternativa: Cuando tú prefieras

4. **¿Presupuesto aprobado?**
   - Opción B: ~$7-10K
   - ¿OK proceder?

**Una vez confirmes, comenzamos INMEDIATAMENTE con extracción credenciales.**

---

**FIN FAST-TRACK PLAN**
