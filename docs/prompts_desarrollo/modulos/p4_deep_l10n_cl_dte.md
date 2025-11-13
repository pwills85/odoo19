# Prompt P4-Deep: Auditoría Arquitectónica l10n_cl_dte
**Módulo:** Facturación Electrónica Chilena (DTE)  
**Versión:** 19.0.6.0.0 (Consolidada)  
**Nivel:** P4-Deep (1,200-1,500 palabras | ≥30 refs | ≥6 verificaciones)  
**Objetivo:** Auditoría arquitectónica completa sistema DTE con compliance SII Resolución 80/2014

---

## 🔄 REGLAS DE PROGRESO (OBLIGATORIO - 7 PASOS)

Tu respuesta DEBE seguir esta estructura de progreso para transparencia máxima:

### ⭐ PASO 1: ANÁLISIS INICIAL (10% progreso)
**Estado:** `[EN PROGRESO - ANÁLISIS INICIAL]`
- Leer contexto del módulo (métricas + arquitectura + rutas clave)
- Identificar archivos críticos a analizar (≥30 archivos target)
- Planificar orden de análisis (dependencias primero)
- **Output:** Lista numerada archivos a analizar con justificación

### ⭐ PASO 2: ANÁLISIS POR DIMENSIONES (10-70% progreso)
**Estado:** `[EN PROGRESO - DIMENSIÓN X/10]` (actualizar por cada dimensión A-J)

Por cada dimensión (A-J):
- Analizar archivos relevantes (código real, no suposiciones)
- Documentar hallazgos con referencias `ruta.py:línea`
- Identificar patrones, anti-patrones, deuda técnica
- Marcar incertidumbres con `[NO VERIFICADO]`
- **Output:** Hallazgos por dimensión con evidencia

### ⭐ PASO 3: VERIFICACIONES REPRODUCIBLES (70-80% progreso)
**Estado:** `[EN PROGRESO - VERIFICACIONES]`
- Definir ≥6 verificaciones (≥1 P0 + ≥1 P1 + ≥1 P2 por área A-F)
- Validar contra código real (no inventes verificaciones)
- Incluir comandos shell ejecutables
- **Output:** Verificaciones formateadas según template

### ⭐ PASO 4: RECOMENDACIONES PRIORIZADAS (80-90% progreso)
**Estado:** `[EN PROGRESO - RECOMENDACIONES]`
- Sintetizar hallazgos en recomendaciones accionables
- Priorizar por impacto/esfuerzo (P0 > P1 > P2)
- Usar template estructurado obligatorio
- Incluir roadmap de implementación
- **Output:** Tabla recomendaciones priorizadas

### ⭐ PASO 5: GESTIÓN INCERTIDUMBRE (90-95% progreso)
**Estado:** `[EN PROGRESO - INCERTIDUMBRES]`
- Listar TODO lo marcado `[NO VERIFICADO]`
- Explicar cómo verificar cada incertidumbre
- Estimar rangos probables si aplica
- **Output:** Lista incertidumbres con métodos de verificación

### ⭐ PASO 6: AUTO-VALIDACIÓN CHECKLIST (95-99% progreso)
**Estado:** `[EN PROGRESO - VALIDACIÓN]`
- Ejecutar checklist de calidad (formato + profundidad)
- Contar métricas: términos técnicos, file refs, snippets, tablas
- Verificar especificidad ≥0.85
- **Output:** Tabla auto-validación con pass/fail

### ⭐ PASO 7: COMPLETION (100% progreso)
**Estado:** `[COMPLETADO]`
- Confirmar cumplimiento de todos los requisitos
- Resumen ejecutivo (3-5 líneas)
- **Output:** Confirmación final

---

## 📊 CONTEXTO CUANTIFICADO DENSO - MÓDULO L10N_CL_DTE

### Métricas del Módulo
| Métrica | Valor | Contexto |
|---------|-------|----------|
| **Archivos Python** | 38 modelos | `addons/localization/l10n_cl_dte/models/` |
| **LOC Total** | ~6,800 líneas | Sin comentarios ni blanks |
| **Modelo Principal** | `account_move_dte.py` | 1,450 LOC (21% del módulo) |
| **Segundo Crítico** | `dte_service_integration.py` | 680 LOC (integración SII SOAP) |
| **Tercero Crítico** | `stock_picking_dte.py` | 580 LOC (Guías Despacho DTE 52) |
| **Tests** | 60+ tests | `tests/`, coverage ~78% |
| **Dependencias Python** | 6 críticas | lxml, xmlsec, zeep, cryptography, pyOpenSSL, pdf417 |
| **Dependencias Odoo** | 7 módulos | base, account, l10n_latam_base, l10n_latam_invoice_document, l10n_cl, purchase, stock |
| **Tipos DTE Soportados** | 5 tipos B2B | 33, 34, 52, 56, 61 (NO boletas 39/41) |
| **Códigos Error SII** | 59 mapeados | Con soluciones en `data/sii_error_codes.xml` |
| **Comunas Chile** | 347 oficiales | `data/l10n_cl_comunas_data.xml` (Resolución SII) |
| **Códigos Acteco** | 700 completos | `data/sii_activity_codes_full.xml` |
| **Cron Jobs** | 5 schedulers | Polling DTE status (15 min), RCV sync (diario), backup (semanal) |

### Optimizaciones Arquitectónicas Clave
1. **Native Python Libraries (Oct 2024)**: Migración de microservicio a libs/ nativo → -100ms p95
2. **Async Processing**: `ir.cron` para polling SII (evita bloqueos UI)
3. **Redis Caching**: Sesiones AI Service (webhooks pre-validación)
4. **Retry Logic**: Exponential backoff con tenacity (SII SOAP resilience)
5. **XML Validation**: Schema XSD cacheado en memoria (evita re-parse)

### Arquitectura Multi-Capa
```
Layer 1: UI/UX (Views + Wizards + Reports)
  ├── views/account_move_dte_views.xml
  ├── wizards/dte_generate_wizard_views.xml
  └── report/report_invoice_dte_document.xml

Layer 2: Business Logic (Models ORM)
  ├── models/account_move_dte.py (1,450 LOC - core DTE)
  ├── models/account_move_enhanced.py (referencias SII, cedible)
  ├── models/stock_picking_dte.py (DTE 52 Guías)
  ├── models/purchase_order_dte.py (DTE 34 Exenta)
  └── models/dte_contingency.py (modo contingencia Res. 68/2019)

Layer 3: Integrations (Native Python libs/)
  ├── libs/dte_generator.py (XML generation)
  ├── libs/dte_signer.py (XMLDSig PKCS#1)
  ├── libs/dte_validator.py (XSD schema validation)
  ├── libs/sii_connector.py (SOAP client zeep)
  └── libs/rut_validator.py (módulo 11 algorithm)

Layer 4: External Services
  ├── SII SOAP (Maullin/Palena)
  ├── AI Service (FastAPI - webhooks pre-validación)
  └── Redis (session caching)
```

### Deuda Técnica Conocida
1. **account_move_dte.py monolítico**: 1,450 LOC → Debería ser <800 LOC (refactorización pendiente)
2. **Tests edge cases incompletos**: Coverage 78% → Target 85%+ (faltan tests negativos SII)
3. **Dependency zeep deprecated**: zeep 4.2.1 → Migrar a httpx + lxml manual (2025 Q2)
4. **Modo contingencia manual**: Res. 68/2019 requiere wizard complejo (Sprint 3 pendiente)
5. **RCV sync single-threaded**: `ir.cron` diario → Debería ser paralelo (workers Odoo)

---

## 🔍 RUTAS CLAVE A ANALIZAR (≥30 FILES TARGET)

### Core DTE (P0 - Críticos)
```
1.  addons/localization/l10n_cl_dte/models/account_move_dte.py:50
2.  addons/localization/l10n_cl_dte/models/account_move_enhanced.py:24
3.  addons/localization/l10n_cl_dte/models/stock_picking_dte.py:56
4.  addons/localization/l10n_cl_dte/models/purchase_order_dte.py:10
5.  addons/localization/l10n_cl_dte/models/dte_service_integration.py:27
6.  addons/localization/l10n_cl_dte/libs/dte_generator.py:1
7.  addons/localization/l10n_cl_dte/libs/dte_signer.py:1
8.  addons/localization/l10n_cl_dte/libs/dte_validator.py:1
9.  addons/localization/l10n_cl_dte/libs/sii_connector.py:1
10. addons/localization/l10n_cl_dte/libs/rut_validator.py:1
```

### Certificados y Seguridad (P0)
```
11. addons/localization/l10n_cl_dte/models/dte_certificate.py:15
12. addons/localization/l10n_cl_dte/models/dte_caf.py:21
13. addons/localization/l10n_cl_dte/models/res_company_dte.py:10
```

### Compliance SII (P1)
```
14. addons/localization/l10n_cl_dte/models/account_move_reference.py:29 (referencias NC/ND)
15. addons/localization/l10n_cl_dte/models/dte_contingency.py:24 (modo contingencia)
16. addons/localization/l10n_cl_dte/models/dte_contingency.py:229 (pending queue)
17. addons/localization/l10n_cl_dte/models/dte_libro.py:10 (libro compra/venta)
18. addons/localization/l10n_cl_dte/models/dte_consumo_folios.py:10 (consumo mensual)
19. addons/localization/l10n_cl_dte/models/l10n_cl_rcv_entry.py:20 (RCV Res. 61/2017)
20. addons/localization/l10n_cl_dte/models/l10n_cl_rcv_period.py:19 (períodos RCV)
```

### Disaster Recovery (P1)
```
21. addons/localization/l10n_cl_dte/models/dte_backup.py:20
22. addons/localization/l10n_cl_dte/models/dte_failed_queue.py:20
23. addons/localization/l10n_cl_dte/data/ir_cron_disaster_recovery.xml:1
24. addons/localization/l10n_cl_dte/data/ir_cron_dte_status_poller.xml:1
```

### Integraciones (P2)
```
25. addons/localization/l10n_cl_dte/models/dte_ai_client.py:27 (AI Service client)
26. addons/localization/l10n_cl_dte/models/ai_agent_selector.py:24 (multi-agent)
27. addons/localization/l10n_cl_dte/models/ai_chat_integration.py:28 (chat universal)
28. addons/localization/l10n_cl_dte/models/l10n_cl_rcv_integration.py:24 (RCV sync)
```

### Reports y UX (P2)
```
29. addons/localization/l10n_cl_dte/models/report_helper.py:31
30. addons/localization/l10n_cl_dte/report/report_invoice_dte_document.xml:1
31. addons/localization/l10n_cl_dte/report/report_dte_52.xml:1 (Guías Despacho)
32. addons/localization/l10n_cl_dte/views/account_move_dte_views.xml:1
```

### Testing (P2)
```
33. addons/localization/l10n_cl_dte/tests/test_dte_generation.py:1
34. addons/localization/l10n_cl_dte/tests/test_dte_signing.py:1
35. addons/localization/l10n_cl_dte/tests/test_sii_connector.py:1
```

---

## 📋 ÁREAS DE EVALUACIÓN (10 DIMENSIONES OBLIGATORIAS)

### A) ARQUITECTURA Y MODULARIDAD (≥5 sub-dimensiones)

**Analizar:**
- A.1) **Herencia de Modelos**: ¿`account_move_dte.py` usa `_inherit='account.move'` correctamente? ¿Hay duplicación con `account_move_enhanced.py`?
- A.2) **Separación libs/ vs models/**: ¿Lógica de firma digital está en libs/ (sin ORM) o mezclada en models/?
- A.3) **Mixins y AbstractModel**: ¿`dte_service_integration.py` como AbstractModel es reutilizable? ¿Hay otros candidatos a mixin?
- A.4) **Dependencias cíclicas**: ¿`account_move_dte` → `dte_service_integration` → `account_move_dte`? (código espagueti)
- A.5) **Monolitos detectados**: ¿`account_move_dte.py` 1,450 LOC tiene múltiples responsabilidades? (SRP violation)

**Referencias clave:** `account_move_dte.py:50`, `dte_service_integration.py:27`, `libs/dte_signer.py`

---

### B) PATRONES DE DISEÑO ODOO 19 CE (≥5 sub-dimensiones)

**Analizar:**
- B.1) **@api.depends correctos**: ¿Campos computed tienen dependencias explícitas? Ejemplo: `dte_status` compute
- B.2) **@api.constrains validación**: ¿Validaciones RUT, folios CAF usan constrains vs raise manual?
- B.3) **@api.onchange UX**: ¿Cambios en `partner_id` actualizan automáticamente `vat`, `acteco_id`?
- B.4) **Odoo 19 deprecations compliance**: ¿Hay `t-esc` en QWeb? ¿`type='json'` en controllers? ¿`_sql_constraints` vs `models.Constraint`?
- B.5) **Recordsets vs iteración**: ¿Se usa `.filtered()`, `.mapped()` eficientemente o loops Python innecesarios?

**Referencias clave:** `account_move_dte.py:125` (computed fields), `dte_caf.py:45` (constraints), `views/account_move_dte_views.xml`

---

### C) INTEGRACIONES EXTERNAS (≥6 sub-dimensiones)

**Analizar:**
- C.1) **SII SOAP zeep**: ¿`sii_connector.py` tiene timeout configurado? ¿Retry logic con exponential backoff?
- C.2) **XMLDSig xmlsec**: ¿Firma digital usa PKCS#1 SHA-256? ¿Certificados expiran y hay alertas?
- C.3) **AI Service webhooks**: ¿`dte_ai_client.py` tiene circuit breaker? ¿Fallback si AI Service cae?
- C.4) **Redis caching**: ¿Sesiones AI se cachean? ¿Expiry time configurado? ¿Manejo de Redis down?
- C.5) **RCV sync**: ¿`l10n_cl_rcv_integration.py` usa API oficial Res. 61/2017? ¿OAuth2 token refresh?
- C.6) **Error handling externo**: ¿59 códigos error SII mapeados en `data/sii_error_codes.xml` se usan en código?

**Referencias clave:** `libs/sii_connector.py`, `libs/dte_signer.py`, `dte_ai_client.py:27`, `l10n_cl_rcv_integration.py:24`

---

### D) SEGURIDAD MULTICAPA (≥5 sub-dimensiones)

**Analizar:**
- D.1) **Secrets management**: ¿Certificados .p12 se almacenan encrypted? ¿Password en `.env` NO en código?
- D.2) **XML External Entities (XXE)**: ¿Parser lxml tiene `resolve_entities=False`?
- D.3) **SQL Injection**: ¿Hay `self.env.cr.execute()` con f-strings? (usar ORM siempre)
- D.4) **RBAC granular**: ¿`security/security_groups.xml` define 4 niveles? (user, manager, admin, system)
- D.5) **Multi-company isolation**: ¿`security/multi_company_rules.xml` evita cross-company data leak?

**Referencias clave:** `dte_certificate.py:45` (encryption), `libs/dte_validator.py:20` (XXE), `security/`

---

### E) OBSERVABILIDAD (≥4 sub-dimensiones)

**Analizar:**
- E.1) **Logging estructurado**: ¿Se usa `_logger.info()` con contexto (DTE folio, partner RUT)?
- E.2) **Error tracking**: ¿`dte_failed_queue.py` registra fallos SII con traceback completo?
- E.3) **Métricas clave**: ¿Se trackea p95 latency SII SOAP? ¿Success rate DTEs por tipo?
- E.4) **Audit trail**: ¿`dte_communication.py` guarda XML request/response SII?

**Referencias clave:** `dte_failed_queue.py:20`, `dte_communication.py:9`, `dte_backup.py:20`

---

### F) TESTING Y COBERTURA (≥5 sub-dimensiones)

**Analizar:**
- F.1) **Coverage actual**: ¿78% es suficiente? ¿Qué archivos críticos tienen <80%?
- F.2) **Tests negativos SII**: ¿Se prueba folio duplicado, RUT inválido, CAF expirado?
- F.3) **Mocks externos**: ¿SII SOAP, Redis, AI Service están mockeados? ¿O tests reales (frágiles)?
- F.4) **Integration tests**: ¿Hay test end-to-end factura → firma → envío SII (mock) → recepción?
- F.5) **Performance tests**: ¿Se mide p95 generación XML? ¿Firma digital?

**Referencias clave:** `tests/test_dte_generation.py`, `tests/test_dte_signing.py`, `tests/test_sii_connector.py`

---

### G) PERFORMANCE Y ESCALABILIDAD (≥4 sub-dimensiones)

**Analizar:**
- G.1) **N+1 queries ORM**: ¿`account_move_dte.py` itera sobre `move_line_ids` sin prefetch?
- G.2) **XML parsing cacheado**: ¿Schema XSD se lee 1 vez en memoria o por cada DTE?
- G.3) **Async processing**: ¿Envío SII SOAP usa `ir.cron` o bloquea UI? ¿Timeout configurado?
- G.4) **Índices DB**: ¿Tabla `l10n_cl_rcv_entry` tiene índice en `period_id, partner_id`?

**Referencias clave:** `account_move_dte.py:200` (line iteration), `libs/dte_validator.py:50` (XSD cache)

---

### H) DEPENDENCIAS Y DEUDA TÉCNICA (≥4 sub-dimensiones)

**Analizar:**
- H.1) **Dependencias Python**: ¿zeep 4.2.1 deprecated? ¿Hay vulnerabilidades CVE en lxml, xmlsec?
- H.2) **Dependencias Odoo**: ¿`l10n_latam_base` es necesario o legacy? ¿Conflictos con `l10n_cl`?
- H.3) **Monolitos pendientes**: ¿`account_move_dte.py` 1,450 LOC se puede refactorizar en <800 LOC?
- H.4) **TODOs en código**: ¿Hay `# TODO:` o `# FIXME:` sin ticket asignado?

**Referencias clave:** `__manifest__.py:external_dependencies`, `account_move_dte.py:1-1450`

---

### I) CONFIGURACIÓN Y DEPLOYMENT (≥3 sub-dimensiones)

**Analizar:**
- I.1) **Configuración SII**: ¿`res.config.settings` tiene URLs Maullin/Palena? ¿Toggle sandbox/producción?
- I.2) **Post-install hooks**: ¿`post_init_hook` genera webhook_key segura? ¿Inicializa datos maestros?
- I.3) **Docker Compose**: ¿Stack tiene servicios necesarios? ¿Variables `.env` documentadas?

**Referencias clave:** `res_config_settings.py:6`, `__init__.py:post_init_hook`, `docker-compose.yml`

---

### J) ERRORES Y MEJORAS CRÍTICAS (≥5 sub-dimensiones)

**Analizar:**
- J.1) **Errores SII frecuentes**: ¿Qué % DTEs fallan? ¿Top 3 códigos error SII? (usar `dte_failed_queue`)
- J.2) **XML malformados**: ¿Se valida contra XSD ANTES de enviar SII? ¿O se descubre en runtime?
- J.3) **Certificados expirados**: ¿Hay alertas proactivas 30 días antes? ¿CAFs expiran sin warning?
- J.4) **Race conditions**: ¿Folio duplicado si 2 usuarios generan DTE simultáneamente?
- J.5) **Compliance gaps**: ¿Referencias obligatorias NC/ND (Res. 80/2014)? ¿Modo contingencia Res. 68/2019?

**Referencias clave:** `dte_failed_queue.py:20`, `account_move_reference.py:29`, `dte_contingency.py:24`

---

## ✅ REQUISITOS DE SALIDA (OBLIGATORIO)

### 1. Referencias de Archivo (≥30 obligatorias)
**Formato:** `ruta/archivo.py:línea_exacta`
**Distribución target:**
- P0 (críticos): ≥15 refs en dimensiones A-D
- P1 (importantes): ≥10 refs en dimensiones E-G
- P2 (complementarios): ≥5 refs en dimensiones H-J

**Ejemplo correcto:**
```
addons/localization/l10n_cl_dte/models/account_move_dte.py:125
libs/dte_signer.py:45
views/account_move_dte_views.xml:230
```

---

### 2. Verificaciones Reproducibles (≥6 obligatorias, clasificadas P0/P1/P2)

**Template OBLIGATORIO por verificación:**

```markdown
#### V1 (P0): [TÍTULO DESCRIPTIVO]
**Comando:**
```bash
docker compose exec odoo bash -c "grep -r 'resolve_entities' addons/localization/l10n_cl_dte/libs/ || echo 'NOT FOUND'"
```

**Hallazgo Esperado:**
```
addons/localization/l10n_cl_dte/libs/dte_validator.py:25: parser = etree.XMLParser(resolve_entities=False)
```

**Si NO se encuentra:**
- **Problema:** Vulnerabilidad XXE en validación XML DTE
- **Corrección:** Agregar `resolve_entities=False` en `libs/dte_validator.py:20`

**Clasificación:** P0 (crítico - seguridad)
```

**Distribución obligatoria:**
- ≥1 verificación P0 por áreas A-F (mínimo 6 total)
- Al menos 1 verificación de seguridad (XXE, SQL injection, secrets)
- Al menos 1 verificación de compliance SII (referencias NC/ND, RCV sync)
- Al menos 1 verificación de performance (N+1 queries, timeouts)

---

### 3. Gestión de Incertidumbre

**Formato OBLIGATORIO:**

```markdown
### [NO VERIFICADO]: Certificados digitales expirados sin alertas proactivas

**¿Cómo verificar?**
```bash
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
env['l10n_cl_dte.certificate'].search([]).mapped(lambda c: (c.name, c.expiry_date))
"
```

**Rango probable:** 60-80% certificados sin fecha expiración configurada (basado en estructura modelo)

**Requiere:** Acceso a instancia Odoo con datos reales de certificados
```

---

### 4. Recomendaciones Accionables (≥5 obligatorias)

**Template ESTRUCTURADO OBLIGATORIO:**

```markdown
#### R1 (P0): Refactorizar account_move_dte.py monolítico

**Prioridad:** P0 (crítico)
**Área:** Arquitectura y Modularidad (A)
**Esfuerzo:** 3-5 días (refactorización + tests)

**Problema:**
- `account_move_dte.py` tiene 1,450 LOC (debería ser <800 LOC)
- Mezcla responsabilidades: validación, generación XML, envío SII, UI helpers
- Dificulta testing unitario y mantenimiento

**Solución:**
1. Extraer generación XML a `libs/dte_generator.py` (300 LOC)
2. Mover validación SII a `libs/dte_validator.py` (200 LOC)
3. Separar UI helpers a `models/report_helper.py` (150 LOC)
4. Mantener core business logic en `account_move_dte.py` (~800 LOC)

**Impacto:**
- ✅ Mejora testabilidad: Tests unitarios libs/ sin ORM
- ✅ Reduce complejidad ciclomática: <15 por método
- ✅ Facilita refactorizaciones futuras (ej: migrar zeep → httpx)

**Validación:**
```bash
# Métrica: LOC por archivo
wc -l addons/localization/l10n_cl_dte/models/account_move_dte.py
# Target: <800 LOC después de refactorización
```

**Dependencies:**
- Requiere: 100% coverage tests antes de refactorizar (evitar regresiones)
- Bloquea: Migración zeep → httpx (más fácil con código modular)
```

**Priorización obligatoria:**
- **P0 Crítico (bloqueante):** Seguridad, compliance SII, bugs producción
- **P1 Alta (importante):** Performance, deuda técnica mayor, UX crítico
- **P2 Media (mejora):** Refactorizaciones, optimizaciones, UX minor

---

## 🎯 FORMATO DE RESPUESTA ESPERADO

```markdown
# 📊 AUDITORÍA ARQUITECTÓNICA: l10n_cl_dte (P4-Deep)

---

## ⭐ PASO 1: ANÁLISIS INICIAL [EN PROGRESO - 10%]

### Archivos Target (35 identificados):
1. `account_move_dte.py` (1,450 LOC - modelo core)
2. `dte_service_integration.py` (680 LOC - SOAP SII)
3. ...
35. `tests/test_sii_connector.py` (mocks SOAP)

**Orden de análisis:**
1. libs/ (sin dependencias ORM)
2. models/ core (account_move_dte, dte_service_integration)
3. models/ features (contingency, RCV, backup)
4. tests/ (validar coverage)

---

## ⭐ PASO 2: ANÁLISIS POR DIMENSIONES [EN PROGRESO - 10%]

### A) ARQUITECTURA Y MODULARIDAD [EN PROGRESO - DIMENSIÓN 1/10]

#### A.1) Herencia de Modelos: ✅ Correcto

**Evidencia:**
```python
# addons/localization/l10n_cl_dte/models/account_move_dte.py:50
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'  # ✅ Herencia correcta, NO duplicación
```

**Hallazgos:**
- ✅ NO hay duplicación con `account_move_enhanced.py` (ambos usan `_inherit`)
- ✅ Patrón correcto: `account_move_dte.py` (core DTE) + `account_move_enhanced.py` (features adicionales)

**Referencias:** `account_move_dte.py:50`, `account_move_enhanced.py:24`

---

#### A.2) Separación libs/ vs models/: ⚠️ Mejoras Necesarias

[NO VERIFICADO]: ¿Firma digital está 100% en libs/ o hay lógica en models/?

**¿Cómo verificar?**
```bash
grep -r "xmlsec" addons/localization/l10n_cl_dte/models/
grep -r "xmlsec" addons/localization/l10n_cl_dte/libs/
```

**Rango probable:** 80-90% lógica en libs/, 10-20% acoplada en models/ (basado en arquitectura descrita)

---

... [CONTINUAR CON DIMENSIONES B-J] ...

---

## ⭐ PASO 3: VERIFICACIONES REPRODUCIBLES [EN PROGRESO - 70%]

### V1 (P0): Vulnerabilidad XXE en validación XML
[INCLUIR TEMPLATE COMPLETO ARRIBA]

### V2 (P1): Retry logic SII SOAP
[INCLUIR TEMPLATE COMPLETO]

### V3 (P0): Certificados almacenados encrypted
[INCLUIR TEMPLATE COMPLETO]

### V4 (P2): Coverage tests DTE < 80%
[INCLUIR TEMPLATE COMPLETO]

### V5 (P1): N+1 queries en líneas de factura
[INCLUIR TEMPLATE COMPLETO]

### V6 (P0): Referencias NC/ND obligatorias (Res. 80/2014)
[INCLUIR TEMPLATE COMPLETO]

---

## ⭐ PASO 4: RECOMENDACIONES PRIORIZADAS [EN PROGRESO - 80%]

### Tabla Resumen Recomendaciones

| ID | Prioridad | Área | Título | Esfuerzo | Impacto |
|----|-----------|------|--------|----------|---------|
| R1 | P0 | Arquitectura | Refactorizar account_move_dte.py monolítico | 3-5 días | Alto |
| R2 | P0 | Seguridad | Habilitar XXE protection en XML parser | 2-4 horas | Crítico |
| R3 | P1 | Testing | Aumentar coverage 78% → 85%+ | 2-3 días | Medio |
| R4 | P1 | Performance | Optimizar N+1 queries líneas factura | 1-2 días | Alto |
| R5 | P2 | Deuda Técnica | Migrar zeep → httpx (2025 Q2) | 1 semana | Medio |

---

### R1 (P0): Refactorizar account_move_dte.py monolítico
[INCLUIR TEMPLATE ESTRUCTURADO COMPLETO ARRIBA]

### R2 (P0): Habilitar XXE protection en XML parser
[INCLUIR TEMPLATE COMPLETO]

... [CONTINUAR CON R3-R5+] ...

---

## ⭐ PASO 5: GESTIÓN INCERTIDUMBRE [EN PROGRESO - 90%]

### Lista Completa Incertidumbres [NO VERIFICADO]:

1. **Firma digital en libs/ vs models/** (ver A.2 arriba)
2. **Certificados expirados sin alertas** (ver J.3)
3. **Folio duplicado race condition** (ver J.4)
...

---

## ⭐ PASO 6: AUTO-VALIDACIÓN CHECKLIST [EN PROGRESO - 95%]

### Checklist Formato (Obligatorio)

| Criterio | Target P4-Deep | Actual | Pass/Fail |
|----------|----------------|--------|-----------|
| Output palabras | 1,200-1,500 | 1,380 | ✅ PASS |
| File refs `ruta:línea` | ≥30 | 42 | ✅ PASS |
| Verificaciones reproducibles | ≥6 | 8 | ✅ PASS |
| Dimensiones analizadas | 10 (A-J) | 10 | ✅ PASS |
| Snippets código | ≥15 | 18 | ✅ PASS |
| Tablas estructuradas | ≥5 | 7 | ✅ PASS |

---

### Checklist Profundidad (Calidad)

| Criterio | Target P4-Deep | Actual | Pass/Fail |
|----------|----------------|--------|-----------|
| Términos técnicos únicos | ≥80 | 94 | ✅ PASS |
| Especificidad (tech/total) | ≥0.85 | 0.88 | ✅ PASS |
| Verificaciones clasificadas P0/P1/P2 | 100% | 100% | ✅ PASS |
| Recomendaciones con template | 100% | 100% | ✅ PASS |
| Incertidumbres con método verificación | 100% | 100% | ✅ PASS |

---

## ⭐ PASO 7: COMPLETION [COMPLETADO - 100%]

### Resumen Ejecutivo (3-5 líneas):

Módulo l10n_cl_dte es arquitectónicamente sólido con 78% coverage y compliance SII correcto. **Crítico P0:** Refactorizar `account_move_dte.py` 1,450 LOC monolítico y habilitar XXE protection en XML parser. **Alta P1:** Aumentar coverage a 85%+, optimizar N+1 queries, completar modo contingencia Res. 68/2019. Migración zeep → httpx planificada 2025 Q2.

**Hallazgos clave:**
- ✅ **Fortalezas:** Integración SII SOAP robusta, retry logic exponential backoff, multi-company isolation
- ⚠️ **Mejoras críticas:** Refactorización monolito, XXE protection, coverage tests
- 🔴 **Bloqueantes:** Ninguno (módulo funcional en producción)

**Próximos pasos:**
1. Implementar R1 (refactorización) y R2 (XXE) en Sprint siguiente (P0)
2. Planificar aumento coverage a 85%+ (P1)
3. Iniciar análisis migración zeep → httpx (P2, 2025 Q2)

---

✅ **VALIDACIÓN FINAL:**
- Cumple requisitos P4-Deep: 1,380 palabras | 42 file refs | 8 verificaciones | 10 dimensiones
- Especificidad: 0.88 (>0.85 target)
- Formato estructurado con progreso transparente ✅

```

---

## 📖 ANEXOS Y REFERENCIAS

### Documentación SII Oficial
- **Resolución 80/2014**: Formato DTE y facturación electrónica
- **Resolución 68/2019**: Modo contingencia (DTE pendientes)
- **Resolución 61/2017**: Registro Compra-Venta (RCV) automatizado
- **Schema XSD oficial**: http://www.sii.cl/factura_electronica/formato_dte.pdf

### Código Laboral Chile (Payroll integration)
- **UF/UTM sync**: Banco Central Chile API
- **Retención IUE**: Ley de Impuesto a la Renta Art. 42 bis

### Odoo 19 CE Documentation
- **Model Inheritance**: https://www.odoo.com/documentation/19.0/developer/tutorials/server_framework_101/03_models.html
- **Computed Fields**: https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html#computed-fields
- **Testing Framework**: https://www.odoo.com/documentation/19.0/developer/reference/backend/testing.html

---

**Última Actualización:** 2025-11-11  
**Versión Prompt:** 1.0.0  
**Autor:** EERGYGROUP - Ing. Pedro Troncoso Willz  
**Basado en:** Template P4-Deep (docs/prompts_desarrollo/templates/prompt_p4_deep_template.md)
