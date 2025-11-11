# 🔍 **PROMPT MASTER - AUDITORÍA PROFUNDA MÓDULO l10n_cl_dte**

**Fecha:** 10 de Noviembre de 2025  
**Versión:** 3.0 Enterprise  
**Objetivo:** Auditoría exhaustiva 360° módulo facturación electrónica chilena  
**Scope:** Odoo 19 CE + SII Compliance + Integration + Security  

---

## 🎯 **OBJETIVO DE LA AUDITORÍA**

Realizar una **auditoría profunda y exhaustiva** del módulo `l10n_cl_dte` (Facturación Electrónica Chilena) cubriendo:

1. ✅ **Cumplimiento Odoo 19 CE** - Estándares técnicos, arquitectura, patterns
2. ✅ **Cumplimiento SII Chile** - Regulación, DTEs, formatos, seguridad
3. ✅ **Integración Base Suite** - account, stock, purchase, hr
4. ✅ **Seguridad Enterprise** - XXE, encryption, RBAC, audit
5. ✅ **Performance** - Tiempos respuesta, N+1 queries, caching
6. ✅ **Testing & QA** - Coverage, edge cases, mocking
7. ✅ **Documentación** - Código, README, knowledge base
8. ✅ **AI Integration** - Microservicio, endpoints, prompts

---

## 📁 **CONTEXTO DEL MÓDULO**

### **Información General**
```yaml
Nombre: Chilean Localization - Electronic Invoicing (DTE)
Código: l10n_cl_dte
Versión: 19.0.6.0.0
Ubicación: /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/
Líneas de Código: ~18,388 líneas
Archivos: 100+ archivos (models, libs, views, wizards, tests)
Estado: ✅ Production Ready (Certificado v1.0.5)
Score Actual: 95/100 (pre-auditoria)
```

### **Estructura del Módulo**
```
l10n_cl_dte/
├── __manifest__.py         # Metadata, dependencies, versión
├── models/ (40+ archivos)  # ORM integration
│   ├── account_move_dte.py # Core: Facturación
│   ├── dte_certificate.py  # Certificados digitales
│   ├── dte_caf.py          # Folios autorizados
│   ├── dte_communication.py # SII SOAP
│   ├── dte_inbox.py        # Recepción DTEs
│   └── ... (35+ modelos)
├── libs/ (15+ archivos)    # Pure Python business logic
│   ├── xml_generator.py    # Generación XML DTE
│   ├── xml_signer.py       # Firma XMLDSig
│   ├── sii_soap_client.py  # Cliente SOAP SII
│   ├── ted_generator.py    # Timbre Electrónico
│   └── ... (11+ librerías)
├── views/ (32 archivos)    # UI XML
├── wizards/ (11 archivos)  # User interactions
├── tests/ (30 archivos)    # Unit tests
├── security/               # Access control
├── data/                   # Master data
└── reports/                # PDF reports
```

### **DTEs en Scope**
```
EERGYGROUP B2B (Supported):
✅ DTE 33 - Factura Electrónica (con IVA)
✅ DTE 34 - Factura Exenta (sin IVA)
✅ DTE 52 - Guía de Despacho (traslado)
✅ DTE 56 - Nota de Débito (ajuste +)
✅ DTE 61 - Nota de Crédito (ajuste -)

NO Supported (Out of Scope):
❌ DTE 39 - Boleta Electrónica (B2C retail)
❌ DTE 41 - Boleta Exenta (B2C retail)
❌ DTE 110 - Factura Exportación
```

### **Dependencies (Críticas)**
```python
'depends': [
    'base',                            # Core Odoo
    'account',                         # Accounting
    'stock',                           # Inventory
    'purchase',                        # Purchases
    'l10n_latam_base',                # LATAM foundation
    'l10n_latam_invoice_document',    # Fiscal documents
    'l10n_cl',                        # Chilean chart of accounts
]
```

### **External Dependencies**
```python
'external_dependencies': {
    'python': [
        'lxml',          # XML processing
        'xmlsec',        # Digital signature XMLDSig
        'zeep',          # SOAP client SII
        'cryptography',  # Certificates encryption
        'pdf417',        # TED barcode
        'Pillow',        # Image processing
    ],
}
```

---

## 🔍 **DOMINIOS DE AUDITORÍA**

### **DOMINIO 1: CUMPLIMIENTO ODOO 19 CE** 🎨

#### **1.1. Arquitectura y Patterns**

**Checklist:**
- [ ] `libs/` contiene **SOLO pure Python classes** (NO `models.AbstractModel`)
- [ ] Uso correcto de `_inherit` (NO `_name` en extensiones)
- [ ] `@api.depends` con dependencies explícitas
- [ ] `@api.constrains` en lugar de `_sql_constraints` (deprecated)
- [ ] `@api.model_create_multi` para batch operations
- [ ] Computed fields con `store=True` cuando corresponde
- [ ] Dependency injection en libs/ cuando necesita `env`

**Preguntas Clave:**
```python
Q1: ¿Todos los archivos en libs/ son pure Python?
Q2: ¿Hay uso de models.AbstractModel en libs/?
Q3: ¿Se usa _inherit correctamente (sin duplicar core)?
Q4: ¿Computed fields tienen @api.depends completo?
Q5: ¿Se usa @api.constrains en lugar de _sql_constraints?
```

**Archivos a Revisar:**
```
✅ libs/*.py (todos deben ser pure Python)
✅ models/*.py (@api decorators, inheritance)
✅ __manifest__.py (dependencies correctas)
```

---

#### **1.2. Data Loading Order**

**Orden Correcto (CRITICAL):**
```xml
1. security/security_groups.xml      # PRIMERO: Grupos
2. security/multi_company_rules.xml  # Record rules
3. security/ir.model.access.csv      # Access rights
4. data/*.xml                         # Master data
5. wizards/*.xml                      # Wizards (actions)
6. views/*.xml                        # Views (actions)
7. views/menus.xml                    # ÚLTIMO: Menus
```

**Checklist:**
- [ ] `security/` es el primer item en `data` list
- [ ] `menus.xml` es el último item
- [ ] Wizards antes de views (actions referenciadas)
- [ ] No hay referencias circulares

**Archivos a Revisar:**
```
✅ __manifest__.py (data loading order)
```

---

#### **1.3. Multi-Company Support**

**Checklist:**
- [ ] `company_id` SOLO en datos transaccionales (no en master data)
- [ ] Record rules para multi-company en modelos transaccionales
- [ ] `default=lambda self: self.env.company` en company_id fields
- [ ] Master data (comunas, activity codes) SIN company_id

**Modelos Transaccionales (deben tener company_id):**
```python
✅ dte.certificate
✅ dte.caf
✅ account.move (hereda de account)
✅ dte.inbox
✅ dte.libro
```

**Master Data (NO deben tener company_id):**
```python
❌ l10n.cl.comuna (347 comunas - shared)
❌ sii.activity.code (catalog - shared)
❌ retencion.iue.tasa (historical rates - shared)
```

**Archivos a Revisar:**
```
✅ models/dte_certificate.py (company_id + rule)
✅ models/l10n_cl_comuna.py (NO company_id)
✅ security/multi_company_rules.xml
```

---

#### **1.4. Security & Access Control**

**Checklist:**
- [ ] Grupos definidos (user, manager)
- [ ] Access rights (ir.model.access.csv completo)
- [ ] Record rules (multi-company)
- [ ] Métodos con `@api.model` para permission validation
- [ ] NO hardcoded passwords/secrets en código

**Archivos a Revisar:**
```
✅ security/security_groups.xml
✅ security/ir.model.access.csv
✅ security/multi_company_rules.xml
```

---

### **DOMINIO 2: CUMPLIMIENTO SII CHILE** 🇨🇱

#### **2.1. DTEs Soportados (Scope Verification)**

**Checklist:**
- [ ] DTE 33 (Factura Electrónica) - Implementado
- [ ] DTE 34 (Factura Exenta) - Implementado
- [ ] DTE 52 (Guía Despacho) - Implementado
- [ ] DTE 56 (Nota Débito) - Implementado
- [ ] DTE 61 (Nota Crédito) - Implementado
- [ ] DTEs fuera de scope documentados (39, 41, 110)

**Preguntas Clave:**
```
Q1: ¿Se generan XML válidos para cada tipo de DTE?
Q2: ¿Se valida contra XSD oficial SII?
Q3: ¿Se incluye TED (Timbre Electrónico)?
Q4: ¿Se firma con XMLDSig PKCS#1?
```

**Archivos a Revisar:**
```
✅ libs/xml_generator.py (generación por DTE type)
✅ libs/xsd_validator.py (validación schemas)
✅ libs/ted_generator.py (timbre)
✅ libs/xml_signer.py (firma digital)
✅ data/dte_document_types.xml (tipos configurados)
```

---

#### **2.2. RUT Validation (Módulo 11)**

**Checklist:**
- [ ] Algoritmo módulo 11 implementado correctamente
- [ ] Soporte para 3 formatos: storage (12345678-5), SII XML (12345678-5), display (12.345.678-5)
- [ ] Validación en campos `vat` de partners y companies
- [ ] Soporte para prefijo 'CL' opcional

**Archivos a Revisar:**
```
✅ tools/rut_validator.py (algoritmo)
✅ models/res_partner_dte.py (validación partner)
✅ models/res_company_dte.py (validación company)
✅ tests/test_rut_validator.py (10+ test cases)
```

---

#### **2.3. CAF Management (Folios Autorizados)**

**Regulación:** Resolución SII 11/2014

**Checklist:**
- [ ] Carga archivo CAF desde SII
- [ ] Validación firma digital CAF (RSASK + RSAPUBK)
- [ ] Extracción rango folios (desde, hasta)
- [ ] Asignación secuencial de folios
- [ ] Alertas cuando CAF agotado
- [ ] Encriptación private key CAF (Fernet AES-128)

**Archivos a Revisar:**
```
✅ models/dte_caf.py (gestión CAF)
✅ libs/caf_handler.py (parsing CAF XML)
✅ libs/caf_signature_validator.py (validación firma)
✅ tests/test_caf_*.py (test cases)
```

---

#### **2.4. Digital Signature (XMLDSig)**

**Estándar:** W3C XMLDSig, PKCS#1
**Algoritmo SII:** RSA-SHA1 (requerido por SII)

**Checklist:**
- [ ] Certificado digital SII clase 2/3
- [ ] Firma XMLDSig con xmlsec library
- [ ] Canonicalización C14N
- [ ] Digest SHA1 (requerido SII)
- [ ] Verificación post-firma
- [ ] Encriptación certificado en storage

**Security:**
- [ ] Private key NUNCA en plain text
- [ ] Decryption solo en memoria
- [ ] Certificados encriptados con Fernet (AES-128)

**Archivos a Revisar:**
```
✅ libs/xml_signer.py (firma XMLDSig)
✅ models/dte_certificate.py (gestión certificados)
✅ tools/encryption_helper.py (encriptación)
✅ tests/test_xml_signature.py
```

---

#### **2.5. SII SOAP Communication**

**Endpoints:**
```
Certificación: https://maullin.sii.cl/DTEWS/
Producción:    https://palena.sii.cl/DTEWS/
```

**Servicios:**
```
1. EnvioDTE      → Envío DTE
2. getEstDte     → Consulta estado
3. RCV           → Registro Compra/Venta
```

**Checklist:**
- [ ] Cliente SOAP (zeep library)
- [ ] Autenticación SII (token)
- [ ] Retry logic (exponential backoff)
- [ ] Timeout configuration
- [ ] 59 códigos error SII mapeados
- [ ] Polling automático estado (cron)

**Archivos a Revisar:**
```
✅ libs/sii_soap_client.py (SOAP client)
✅ libs/sii_authenticator.py (autenticación)
✅ libs/sii_error_codes.py (59 códigos)
✅ models/dte_communication.py (orchestration)
✅ data/ir_cron_dte_status_poller.xml (polling)
```

---

#### **2.6. TED (Timbre Electrónico)**

**Estándar:** PDF417 barcode

**Checklist:**
- [ ] Generación TED por DTE
- [ ] Datos: RUT, folio, fecha, monto, firma CAF
- [ ] Código PDF417 generado (pdf417 library)
- [ ] Validación post-generación
- [ ] TED incluido en PDF report

**Archivos a Revisar:**
```
✅ libs/ted_generator.py (generación TED)
✅ libs/ted_validator.py (validación)
✅ report/report_invoice_dte_document.xml (PDF con TED)
```

---

#### **2.7. Libro de Ventas/Compras**

**Obligación:** Envío mensual al SII

**Checklist:**
- [ ] Libro de Ventas (DTEs emitidos)
- [ ] Libro de Compras (DTEs recibidos)
- [ ] Libro de Guías (DTE 52)
- [ ] Formato XML según schema SII
- [ ] Firma digital libro
- [ ] Envío automático mensual (cron)

**Archivos a Revisar:**
```
✅ models/dte_libro.py (libros ventas/compras)
✅ models/dte_libro_guias.py (libro guías)
✅ libs/libro_guias_generator.py (generación XML)
✅ data/cron_jobs.xml (envío mensual)
```

---

#### **2.8. Referencias (NC/ND)**

**Obligación:** Resolución SII 80/2014

**Checklist:**
- [ ] Notas de Crédito referencian factura original
- [ ] Notas de Débito referencian factura original
- [ ] Campos: RUT emisor, tipo DTE, folio, fecha
- [ ] Validación referencias en XML

**Archivos a Revisar:**
```
✅ models/account_move_reference.py (referencias)
✅ models/account_move_enhanced.py (integration)
✅ libs/xml_generator.py (inclusión en XML)
```

---

### **DOMINIO 3: INTEGRACIÓN BASE SUITE** 🔗

#### **3.1. Integración account.move**

**Checklist:**
- [ ] `_inherit = 'account.move'` (NO _name)
- [ ] Campos DTE agregados (dte_status, dte_folio, dte_xml)
- [ ] NO duplica campos existentes
- [ ] Mantiene workflow Odoo (draft → posted → paid)
- [ ] Botones DTE en form view
- [ ] Validaciones no rompen core

**Archivos a Revisar:**
```
✅ models/account_move_dte.py
✅ views/account_move_views.xml
✅ tests/test_account_move_integration.py
```

---

#### **3.2. Integración stock.picking**

**DTE 52 - Guía de Despacho**

**Checklist:**
- [ ] `_inherit = 'stock.picking'`
- [ ] Generación DTE 52 desde picking
- [ ] Datos traslado (dirección, transporte)
- [ ] NO duplica funcionalidad stock
- [ ] Workflow compatible

**Archivos a Revisar:**
```
✅ models/stock_picking_dte.py
✅ views/stock_picking_views.xml
✅ libs/dte_52_generator.py (específico DTE 52)
```

---

#### **3.3. Integración purchase.order**

**DTE 34 - Factura Exenta (Honorarios)**

**Checklist:**
- [ ] `_inherit = 'purchase.order'`
- [ ] Generación Boleta Honorarios
- [ ] Cálculo retención IUE automático
- [ ] NO duplica PO workflow

**Archivos a Revisar:**
```
✅ models/purchase_order_dte.py
✅ models/boleta_honorarios.py
✅ models/retencion_iue.py (cálculo retención)
```

---

#### **3.4. Integración res.partner**

**Checklist:**
- [ ] `_inherit = 'res.partner'`
- [ ] Validación RUT (campo vat)
- [ ] Activity codes chilenos
- [ ] Giro comercial
- [ ] Comuna chilena (347 comunas)

**Archivos a Revisar:**
```
✅ models/res_partner_dte.py
✅ data/l10n_cl_comunas_data.xml (347 comunas)
✅ data/sii_activity_codes_full.xml (códigos CIIU)
```

---

#### **3.5. Integración res.company**

**Checklist:**
- [ ] `_inherit = 'res.company'`
- [ ] RUT empresa validado
- [ ] Certificado digital asociado
- [ ] Activity codes empresa
- [ ] Multi-company isolation

**Archivos a Revisar:**
```
✅ models/res_company_dte.py
✅ models/res_company_bank_info.py (datos bancarios)
```

---

### **DOMINIO 4: SEGURIDAD ENTERPRISE** 🔒

#### **4.1. XXE Protection**

**Vulnerabilidad:** XML External Entity (OWASP A4:2017)

**Checklist:**
- [ ] Parser XML con `no_network=True`
- [ ] `dtd_validation=False`
- [ ] `load_dtd=False`
- [ ] `resolve_entities=False`
- [ ] Usar `safe_xml_parser.py` en todos los parseos

**Archivos a Revisar:**
```
✅ libs/safe_xml_parser.py (parser seguro)
✅ libs/xml_generator.py (uso safe parser)
✅ libs/caf_handler.py (uso safe parser)
✅ models/dte_inbox.py (recepción DTEs externos)
```

---

#### **4.2. Certificate Encryption**

**Checklist:**
- [ ] Private keys NUNCA en plain text
- [ ] Encriptación Fernet (AES-128)
- [ ] Decryption solo en memoria
- [ ] Key rotation support
- [ ] Certificados expirados detectados

**Archivos a Revisar:**
```
✅ models/dte_certificate.py (gestión)
✅ tools/encryption_helper.py (Fernet)
✅ libs/xml_signer.py (decryption en memoria)
```

---

#### **4.3. SQL Injection Prevention**

**Checklist:**
- [ ] SIEMPRE usar ORM (self.env['model'].search())
- [ ] NUNCA usar raw SQL con user input
- [ ] Si usa cr.execute, usar parámetros (%s)
- [ ] NO usar string formatting en SQL

**Archivos a Revisar:**
```
✅ ALL models/*.py (buscar cr.execute)
```

---

#### **4.4. RBAC (Role-Based Access Control)**

**Checklist:**
- [ ] Grupos: dte_user, dte_manager
- [ ] Access rights granulares
- [ ] Record rules multi-company
- [ ] Métodos sensibles con @api.model

**Archivos a Revisar:**
```
✅ security/security_groups.xml
✅ security/ir.model.access.csv
✅ security/multi_company_rules.xml
```

---

#### **4.5. Audit Logging**

**Checklist:**
- [ ] Log operaciones críticas (firma, envío SII)
- [ ] Track ID en logs
- [ ] Timestamps precisos
- [ ] Structured logging
- [ ] Retention 7 años (Art. 54 CT)

**Archivos a Revisar:**
```
✅ libs/structured_logging.py
✅ models/dte_communication.py (logging SII)
✅ models/account_move_dte.py (logging operaciones)
```

---

### **DOMINIO 5: PERFORMANCE** ⚡

#### **5.1. N+1 Query Detection**

**Anti-Pattern:**
```python
# ❌ BAD: N+1 queries
for invoice in invoices:
    partner = invoice.partner_id.name  # Query por invoice
```

**Pattern:**
```python
# ✅ GOOD: Prefetch
invoices = self.env['account.move'].search([]).with_context(prefetch_fields=True)
for invoice in invoices:
    partner = invoice.partner_id.name  # Cached
```

**Archivos a Revisar:**
```
✅ ALL models/*.py (buscar loops con acceso relacional)
```

---

#### **5.2. Computed Fields Optimization**

**Checklist:**
- [ ] Computed fields con `store=True` si acceso frecuente
- [ ] `@api.depends` completo (no missing dependencies)
- [ ] NO computed fields en loops
- [ ] Batch computation cuando posible

**Archivos a Revisar:**
```
✅ models/dte_caf.py (folio_remaining computed)
✅ models/account_move_dte.py (dte_status computed)
```

---

#### **5.3. ORM Cache Usage**

**Checklist:**
- [ ] `@tools.ormcache` para operaciones costosas
- [ ] Cache invalidation cuando datos cambian
- [ ] NO cachear data transaccional

**Archivos a Revisar:**
```
✅ models/res_partner_dte.py (RUT formatting cached)
```

---

#### **5.4. Batch Operations**

**Checklist:**
- [ ] `@api.model_create_multi` para create
- [ ] `write()` en batch (no one-by-one)
- [ ] `unlink()` en batch
- [ ] Single transaction para operaciones múltiples

**Archivos a Revisar:**
```
✅ ALL models/*.py (buscar create/write/unlink)
```

---

#### **5.5. Response Time Targets**

**SLA:**
```
✅ DTE Generation: < 500ms (p95)
✅ SII Send: < 2000ms (p95) [incluye red]
✅ Status Polling: < 1000ms (p95)
✅ Report PDF: < 800ms (p95)
```

**Archivos a Revisar:**
```
✅ libs/performance_metrics.py (timing decorators)
✅ tests/ (performance tests)
```

---

### **DOMINIO 6: TESTING & QA** 🧪

#### **6.1. Test Coverage**

**Target:** 80% (ALCANZADO según README)

**Checklist:**
- [ ] Unit tests para libs/ (pure Python)
- [ ] Integration tests para models/
- [ ] Mock de servicios externos (SII SOAP)
- [ ] Edge cases cubiertos
- [ ] Test data realista

**Archivos a Revisar:**
```
✅ tests/ (30+ archivos test)
✅ tests/test_rut_validator.py (10+ cases)
✅ tests/test_xml_signature.py (signature)
✅ tests/test_sii_communication.py (mocks)
```

---

#### **6.2. Test Patterns Odoo 19**

**Checklist:**
- [ ] `TransactionCase` para unit tests
- [ ] `@tagged('post_install', '-at_install')`
- [ ] `setUp()` con datos test
- [ ] `assertRaises` para validations
- [ ] NO tests dependientes entre sí

**Archivos a Revisar:**
```
✅ tests/test_*.py (convenciones)
```

---

#### **6.3. Mocking External Services**

**Checklist:**
- [ ] SII SOAP mocked (`@patch`)
- [ ] Certificados test disponibles
- [ ] CAF test válidos
- [ ] NO llamadas reales a SII en tests

**Archivos a Revisar:**
```
✅ tests/test_sii_communication.py
✅ tests/fixtures/ (datos test)
```

---

### **DOMINIO 7: DOCUMENTACIÓN** 📚

#### **7.1. Code Documentation**

**Checklist:**
- [ ] Docstrings en todos los métodos públicos
- [ ] Type hints cuando corresponde
- [ ] Inline comments para lógica compleja
- [ ] Regulación SII referenciada (Resolución N°)

**Archivos a Revisar:**
```
✅ libs/*.py (docstrings)
✅ models/*.py (docstrings)
```

---

#### **7.2. README & User Docs**

**Checklist:**
- [ ] README.md completo
- [ ] README.rst (Odoo App Store)
- [ ] CHANGELOG.md actualizado
- [ ] Instrucciones instalación
- [ ] Ejemplos de uso

**Archivos a Revisar:**
```
✅ README.md
✅ README.rst
✅ CHANGELOG.md
✅ static/description/index.html
```

---

#### **7.3. Knowledge Base**

**Checklist:**
- [ ] `.github/agents/knowledge/sii_regulatory_context.md` actualizado
- [ ] `.knowledge-base-unified/` referenciando módulo
- [ ] Documentación SII (Resoluciones, schemas)

**Archivos a Revisar:**
```
✅ .github/agents/knowledge/sii_regulatory_context.md
✅ .knowledge-base-unified/regulatory/
```

---

### **DOMINIO 8: AI INTEGRATION** 🤖

#### **8.1. AI Service Integration**

**Checklist:**
- [ ] AI Service para features NO críticas solamente
- [ ] DTE signature/validation usa libs/ nativas
- [ ] Endpoints AI documentados
- [ ] Retry logic en AI calls
- [ ] Fallback si AI no disponible

**Archivos a Revisar:**
```
✅ models/dte_ai_client.py
✅ models/ai_chat_integration.py
✅ ai-service/app/main.py (endpoints)
```

---

#### **8.2. AI Use Cases**

**Checklist:**
- [ ] AI Chat (Previred questions) ✅
- [ ] Project matching (ML) ✅
- [ ] Cost tracking analytics ✅
- [ ] Pre-validation DTEs (opcional)
- [ ] NO en critical path (firma, validación)

**Archivos a Revisar:**
```
✅ models/ai_agent_selector.py
✅ models/analytic_dashboard.py
```

---

## 🎯 **METODOLOGÍA DE AUDITORÍA**

### **Fase 1: Análisis Estructural** (15 min)

```bash
# Análisis automático de estructura
tree -L 3 addons/localization/l10n_cl_dte/

# Contar líneas de código
find addons/localization/l10n_cl_dte/ -name "*.py" | xargs wc -l

# Detectar patterns anti-Odoo 19
grep -r "models.AbstractModel" addons/localization/l10n_cl_dte/libs/
grep -r "_sql_constraints" addons/localization/l10n_cl_dte/models/
```

---

### **Fase 2: Auditoría por Dominio** (2-3 horas)

**Para cada dominio (1-8):**

1. **Leer Checklist** del dominio
2. **Revisar Archivos** listados
3. **Ejecutar Tests** (si aplica)
4. **Documentar Hallazgos:**
   ```
   - ✅ FORTALEZA: Descripción
   - ⚠️ WARNING: Descripción + Impacto
   - 🔴 CRÍTICO: Descripción + Solución Propuesta
   ```
5. **Asignar Score** (0-100) por dominio

---

### **Fase 3: Consolidación y Reporte** (30 min)

```markdown
## REPORTE FINAL AUDITORÍA

### Scores por Dominio

| Dominio | Score | Status |
|---------|-------|--------|
| Odoo 19 CE | X/100 | ✅⚠️🔴 |
| SII Compliance | X/100 | ✅⚠️🔴 |
| Integration | X/100 | ✅⚠️🔴 |
| Security | X/100 | ✅⚠️🔴 |
| Performance | X/100 | ✅⚠️🔴 |
| Testing | X/100 | ✅⚠️🔴 |
| Documentation | X/100 | ✅⚠️🔴 |
| AI Integration | X/100 | ✅⚠️🔴 |

**SCORE TOTAL:** XX/100

### Top 10 Hallazgos Críticos
1. [🔴 P0] ...
2. [⚠️ P1] ...
...

### Recomendaciones Prioritarias
- P0 (CRÍTICO): ...
- P1 (IMPORTANTE): ...
- P2 (NICE-TO-HAVE): ...
```

---

## 🚀 **ORQUESTACIÓN CLI**

### **CLI Assignments:**

```yaml
Codex CLI:
  Role: Compliance Specialist
  Focus:
    - Odoo 19 CE patterns
    - SII Compliance
    - Code quality
  Profiles: dte-specialist, odoo-dev
  Temperature: 0.05 (máxima precisión)

Gemini CLI:
  Role: Architecture Analyst
  Focus:
    - Integration analysis
    - Performance review
    - Security audit
  Model: gemini-1.5-ultra-002
  Temperature: 0.1
  Context: 2M tokens

Copilot CLI:
  Role: Testing & Documentation
  Focus:
    - Test coverage
    - Documentation completeness
    - Best practices
  Model: gpt-5
  Temperature: 0.1
```

---

## 📊 **OUTPUT ESPERADO**

### **Formato Reporte:**

```markdown
# AUDITORÍA PROFUNDA l10n_cl_dte - REPORTE FINAL

## Metadata
- Fecha: YYYY-MM-DD
- CLI: [Codex/Gemini/Copilot]
- Dominio: [Nombre]
- Tiempo: XX minutos

## Executive Summary
[3-4 líneas con hallazgos principales]

## Scores
| Dimensión | Score | Tendencia |
|-----------|-------|-----------|
| ...

## Hallazgos Detallados

### ✅ FORTALEZAS (Score 90-100)
1. ...

### ⚠️ WARNINGS (Score 70-89)
1. ...

### 🔴 CRÍTICOS (Score <70)
1. ...

## Recomendaciones Accionables

### P0 - URGENTE
- [ ] Acción 1
- [ ] Acción 2

### P1 - IMPORTANTE
- [ ] Acción 1

### P2 - MEJORAS
- [ ] Acción 1

## Archivos Revisados
- `archivo1.py` (líneas X-Y)
- `archivo2.xml` (completo)

## Tests Ejecutados
```bash
pytest tests/test_*.py -v
```

## Conclusión
[Score final + próximos pasos]
```

---

## ✅ **CRITERIOS DE ÉXITO**

1. ✅ **Todos los 8 dominios auditados**
2. ✅ **Score ≥ 90/100 para producción**
3. ✅ **Zero hallazgos críticos (P0)**
4. ✅ **Máximo 3 warnings (P1)**
5. ✅ **100% compliance SII verificado**
6. ✅ **Reporte consolidado generado**
7. ✅ **Plan de acción para gaps identificados**

---

**INICIO DE AUDITORÍA:** Al recibir este prompt

**TIEMPO ESTIMADO:** 2-3 horas (profunda)

**RESULTADO ESPERADO:** Reporte enterprise-grade con hallazgos accionables

---

🎯 **¡INICIAR AUDITORÍA AHORA!**

