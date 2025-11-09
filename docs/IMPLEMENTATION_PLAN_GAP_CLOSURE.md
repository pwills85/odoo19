# Plan de Implementación - Cierre de Brechas SII + Optimizaciones

**Fecha Inicio:** 2025-10-29
**Ingeniero Lead:** Pedro Troncoso (Senior Developer)
**Proyecto:** l10n_cl_dte - Gap Closure Complete
**Timeline:** 10 semanas
**Metodología:** Agile Sprints (1 semana cada uno)

---

## 🎯 Objetivo

Cerrar TODAS las brechas identificadas:
- **P0-P2:** Compliance SII (8 semanas)
- **Optimizaciones:** UX Improvements (2 semanas adicionales)

---

## 📋 Sprint Planning

### FASE 1: P0 - CRÍTICO (4 semanas)

#### Sprint 1: Autenticación SII + EnvioDTE (Semana 1-2)

**Archivos a modificar/crear:**
```
addons/localization/l10n_cl_dte/
├── libs/
│   ├── sii_soap_client.py          # MODIFICAR: Agregar auth
│   ├── sii_authenticator.py        # CREAR: getSeed/getToken
│   ├── envio_dte_generator.py      # CREAR: EnvioDTE + Carátula
│   └── xml_generator.py            # MODIFICAR: Integrar EnvioDTE
├── models/
│   ├── account_move_dte.py         # MODIFICAR: Usar EnvioDTE
│   └── res_company_dte.py          # MODIFICAR: Campos resolución
└── tests/
    ├── test_sii_authenticator.py   # CREAR
    └── test_envio_dte.py            # CREAR
```

**Tareas Sprint 1:**
- [x] Day 1-2: Implementar `SIIAuthenticator` (getSeed/getToken)
- [ ] Day 3-4: Implementar `EnvioDTEGenerator` (Carátula + envoltorio)
- [ ] Day 5-6: Modificar `SIISoapClient` integrar autenticación
- [ ] Day 7-8: Modificar `account_move_dte.py` usar EnvioDTE
- [ ] Day 9-10: Testing + debugging

**Entregable Sprint 1:**
✅ DTEs enviados con EnvioDTE firmado + autenticación válida

---

#### Sprint 2: TED Firmado + XSD Validation (Semana 3-4)

**Archivos a modificar/crear:**
```
addons/localization/l10n_cl_dte/
├── libs/
│   ├── ted_generator.py            # MODIFICAR: Firma FRMT con CAF
│   ├── caf_manager.py              # CREAR: Extract private key
│   └── xsd_validator.py            # MODIFICAR: Validación obligatoria
├── models/
│   ├── account_move_dte.py         # MODIFICAR: Campo dte_ted_xml
│   └── dte_caf.py                  # MODIFICAR: Extracción llave
├── static/xsd/                      # CREAR: Descargar XSDs oficiales
│   ├── DTE_v10.xsd
│   ├── FacturaAfectaExenta_v10.xsd
│   ├── NotaCredito_v10.xsd
│   ├── NotaDebito_v10.xsd
│   ├── GuiaDespacho_v10.xsd
│   └── EnvioDTE_v10.xsd
├── report/
│   └── report_invoice_dte_document.xml  # MODIFICAR: Usar dte_ted_xml
└── tests/
    ├── test_ted_generator.py       # CREAR
    └── test_xsd_validator.py       # CREAR
```

**Tareas Sprint 2:**
- [ ] Day 1-2: Descargar XSDs oficiales SII + configurar
- [ ] Day 3-4: Implementar extracción llave privada CAF
- [ ] Day 5-6: Completar firma FRMT en `ted_generator.py`
- [ ] Day 7-8: Agregar campo `dte_ted_xml` + migration
- [ ] Day 9-10: Testing + integración PDF417 en reporte

**Entregable Sprint 2:**
✅ TED completo firmado + validación XSD obligatoria + PDF417 funcional

---

### FASE 2: P1 - ALTO (3 semanas)

#### Sprint 3: Fix Tipos DTE 34/52/56/61 (Semana 5)

**Archivos a modificar:**
```
addons/localization/l10n_cl_dte/
├── libs/
│   └── xml_generator.py            # MODIFICAR: Normalizar contratos
├── models/
│   └── account_move_dte.py         # MODIFICAR: _prepare_dte_data_native
└── tests/
    ├── test_dte_34.py              # CREAR
    ├── test_dte_52.py              # CREAR
    ├── test_dte_56.py              # CREAR
    └── test_dte_61.py              # CREAR
```

**Tareas Sprint 3:**
- [ ] Day 1-2: Mapear campos requeridos por tipo DTE
- [ ] Day 3-4: Normalizar `_prepare_dte_data_native()`
- [ ] Day 5-6: Ajustar generadores XML por tipo
- [ ] Day 7: Testing cada tipo DTE

**Entregable Sprint 3:**
✅ Tipos 34/52/56/61 generan correctamente sin KeyError

---

#### Sprint 4: Consulta Estado + Resp. Comerciales (Semana 6-7)

**Archivos a modificar/crear:**
```
addons/localization/l10n_cl_dte/
├── libs/
│   └── sii_soap_client.py          # MODIFICAR: Fix query_status
├── models/
│   ├── account_move_dte.py         # MODIFICAR: Fix método status
│   └── dte_inbox.py                # MODIFICAR: Resp comerciales nativas
├── wizards/
│   └── dte_commercial_response_wizard.py  # MODIFICAR: Llamadas nativas
└── tests/
    ├── test_query_status.py        # CREAR
    └── test_commercial_responses.py # CREAR
```

**Tareas Sprint 4:**
- [ ] Day 1-2: Corregir `query_dte_status` naming bug
- [ ] Day 3-4: Implementar query status con auth
- [ ] Day 5-7: Implementar respuestas comerciales nativas SII
- [ ] Day 8-10: Testing + integración

**Entregable Sprint 4:**
✅ Consulta estado funcional + respuestas comerciales nativas

---

### FASE 3: P2 - MEDIO (1 semana)

#### Sprint 5: Fixes Menores (Semana 8)

**Archivos a modificar:**
```
addons/localization/l10n_cl_dte/
├── libs/
│   └── sii_soap_client.py          # FIX: Timeout zeep
├── models/
│   ├── account_move_dte.py         # FIX: Remover _name
│   ├── dte_certificate.py          # FIX: SQL constraints
│   └── dte_caf.py                  # FIX: SQL constraints
├── report/
│   └── account_move_dte_report.py  # FIX: TED field
└── tests/
    └── test_constraints.py         # CREAR
```

**Tareas Sprint 5:**
- [ ] Day 1: Fix timeout zeep Transport
- [ ] Day 2: Corregir SQL constraints
- [ ] Day 3: Remover `_name` en account.move extension
- [ ] Day 4: Fix reporte PDF TED field
- [ ] Day 5: Testing + cleanup

**Entregable Sprint 5:**
✅ Todos los fixes P2 aplicados + código limpio

---

### FASE 4: DEPLOYMENT (1 semana)

#### Sprint 6: Testing Integral + Deploy (Semana 9)

**Tareas Sprint 6:**
- [ ] Day 1-2: Testing integral todos los flujos
- [ ] Day 3: Testing con sandbox SII (Maullin)
- [ ] Day 4: Performance testing + optimization
- [ ] Day 5: Deploy staging + smoke tests
- [ ] Day 6: Deploy producción + monitoring
- [ ] Day 7: Post-deployment support + hotfixes

**Entregable Sprint 6:**
✅ Sistema en producción 100% compliant SII

---

### FASE 5 (OPCIONAL): OPTIMIZACIONES UX (2 semanas)

#### Sprint 7-8: Optimizaciones UX

**Features:**
1. PDF Guías DTE 52 ($2,250)
2. Import BHE XML ($4,050)
3. Certificado Retención PDF ($3,150)
4. Dashboard Enhanced ($4,050)
5. AI Email Routing ($4,950)

**Nota:** Esta fase es OPCIONAL y se ejecutará solo si hay presupuesto/tiempo.

---

## 🏗️ Arquitectura de Solución

### Componentes Nuevos

```
l10n_cl_dte/
├── libs/
│   ├── sii_authenticator.py        # NEW: Autenticación SII
│   ├── envio_dte_generator.py      # NEW: EnvioDTE + Carátula
│   ├── caf_manager.py              # NEW: CAF private key extraction
│   └── [existing files modified]
├── models/
│   └── [existing files modified]
├── static/xsd/                      # NEW: XSD schemas oficiales
└── tests/                           # NEW: 20+ test files
```

### Flujo Completo Post-Implementation

```python
# 1. Usuario confirma factura
invoice.action_post()

# 2. Genera DTE XML
dte_xml = invoice._generate_dte_xml()

# 3. Valida contra XSD
validator.validate_dte_xml(dte_xml, dte_type='33')  # ✅ XSD OK

# 4. Genera TED firmado
ted_xml = invoice._generate_ted_with_caf()  # ✅ FRMT firmado
invoice.dte_ted_xml = ted_xml

# 5. Crea EnvioDTE + Carátula
envio_xml = envio_generator.create_envio_dte(
    dtes=[dte_xml],
    caratula={
        'RutEmisor': company.vat,
        'RutEnvia': user.vat,
        'RutReceptor': partner.vat,
        'FchResol': company.dte_fecha_resolucion,
        'NroResol': company.dte_numero_resolucion,
    }
)

# 6. Firma EnvioDTE completo
envio_firmado = xml_signer.sign_envio_dte(envio_xml)

# 7. Autentica con SII
token = authenticator.get_token()  # ✅ getSeed + getToken

# 8. Envía a SII con autenticación
response = soap_client.send_envio_dte(
    envio_firmado,
    token=token
)

# 9. Procesa respuesta
if response.track_id:
    invoice.dte_track_id = response.track_id
    invoice.dte_status = 'sent'
    # ✅ DTE enviado exitosamente
```

---

## 🧪 Testing Strategy

### Test Coverage Target: 90%

**Unit Tests (40+ tests):**
```
tests/
├── test_sii_authenticator.py           # 5 tests
├── test_envio_dte_generator.py         # 8 tests
├── test_ted_generator.py               # 6 tests
├── test_caf_manager.py                 # 4 tests
├── test_xsd_validator.py               # 6 tests
├── test_dte_types/
│   ├── test_dte_33.py                  # 3 tests
│   ├── test_dte_34.py                  # 3 tests
│   ├── test_dte_52.py                  # 3 tests
│   ├── test_dte_56.py                  # 3 tests
│   └── test_dte_61.py                  # 3 tests
└── test_integration/
    ├── test_full_flow_emission.py      # 5 tests
    ├── test_full_flow_reception.py     # 3 tests
    └── test_sii_sandbox.py             # 4 tests (requiere sandbox)
```

**Integration Tests:**
- End-to-end emisión DTE con SII sandbox
- End-to-end recepción + respuesta comercial
- Performance tests (100 DTEs simultáneos)

**Manual UAT:**
- 10 facturas reales en sandbox Maullin
- Verificación PDF417 con scanner
- Consulta estado SII cada DTE
- Envío respuestas comerciales

---

## 📊 Success Criteria

### Post-Sprint 2 (P0 Complete):
- [ ] DTEs envían con EnvioDTE + auth → Aceptados por SII
- [ ] TED firma FRMT correctamente → PDF417 escaneable
- [ ] XSD validation → 100% DTEs válidos pre-envío
- [ ] Test coverage → >80%

### Post-Sprint 4 (P1 Complete):
- [ ] Tipos 34/52/56/61 → Sin errores runtime
- [ ] Consulta estado → Funcional
- [ ] Resp. comerciales → Enviadas correctamente
- [ ] Test coverage → >85%

### Post-Sprint 5 (P2 Complete):
- [ ] Zero bugs conocidos P0-P2
- [ ] Código limpio, sin warnings
- [ ] Test coverage → >90%

### Post-Sprint 6 (Production):
- [ ] Sistema en producción
- [ ] Monitoring activo
- [ ] Zero downtime deployment
- [ ] Rollback plan tested

---

## ⚠️ Risk Management

| Riesgo | Probabilidad | Impact | Mitigación |
|--------|--------------|--------|------------|
| **Cambios API SII durante dev** | Baja | Alto | Monitoreo continuo docs SII |
| **Certificado digital expira** | Baja | Alto | Validación pre-sprint |
| **CAF sin llave privada** | Media | Alto | Verificar formato CAF con SII |
| **XSD schemas desactualizados** | Baja | Medio | Descargar últimas versiones |
| **Timeout sandbox SII** | Media | Bajo | Retry logic + exponential backoff |
| **Performance degradation** | Media | Medio | Load testing continuo |

---

## 💰 Budget Tracking

### Inversión por Fase:

| Fase | Sprints | Horas | Costo | Status |
|------|---------|-------|-------|--------|
| **P0 - Crítico** | 1-2 | 160h | $14,400 | 🟡 In Progress |
| **P1 - Alto** | 3-4 | 100h | $9,000 | ⚪ Pending |
| **P2 - Medio** | 5 | 40h | $3,600 | ⚪ Pending |
| **Deploy** | 6 | 40h | $3,600 | ⚪ Pending |
| **TOTAL P0-P2** | 1-6 | **340h** | **$30,600** | - |
| **UX Opt (Opcional)** | 7-8 | 80h | $7,200 | ⚪ Optional |
| **GRAN TOTAL** | 1-8 | **420h** | **$37,800** | - |

**Nota:** Budget puede ajustarse eliminando Sprint 7-8 (UX Opt).

---

## 📅 Timeline Visual

```
Oct 29 - Nov 2  ████████████ Sprint 1: Auth + EnvioDTE (Week 1)
Nov 3 - Nov 9   ████████████ Sprint 1: Auth + EnvioDTE (Week 2)

Nov 10 - Nov 16 ████████████ Sprint 2: TED + XSD (Week 3)
Nov 17 - Nov 23 ████████████ Sprint 2: TED + XSD (Week 4)

Nov 24 - Nov 30 ████████████ Sprint 3: Fix DTE Types (Week 5)

Dec 1 - Dec 7   ████████████ Sprint 4: Status + Responses (Week 6)
Dec 8 - Dec 14  ████████████ Sprint 4: Status + Responses (Week 7)

Dec 15 - Dec 21 ████████████ Sprint 5: P2 Fixes (Week 8)

Dec 22 - Dec 28 ████████████ Sprint 6: Testing + Deploy (Week 9)

                ⚪⚪⚪⚪⚪⚪⚪⚪ Sprint 7-8: UX Opt (Optional)
```

**Fecha Entrega Estimada:** Diciembre 28, 2025 (P0-P2 completo)

---

## 🚀 Deployment Strategy

### Environments:

**Development:**
- Branch: `feature/gap-closure-complete`
- Testing: Local + unit tests
- Deploy: Manual

**Staging:**
- Branch: `develop`
- Testing: Integration + sandbox SII
- Deploy: Automated on merge
- URL: https://staging.eergygroup.cl

**Production:**
- Branch: `main`
- Testing: Smoke tests
- Deploy: Manual approval required
- URL: https://erp.eergygroup.cl

### Deployment Checklist:

**Pre-Deployment:**
- [ ] All tests passing (unit + integration)
- [ ] Code review completed
- [ ] XSD schemas in place
- [ ] Database migration tested
- [ ] Backup production DB
- [ ] Rollback plan ready
- [ ] Stakeholders notified

**Deployment:**
```bash
# 1. Backup
pg_dump odoo19_prod > backup_gap_closure_$(date +%Y%m%d).sql

# 2. Deploy code
git checkout main
git merge feature/gap-closure-complete
git push origin main

# 3. Update module
docker-compose exec odoo odoo-bin -c /etc/odoo/odoo.conf \
  -d odoo19_prod \
  -u l10n_cl_dte \
  --stop-after-init

# 4. Restart
docker-compose restart odoo

# 5. Smoke tests
python3 scripts/smoke_tests.py --env production
```

**Post-Deployment:**
- [ ] Smoke tests pass
- [ ] Monitor logs 24h
- [ ] Test 5 DTEs reales
- [ ] Verify SII acceptance
- [ ] User training scheduled

---

## 📞 Communication Plan

### Daily Standups:
- **Time:** 9:00 AM CL
- **Duration:** 15 min
- **Attendees:** Dev team + Product Owner
- **Format:** What done / What doing / Blockers

### Weekly Reviews:
- **Time:** Friday 4:00 PM CL
- **Duration:** 1 hour
- **Attendees:** All stakeholders
- **Format:** Demo + retrospective + planning

### Slack Channels:
- `#l10n-cl-dte-dev` - Development updates
- `#l10n-cl-dte-bugs` - Bug reports
- `#l10n-cl-dte-deploy` - Deployment notifications

---

## 📄 Documentation Deliverables

- [ ] Technical Architecture Document
- [ ] API Documentation (libs/)
- [ ] Database Schema Changes
- [ ] Migration Guide (Odoo 11 → 19)
- [ ] User Manual (español)
- [ ] Admin Manual (español)
- [ ] Testing Guide
- [ ] Deployment Runbook

---

## ✅ Definition of Done

### Sprint-level DoD:
- [ ] Code written + reviewed
- [ ] Unit tests written + passing
- [ ] Integration tests passing (if applicable)
- [ ] Documentation updated
- [ ] No regressions introduced
- [ ] Deployed to staging
- [ ] Product Owner approval

### Release-level DoD:
- [ ] All sprint DoDs met
- [ ] Test coverage >90%
- [ ] Performance benchmarks met
- [ ] Security audit passed
- [ ] Deployed to production
- [ ] Monitoring confirmed working
- [ ] User training completed

---

**Documento Preparado Por:** Pedro Troncoso, Senior Developer
**Fecha:** 2025-10-29
**Versión:** 1.0
**Status:** ✅ PLAN APPROVED - READY TO EXECUTE

---

*Este plan maestro guiará la implementación completa del cierre de brechas.*
