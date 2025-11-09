# PLAN DE EJECUCIÓN FASE 0 AJUSTADO
## Post Quick Wins - Eliminación de Críticos Restantes

**Fecha:** 2025-11-07
**Objetivo:** Reducir críticos activos de 10 → 0 en ≤ 2.5 semanas (2 devs paralelo)
**Matriz Base:** `MATRIZ_BRECHAS_GLOBAL_CONSOLIDADA_2025-11-07.csv`

---

## ✅ QUICK WINS COMPLETADOS

| ID | Dominio | Acción | Esfuerzo | Estado | Evidencia |
|----|---------|--------|----------|--------|-----------|
| **DTE-C001** | DTE | Eliminar `_name` duplicado account.move | 5 min | ✅ **CERRADO** | account_move_dte.py:57 |
| **NOM-M002** | NÓMINA | Agregar ACLs wizard LRE | 30 min | ✅ **CERRADO** | ir.model.access.csv:34-35 |

**Total cerrados:** 2 issues (1 CRÍTICO + 1 MEDIO)
**Tiempo invertido:** 35 minutos

---

## 🔥 CRÍTICOS ACTIVOS POST QUICK-WINS (10 issues)

| ID | Dominio | Descripción | Esfuerzo | PR Target | Prioridad |
|----|---------|-------------|----------|-----------|-----------|
| **DTE-C002** | DTE | FALTA TIMEOUT SOAP | 4h | PR-1 | P0-A |
| **NOM-C001** | NÓMINA | Tope AFP campo inexistente | 3h | PR-2 | P0-A |
| **REP-C001** | REPORTES | Models no importa submódulos | 6h | PR-3 | P0-B |
| **REP-C002** | REPORTES | Vista F29 campos inexistentes | 16h | PR-3 | P0-B |
| **REP-C003** | REPORTES | F29 cálculos TypeError | 20h | PR-3 | P0-B |
| **REP-C004** | REPORTES | F29 account.report XML | 18h | PR-3 | P0-B |
| **REP-C005** | REPORTES | F22 SII Integration KeyError | 8h | PR-3 | P0-B |
| **REP-C006** | REPORTES | Cron create_monthly_f29() | 10h | PR-3 | P0-B |
| **NOM-C002** | NÓMINA | Finiquito ausente | 60h | PR-4 | P0-C |
| **NOM-C003** | NÓMINA | Export Previred ausente | 70h | PR-5 | P0-C |
| **QA-C001** | QA | Suite pytest unificada | 16h | PR-6 | P0-D |

**Total esfuerzo P0:** 231h

---

## 📋 PR SLICING - 6 PRs PARALELOS

### 🚀 PR-1: DTE-SOAP-TIMEOUT (Priority: P0-A)
**Branch:** `fix/dte-soap-timeout`
**Esfuerzo:** 4h
**Owner:** Dev Backend DTE
**Dependencias:** Ninguna
**Ejecutable:** ✅ Inmediatamente

#### Issues Cerrados
- DTE-C002: SOAP timeout + retry

#### Archivos Modificados
```
addons/localization/l10n_cl_dte/libs/sii_soap_client.py
addons/localization/l10n_cl_dte/tests/test_sii_soap_client.py (nuevo)
```

#### Checklist Implementación
- [ ] Configurar `session.timeout = (10, 30)` (connect, read)
- [ ] Implementar retry policy con backoff exponencial (3 intentos)
- [ ] Logging estructurado en timeout (correlationId + timestamp)
- [ ] Test: simular endpoint lento (> 30s) → validar timeout exception
- [ ] Test: simular endpoint 500 → validar 3 reintentos
- [ ] Documentar timeouts en docstring clase

#### Criterios Aceptación
- [ ] Timeout connect=10s, read=30s configurado
- [ ] Retry 3x con backoff 0.5s
- [ ] Test coverage ≥ 90% sii_soap_client.py
- [ ] No workers colgados en test stress

---

### 🚀 PR-2: NOMINA-TOPE-AFP-FIX (Priority: P0-A)
**Branch:** `fix/nomina-tope-afp`
**Esfuerzo:** 3h
**Owner:** Dev Backend Nómina
**Dependencias:** Ninguna
**Ejecutable:** ✅ Inmediatamente

#### Issues Cerrados
- NOM-C001: Búsqueda tope AFP campo inexistente

#### Archivos Modificados
```
addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml
addons/localization/l10n_cl_hr_payroll/data/l10n_cl_legal_caps_2025.xml
addons/localization/l10n_cl_hr_payroll/tests/test_payroll_calculation_p1.py
```

#### Checklist Implementación
- [ ] Agregar registro `AFP_TOPE_IMPONIBLE` en l10n_cl_legal_caps_2025.xml
  ```xml
  <record id="legal_cap_afp_tope_2025" model="l10n_cl.legal.caps">
    <field name="code">AFP_TOPE_IMPONIBLE</field>
    <field name="amount">81.6</field>
    <field name="unit">uf</field>
    <field name="valid_from">2025-01-01</field>
    <field name="valid_until">2025-12-31</field>
  </record>
  ```
- [ ] Corregir regla TOPE_IMPONIBLE_UF línea 85
  ```python
  # Buscar por método get_cap()
  cap_amount, cap_unit = env['l10n_cl.legal_caps'].get_cap(
      'AFP_TOPE_IMPONIBLE',
      payslip.date_to
  )
  if cap_unit == 'uf' and payslip.indicadores_id:
      result = cap_amount * payslip.indicadores_id.uf
  else:
      raise UserError(_('No se encontró tope AFP vigente para %s') % payslip.date_to)
  ```
- [ ] Eliminar fallback hardcoded línea 91-92
- [ ] Test: payslip con fecha 2025 → usa tope 81.6 UF
- [ ] Test: payslip sin indicadores → UserError

#### Criterios Aceptación
- [ ] Registro AFP_TOPE_IMPONIBLE cargado en BD
- [ ] Regla usa get_cap() correctamente
- [ ] Sin fallback hardcoded
- [ ] Test cobertura regla TOPE_IMPONIBLE_UF ≥ 95%

---

### 🚀 PR-3: REPORTES-F29-F22-CORE (Priority: P0-B)
**Branch:** `fix/reportes-f29-f22-core`
**Esfuerzo:** 78h (dividir en sub-PRs si necesario)
**Owner:** Dev Backend Reportes (lead) + QA
**Dependencias:** Ninguna
**Ejecutable:** ✅ Inmediatamente
**Sugerencia:** Dividir en 3 sub-PRs secuenciales

#### Issues Cerrados
- REP-C001: Imports submódulos
- REP-C002: Vista F29 campos
- REP-C003: F29 cálculos
- REP-C004: F29 XML account.report
- REP-C005: F22 SII Integration
- REP-C006: Cron create_monthly_f29()

#### Sub-PR 3.1: Imports + Modelo Base (12h)
**Archivos:**
```
addons/localization/l10n_cl_financial_reports/models/__init__.py
addons/localization/l10n_cl_financial_reports/models/core/__init__.py
addons/localization/l10n_cl_financial_reports/models/services/__init__.py
addons/localization/l10n_cl_financial_reports/tests/test_model_loading.py (nuevo)
```

**Checklist:**
- [ ] Agregar `from . import core` en models/__init__.py
- [ ] Agregar `from . import services` en models/__init__.py
- [ ] Test smoke: verificar modelos existen
  ```python
  def test_models_loaded(self):
      self.assertTrue(self.env['financial.report.service.registry'])
      self.assertTrue(self.env['account.financial.report.sii.integration.service'])
  ```

#### Sub-PR 3.2: F29 Vista + Cálculo (32h)
**Archivos:**
```
addons/localization/l10n_cl_financial_reports/models/l10n_cl_f29.py
addons/localization/l10n_cl_financial_reports/views/l10n_cl_f29_views.xml
addons/localization/l10n_cl_financial_reports/tests/test_f29_calculation.py (nuevo)
```

**Checklist:**
- [ ] Agregar campos faltantes en l10n_cl_f29.py
  ```python
  period_string = fields.Char(compute='_compute_period_string')
  ventas_gravadas = fields.Monetary(compute='_compute_ventas')
  compras_total = fields.Monetary(compute='_compute_compras')
  move_ids = fields.Many2many('account.move')
  folio = fields.Char()
  sii_track_id = fields.Char()
  ```
- [ ] Implementar métodos acción
  ```python
  def action_send_sii(self):
      # Mock service call
      sii_service = self.env['account.financial.report.sii.integration.service']
      return sii_service.send_f29(self)

  def action_check_status(self):
      # Check track_id status
      pass

  def action_replace(self):
      # Replace F29
      pass
  ```
- [ ] Corregir action_calculate
  ```python
  def action_calculate(self):
      # Normalizar period_date
      period_date = fields.Date.to_date(self.period_date)

      # Buscar movimientos por tags impuestos
      ventas_afectas_tag = self.env.ref('l10n_cl.tag_ventas_afectas')
      moves = self.env['account.move'].search([
          ('date', '>=', period_date.replace(day=1)),
          ('date', '<=', period_date),
          ('company_id', '=', self.company_id.id),
          ('state', '=', 'posted'),
      ])

      # Calcular bases por tax tags
      self.ventas_gravadas = sum(moves.mapped(lambda m: m.amount_tax_signed if ventas_afectas_tag in m.tax_tag_ids else 0))
      # ... cálculo completo con NC/ND + multi-company
  ```
- [ ] Test: cálculo básico con movimientos
- [ ] Test: multi-company isolation

#### Sub-PR 3.3: F29 XML + F22 + Cron (34h)
**Archivos:**
```
addons/localization/l10n_cl_financial_reports/data/account_report_f29_cl_data.xml
addons/localization/l10n_cl_financial_reports/data/l10n_cl_tax_forms_cron.xml
addons/localization/l10n_cl_financial_reports/models/l10n_cl_f22.py
addons/localization/l10n_cl_financial_reports/tests/test_f29_report.py (nuevo)
```

**Checklist:**
- [ ] Reescribir XML con comandos (0,0,values)
  ```xml
  <record id="report_f29_cl" model="account.report">
    <field name="name">Formulario 29 SII</field>
    <field name="line_ids" eval="[
      (0, 0, {
        'name': 'Débito Fiscal IVA',
        'code': 'F29_20',
        'expression_ids': [(0, 0, {
          'label': 'balance',
          'engine': 'tax_tags',
          'formula': 'ventas_afectas_iva',
        })],
      }),
      (0, 0, {
        'name': 'Crédito Fiscal IVA',
        'code': 'F29_520',
        ...
      }),
    ]"/>
  </record>
  ```
- [ ] Crear tax tags F29_20, F29_520, etc.
- [ ] Implementar create_monthly_f29() o retirar cron
  ```python
  @api.model
  def create_monthly_f29(self):
      """Crea F29 mensual por compañía."""
      companies = self.env['res.company'].search([])
      for company in companies:
          existing = self.search([
              ('company_id', '=', company.id),
              ('period_date', '=', fields.Date.today().replace(day=1)),
          ])
          if not existing:
              self.create({
                  'company_id': company.id,
                  'period_date': fields.Date.today().replace(day=1),
              })
  ```
- [ ] Eliminar creación manual ir.model en cron XML
- [ ] Fix F22 action_calculate (usar service correcto)
- [ ] Test: carga reporte F29
- [ ] Test: cron crea F29 sin duplicados

#### Criterios Aceptación PR-3 Global
- [ ] Modelos core/services cargados
- [ ] Vista F29 carga sin MissingError
- [ ] Cálculo F29 funciona con movimientos reales
- [ ] XML F29 importa correctamente
- [ ] F22 no lanza KeyError
- [ ] Cron funciona o está retirado documentadamente
- [ ] Test coverage ≥ 85% archivos tocados
- [ ] QueryCounter: F29 cálculo < 50 queries

---

### 🚀 PR-4: NOMINA-FINIQUITO (Priority: P0-C)
**Branch:** `feat/nomina-finiquito`
**Esfuerzo:** 60h
**Owner:** Dev Backend Nómina (lead) + Legal Reviewer
**Dependencias:** PR-2 (opcional, puede ser paralelo)
**Ejecutable:** ✅ Inmediatamente

#### Issues Cerrados
- NOM-C002: Finiquito ausente

#### Archivos Creados/Modificados
```
addons/localization/l10n_cl_hr_payroll/wizards/hr_payslip_severance_wizard.py (nuevo)
addons/localization/l10n_cl_hr_payroll/wizards/hr_payslip_severance_wizard_views.xml (nuevo)
addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
addons/localization/l10n_cl_hr_payroll/i18n/es_CL.po
addons/localization/l10n_cl_hr_payroll/i18n/en_US.po
addons/localization/l10n_cl_hr_payroll/tests/test_severance_calculation.py (nuevo)
```

#### Checklist Implementación
- [ ] Crear modelo wizard
  ```python
  class HrPayslipSeveranceWizard(models.TransientModel):
      _name = 'hr.payslip.severance.wizard'
      _description = 'Wizard Finiquito'

      employee_id = fields.Many2one('hr.employee', required=True)
      termination_date = fields.Date(required=True)
      termination_reason = fields.Selection([
          ('resignation', 'Renuncia Voluntaria'),
          ('dismissal_justified', 'Despido Justificado Art. 160'),
          ('dismissal_unjustified', 'Despido Injustificado'),
          ('mutual_agreement', 'Mutuo Acuerdo'),
      ], required=True)
      years_of_service = fields.Float(compute='_compute_years_service')

      # Indemnizaciones
      vacation_days_pending = fields.Float()
      indemnizacion_years = fields.Monetary(compute='_compute_indemnizacion')
      aviso_previo_amount = fields.Monetary(compute='_compute_aviso_previo')

      @api.depends('employee_id', 'termination_date')
      def _compute_years_service(self):
          # Calcular años servicio
          pass

      @api.depends('termination_reason', 'years_of_service')
      def _compute_indemnizacion(self):
          # Art. 162-163: 30 días por año (max 11 años)
          for rec in self:
              if rec.termination_reason == 'dismissal_unjustified':
                  years = min(rec.years_of_service, 11)
                  monthly_salary = rec.employee_id.contract_id.wage
                  rec.indemnizacion_years = (monthly_salary / 30) * 30 * years
              else:
                  rec.indemnizacion_years = 0
  ```
- [ ] Implementar cálculos Art. 162-177 CT
  - Vacaciones proporcionales (días pendientes × sueldo diario)
  - Indemnización años servicio (30 días × año, max 11 años)
  - Aviso previo (solo si aplicable según razón término)
  - Gratificación proporcional
- [ ] Vista wizard con campos claros
- [ ] Acción generar payslip finiquito
- [ ] ACLs wizard
- [ ] i18n completo (es_CL + en_US)
- [ ] Tests:
  - Caso base: 5 años servicio, despido injustificado
  - Edge: 15 años servicio (max 11 para indemnización)
  - Edge: Renuncia voluntaria (sin indemnización)
  - Validar cálculos con casos SII/DT

#### Criterios Aceptación
- [ ] Wizard funcional desde menú Nómina
- [ ] Cálculos Art. 162 correctos (validados con casos DT)
- [ ] Genera payslip tipo "finiquito"
- [ ] Test coverage ≥ 90%
- [ ] i18n es_CL/en_US ≥ 95% strings
- [ ] Sin hardcoding montos legales (usa indicadores)
- [ ] Documentación con referencias Art. CT

---

### 🚀 PR-5: NOMINA-PREVIRED-EXPORT (Priority: P0-C)
**Branch:** `feat/nomina-previred-export`
**Esfuerzo:** 70h
**Owner:** Dev Backend Nómina + Compliance Reviewer
**Dependencias:** PR-2 (opcional)
**Ejecutable:** ✅ Inmediatamente

#### Issues Cerrados
- NOM-C003: Export Previred ausente

#### Archivos Creados/Modificados
```
addons/localization/l10n_cl_hr_payroll/wizards/previred_export_wizard.py (nuevo)
addons/localization/l10n_cl_hr_payroll/wizards/previred_export_wizard_views.xml (nuevo)
addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
addons/localization/l10n_cl_hr_payroll/data/previred_campo_mapping.xml (nuevo)
addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv
addons/localization/l10n_cl_hr_payroll/i18n/es_CL.po
addons/localization/l10n_cl_hr_payroll/i18n/en_US.po
addons/localization/l10n_cl_hr_payroll/tests/test_previred_export.py (nuevo)
```

#### Checklist Implementación
- [ ] Crear wizard export
  ```python
  class PreviredExportWizard(models.TransientModel):
      _name = 'previred.export.wizard'
      _description = 'Exportar Previred 105 Campos'

      period_month = fields.Selection([...], required=True)
      period_year = fields.Integer(required=True)
      company_id = fields.Many2one('res.company', required=True)
      payslip_run_id = fields.Many2one('hr.payslip.run')

      export_file = fields.Binary(readonly=True)
      export_filename = fields.Char(readonly=True)

      def action_generate_previred(self):
          # Buscar payslips del período
          payslips = self.env['hr.payslip'].search([
              ('date_from', '>=', ...),
              ('date_to', '<=', ...),
              ('company_id', '=', self.company_id.id),
              ('state', '=', 'done'),
          ])

          # Generar archivo 105 campos
          csv_lines = []
          for payslip in payslips:
              line = self._build_previred_line(payslip)
              csv_lines.append(line)

          csv_content = '\n'.join(csv_lines)
          self.export_file = base64.b64encode(csv_content.encode('utf-8'))
          self.export_filename = f'Previred_{self.period_year}_{self.period_month}.txt'
  ```
- [ ] Mapeo 105 campos Previred (según especificación Previred 2025)
  - Campos empleador (RUT, razón social, etc.)
  - Campos trabajador (RUT, nombres, AFP, ISAPRE, etc.)
  - Campos remuneración (haberes, descuentos, líquido)
  - Campos previsionales (AFP, salud, AFC, SIS, APV)
  - Campos tributarios (impuesto único, retenciones)
- [ ] Validaciones formato
  - Longitud campos
  - Formatos numéricos (sin decimales, separadores)
  - Validación RUT checksums
  - Validación códigos AFP/ISAPRE contra catálogo oficial
- [ ] Vista wizard con parámetros período
- [ ] Acción descarga archivo
- [ ] ACLs wizard
- [ ] i18n completo
- [ ] Tests:
  - Generar archivo con 3 payslips
  - Validar 105 columnas presentes
  - Validar encabezados correctos
  - Validar formatos numéricos
  - Edge: payslip sin AFP (validación)

#### Criterios Aceptación
- [ ] Wizard funcional desde menú Nómina
- [ ] Genera archivo TXT con 105 campos
- [ ] Formato conforme especificación Previred 2025
- [ ] Validaciones obligatorias implementadas
- [ ] Test genera archivo parseabl por validador Previred
- [ ] Test coverage ≥ 90%
- [ ] i18n es_CL/en_US ≥ 95%
- [ ] Documentación con referencia especificación Previred

---

### 🚀 PR-6: QA-BASE-SUITE (Priority: P0-D)
**Branch:** `feat/qa-base-suite`
**Esfuerzo:** 16h
**Owner:** QA Lead
**Dependencias:** PR-1, PR-2, PR-3 (para smoke tests completos)
**Ejecutable:** ⏳ Después de PR-1/2/3 o en paralelo con mocks

#### Issues Cerrados
- QA-C001: Suite pytest unificada

#### Archivos Creados/Modificados
```
pytest.ini (raíz proyecto)
.coveragerc (raíz proyecto)
addons/localization/tests/conftest.py (nuevo)
addons/localization/tests/__init__.py (nuevo)
addons/localization/tests/test_smoke_dte.py (nuevo)
addons/localization/tests/test_smoke_nomina.py (nuevo)
addons/localization/tests/test_smoke_reportes.py (nuevo)
.github/workflows/pytest-coverage.yml (nuevo)
```

#### Checklist Implementación
- [ ] Configurar pytest.ini
  ```ini
  [pytest]
  python_files = test_*.py
  python_classes = Test*
  python_functions = test_*
  testpaths = addons/localization
  addopts =
      -v
      --strict-markers
      --cov=addons/localization
      --cov-report=term-missing
      --cov-report=html:coverage_html
      --cov-report=xml:coverage.xml
      --cov-fail-under=85
  markers =
      smoke: Smoke tests (quick validation)
      unit: Unit tests
      integration: Integration tests
      performance: Performance tests
  ```
- [ ] Configurar .coveragerc
  ```ini
  [run]
  source = addons/localization
  omit =
      */tests/*
      */migrations/*
      */__pycache__/*

  [report]
  precision = 2
  show_missing = True
  skip_covered = False
  ```
- [ ] Smoke test DTE
  ```python
  @pytest.mark.smoke
  def test_dte_soap_client_timeout():
      """Validar SOAP client tiene timeout configurado."""
      client = SIISoapClient(env)
      assert client.session.timeout == (10, 30)

  @pytest.mark.smoke
  def test_dte_xml_signer_no_duplicate_name():
      """Validar account.move no tiene _name duplicado."""
      # Read account_move_dte.py
      content = open('...').read()
      assert '_name = "account.move"' not in content
  ```
- [ ] Smoke test Nómina
  ```python
  @pytest.mark.smoke
  def test_payslip_afp_cap_exists():
      """Validar tope AFP existe en l10n_cl.legal_caps."""
      cap = env['l10n_cl.legal_caps'].search([
          ('code', '=', 'AFP_TOPE_IMPONIBLE'),
      ])
      assert cap, "Tope AFP no encontrado"

  @pytest.mark.smoke
  def test_lre_wizard_acl_exists():
      """Validar ACLs wizard LRE existen."""
      acl = env['ir.model.access'].search([
          ('model_id.model', '=', 'hr.lre.wizard'),
      ])
      assert len(acl) >= 2, "Faltan ACLs wizard LRE"
  ```
- [ ] Smoke test Reportes
  ```python
  @pytest.mark.smoke
  def test_financial_models_loaded():
      """Validar modelos financieros cargados."""
      assert env['financial.report.service.registry']
      assert env['account.financial.report.sii.integration.service']

  @pytest.mark.smoke
  def test_f29_view_loads():
      """Validar vista F29 carga sin error."""
      view = env.ref('l10n_cl_financial_reports.view_l10n_cl_f29_form')
      assert view
  ```
- [ ] Configurar CI pipeline GitHub Actions
  ```yaml
  name: Pytest Coverage
  on: [push, pull_request]
  jobs:
    test:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v3
        - name: Set up Python
          uses: actions/setup-python@v4
          with:
            python-version: '3.11'
        - name: Install dependencies
          run: |
            pip install -r requirements.txt
            pip install pytest pytest-cov pytest-odoo
        - name: Run tests
          run: pytest
        - name: Upload coverage
          uses: codecov/codecov-action@v3
          with:
            file: ./coverage.xml
  ```
- [ ] Generar reporte coverage inicial

#### Criterios Aceptación
- [ ] pytest ejecuta desde raíz proyecto
- [ ] Smoke tests ≥ 1 por dominio (DTE, Nómina, Reportes)
- [ ] Coverage report generado (HTML + XML)
- [ ] Coverage global ≥ 85% (o baseline medido)
- [ ] CI pipeline GitHub Actions funcional
- [ ] Documentación cómo ejecutar tests (README)

---

## 📊 DEPENDENCIAS Y ORDEN DE EJECUCIÓN

### Grafo de Dependencias

```
                    ┌─────────────┐
                    │  QuickWins  │
                    │  (CERRADO)  │
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┬─────────────┐
            │              │              │             │
       ┌────▼─────┐   ┌────▼─────┐  ┌────▼─────┐  ┌───▼────┐
       │   PR-1   │   │   PR-2   │  │   PR-4   │  │  PR-5  │
       │ DTE-SOAP │   │ NOM-AFP  │  │ NOM-FIN  │  │ NOM-PRE│
       │   (4h)   │   │   (3h)   │  │  (60h)   │  │ (70h)  │
       └────┬─────┘   └────┬─────┘  └──────────┘  └────────┘
            │              │
            │         ┌────▼─────┐
            │         │   PR-3   │
            │         │ REP-F29  │
            │         │  (78h)   │
            │         └────┬─────┘
            │              │
            └──────────────┼──────────────┐
                           │              │
                      ┌────▼─────┐        │
                      │   PR-6   │        │
                      │ QA-SUITE │        │
                      │  (16h)   │        │
                      └──────────┘        │
                                          │
                                    ┌─────▼──────┐
                                    │  FASE 0    │
                                    │  COMPLETA  │
                                    └────────────┘
```

### Orden de Ejecución Sugerido

**Semana 1 (Paralelo - 2 devs):**
- Dev 1: PR-1 (4h) → PR-3.1 (12h) → PR-3.2 (32h)
- Dev 2: PR-2 (3h) → PR-4 inicio (40h)

**Semana 2 (Paralelo):**
- Dev 1: PR-3.3 (34h) → PR-6 (16h)
- Dev 2: PR-4 completar (20h) → PR-5 inicio (30h)

**Semana 3 (Finalización):**
- Dev 1: QA reviews + fixes
- Dev 2: PR-5 completar (40h) + tests

**Total tiempo calendario:** ~2.5 semanas con 2 devs en paralelo

---

## ✅ GUARDRAILS Y ESTÁNDARES

### Código
- [ ] Sin nuevos hardcodes regulatorios
- [ ] Usar `valid_from/valid_until` para vigencias
- [ ] Campos computados con `store` explícito
- [ ] Sin `eval()` inseguro en server actions

### i18n
- [ ] Nuevos strings marcados traducibles `_('...')`
- [ ] Export POT y traducciones es_CL/en_US
- [ ] Cobertura ≥ 95% strings nuevos

### Performance
- [ ] QueryCounter en cálculos (F29, payslip, finiquito)
- [ ] Limitar queries < 50 por acción
- [ ] Tests performance con datasets realistas

### Testing
- [ ] Smoke tests mínimo (1 por funcionalidad)
- [ ] Tests negativos (edge cases, errores esperados)
- [ ] Coverage ≥ 85% archivos tocados

### Documentación
- [ ] CHANGELOG entry por PR
- [ ] Docstrings métodos públicos
- [ ] Referencias legales (Art. CT, Res. SII, etc.)

---

## 📝 TEMPLATE PR

```markdown
## [PR-X] Título Descriptivo

**Issues Cerrados:** #DTE-C00X, #NOM-C00X
**Dominio:** DTE / Nómina / Reportes / QA
**Esfuerzo:** Xh
**Branch:** `fix/nombre-descriptivo`

### Objetivo
Breve descripción (1-2 líneas) del problema resuelto.

### Cambios
- Lista de archivos modificados/creados
- Descripción cambios principales

### Riesgos
- Posibles efectos secundarios
- Áreas que requieren atención

### Tests
- [ ] Tests unitarios agregados (X tests)
- [ ] Coverage ≥ 85% archivos tocados
- [ ] Smoke test funcional
- [ ] QueryCounter validado (< 50 queries)

### Performance
- Baseline: X ms
- Después fix: Y ms
- Queries: Z

### i18n
- [ ] Strings traducibles marcados
- [ ] es_CL.po actualizado
- [ ] en_US.po actualizado

### Evidencias
- Screenshots (si UI)
- Logs tests exitosos
- Coverage report snippet

### Checklist
- [ ] Sin hardcoding valores legales
- [ ] CHANGELOG entry agregado
- [ ] Docstrings actualizados
- [ ] Código revisado (self-review)
- [ ] Tests locales PASS
- [ ] No introduce issues nuevos

### Referencias
- Auditoría: `AUDITORIA_*.md`
- Issues relacionados: #XX, #YY
- Normativa: Art. XXX CT / Res. SII XXX

---
🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## 🎯 MÉTRICAS DE ÉXITO FASE 0

### KPIs Target

| Métrica | Baseline | Target | Medición |
|---------|----------|--------|----------|
| **Issues CRÍTICOS** | 12 | 0 | Matriz CSV |
| **Test Coverage Global** | ~60% estimado | ≥ 85% | pytest --cov |
| **F29 Funcional** | No | Sí | Smoke test |
| **Finiquito Funcional** | No | Sí | Smoke test |
| **Previred Export Funcional** | No | Sí | Smoke test |
| **SOAP Timeouts** | No | Sí | Test stress |
| **Tope AFP Dinámico** | No | Sí | Test payslip |

### Definition of Done Global

- [ ] 0 issues P0 (CRÍTICO) ABIERTOS
- [ ] 6 PRs mergeados a main/develop
- [ ] Suite pytest base ejecutable
- [ ] Coverage ≥ 85% módulos tocados
- [ ] CI pipeline funcional (GitHub Actions)
- [ ] CHANGELOG actualizado por PR
- [ ] Matriz brechas actualizada (post-Fase0)
- [ ] Smoke tests 100% PASS
- [ ] Sin regresiones introducidas

---

## 📅 CRONOGRAMA DETALLADO (2 Devs)

### Semana 1 (Lun-Vie)

**Dev 1 (Backend DTE + Reportes):**
- Lun: PR-1 DTE-SOAP-TIMEOUT (4h) → abrir PR
- Mar: PR-3.1 Imports (6h) + inicio PR-3.2
- Mié-Jue: PR-3.2 F29 Vista+Cálculo (26h restantes)
- Vie: Finalizar PR-3.2 (6h) + review PR-2

**Dev 2 (Backend Nómina):**
- Lun: PR-2 NOM-TOPE-AFP (3h) → abrir PR
- Mar-Jue: PR-4 Finiquito wizard + cálculos (32h)
- Vie: Continuar PR-4 (8h)

### Semana 2 (Lun-Vie)

**Dev 1:**
- Lun-Mar: PR-3.3 F29 XML + F22 + Cron (16h)
- Mié: Finalizar PR-3.3 (8h) + abrir PR
- Jue-Vie: PR-6 QA-BASE-SUITE (16h) + integración

**Dev 2:**
- Lun: Finalizar PR-4 (12h)
- Mar: Tests PR-4 + abrir PR
- Mié-Vie: PR-5 Previred wizard + mapping (24h)

### Semana 3 (Lun-Mié)

**Dev 1:**
- Lun: QA reviews + fixes menores
- Mar: Integración final + smoke tests
- Mié: Documentación + matriz actualizada

**Dev 2:**
- Lun-Mar: Finalizar PR-5 (40h restantes)
- Mié: Tests PR-5 + abrir PR + merge

**Jueves:** Release Fase 0 ✅

---

## 🚀 SIGUIENTE: IMPLEMENTACIÓN

**Comando para comenzar:**
```bash
# Verificar estado actual
cd /Users/pedro/Documents/odoo19
git status
git log --oneline -5

# Crear branches
git checkout -b fix/dte-soap-timeout
git checkout main
git checkout -b fix/nomina-tope-afp

# Ejecutar tests baseline
pytest addons/localization/ -v --cov
```

**Prioridad inmediata:** PR-1 y PR-2 (7h total) → Quick impact

**¿Proceder con implementación PR-1?**
