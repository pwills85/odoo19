# PROMPT PROFESIONAL: CIERRE TOTAL BRECHAS L10N_CL_DTE
## Auditoría Integrada + Plan de Implementación Enterprise-Grade

**Fecha:** 2025-11-09  
**Proyecto:** EERGYGROUP Odoo 19 CE - Localización Chilena DTE  
**Alcance:** Cierre completo brechas P0 (Bloqueantes) + P1 (Alta Prioridad)  
**Metodología:** Evidence-based, Test-driven, Rollback-safe  
**Objetivo:** Production-ready 100/100 score

---

## 📋 CONTEXTO EJECUTIVO

### Auditorías Completadas

Se realizaron **3 auditorías complementarias** que identificaron brechas críticas:

1. **Auditoría Remota** (946 líneas)
   - Archivo: `.claude/AUDITORIA_L10N_CL_DTE_REPORTE_FINAL.md`
   - Score: 75/100 (2 false positives corregidos → 82/100)
   - Hallazgos: 8 (1 P0, 2 P1, 4 P2, 1 P3)

2. **Ratificación Código Real** (análisis local)
   - Verificación exhaustiva con código fuente
   - Corrección false positives (H3 DTE types, H5 datos maestros)
   - Descubrimiento: Certificado SII placeholder

3. **Análisis Complementario** (agente externo)
   - Enfoque: Compliance SII, modularidad, observabilidad
   - **Hallazgo crítico nuevo:** H9 Cumplimiento Normativo Incompleto (P0)
   - 15 sugerencias adicionales validadas

### Score Final Integrado

| Estado | Score | Certificación |
|--------|-------|---------------|
| **Actual** | **64/100** 🔴 | NO Production Ready |
| Post P0 (XXE) | 89/100 ✅ | Production Ready Básico |
| Post P0 (XXE + Compliance) | 89/100 ✅ | Production Ready Completo |
| **Post P0+P1** | **100/100** ⭐⭐⭐ | **Enterprise Grade** |

---

## 🔴 BRECHAS CRÍTICAS IDENTIFICADAS

### P0 - BLOQUEANTES PRODUCCIÓN (2 issues)

#### H1: XXE Vulnerability (OWASP A4:2017)
- **Severidad:** 🔴 P0 BLOCKER
- **Archivos afectados:** 16 archivos críticos
- **Descripción:** Uso de `etree.fromstring()` sin protección XXE
- **Impacto:** File disclosure, SSRF, DoS (billion laughs)
- **ETA:** 2-4 horas
- **Score impact:** -25 puntos

**Archivos críticos:**
```
libs/caf_signature_validator.py:181
libs/dte_structure_validator.py:80
libs/envio_dte_generator.py:139,141,257,259 (4 ocurrencias)
libs/sii_authenticator.py:180,346 (2 ocurrencias)
libs/ted_validator.py:69,278 (2 ocurrencias)
libs/xsd_validator.py:92
models/account_move_dte.py:1613,1616 (2 ocurrencias)
models/dte_caf.py:404
```

**Solución disponible:**
- ✅ `libs/safe_xml_parser.py` existe (enterprise-grade)
- ✅ `fromstring_safe()` implementado
- ✅ Tests `test_xxe_protection()` disponibles

---

#### H9: Cumplimiento Normativo SII Incompleto (NUEVO)
- **Severidad:** 🔴 P0 BLOCKER
- **Módulos afectados:** 3 reportes obligatorios SII
- **Descripción:** Esqueletos sin implementación real
- **Impacto:** Multas SII, incumplimiento fiscal chileno
- **ETA:** 40-60 horas
- **Score impact:** -15 puntos

**Reportes NO funcionales:**

1. **Consumo de Folios** (Mensual obligatorio)
   - Archivo: `models/dte_consumo_folios.py`
   - Estado: Placeholder línea 217-226
   - Formato: XML según Resolución Ex. SII
   - Envío: SOAP SII endpoint

2. **Libro de Compras** (Mensual obligatorio)
   - Archivo: `models/dte_libro.py`
   - Estado: Placeholder línea 225-234
   - Formato: XML IEC según instructivo SII
   - Envío: SOAP SII endpoint

3. **Libro de Ventas** (Mensual obligatorio)
   - Archivo: `models/dte_libro.py`
   - Estado: Placeholder línea 225-234
   - Formato: XML IEC según instructivo SII
   - Envío: SOAP SII endpoint

---

### P1 - ALTA PRIORIDAD (3 issues)

#### H2: Odoo Imports en libs/ (Arquitectura)
- **Severidad:** ⚠️ P1 ALTA
- **Archivos:** 2 (sii_authenticator.py, envio_dte_generator.py)
- **Descripción:** Viola patrón Pure Python Odoo 19
- **Impacto:** Testability, portabilidad, estándares
- **ETA:** 4-6 horas
- **Score impact:** -3 puntos

#### H10: Certificado SII Placeholder (Compliance)
- **Severidad:** ⚠️ P1 ALTA
- **Archivo:** `libs/caf_signature_validator.py:53-62`
- **Descripción:** Certificado autofirmado testing, no oficial SII
- **Impacto:** Validación CAF incorrecta en producción
- **ETA:** 2-3 horas
- **Score impact:** -3 puntos

#### H11: dte_inbox.py Monolítico (Calidad Código)
- **Severidad:** ⚠️ P1 ALTA
- **Archivo:** `models/dte_inbox.py` (1,237 líneas)
- **Descripción:** 6 responsabilidades en un solo modelo
- **Impacto:** Mantenibilidad, testing, escalabilidad
- **ETA:** 6-10 horas
- **Score impact:** -2 puntos

---

## 🎯 PLAN DE IMPLEMENTACIÓN ENTERPRISE-GRADE

### SPRINT 0: Preparación Mandatory (30 minutos)

**Objetivo:** Backup completo, rollback preparation

```bash
# 1. Backup SQL
docker exec odoo19_db pg_dump -U odoo odoo19 | gzip > \
  backups/pre_cierre_brechas_$(date +%Y%m%d_%H%M%S).sql.gz

# 2. Git checkpoint
git add .
git commit -m "chore(sprint0): checkpoint before comprehensive gap closure

- Pre H1-H11 fixes
- Baseline: 64/100 score
- 2 P0 blockers + 3 P1 high priority
- Backup: backups/pre_cierre_brechas_YYYYMMDD_HHMMSS.sql.gz"

git tag -a sprint_cierre_v4_baseline_$(date +%Y%m%d) -m "Baseline before gap closure V4"

# 3. Verificar tests baseline
cd addons/localization/l10n_cl_dte
pytest tests/ -v --tb=short -x
# Expected: 297 tests, 80%+ coverage
```

---

### SPRINT 1: H1 - Fix XXE Vulnerability (2-4h) 🔴 P0

**Objetivo:** Eliminar 100% usos inseguros `etree.fromstring()`, usar `fromstring_safe()`

#### Task 1.1: Refactor libs/ (9 archivos, 90 min)

**Patrón de refactor:**

```python
# ❌ ANTES (INSEGURO):
from lxml import etree
root = etree.fromstring(xml_string.encode('utf-8'))

# ✅ DESPUÉS (SEGURO):
from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe
root = fromstring_safe(xml_string)
```

**Archivos a modificar:**

1. `libs/caf_signature_validator.py:181`
   - Método: `validate_signature()`
   - Contexto: Validación firma CAF SII
   - Critical: Procesa CAF files externos

2. `libs/dte_structure_validator.py:80`
   - Método: `validate_xml_structure()`
   - Contexto: Validación estructura DTE
   - Critical: Procesa DTEs recibidos proveedores

3. `libs/envio_dte_generator.py:139,141,257,259` (4 ocurrencias)
   - Métodos: `_add_dte_to_envio()`, `validate_envio()`
   - Contexto: Generación EnvioDTE para SII
   - Critical: Procesa DTEs antes envío

4. `libs/sii_authenticator.py:180,346` (2 ocurrencias)
   - Método: `_parse_seed_response()`, `_parse_token_response()`
   - Contexto: Respuestas SOAP SII
   - Critical: Man-in-the-middle vulnerable

5. `libs/ted_validator.py:69,278` (2 ocurrencias)
   - Métodos: `validate_ted()`, `extract_ted_data()`
   - Contexto: Timbre Electrónico DTE
   - Critical: Validación integridad documento

6. `libs/xsd_validator.py:92`
   - Método: `validate_against_xsd()`
   - Contexto: Validación esquemas XSD SII
   - Note: También usar `parse_safe()` para archivos XSD

#### Task 1.2: Refactor models/ (2 archivos, 30 min)

7. `models/account_move_dte.py:1613,1616` (2 ocurrencias)
   - Métodos: `_extract_dte_data()`, `_extract_ted_data()`
   - Contexto: ORM Odoo, extracción datos DTE
   - Import: `from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe`

8. `models/dte_caf.py:404`
   - Método: `_validate_caf_structure()`
   - Contexto: Validación archivo CAF
   - Critical: Gestión folios autorización SII

#### Task 1.3: Testing XXE Protection (60 min)

**Testing exhaustivo:**

```python
# tests/test_xxe_security.py (NUEVO)
from odoo.tests import TransactionCase, tagged
from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe, test_xxe_protection
from lxml import etree

@tagged('post_install', 'xxe_security', '-at_install')
class TestXXESecurity(TransactionCase):
    """
    Test suite para validar protección XXE en todos los parsers.
    
    OWASP A4:2017 - XML External Entities (XXE)
    CWE-611: Improper Restriction of XML External Entity Reference
    """
    
    def test_01_xxe_file_disclosure_blocked(self):
        """Test: External entity file disclosure debe ser bloqueado"""
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<CAF>
  <RUT>&xxe;</RUT>
</CAF>'''
        
        # Safe parser debe bloquear XXE
        with self.assertRaises(Exception):
            root = fromstring_safe(xxe_payload)
    
    def test_02_billion_laughs_blocked(self):
        """Test: Billion laughs attack debe ser bloqueado"""
        billion_laughs = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<CAF>&lol3;</CAF>'''
        
        with self.assertRaises(Exception):
            root = fromstring_safe(billion_laughs)
    
    def test_03_ssrf_blocked(self):
        """Test: SSRF via external entities debe ser bloqueado"""
        ssrf_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/secret">
]>
<DTE>&xxe;</DTE>'''
        
        with self.assertRaises(Exception):
            root = fromstring_safe(ssrf_payload)
    
    def test_04_safe_xml_parser_builtin_test(self):
        """Test: Función builtin test_xxe_protection()"""
        result = test_xxe_protection()
        self.assertTrue(result, "Built-in XXE protection test failed")
    
    def test_05_normal_xml_parsing_works(self):
        """Test: XML normal debe parsearse correctamente"""
        normal_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<DTE>
  <Documento>
    <Encabezado>
      <IdDoc>
        <TipoDTE>33</TipoDTE>
        <Folio>12345</Folio>
      </IdDoc>
    </Encabezado>
  </Documento>
</DTE>'''
        
        root = fromstring_safe(normal_xml)
        self.assertEqual(root.tag, 'DTE')
        self.assertIsNotNone(root.find('.//TipoDTE'))
```

**Ejecutar tests:**

```bash
# Test suite específico XXE
pytest tests/test_xxe_security.py -v --tb=short

# Regression: Todos los tests deben pasar
pytest tests/ -v --tb=short -x

# Coverage específico safe_xml_parser
pytest --cov=libs/safe_xml_parser --cov-report=term-missing tests/
# Target: 100% coverage safe_xml_parser.py
```

#### Task 1.4: Commit Atómico (15 min)

```bash
git add addons/localization/l10n_cl_dte/libs/*.py
git add addons/localization/l10n_cl_dte/models/account_move_dte.py
git add addons/localization/l10n_cl_dte/models/dte_caf.py
git add addons/localization/l10n_cl_dte/tests/test_xxe_security.py

git commit -m "fix(security): eliminate XXE vulnerability P0 (OWASP A4:2017)

CRITICAL SECURITY FIX - XXE Vulnerability (CWE-611)

Replace 16 unsafe etree.fromstring() calls with fromstring_safe():
- libs/: 9 files (caf_validator, dte_validator, envio_gen, sii_auth, ted_validator, xsd_validator)
- models/: 2 files (account_move_dte, dte_caf)

Protection implemented:
- resolve_entities=False (no external entities)
- no_network=True (no SSRF)
- dtd_validation=False (no DTD processing)
- load_dtd=False (no external DTD)

Testing:
- 5 new XXE security tests (file disclosure, billion laughs, SSRF)
- All 297 existing tests passing
- Coverage: 100% safe_xml_parser.py

Security References:
- OWASP Top 10 A4:2017 - XML External Entities (XXE)
- CWE-611: Improper Restriction of XML External Entity Reference
- SII DTEs: External sources (proveedores, SOAP responses, CAF files)

Impact:
- Score: 64/100 → 89/100 (+25 points)
- Production: BLOCKER REMOVED
- Security: Critical vulnerability eliminated

Related: .claude/AUDITORIA_L10N_CL_DTE_REPORTE_FINAL.md H1
Sprint: Cierre Brechas V4 - SPRINT 1"

# Tag milestone
git tag -a h1_xxe_fixed_$(date +%Y%m%d) -m "H1 XXE Vulnerability fixed - Score 89/100"
```

---

### SPRINT 2: H9 - Implementar Cumplimiento SII (40-60h) 🔴 P0

**Objetivo:** Implementar 100% funcional 3 reportes obligatorios SII

#### Task 2.1: Consumo de Folios (15-20h)

**Archivo:** `models/dte_consumo_folios.py`

**Especificación SII:**
- Formato: XML según Resolución Ex. SII
- Periodicidad: Mensual
- Contenido: Folios utilizados por tipo DTE
- Envío: SOAP SII endpoint `https://palena.sii.cl/DTEWS/services/`

**Implementación:**

```python
# models/dte_consumo_folios.py

def action_generar_y_enviar(self):
    """
    Genera XML de consumo de folios y envía al SII.
    
    Implementación completa según Resolución Ex. SII.
    """
    self.ensure_one()
    
    if not self.folio_inicio or not self.folio_fin:
        raise ValidationError(_('Debe calcular los folios primero'))
    
    # 1. Generar XML consumo folios
    xml_content = self._generate_consumo_xml()
    
    # 2. Firmar XML con certificado digital
    from odoo.addons.l10n_cl_dte.libs.xml_signer import XMLSigner
    signer = XMLSigner(env=self.env)
    
    signed_xml = signer.sign_xml(
        xml_content=xml_content,
        certificate=self.company_id.dte_certificate_id,
        reference_uri='#SetDTE'
    )
    
    # 3. Enviar a SII via SOAP
    from odoo.addons.l10n_cl_dte.libs.sii_soap_client import SIISOAPClient
    client = SIISOAPClient(env=self.env)
    
    response = client.send_consumo_folios(
        company=self.company_id,
        xml_content=signed_xml,
        periodo=self.periodo_mes
    )
    
    # 4. Procesar respuesta SII
    if response['status'] == 'accepted':
        self.write({
            'state': 'sent',
            'sii_track_id': response.get('track_id'),
            'sii_response_date': fields.Datetime.now(),
            'sii_response': response.get('message')
        })
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Consumo de Folios Enviado'),
                'message': _('Track ID: %s') % response.get('track_id'),
                'type': 'success',
            }
        }
    else:
        raise UserError(_('SII rechazó el consumo de folios: %s') % response.get('error'))

def _generate_consumo_xml(self):
    """
    Genera XML según formato SII Consumo de Folios.
    
    Estructura:
    <ConsumoFolios>
      <DocumentoConsumoFolios>
        <Caratula>...</Caratula>
        <Resumen>...</Resumen>
      </DocumentoConsumoFolios>
    </ConsumoFolios>
    
    Returns:
        str: XML generado sin firmar
    """
    from lxml import etree
    from datetime import datetime
    
    # Namespace SII
    NS_SII = 'http://www.sii.cl/SiiDte'
    
    # Root element
    root = etree.Element(
        '{%s}ConsumoFolios' % NS_SII,
        nsmap={'': NS_SII},
        version='1.0'
    )
    
    doc = etree.SubElement(root, 'DocumentoConsumoFolios', ID='SetDTE')
    
    # Carátula
    caratula = etree.SubElement(doc, 'Caratula')
    etree.SubElement(caratula, 'RutEmisor').text = self.company_id.vat
    etree.SubElement(caratula, 'RutEnvia').text = self.env.user.partner_id.vat or self.company_id.vat
    etree.SubElement(caratula, 'FchResol').text = self.company_id.dte_resolution_date.strftime('%Y-%m-%d')
    etree.SubElement(caratula, 'NroResol').text = str(self.company_id.dte_resolution_number)
    etree.SubElement(caratula, 'FchInicio').text = self.periodo_mes.replace(day=1).strftime('%Y-%m-%d')
    
    # Último día del mes
    from dateutil.relativedelta import relativedelta
    ultimo_dia = (self.periodo_mes.replace(day=1) + relativedelta(months=1, days=-1))
    etree.SubElement(caratula, 'FchFinal').text = ultimo_dia.strftime('%Y-%m-%d')
    
    etree.SubElement(caratula, 'SecEnvio').text = '1'
    etree.SubElement(caratula, 'TmstFirmaEnv').text = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    
    # Resumen
    resumen = etree.SubElement(doc, 'Resumen')
    etree.SubElement(resumen, 'TipoDocumento').text = self.dte_type
    etree.SubElement(resumen, 'MntNeto').text = '0'  # Solo informativo
    etree.SubElement(resumen, 'MntIva').text = '0'
    etree.SubElement(resumen, 'TasaIVA').text = '19'
    etree.SubElement(resumen, 'MntExento').text = '0'
    etree.SubElement(resumen, 'MntTotal').text = '0'
    etree.SubElement(resumen, 'FoliosEmitidos').text = str(self.cantidad_folios)
    etree.SubElement(resumen, 'FoliosAnulados').text = '0'
    etree.SubElement(resumen, 'FoliosUtilizados').text = str(self.cantidad_folios)
    
    # Rangos
    rangos = etree.SubElement(resumen, 'RangoUtilizados')
    etree.SubElement(rangos, 'Inicial').text = str(self.folio_inicio)
    etree.SubElement(rangos, 'Final').text = str(self.folio_fin)
    
    # Convertir a string
    xml_string = etree.tostring(
        root,
        pretty_print=True,
        xml_declaration=True,
        encoding='ISO-8859-1'
    ).decode('ISO-8859-1')
    
    return xml_string
```

**Testing:**

```python
# tests/test_consumo_folios.py (NUEVO)
@tagged('post_install', 'consumo_folios', '-at_install')
class TestConsumoFolios(TransactionCase):
    
    def test_01_generate_xml_structure(self):
        """Test: XML generado cumple estructura SII"""
        consumo = self.env['dte.consumo.folios'].create({
            'periodo_mes': '2025-11-01',
            'dte_type': '33',
            'folio_inicio': 100,
            'folio_fin': 150,
        })
        
        xml_string = consumo._generate_consumo_xml()
        
        # Validar estructura
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe
        root = fromstring_safe(xml_string)
        
        self.assertEqual(root.tag, '{http://www.sii.cl/SiiDte}ConsumoFolios')
        self.assertIsNotNone(root.find('.//{http://www.sii.cl/SiiDte}DocumentoConsumoFolios'))
        self.assertIsNotNone(root.find('.//{http://www.sii.cl/SiiDte}Caratula'))
        self.assertIsNotNone(root.find('.//{http://www.sii.cl/SiiDte}Resumen'))
    
    def test_02_send_to_sii_mock(self):
        """Test: Envío a SII (mock)"""
        # Mock SII response
        # ... implementar con unittest.mock
```

#### Task 2.2: Libro de Compras (15-20h)

**Similar a Task 2.1, pero:**
- Formato: IEC (Información Electrónica de Compras)
- Agrupación: Documentos recibidos (in_invoice, in_refund)
- Detalle: Línea por DTE recibido

#### Task 2.3: Libro de Ventas (10-15h)

**Similar a Task 2.1, pero:**
- Formato: IEC (Información Electrónica de Ventas)
- Agrupación: Documentos emitidos (out_invoice, out_refund)
- Detalle: Línea por DTE emitido

#### Task 2.4: SII SOAP Client Enhancement (5-10h)

**Archivo:** `libs/sii_soap_client.py`

Agregar endpoints:
- `send_consumo_folios()`
- `send_libro_compras()`
- `send_libro_ventas()`
- `get_track_status()` (consulta estado envío)

#### Task 2.5: Testing Integración (5h)

**Tests end-to-end:**
- Generación XML completo
- Firma digital
- Envío SOAP (mock SII)
- Procesamiento respuestas
- Estados workflow

#### Task 2.6: Commit Atómico

```bash
git commit -m "feat(compliance): implement SII mandatory reports (P0)

CRITICAL COMPLIANCE FIX - SII Mandatory Reports

Implement 3 obligatory monthly reports:
1. Consumo de Folios (Folio consumption report)
2. Libro de Compras (Purchase book)
3. Libro de Ventas (Sales book)

Implementation:
- models/dte_consumo_folios.py: Full XML generation + SOAP send
- models/dte_libro.py: Purchase/Sales books XML + SOAP send
- libs/sii_soap_client.py: New endpoints for reports

Features:
- XML generation according SII Resolución Ex.
- Digital signature (XMLDSig)
- SOAP integration with SII endpoints
- Track ID management
- Response processing
- Workflow states (draft → sent → accepted/rejected)

Testing:
- 15+ new tests (XML structure, SOAP mock, integration)
- All 297 existing tests passing
- Coverage: 90%+ new modules

Compliance:
- SII Chile mandatory monthly reports
- Avoid fiscal penalties
- Production ready

Impact:
- Score: 89/100 → 89/100 (compliance complete)
- Production: BLOCKER REMOVED
- Compliance: 100% SII mandatory reports

ETA: 40-60h
Related: .claude/PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md H9
Sprint: Cierre Brechas V4 - SPRINT 2"

git tag -a h9_compliance_fixed_$(date +%Y%m%d) -m "H9 SII Compliance Complete - Score 89/100"
```

---

### SPRINT 3: H2 - Refactor Odoo Imports libs/ (4-6h) ⚠️ P1

**Objetivo:** Eliminar imports Odoo en libs/, implementar Pure Python pattern

#### Task 3.1: Refactor sii_authenticator.py (2-3h)

**Patrón:** Wrapper ORM + Pure Python core

```python
# libs/sii_authenticator.py (Pure Python)
class SIIAuthenticatorPure:
    """
    Pure Python SII authenticator.
    No Odoo dependencies.
    """
    
    def __init__(self, company_data, certificate_data):
        """
        Args:
            company_data (dict): {vat, name, environment}
            certificate_data (dict): {cert_pem, key_pem, password}
        """
        self.company_vat = company_data['vat']
        self.company_name = company_data['name']
        self.environment = company_data['environment']
        self.certificate = certificate_data
    
    def get_token(self, force_refresh=False):
        """
        Obtiene token SII.
        
        Raises:
            ValueError: Si certificado inválido
            ConnectionError: Si SII no responde
        """
        # ... implementación sin odoo imports


# models/sii_authenticator_wrapper.py (ORM Wrapper)
from odoo import models, _, exceptions
from ..libs.sii_authenticator import SIIAuthenticatorPure

class SIIAuthenticatorOdoo(models.AbstractModel):
    _name = 'sii.authenticator'
    
    def get_token(self, company, force_refresh=False):
        """
        Wrapper ORM para sii_authenticator.
        
        Args:
            company (res.company): Company recordset
            force_refresh (bool): Force token refresh
            
        Returns:
            str: SII token
            
        Raises:
            UserError: Si error en autenticación
        """
        # Preparar datos
        company_data = {
            'vat': company.vat,
            'name': company.name,
            'environment': company.dte_environment
        }
        
        certificate_data = {
            'cert_pem': company.dte_certificate_id.certificate_pem,
            'key_pem': company.dte_certificate_id.private_key_pem,
            'password': company.dte_certificate_id.password
        }
        
        # Llamar Pure Python
        authenticator = SIIAuthenticatorPure(company_data, certificate_data)
        
        try:
            return authenticator.get_token(force_refresh)
        except ValueError as e:
            raise exceptions.UserError(_(str(e)))
        except ConnectionError as e:
            raise exceptions.UserError(_('SII connection error: %s') % str(e))
```

#### Task 3.2: Refactor envio_dte_generator.py (2-3h)

**Similar pattern:** Pure Python core + ORM wrapper

#### Task 3.3: Testing (1h)

```python
# tests/test_pure_python_libs.py
def test_sii_authenticator_pure_python():
    """Test: SII authenticator sin Odoo dependencies"""
    from odoo.addons.l10n_cl_dte.libs.sii_authenticator import SIIAuthenticatorPure
    
    # Pure Python debe funcionar sin ORM
    company_data = {'vat': '76123456-7', 'name': 'Test', 'environment': 'certificacion'}
    cert_data = {'cert_pem': '...', 'key_pem': '...', 'password': 'test'}
    
    auth = SIIAuthenticatorPure(company_data, cert_data)
    # ... test methods
```

#### Task 3.4: Commit Atómico

```bash
git commit -m "refactor(arch): implement Pure Python pattern in libs/ (P1)

ARCHITECTURE FIX - Odoo 19 Pure Python Pattern

Refactor 2 files to eliminate Odoo imports in libs/:
- libs/sii_authenticator.py → Pure Python core
- libs/envio_dte_generator.py → Pure Python core
- models/sii_authenticator_wrapper.py → ORM wrapper (NEW)
- models/envio_dte_generator_wrapper.py → ORM wrapper (NEW)

Pattern:
- libs/: Pure Python (no odoo imports)
- models/: ORM wrappers (dependency injection)
- Improved testability (unit tests without ORM)
- Better portability (reuse outside Odoo)

Testing:
- 8+ new Pure Python unit tests
- All 297 existing tests passing
- Improved test isolation

Impact:
- Score: 89/100 → 92/100 (+3 points)
- Architecture: Odoo 19 compliant
- Testability: Improved

Related: .claude/AUDITORIA_L10N_CL_DTE_REPORTE_FINAL.md H2
Sprint: Cierre Brechas V4 - SPRINT 3"
```

---

### SPRINT 4: H10 - Certificado SII Oficial (2-3h) ⚠️ P1

**Objetivo:** Reemplazar certificado placeholder por oficial SII

#### Task 4.1: Obtener Certificados Oficiales SII (1h)

**Certificación (Maullin):**
- URL: https://maullin.sii.cl/
- Descargar certificado público SII testing

**Producción (Palena):**
- URL: https://palena.sii.cl/
- Descargar certificado público SII producción

**Proceso:**
```bash
# 1. Descargar certificado (.cer o .der)
curl -O https://maullin.sii.cl/certificates/sii_certificacion.cer

# 2. Convertir a PEM
openssl x509 -inform DER -in sii_certificacion.cer -out sii_certificacion.pem

# 3. Verificar
openssl x509 -in sii_certificacion.pem -text -noout
```

#### Task 4.2: Implementar Gestión por Entorno (1-2h)

```python
# libs/caf_signature_validator.py

# Certificados por entorno
SII_CERTIFICATES = {
    'certificacion': """-----BEGIN CERTIFICATE-----
[CERTIFICADO OFICIAL MAULLIN]
-----END CERTIFICATE-----""",
    
    'produccion': """-----BEGIN CERTIFICATE-----
[CERTIFICADO OFICIAL PALENA]
-----END CERTIFICATE-----"""
}

class CAFSignatureValidator:
    
    def __init__(self, environment='certificacion'):
        """
        Args:
            environment (str): 'certificacion' o 'produccion'
        """
        self.environment = environment
        self.sii_certificate_pem = SII_CERTIFICATES.get(environment)
        
        if not self.sii_certificate_pem:
            raise ValueError(f"Invalid environment: {environment}")
    
    def _get_sii_public_key(self):
        """Obtiene public key del certificado SII según environment"""
        cert = x509.load_pem_x509_certificate(
            self.sii_certificate_pem.encode('utf-8'),
            default_backend()
        )
        return cert.public_key()
```

#### Task 4.3: Testing (30 min)

```python
def test_sii_certificate_valid():
    """Test: Certificado SII oficial válido"""
    validator = CAFSignatureValidator(environment='certificacion')
    public_key = validator._get_sii_public_key()
    
    # Verificar es RSA key
    from cryptography.hazmat.primitives.asymmetric import rsa
    assert isinstance(public_key, rsa.RSAPublicKey)
```

#### Task 4.4: Commit Atómico

```bash
git commit -m "fix(security): replace SII certificate placeholder with official (P1)

SECURITY FIX - SII Official Certificates

Replace testing self-signed certificate with official SII certificates:
- Certificación: Maullin SII certificate (testing environment)
- Producción: Palena SII certificate (production environment)

Implementation:
- libs/caf_signature_validator.py: Certificates by environment
- Environment-aware certificate selection
- Proper CAF signature validation

Security:
- Official SII public certificates
- Environment separation (certificacion/produccion)
- Proper cryptographic validation

Impact:
- Score: 92/100 → 95/100 (+3 points)
- Security: Official certificates
- Compliance: SII validation correct

Related: .claude/PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md H10
Sprint: Cierre Brechas V4 - SPRINT 4"
```

---

### SPRINT 5: H11 - Refactor dte_inbox.py (6-10h) ⚠️ P1

**Objetivo:** Separar 6 responsabilidades en servicios independientes

#### Task 5.1: Diseño Arquitectura (1h)

**Estructura propuesta:**

```
addons/localization/l10n_cl_dte/
├── services/              # NUEVO
│   ├── __init__.py
│   ├── email_processor.py       # Parse emails, extract attachments
│   ├── dte_parser.py            # Parse XML, extract data
│   ├── validation_service.py   # Native + AI validation
│   ├── po_matcher.py            # AI-powered PO matching
│   └── invoice_generator.py    # Generate vendor bills
├── models/
│   └── dte_inbox.py             # REFACTORED (orchestrator only)
```

#### Task 5.2: Implementar Servicios (5-8h)

**Email Processor:**
```python
# services/email_processor.py
class EmailProcessor:
    """
    Service para procesamiento de emails con DTEs adjuntos.
    
    Responsabilidades:
    - Parse email headers
    - Extract attachments
    - Filter XML files
    """
    
    def __init__(self, env):
        self.env = env
    
    def process_email(self, email_message):
        """
        Procesa email y extrae DTEs.
        
        Args:
            email_message (mail.message): Email recordset
            
        Returns:
            list: [{filename, content, mime_type}]
        """
        attachments = []
        for attachment in email_message.attachment_ids:
            if attachment.mimetype == 'text/xml' or attachment.name.endswith('.xml'):
                attachments.append({
                    'filename': attachment.name,
                    'content': base64.b64decode(attachment.datas).decode('ISO-8859-1'),
                    'mime_type': attachment.mimetype
                })
        return attachments
```

**DTE Parser:**
```python
# services/dte_parser.py
class DTEParser:
    """
    Service para parsing XML DTEs.
    
    Responsabilidades:
    - Parse XML seguro (XXE protected)
    - Extract structured data
    - Handle encoding issues
    """
    
    def parse_dte_xml(self, xml_string):
        """
        Parse DTE XML y extrae datos estructurados.
        
        Args:
            xml_string (str): XML del DTE
            
        Returns:
            dict: Datos parseados {emisor, receptor, totales, lineas}
        """
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe
        
        root = fromstring_safe(xml_string)
        
        # Extract data
        data = {
            'tipo_dte': root.findtext('.//TipoDTE'),
            'folio': root.findtext('.//Folio'),
            # ... etc
        }
        return data
```

**Validation Service, PO Matcher, Invoice Generator:** Similar pattern

#### Task 5.3: Refactor dte_inbox.py (2h)

```python
# models/dte_inbox.py (REFACTORED - Orchestrator only)
from odoo.addons.l10n_cl_dte.services.email_processor import EmailProcessor
from odoo.addons.l10n_cl_dte.services.dte_parser import DTEParser
from odoo.addons.l10n_cl_dte.services.validation_service import ValidationService
from odoo.addons.l10n_cl_dte.services.po_matcher import POMatcher
from odoo.addons.l10n_cl_dte.services.invoice_generator import InvoiceGenerator

class DTEInbox(models.Model):
    _name = 'dte.inbox'
    # ... fields
    
    def action_validate(self):
        """Orchestrator: Delega a servicios"""
        self.ensure_one()
        
        # 1. Parse (delegar a service)
        parser = DTEParser(self.env)
        parsed_data = parser.parse_dte_xml(self.raw_xml)
        
        # 2. Validate (delegar a service)
        validator = ValidationService(self.env)
        validation_result = validator.validate(parsed_data, self.raw_xml)
        
        if not validation_result['valid']:
            raise UserError('\n'.join(validation_result['errors']))
        
        # 3. PO Match (delegar a service)
        matcher = POMatcher(self.env)
        match_result = matcher.find_match(self, parsed_data)
        
        # 4. Generate Invoice (delegar a service)
        if match_result['matched']:
            generator = InvoiceGenerator(self.env)
            invoice = generator.create_from_dte(self, match_result['po'])
            self.write({'invoice_id': invoice.id, 'state': 'invoiced'})
        
        return True
```

**Reducción:** 1,237 líneas → ~300 líneas (orchestrator)

#### Task 5.4: Testing (1h)

```python
# tests/test_services.py
def test_email_processor_service():
    """Test: Email processor extrae attachments correctamente"""
    processor = EmailProcessor(self.env)
    # ... test

def test_dte_parser_service():
    """Test: DTE parser extrae datos correctamente"""
    parser = DTEParser(self.env)
    # ... test
```

#### Task 5.5: Commit Atómico

```bash
git commit -m "refactor(quality): separate dte_inbox.py responsibilities (P1)

CODE QUALITY FIX - Single Responsibility Principle

Refactor monolithic dte_inbox.py (1,237 lines) into services:
- services/email_processor.py: Email parsing, attachments
- services/dte_parser.py: XML parsing, data extraction
- services/validation_service.py: Native + AI validation
- services/po_matcher.py: AI-powered PO matching
- services/invoice_generator.py: Vendor bill generation
- models/dte_inbox.py: Orchestrator only (~300 lines)

Benefits:
- Single Responsibility Principle
- Improved testability (unit tests per service)
- Better maintainability
- Easier debugging
- Cleaner code structure

Testing:
- 20+ new service unit tests
- All 297 existing tests passing
- Improved test isolation

Impact:
- Score: 95/100 → 97/100 (+2 points)
- Maintainability: Greatly improved
- Code quality: Enterprise-grade

Related: .claude/PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md H11
Sprint: Cierre Brechas V4 - SPRINT 5"
```

---

### SPRINT 6: H4 - Soporte RUT Prefijo 'CL' (1h) 📋 P2

**Quick win - Low effort, medium value**

```python
# libs/dte_structure_validator.py

@staticmethod
def validate_rut(rut):
    """
    Valida RUT chileno (algoritmo módulo 11).
    
    Soporta formatos:
    - 12345678-9
    - 12.345.678-9
    - CL12345678-9  # NUEVO
    - CL12.345.678-9  # NUEVO
    """
    if not rut or not isinstance(rut, str):
        return False
    
    # Limpiar RUT
    rut = rut.replace('.', '').replace('-', '').upper().strip()
    
    # ✅ NUEVO: Remover prefijo 'CL' si existe
    if rut.startswith('CL'):
        rut = rut[2:]
    
    # ... resto del algoritmo (ya correcto)
```

**Testing:**
```python
def test_rut_validation_with_cl_prefix():
    """Test: RUT con prefijo 'CL' debe validarse correctamente"""
    assert DTEStructureValidator.validate_rut('CL12345678-5') == True
    assert DTEStructureValidator.validate_rut('12345678-5') == True  # Sin prefijo también
```

**Commit:**
```bash
git commit -m "feat(validation): support 'CL' prefix in RUT validation (P2)

Add support for RUT format with 'CL' prefix:
- 12345678-5 (standard)
- CL12345678-5 (international format)

Use case: Some foreign systems use 'CL' country prefix

Impact: +1 point (97/100 → 98/100)
Related: H4
Sprint: Cierre Brechas V4 - SPRINT 6"
```

---

## 📊 VALIDACIÓN FINAL

### Pre-Merge Checklist

**Antes de merge a main:**

```bash
# 1. Ejecutar TODOS los tests
cd addons/localization/l10n_cl_dte
pytest tests/ -v --tb=short -x
# Expected: 320+ tests (297 base + 23 nuevos), 0 failures

# 2. Coverage
pytest --cov=. --cov-report=term-missing tests/
# Expected: ≥85% coverage global

# 3. Linter
ruff check . --fix
mypy . --ignore-missing-imports

# 4. Security scan
bandit -r . -ll

# 5. Performance smoke tests
pytest tests/test_performance.py -v

# 6. Manual testing
# - Crear DTE inbox
# - Validar DTE (native + AI)
# - Generar consumo folios
# - Enviar libro compras/ventas (mock)
# - Verificar certificado SII correcto por environment
```

### Score Validation

| Sprint | Hallazgo | Score Antes | Score Después | Delta |
|--------|----------|-------------|---------------|-------|
| 1 | H1 XXE | 64/100 | 89/100 | +25 |
| 2 | H9 Compliance | 89/100 | 89/100 | 0* |
| 3 | H2 Odoo imports | 89/100 | 92/100 | +3 |
| 4 | H10 Certificado | 92/100 | 95/100 | +3 |
| 5 | H11 dte_inbox | 95/100 | 97/100 | +2 |
| 6 | H4 RUT CL | 97/100 | 98/100 | +1 |
| **FINAL** | - | **64/100** | **98/100** | **+34** |

*H9 no suma puntos directos pero elimina bloqueante producción

### Production Readiness Criteria

**PASS Criteria:**

- ✅ Score ≥ 90/100
- ✅ 0 issues P0 (bloqueantes)
- ✅ ≤2 issues P1 (alta prioridad) - todos documentados
- ✅ Tests ≥300 passing, 0 failures
- ✅ Coverage ≥85%
- ✅ Linter warnings <10
- ✅ Security scan: 0 high/critical
- ✅ Manual smoke tests: PASS
- ✅ Compliance SII: 100%

**Result:** ✅ **PRODUCTION READY - SCORE 98/100** ⭐⭐⭐

---

## 🚀 DEPLOYMENT PLAN

### Staging Deployment (1 día)

```bash
# 1. Deploy a staging
git checkout feat/cierre_total_brechas_profesional
docker-compose -f docker-compose.staging.yml up -d

# 2. Actualizar módulos
docker exec odoo19_staging odoo -u l10n_cl_dte --stop-after-init

# 3. Smoke tests staging
pytest tests/test_smoke.py --env=staging -v

# 4. Manual validation staging
# - Login staging environment
# - Test DTE reception flow
# - Test compliance reports generation
# - Verify SII integration (certificacion environment)
```

### Production Deployment (medio día)

```bash
# 1. Backup producción
pg_dump -U odoo odoo19_prod | gzip > backups/pre_deployment_$(date +%Y%m%d).sql.gz

# 2. Maintenance mode
# - Notificar usuarios
# - Activar modo mantenimiento

# 3. Deploy
git checkout feat/cierre_total_brechas_profesional
docker-compose -f docker-compose.prod.yml up -d

# 4. Actualizar módulos
docker exec odoo19_prod odoo -u l10n_cl_dte --stop-after-init

# 5. Smoke tests production
pytest tests/test_smoke.py --env=production -v

# 6. Desactivar modo mantenimiento

# 7. Monitoring 24h
# - Logs errors
# - Performance metrics
# - User feedback
```

---

## 📝 DOCUMENTACIÓN REQUERIDA

### Durante Implementación

**Por cada Sprint, documentar:**

1. **Technical Documentation**
   - Cambios arquitectura
   - APIs nuevas/modificadas
   - Breaking changes
   - Migration notes

2. **Testing Evidence**
   - Test results screenshots
   - Coverage reports
   - Performance benchmarks

3. **Code Review**
   - Self-review checklist
   - Peer review (si aplica)
   - Security review

### Post-Implementación

**Generar:**

1. **REPORTE_CIERRE_BRECHAS_V4.md**
   - Resumen ejecutivo
   - Hallazgos vs implementaciones
   - Metrics (score, coverage, performance)
   - Lessons learned

2. **CHANGELOG.md** (actualizar)
   - Version bump (v19.0.7.0.0)
   - New features
   - Bug fixes
   - Breaking changes
   - Migration guide

3. **README.md** (actualizar)
   - New compliance features
   - Configuration guides
   - Troubleshooting

---

## ⚠️ RESTRICCIONES Y CONSIDERACIONES

### Restricciones Técnicas

1. **NO IMPROVISAR**
   - Seguir patrones Odoo 19 CE documentados
   - Usar librerías estándar (no experimentales)
   - Respetar arquitectura existente

2. **NO PARCHES**
   - Soluciones completas, no workarounds
   - Testing exhaustivo requerido
   - Documentation mandatory

3. **ZERO BREAKING CHANGES**
   - Backward compatibility obligatoria
   - Migrations scripts si necesario
   - Deprecation warnings antes de remover

### Consideraciones Operativas

1. **Rollback Plan**
   - Git tags por sprint
   - SQL backups diarios
   - Rollback procedures documented

2. **Communication**
   - Notificar stakeholders por sprint completado
   - Demo features post-implementation
   - Training sessions si necesario

3. **Monitoring**
   - Sentry/error tracking activo
   - Performance metrics (Prometheus)
   - User feedback channels

---

## 🎯 SUCCESS CRITERIA

### Technical Success

- ✅ Score: 64/100 → 98/100 (+34 puntos)
- ✅ P0 issues: 2 → 0 (100% resolved)
- ✅ P1 issues: 3 → 0 (100% resolved)
- ✅ Tests: 297 → 320+ (23+ nuevos)
- ✅ Coverage: 80% → 85%+ (+5%)
- ✅ Architecture: 100% Odoo 19 compliant

### Business Success

- ✅ Compliance: 100% SII mandatory reports
- ✅ Security: 0 critical vulnerabilities
- ✅ Performance: No degradation
- ✅ Availability: 99.9%+ uptime
- ✅ User satisfaction: Positive feedback

### Certification

**Final Score:** **98/100** ⭐⭐⭐

**Certificación:** **ENTERPRISE-GRADE PRODUCTION READY**

---

## 📞 CONTACTO Y SOPORTE

**Engineering Lead:** Pedro Troncoso  
**Project:** EERGYGROUP Odoo 19 CE  
**Sprint:** Cierre Brechas V4  
**Fecha inicio:** 2025-11-09  
**ETA Completion:** 2 semanas (58-80h effort)

**Agentes Disponibles:**
- @odoo-dev: Desarrollo Odoo 19 CE
- @dte-compliance: Compliance SII
- @test-automation: Testing enterprise-grade
- @docker-devops: Deployment & infrastructure

---

## 🔗 REFERENCIAS

**Auditorías Base:**
- `.claude/AUDITORIA_L10N_CL_DTE_REPORTE_PARCIAL.md` (513 líneas, 20% progreso)
- `.claude/AUDITORIA_L10N_CL_DTE_REPORTE_FINAL.md` (946 líneas, 100% progreso)
- Ratificación código real (análisis local)
- Análisis agente complementario (15 sugerencias)

**Knowledge Base:**
- `.claude/agents/knowledge/sii_regulatory_context.md`
- `.claude/agents/knowledge/odoo19_patterns.md`
- `.claude/agents/knowledge/project_architecture.md`

**Standards:**
- OWASP Top 10 (Security)
- SII Chile Resolutions (Compliance)
- PEP8 + Odoo Coding Standards
- Semantic Versioning 2.0.0

---

**FIN DEL PROMPT PROFESIONAL V4**

**Status:** Ready for execution  
**Approval:** Pending stakeholder sign-off  
**Priority:** 🔴 CRITICAL - Production blockers  
**Deadline:** 2 semanas (Nov 23, 2025)
