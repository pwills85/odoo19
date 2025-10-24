# 🤖 INSTRUCCIONES PARA AGENTES IA
## Proyecto Odoo 19 CE - Facturación Electrónica Chile

**Versión:** 1.0  
**Fecha:** 2025-10-23  
**Para:** Claude, GPT-4, Copilot, y otros agentes IA  
**Propósito:** Contexto completo y reglas de desarrollo

---

## 🎯 CONTEXTO DEL PROYECTO

### Descripción General
Sistema **enterprise-grade** de facturación electrónica chilena basado en Odoo 19 CE con arquitectura de microservicios.

**Stack Tecnológico:**
- **Frontend/Backend:** Odoo 19 CE (Python 3.11, PostgreSQL 15)
- **Microservicios:** FastAPI (Python 3.11)
- **IA:** Anthropic Claude 3.5 Sonnet
- **Infraestructura:** Docker Compose, Redis 7, RabbitMQ 3.12
- **Compliance:** 100% SII Chile (Servicio de Impuestos Internos)

### Arquitectura Three-Tier

```
┌─────────────────────────────────────────┐
│  TIER 1: PRESENTACIÓN                   │
│  Odoo 19 CE (Puerto 8169)               │
│  • UI/UX                                │
│  • Business Logic                       │
│  • ORM (PostgreSQL)                     │
└─────────────────────────────────────────┘
           ↓ REST API
┌─────────────────────────────────────────┐
│  TIER 2: MICROSERVICIOS                 │
│  ├─ DTE Service (8001) - XML/Firma/SII  │
│  └─ AI Service (8002) - Claude/Analytics│
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│  TIER 3: DATOS                          │
│  PostgreSQL + Redis + RabbitMQ          │
└─────────────────────────────────────────┘
```

---

## 📋 REGLAS FUNDAMENTALES

### ✅ SIEMPRE HACER

1. **Seguir Clean Architecture**
   - Separación clara de responsabilidades
   - Odoo = UI/Business Logic
   - DTE Service = XML/Firma/SOAP
   - AI Service = IA/Analytics

2. **Extender, NO Duplicar**
   ```python
   # ✅ CORRECTO: Extender modelo existente
   class AccountMoveDTE(models.Model):
       _inherit = 'account.move'
       dte_status = fields.Selection(...)
   
   # ❌ INCORRECTO: Crear modelo nuevo
   class DTEInvoice(models.Model):
       _name = 'dte.invoice'  # NO hacer esto
   ```

3. **Usar Patrones Establecidos**
   - Factory Pattern para generadores DTE
   - Singleton para clientes externos (SII, Claude)
   - Repository Pattern para acceso a datos
   - Dependency Injection en FastAPI

4. **Testing Obligatorio**
   - Mínimo 80% code coverage
   - Tests unitarios para toda lógica de negocio
   - Mocks para servicios externos (SII, Claude)
   - Performance tests (p95 < 500ms)

5. **Documentación Inline**
   ```python
   def generate_dte_33(self, invoice_data: dict) -> str:
       """
       Genera XML DTE 33 (Factura Electrónica) según normativa SII.
       
       Args:
           invoice_data: Diccionario con datos factura
               - rut_emisor: RUT empresa emisora
               - rut_receptor: RUT cliente
               - items: Lista de líneas factura
               
       Returns:
           str: XML firmado digitalmente
           
       Raises:
           ValidationError: Si datos inválidos
           SIIConnectionError: Si SII no responde
       """
   ```

6. **Logging Estructurado**
   ```python
   import structlog
   logger = structlog.get_logger()
   
   logger.info("dte_generated", 
               dte_type=33, 
               folio=12345, 
               rut_receptor="12345678-9")
   ```

### ❌ NUNCA HACER

1. **NO Duplicar Funcionalidad de Odoo Base**
   - NO crear sistema de usuarios (usar res.users)
   - NO crear sistema de empresas (usar res.company)
   - NO crear sistema de partners (usar res.partner)

2. **NO Hardcodear Valores**
   ```python
   # ❌ INCORRECTO
   sii_url = "https://maullin.sii.cl/DTEWS/services/..."
   
   # ✅ CORRECTO
   sii_url = self.env['ir.config_parameter'].get_param('l10n_cl_dte.sii_url')
   ```

3. **NO Exponer Microservicios al Exterior**
   - DTE Service y AI Service solo en red interna Docker
   - Solo Odoo expuesto en puerto 8169
   - APIs internas sin autenticación externa

4. **NO Mezclar Responsabilidades**
   ```python
   # ❌ INCORRECTO: Odoo generando XML
   class AccountMove(models.Model):
       def generate_xml(self):
           # NO hacer esto en Odoo
           xml = "<DTE>...</DTE>"
   
   # ✅ CORRECTO: Delegar a DTE Service
   class AccountMove(models.Model):
       def generate_dte(self):
           response = requests.post(
               'http://dte-service:8001/api/dte/generate',
               json=self._prepare_dte_data()
           )
   ```

5. **NO Ignorar Errores SII**
   - Siempre manejar 59 códigos de error SII
   - Retry logic con exponential backoff
   - Logging completo de errores

---

## 🎨 PATRONES DE CÓDIGO

### Patrón 1: Extensión de Modelos Odoo

```python
# addons/localization/l10n_cl_dte/models/account_move_dte.py
from odoo import models, fields, api
from odoo.exceptions import ValidationError

class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    
    # Campos DTE
    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('61', 'Nota de Crédito'),
        ('56', 'Nota de Débito'),
    ], string='Tipo DTE')
    
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado'),
        ('rejected', 'Rechazado'),
    ], default='draft')
    
    dte_folio = fields.Integer('Folio DTE', readonly=True)
    dte_xml = fields.Text('XML DTE', readonly=True)
    dte_track_id = fields.Char('Track ID SII', readonly=True)
    
    @api.depends('dte_status')
    def _compute_dte_can_send(self):
        """Computed field para validar si se puede enviar."""
        for record in self:
            record.dte_can_send = (
                record.state == 'posted' and 
                record.dte_status == 'draft'
            )
    
    def action_send_dte(self):
        """Envía DTE a SII vía DTE Service."""
        self.ensure_one()
        
        if not self.dte_can_send:
            raise ValidationError("DTE no puede ser enviado")
        
        # Preparar datos
        dte_data = self._prepare_dte_data()
        
        # Llamar DTE Service
        dte_service_url = self.env['ir.config_parameter'].get_param(
            'l10n_cl_dte.dte_service_url'
        )
        
        response = requests.post(
            f"{dte_service_url}/api/dte/generate",
            json=dte_data,
            headers={'X-API-Key': self._get_api_key()}
        )
        
        if response.status_code == 200:
            result = response.json()
            self.write({
                'dte_xml': result['xml'],
                'dte_folio': result['folio'],
                'dte_track_id': result['track_id'],
                'dte_status': 'sent',
            })
        else:
            raise ValidationError(f"Error DTE Service: {response.text}")
    
    def _prepare_dte_data(self):
        """Prepara datos para enviar a DTE Service."""
        return {
            'dte_type': self.dte_type,
            'rut_emisor': self.company_id.vat,
            'rut_receptor': self.partner_id.vat,
            'fecha_emision': self.invoice_date.isoformat(),
            'monto_total': self.amount_total,
            'items': [
                {
                    'nombre': line.product_id.name,
                    'cantidad': line.quantity,
                    'precio': line.price_unit,
                    'monto': line.price_subtotal,
                }
                for line in self.invoice_line_ids
            ]
        }
```

### Patrón 2: Generador DTE (Factory Pattern)

```python
# dte-service/generators/dte_factory.py
from abc import ABC, abstractmethod
from typing import Dict
from lxml import etree

class DTEGenerator(ABC):
    """Base class para generadores DTE."""
    
    @abstractmethod
    def generate(self, data: Dict) -> str:
        """Genera XML DTE."""
        pass
    
    @abstractmethod
    def validate(self, data: Dict) -> bool:
        """Valida datos antes de generar."""
        pass

class DTE33Generator(DTEGenerator):
    """Generador DTE 33 - Factura Electrónica."""
    
    def validate(self, data: Dict) -> bool:
        required_fields = [
            'rut_emisor', 'rut_receptor', 
            'fecha_emision', 'monto_total', 'items'
        ]
        return all(field in data for field in required_fields)
    
    def generate(self, data: Dict) -> str:
        if not self.validate(data):
            raise ValueError("Datos inválidos para DTE 33")
        
        # Crear estructura XML
        root = etree.Element("DTE", version="1.0")
        documento = etree.SubElement(root, "Documento", ID="DTE33")
        
        # Encabezado
        encabezado = etree.SubElement(documento, "Encabezado")
        id_doc = etree.SubElement(encabezado, "IdDoc")
        etree.SubElement(id_doc, "TipoDTE").text = "33"
        etree.SubElement(id_doc, "Folio").text = str(data['folio'])
        etree.SubElement(id_doc, "FchEmis").text = data['fecha_emision']
        
        # Emisor
        emisor = etree.SubElement(encabezado, "Emisor")
        etree.SubElement(emisor, "RUTEmisor").text = data['rut_emisor']
        
        # Receptor
        receptor = etree.SubElement(encabezado, "Receptor")
        etree.SubElement(receptor, "RUTRecep").text = data['rut_receptor']
        
        # Totales
        totales = etree.SubElement(encabezado, "Totales")
        etree.SubElement(totales, "MntTotal").text = str(data['monto_total'])
        
        # Detalle (items)
        for idx, item in enumerate(data['items'], start=1):
            detalle = etree.SubElement(documento, "Detalle")
            etree.SubElement(detalle, "NroLinDet").text = str(idx)
            etree.SubElement(detalle, "NmbItem").text = item['nombre']
            etree.SubElement(detalle, "QtyItem").text = str(item['cantidad'])
            etree.SubElement(detalle, "PrcItem").text = str(item['precio'])
            etree.SubElement(detalle, "MontoItem").text = str(item['monto'])
        
        return etree.tostring(root, encoding='ISO-8859-1', xml_declaration=True)

class DTEFactory:
    """Factory para crear generadores DTE."""
    
    _generators = {
        '33': DTE33Generator,
        '61': DTE61Generator,
        '56': DTE56Generator,
        '52': DTE52Generator,
        '34': DTE34Generator,
    }
    
    @classmethod
    def create(cls, dte_type: str) -> DTEGenerator:
        generator_class = cls._generators.get(dte_type)
        if not generator_class:
            raise ValueError(f"DTE tipo {dte_type} no soportado")
        return generator_class()
```

### Patrón 3: Cliente SOAP SII (Singleton + Retry)

```python
# dte-service/clients/sii_soap_client.py
import zeep
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog

logger = structlog.get_logger()

class SIISoapClient:
    """Cliente SOAP para comunicación con SII (Singleton)."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.environment = os.getenv('SII_ENVIRONMENT', 'sandbox')
        self.wsdl_url = self._get_wsdl_url()
        self.client = zeep.Client(wsdl=self.wsdl_url)
        self._initialized = True
    
    def _get_wsdl_url(self) -> str:
        if self.environment == 'production':
            return "https://palena.sii.cl/DTEWS/services/..."
        return "https://maullin.sii.cl/DTEWS/services/..."
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def send_dte(self, xml: str, rut_emisor: str) -> dict:
        """
        Envía DTE a SII con retry automático.
        
        Args:
            xml: XML DTE firmado
            rut_emisor: RUT empresa emisora
            
        Returns:
            dict con track_id y estado
        """
        logger.info("sii_send_dte", rut_emisor=rut_emisor)
        
        try:
            response = self.client.service.EnvioDTE(
                RutEmisor=rut_emisor,
                DvEmisor=self._get_dv(rut_emisor),
                RutEnvia=rut_emisor,
                DvEnvia=self._get_dv(rut_emisor),
                Archivo=xml
            )
            
            logger.info("sii_response", 
                       track_id=response.TRACKID,
                       estado=response.ESTADO)
            
            return {
                'track_id': response.TRACKID,
                'estado': response.ESTADO,
                'glosa': response.GLOSA
            }
            
        except Exception as e:
            logger.error("sii_error", error=str(e))
            raise
```

### Patrón 4: Integración Claude AI

```python
# ai-service/clients/claude_client.py
from anthropic import Anthropic
import structlog

logger = structlog.get_logger()

class ClaudeClient:
    """Cliente para Anthropic Claude API."""
    
    def __init__(self):
        self.api_key = os.getenv('ANTHROPIC_API_KEY')
        self.model = os.getenv('ANTHROPIC_MODEL', 'claude-3-5-sonnet-20241022')
        self.client = Anthropic(api_key=self.api_key)
    
    def validate_dte(self, dte_data: dict) -> dict:
        """
        Pre-validación inteligente de DTE con Claude.
        
        Returns:
            dict con is_valid, confidence, issues
        """
        prompt = f"""
        Analiza los siguientes datos de factura electrónica chilena (DTE):
        
        {json.dumps(dte_data, indent=2)}
        
        Valida:
        1. RUT emisor y receptor (formato válido)
        2. Montos coherentes (suma items = total)
        3. Fechas lógicas
        4. Datos obligatorios presentes
        
        Responde en JSON:
        {{
            "is_valid": true/false,
            "confidence": 0-100,
            "issues": ["lista de problemas encontrados"]
        }}
        """
        
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )
        
        result = json.loads(response.content[0].text)
        
        logger.info("claude_validation",
                   is_valid=result['is_valid'],
                   confidence=result['confidence'])
        
        return result
```

---

## 🔄 FLUJOS DE TRABAJO COMUNES

### Flujo 1: Emisión de Factura Electrónica (DTE 33)

```
1. Usuario crea factura en Odoo
   └─> account.move (state='draft')

2. Usuario valida y confirma factura
   └─> account.move.action_post()
   └─> state='posted'

3. Usuario hace clic "Enviar DTE"
   └─> account.move.action_send_dte()
   
4. Odoo prepara datos
   └─> _prepare_dte_data()
   
5. Odoo llama DTE Service
   └─> POST http://dte-service:8001/api/dte/generate
   
6. DTE Service:
   a. Valida datos
   b. Genera XML (DTEFactory)
   c. Incluye CAF
   d. Firma digitalmente (XMLDsig)
   e. Envía a SII (SOAP)
   f. Retorna track_id
   
7. Odoo actualiza estado
   └─> dte_status='sent'
   └─> dte_track_id=12345
   
8. Polling automático (cada 15 min)
   └─> DTE Service consulta estado en SII
   └─> Si aceptado → Webhook a Odoo
   
9. Odoo recibe webhook
   └─> dte_status='accepted'
   └─> Usuario puede descargar PDF
```

### Flujo 2: Sugerencia Inteligente de Proyecto (IA)

```
1. Usuario crea orden de compra
   └─> purchase.order

2. Odoo detecta que falta proyecto
   └─> project_id is False

3. Odoo llama AI Service
   └─> POST http://ai-service:8002/api/ai/analytics/suggest_project
   
4. AI Service:
   a. Analiza descripción productos
   b. Busca histórico proveedor
   c. Claude hace matching semántico
   d. Calcula confidence score
   
5. AI Service retorna sugerencia
   └─> {project_id: 5, confidence: 92}
   
6. Odoo evalúa confidence:
   - Si ≥ 85% → Auto-asigna proyecto
   - Si 70-84% → Sugiere al usuario
   - Si < 70% → Usuario elige manual
```

---

## 📊 MÉTRICAS Y PERFORMANCE

### Targets de Performance

```python
# Todos los endpoints deben cumplir:
PERFORMANCE_TARGETS = {
    'p50': 100,   # ms
    'p95': 500,   # ms (CRÍTICO)
    'p99': 1000,  # ms
}

# Throughput mínimo:
THROUGHPUT_MIN = {
    'dtes_per_hour': 1000,
    'concurrent_users': 500,
    'requests_per_second': 200,
}

# Resources:
RESOURCE_LIMITS = {
    'cpu_util': 60,      # %
    'memory_util': 70,   # %
    'cache_hit_rate': 80, # %
    'disk_util': 80,     # %
}
```

### Testing Coverage

```python
# Mínimo requerido:
MIN_COVERAGE = {
    'unit_tests': 80,        # %
    'integration_tests': 60, # %
    'e2e_tests': 40,         # %
}

# Ejecutar tests:
# cd dte-service
# pytest --cov=. --cov-report=html --cov-report=term
# 
# Debe mostrar:
# TOTAL coverage: 80%+
```

---

## 🔒 SEGURIDAD

### Reglas de Seguridad

1. **Nunca Hardcodear Secrets**
   ```python
   # ❌ INCORRECTO
   api_key = "sk-ant-api03-..."
   
   # ✅ CORRECTO
   api_key = os.getenv('ANTHROPIC_API_KEY')
   ```

2. **Validar Todos los Inputs**
   ```python
   from pydantic import BaseModel, validator
   
   class DTERequest(BaseModel):
       rut_emisor: str
       rut_receptor: str
       
       @validator('rut_emisor', 'rut_receptor')
       def validate_rut(cls, v):
           if not is_valid_rut(v):
               raise ValueError('RUT inválido')
           return v
   ```

3. **Sanitizar Outputs**
   - Nunca exponer stack traces al usuario
   - Logging sin datos sensibles
   - Encriptar certificados en DB

4. **Rate Limiting**
   ```python
   from slowapi import Limiter
   
   limiter = Limiter(key_func=get_remote_address)
   
   @app.post("/api/dte/generate")
   @limiter.limit("10/minute")
   async def generate_dte(request: Request):
       ...
   ```

---

## 📝 CONVENCIONES DE CÓDIGO

### Naming Conventions

```python
# Variables y funciones: snake_case
dte_status = 'sent'
def generate_dte_xml():
    pass

# Clases: PascalCase
class DTEGenerator:
    pass

# Constantes: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3
SII_TIMEOUT_SECONDS = 30

# Archivos: snake_case
# account_move_dte.py
# dte_generator.py
```

### Imports Organization

```python
# 1. Standard library
import os
import json
from typing import Dict, List

# 2. Third-party
from odoo import models, fields, api
import requests
from lxml import etree

# 3. Local
from .dte_validator import DTEValidator
from ..utils.rut import validate_rut
```

### Docstrings

```python
def generate_dte(self, dte_type: str, data: Dict) -> str:
    """
    Genera XML DTE según tipo y datos proporcionados.
    
    Args:
        dte_type: Código DTE (33, 61, 56, 52, 34)
        data: Diccionario con datos del documento
            - rut_emisor (str): RUT empresa emisora
            - rut_receptor (str): RUT cliente
            - items (list): Lista de líneas
            
    Returns:
        str: XML DTE firmado digitalmente
        
    Raises:
        ValidationError: Si datos inválidos
        SIIConnectionError: Si SII no responde
        
    Example:
        >>> generator = DTEFactory.create('33')
        >>> xml = generator.generate({
        ...     'rut_emisor': '12345678-9',
        ...     'rut_receptor': '98765432-1',
        ...     'items': [...]
        ... })
    """
```

---

## 🚨 ERRORES COMUNES Y SOLUCIONES

### Error 1: "DTE Service not reachable"

**Causa:** Odoo no puede conectar con DTE Service

**Solución:**
```bash
# Verificar que servicios estén en misma red Docker
docker network inspect odoo19_stack_network

# Verificar que DTE Service esté corriendo
docker-compose ps dte-service

# Test conectividad desde Odoo
docker-compose exec odoo curl http://dte-service:8001/health
```

### Error 2: "ANTHROPIC_API_KEY not found"

**Causa:** Variable de entorno no configurada

**Solución:**
```bash
# Verificar .env
cat .env | grep ANTHROPIC_API_KEY

# Debe tener: ANTHROPIC_API_KEY=sk-ant-api03-...

# Reiniciar servicio
docker-compose restart ai-service
```

### Error 3: "SII SOAP Error: Schema validation failed"

**Causa:** XML DTE no cumple esquema XSD del SII

**Solución:**
```python
# Validar XML antes de enviar
from lxml import etree

schema = etree.XMLSchema(file='schemas/DTE_v10.xsd')
xml_doc = etree.fromstring(xml_string)

if not schema.validate(xml_doc):
    print(schema.error_log)
```

---

## ✅ CHECKLIST ANTES DE COMMIT

- [ ] Tests pasan (pytest)
- [ ] Coverage ≥ 80%
- [ ] Linting OK (flake8, pylint)
- [ ] Type hints agregados
- [ ] Docstrings completos
- [ ] Logging estructurado
- [ ] Sin secrets hardcodeados
- [ ] Performance validado (p95 < 500ms)
- [ ] Documentación actualizada
- [ ] CHANGELOG.md actualizado

---

## 📚 RECURSOS ADICIONALES

### Documentación del Proyecto
- [README.md](../README.md) - Documentación principal
- [TEAM_ONBOARDING.md](../TEAM_ONBOARDING.md) - Guía onboarding
- [QUICK_START.md](../QUICK_START.md) - Setup rápido
- [/docs/](../docs/) - Documentación técnica completa

### APIs Externas
- [Anthropic Claude API](https://docs.anthropic.com/claude/reference)
- [SII Web Services](https://www.sii.cl/servicios_online/1039-1208.html)
- [Odoo 19 Developer Docs](https://www.odoo.com/documentation/19.0/developer.html)

### Normativa SII
- [Resolución 80/2014](https://www.sii.cl/normativa_legislacion/resoluciones/2014/reso80.pdf)
- [Formato DTE](https://www.sii.cl/factura_electronica/formato_dte.pdf)
- [Códigos de Error SII](https://www.sii.cl/factura_electronica/codigos_error.pdf)

---

**Versión:** 1.0  
**Última Actualización:** 2025-10-23  
**Mantenido por:** Ing. Pedro Troncoso Willz  
**Empresa:** EERGYGROUP

**Para agentes IA:** Este documento es tu guía completa. Síguelo estrictamente.
