# 🤖 AI AGENTS - Instrucciones para Agentes IA

Este directorio contiene instrucciones, contexto y reglas para agentes de IA (Claude, GPT-4, Copilot, etc.).

---

## 📚 Documentos Disponibles

### Principal
- **`AI_AGENT_INSTRUCTIONS.md`** - Instrucciones completas para agentes IA
  - Contexto del proyecto
  - Reglas fundamentales (✅ SIEMPRE / ❌ NUNCA)
  - Patrones de código con ejemplos
  - Flujos de trabajo comunes
  - Convenciones de código
  - Checklist antes de commit

---

## 🎯 Para Agentes IA: LEER PRIMERO

Si eres un agente de IA trabajando en este proyecto:

1. **LEE COMPLETO:** `AI_AGENT_INSTRUCTIONS.md`
2. **SIGUE ESTRICTAMENTE:** Las reglas definidas
3. **USA LOS PATRONES:** Ejemplos de código proporcionados
4. **VALIDA SIEMPRE:** Checklist antes de generar código

---

## 🔑 Reglas Fundamentales (Resumen)

### ✅ SIEMPRE HACER

1. **Seguir Clean Architecture**
   - Odoo = UI/Business Logic
   - DTE Service = XML/Firma/SOAP
   - AI Service = IA/Analytics

2. **Extender, NO Duplicar**
   ```python
   # ✅ CORRECTO
   class AccountMoveDTE(models.Model):
       _inherit = 'account.move'
   
   # ❌ INCORRECTO
   class DTEInvoice(models.Model):
       _name = 'dte.invoice'
   ```

3. **Testing Obligatorio**
   - Mínimo 80% coverage
   - Tests unitarios para toda lógica
   - Mocks para servicios externos

4. **Documentación Inline**
   - Docstrings completos
   - Type hints
   - Comentarios explicativos

### ❌ NUNCA HACER

1. **NO Hardcodear Secrets**
   ```python
   # ❌ INCORRECTO
   api_key = "sk-ant-api03-..."
   
   # ✅ CORRECTO
   api_key = os.getenv('ANTHROPIC_API_KEY')
   ```

2. **NO Duplicar Funcionalidad Odoo**
   - Usar res.users, res.company, res.partner

3. **NO Mezclar Responsabilidades**
   - Odoo NO genera XML
   - Delegar a DTE Service

4. **NO Ignorar Errores**
   - Siempre manejar excepciones
   - Logging completo

---

## 🎨 Patrones de Código

### Patrón 1: Extensión de Modelos Odoo

```python
from odoo import models, fields, api

class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    
    dte_type = fields.Selection([...])
    dte_status = fields.Selection([...])
    
    def action_send_dte(self):
        # Delegar a DTE Service
        response = requests.post(
            'http://dte-service:8001/api/dte/generate',
            json=self._prepare_dte_data()
        )
```

### Patrón 2: Factory Pattern (Generadores DTE)

```python
class DTEFactory:
    _generators = {
        '33': DTE33Generator,
        '61': DTE61Generator,
    }
    
    @classmethod
    def create(cls, dte_type: str) -> DTEGenerator:
        generator_class = cls._generators.get(dte_type)
        if not generator_class:
            raise ValueError(f"DTE tipo {dte_type} no soportado")
        return generator_class()
```

### Patrón 3: Singleton (Cliente SII)

```python
class SIISoapClient:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
```

---

## 📊 Métricas y Performance

### Targets Obligatorios

```python
PERFORMANCE_TARGETS = {
    'p50': 100,   # ms
    'p95': 500,   # ms (CRÍTICO)
    'p99': 1000,  # ms
}

MIN_COVERAGE = {
    'unit_tests': 80,        # %
    'integration_tests': 60, # %
}
```

---

## 🔒 Seguridad

### Checklist de Seguridad

- [ ] Sin secrets hardcodeados
- [ ] Validación de todos los inputs (Pydantic)
- [ ] Sanitización de outputs
- [ ] Rate limiting en endpoints públicos
- [ ] Logging sin datos sensibles
- [ ] Certificados encriptados en DB

---

## 📝 Convenciones

### Naming
```python
# Variables/funciones: snake_case
dte_status = 'sent'
def generate_xml():
    pass

# Clases: PascalCase
class DTEGenerator:
    pass

# Constantes: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3
```

### Imports
```python
# 1. Standard library
import os
import json

# 2. Third-party
from odoo import models, fields
import requests

# 3. Local
from .validators import DTEValidator
```

### Docstrings
```python
def function(param: str) -> bool:
    """
    Descripción breve.
    
    Args:
        param: Descripción parámetro
        
    Returns:
        bool: Descripción retorno
        
    Raises:
        ValueError: Cuándo se lanza
    """
    pass
```

---

## ✅ Checklist Antes de Commit

- [ ] Tests pasan (`pytest`)
- [ ] Coverage ≥ 80%
- [ ] Linting OK (`flake8`, `pylint`)
- [ ] Type hints agregados
- [ ] Docstrings completos
- [ ] Sin secrets hardcodeados
- [ ] Performance validado (p95 < 500ms)
- [ ] Documentación actualizada

---

## 🔗 Enlaces Relacionados

- **Instrucciones Completas:** [AI_AGENT_INSTRUCTIONS.md](AI_AGENT_INSTRUCTIONS.md)
- **Guías de Desarrollo:** [../guides/](../guides/)
- **Arquitectura:** [../architecture/](../architecture/)
- **Contributing:** [../../CONTRIBUTING.md](../../CONTRIBUTING.md)

---

## 🎯 Flujos de Trabajo Comunes

### Flujo 1: Emisión DTE
1. Usuario crea factura en Odoo
2. Odoo valida datos
3. Odoo llama DTE Service
4. DTE Service genera XML + firma + envía SII
5. SII retorna Track ID
6. Polling automático de estado
7. Webhook a Odoo cuando aceptado

### Flujo 2: Sugerencia IA
1. Usuario crea orden de compra
2. Odoo llama AI Service
3. AI Service analiza con Claude
4. Retorna proyecto sugerido + confidence
5. Auto-asigna si confidence ≥ 85%

---

## 📚 Recursos Adicionales

### APIs Externas
- [Anthropic Claude API](https://docs.anthropic.com/claude/reference)
- [SII Web Services](https://www.sii.cl/servicios_online/1039-1208.html)
- [Odoo 19 Developer Docs](https://www.odoo.com/documentation/19.0/developer.html)

### Normativa SII
- [Resolución 80/2014](https://www.sii.cl/normativa_legislacion/resoluciones/2014/reso80.pdf)
- [Formato DTE](https://www.sii.cl/factura_electronica/formato_dte.pdf)

---

**Para agentes IA:** Este directorio es tu guía completa. Síguelo estrictamente.

**Última actualización:** 2025-10-23  
**Mantenido por:** Ing. Pedro Troncoso Willz
