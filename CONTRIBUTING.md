# 🤝 CONTRIBUTING - Guía para Contribuir

**Proyecto:** Odoo 19 CE - Facturación Electrónica Chile  
**Última actualización:** 2025-10-23

---

## 📋 ANTES DE EMPEZAR

### Lectura Obligatoria

1. **[QUICK_START.md](QUICK_START.md)** - Setup del entorno (5 min)
2. **[TEAM_ONBOARDING.md](TEAM_ONBOARDING.md)** - Onboarding completo (15 min)
3. **[AI_AGENT_INSTRUCTIONS.md](AI_AGENT_INSTRUCTIONS.md)** - Reglas y patrones de código

### Requisitos Previos

- Docker 24+ y Docker Compose 2.20+
- Git 2.40+
- Python 3.11+ (para desarrollo local)
- Conocimientos de Odoo 19 CE
- Familiaridad con FastAPI (para microservicios)

---

## 🔄 FLUJO DE TRABAJO

### 1. Fork y Clone

```bash
# Fork el repositorio en GitHub (si aplica)
# Luego clona tu fork
git clone https://github.com/tu-usuario/odoo19.git
cd odoo19
```

### 2. Crear Rama de Feature

```bash
# Nomenclatura: feature/nombre-descriptivo
git checkout -b feature/nueva-funcionalidad

# Para bugs: bugfix/nombre-bug
git checkout -b bugfix/corregir-validacion-rut

# Para hotfix: hotfix/nombre-urgente
git checkout -b hotfix/sii-connection-error
```

### 3. Configurar Entorno

```bash
# Copiar .env.example si no existe .env
cp .env.example .env

# Editar .env con tus credenciales
nano .env

# Iniciar stack
docker-compose up -d

# Verificar que todo funcione
docker-compose ps
```

---

## 💻 DESARROLLO

### Estructura de Commits

Usamos **Conventional Commits**:

```bash
# Formato
<tipo>(<scope>): <descripción corta>

[cuerpo opcional]

[footer opcional]
```

**Tipos permitidos:**
- `feat`: Nueva funcionalidad
- `fix`: Corrección de bug
- `docs`: Cambios en documentación
- `style`: Formato, punto y coma faltante, etc.
- `refactor`: Refactorización de código
- `test`: Agregar o modificar tests
- `chore`: Mantenimiento, dependencias, etc.

**Ejemplos:**

```bash
# Feature
git commit -m "feat(dte): agregar soporte para DTE 39 (Boleta Electrónica)"

# Bugfix
git commit -m "fix(sii): corregir timeout en envío SOAP"

# Documentación
git commit -m "docs(readme): actualizar instrucciones de deployment"

# Tests
git commit -m "test(dte): agregar tests para generador DTE 61"

# Refactor
git commit -m "refactor(ai): optimizar cliente Claude para reducir latencia"
```

### Reglas de Código

#### **1. Python (Odoo + Microservicios)**

```python
# Seguir PEP 8
# Usar type hints
# Docstrings obligatorios

def generate_dte(
    self, 
    dte_type: str, 
    data: Dict[str, Any]
) -> str:
    """
    Genera XML DTE según tipo y datos.
    
    Args:
        dte_type: Código DTE (33, 61, 56, 52, 34)
        data: Diccionario con datos del documento
        
    Returns:
        str: XML DTE firmado digitalmente
        
    Raises:
        ValidationError: Si datos inválidos
    """
    pass
```

#### **2. Odoo - Extender, NO Duplicar**

```python
# ✅ CORRECTO: Extender modelo existente
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    
    dte_status = fields.Selection([...])

# ❌ INCORRECTO: Crear modelo nuevo
class DTEInvoice(models.Model):
    _name = 'dte.invoice'  # NO hacer esto
```

#### **3. Naming Conventions**

```python
# Variables y funciones: snake_case
dte_status = 'sent'
def generate_xml():
    pass

# Clases: PascalCase
class DTEGenerator:
    pass

# Constantes: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3
SII_TIMEOUT_SECONDS = 30
```

#### **4. Imports Organization**

```python
# 1. Standard library
import os
import json
from typing import Dict, List

# 2. Third-party
from odoo import models, fields, api
import requests

# 3. Local
from .validators import DTEValidator
```

---

## 🧪 TESTING

### Requisitos de Testing

**Mínimo obligatorio:**
- ✅ 80% code coverage
- ✅ Todos los tests pasan
- ✅ No warnings críticos

### Ejecutar Tests

```bash
# Tests DTE Service
cd dte-service
pytest --cov=. --cov-report=term --cov-report=html
# Debe mostrar: coverage >= 80%

# Tests AI Service
cd ai-service
pytest --cov=. --cov-report=term

# Tests Odoo (desde contenedor)
docker-compose exec odoo odoo -d odoo19 -u l10n_cl_dte --test-enable --stop-after-init
```

### Escribir Tests

```python
# tests/test_dte_generator.py
import pytest
from generators.dte_factory import DTEFactory

class TestDTE33Generator:
    """Tests para generador DTE 33."""
    
    def test_generate_valid_dte33(self):
        """Test generación DTE 33 válido."""
        generator = DTEFactory.create('33')
        data = {
            'rut_emisor': '12345678-9',
            'rut_receptor': '98765432-1',
            'folio': 12345,
            'fecha_emision': '2025-10-23',
            'monto_total': 100000,
            'items': [
                {
                    'nombre': 'Producto Test',
                    'cantidad': 1,
                    'precio': 100000,
                    'monto': 100000
                }
            ]
        }
        
        xml = generator.generate(data)
        
        assert xml is not None
        assert '<TipoDTE>33</TipoDTE>' in xml
        assert '<Folio>12345</Folio>' in xml
    
    def test_generate_invalid_data_raises_error(self):
        """Test que datos inválidos lanzan error."""
        generator = DTEFactory.create('33')
        
        with pytest.raises(ValueError):
            generator.generate({})  # Datos vacíos
```

---

## 📝 DOCUMENTACIÓN

### Actualizar Documentación

**Si modificas código, actualiza:**

1. **Docstrings** en el código
2. **README.md** si cambia funcionalidad principal
3. **docs/guides/** si es una nueva guía
4. **docs/api/** si cambian endpoints
5. **CHANGELOG.md** con el cambio

### Formato de Docstrings

```python
def function_name(param1: str, param2: int) -> bool:
    """
    Descripción breve de una línea.
    
    Descripción más detallada si es necesario.
    Puede tener múltiples párrafos.
    
    Args:
        param1: Descripción del parámetro 1
        param2: Descripción del parámetro 2
        
    Returns:
        bool: Descripción del valor retornado
        
    Raises:
        ValueError: Cuándo se lanza este error
        TypeError: Cuándo se lanza este error
        
    Example:
        >>> function_name("test", 42)
        True
    """
    pass
```

---

## 🔍 CODE REVIEW

### Antes de Crear Pull Request

**Checklist obligatorio:**

- [ ] Tests pasan (`pytest`)
- [ ] Coverage ≥ 80%
- [ ] Linting OK (`flake8`, `pylint`)
- [ ] Type hints agregados
- [ ] Docstrings completos
- [ ] Documentación actualizada
- [ ] Sin secrets hardcodeados
- [ ] Performance validado (p95 < 500ms)
- [ ] CHANGELOG.md actualizado
- [ ] Commits siguen Conventional Commits

### Crear Pull Request

```bash
# Push a tu rama
git push origin feature/nueva-funcionalidad

# Crear PR en GitHub con:
# - Título descriptivo
# - Descripción de cambios
# - Screenshots si aplica
# - Referencia a issue (si existe)
```

**Template de PR:**

```markdown
## Descripción
Breve descripción de los cambios realizados.

## Tipo de cambio
- [ ] Bug fix
- [ ] Nueva funcionalidad
- [ ] Breaking change
- [ ] Documentación

## ¿Cómo se ha probado?
Describe los tests realizados.

## Checklist
- [ ] Tests pasan
- [ ] Coverage ≥ 80%
- [ ] Documentación actualizada
- [ ] CHANGELOG.md actualizado
```

---

## 🚫 QUÉ NO HACER

### ❌ Prohibido

1. **NO hardcodear secrets**
   ```python
   # ❌ INCORRECTO
   api_key = "sk-ant-api03-..."
   
   # ✅ CORRECTO
   api_key = os.getenv('ANTHROPIC_API_KEY')
   ```

2. **NO duplicar funcionalidad de Odoo**
   ```python
   # ❌ NO crear sistema de usuarios
   # ✅ Usar res.users de Odoo
   ```

3. **NO mezclar responsabilidades**
   ```python
   # ❌ Odoo generando XML
   # ✅ Delegar a DTE Service
   ```

4. **NO ignorar errores**
   ```python
   # ❌ INCORRECTO
   try:
       result = api_call()
   except:
       pass  # Silenciar error
   
   # ✅ CORRECTO
   try:
       result = api_call()
   except APIError as e:
       logger.error("api_error", error=str(e))
       raise
   ```

5. **NO hacer commits directos a main/master**
   ```bash
   # ❌ INCORRECTO
   git checkout main
   git commit -m "cambios"
   
   # ✅ CORRECTO
   git checkout -b feature/mi-cambio
   git commit -m "feat: mi cambio"
   # Luego crear PR
   ```

---

## 🎨 ESTÁNDARES DE CÓDIGO

### Linting

```bash
# Python
flake8 .
pylint **/*.py

# Configuración en .flake8
[flake8]
max-line-length = 100
exclude = .git,__pycache__,venv

# Configuración en .pylintrc
[MASTER]
max-line-length=100
```

### Formatting

```bash
# Usar black para formateo automático
black .

# Configuración en pyproject.toml
[tool.black]
line-length = 100
target-version = ['py311']
```

---

## 🔒 SEGURIDAD

### Reglas de Seguridad

1. **Nunca commitear secrets**
   - Usar `.env` para secrets
   - Agregar `.env` a `.gitignore`
   - Usar variables de entorno

2. **Validar todos los inputs**
   ```python
   from pydantic import BaseModel, validator
   
   class DTERequest(BaseModel):
       rut_emisor: str
       
       @validator('rut_emisor')
       def validate_rut(cls, v):
           if not is_valid_rut(v):
               raise ValueError('RUT inválido')
           return v
   ```

3. **Sanitizar outputs**
   - No exponer stack traces
   - Logging sin datos sensibles
   - Encriptar certificados

4. **Dependencias actualizadas**
   ```bash
   # Verificar vulnerabilidades
   pip install safety
   safety check
   ```

---

## 📊 PERFORMANCE

### Targets de Performance

```python
PERFORMANCE_TARGETS = {
    'p50': 100,   # ms
    'p95': 500,   # ms (CRÍTICO)
    'p99': 1000,  # ms
}
```

### Profiling

```bash
# Python profiling
python -m cProfile -o output.prof script.py
snakeviz output.prof

# Odoo profiling
# Activar modo debug en odoo.conf
```

---

## 🐛 DEBUGGING

### Logs Estructurados

```python
import structlog

logger = structlog.get_logger()

logger.info("dte_generated",
           dte_type=33,
           folio=12345,
           rut_receptor="12345678-9")

logger.error("sii_error",
            error=str(e),
            track_id=track_id)
```

### Debug en Docker

```bash
# Ver logs en tiempo real
docker-compose logs -f odoo
docker-compose logs -f dte-service

# Ejecutar shell en contenedor
docker-compose exec odoo bash
docker-compose exec dte-service bash

# Debug Python en contenedor
docker-compose exec odoo python -m pdb script.py
```

---

## 📞 OBTENER AYUDA

### Recursos

1. **Documentación del Proyecto**
   - [README.md](README.md)
   - [TEAM_ONBOARDING.md](TEAM_ONBOARDING.md)
   - [docs/](docs/)

2. **Documentación Externa**
   - [Odoo 19 Docs](https://www.odoo.com/documentation/19.0/)
   - [FastAPI Docs](https://fastapi.tiangolo.com/)
   - [Anthropic Claude API](https://docs.anthropic.com/)

3. **Normativa SII**
   - [Resolución 80/2014](https://www.sii.cl/normativa_legislacion/resoluciones/2014/reso80.pdf)
   - [Formato DTE](https://www.sii.cl/factura_electronica/formato_dte.pdf)

### Contacto

**Desarrollador Principal:**  
Ing. Pedro Troncoso Willz  
Email: contacto@eergygroup.cl  
Empresa: EERGYGROUP

---

## ✅ CHECKLIST FINAL

Antes de crear PR, verifica:

- [ ] Código sigue estándares del proyecto
- [ ] Tests escritos y pasando (≥80% coverage)
- [ ] Linting OK (flake8, pylint)
- [ ] Type hints agregados
- [ ] Docstrings completos
- [ ] Documentación actualizada
- [ ] Sin secrets hardcodeados
- [ ] Performance validado
- [ ] CHANGELOG.md actualizado
- [ ] Commits siguen Conventional Commits
- [ ] PR tiene descripción clara

---

**¡Gracias por contribuir al proyecto! 🚀**

Si tienes dudas, revisa la documentación o contacta al equipo.
