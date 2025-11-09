# 🚀 PLAN DE UPGRADE: AI MICROSERVICE - RESUMEN EJECUTIVO

**Objetivo:** Transformar AI Service de DTE-only a multi-módulo **SIN PERDER funcionalidad**  
**Fecha:** 2025-10-22  
**Duración:** 4-6 semanas  
**Riesgo:** ⚠️ MEDIO (mitigable)

---

## ✅ GARANTÍA: CERO PÉRDIDA DE FUNCIONALIDAD DTE

### Componentes DTE que se PRESERVAN 100%

| Componente | Estado | Estrategia |
|------------|--------|------------|
| `/api/ai/validate` endpoint | ✅ INTACTO | Wrapper + backward compatibility |
| Chat con prompt DTE | ✅ MIGRADO | Extraer a DTEPlugin, mantener funcionalidad |
| Knowledge Base DTE (10+ docs) | ✅ MIGRADO | Extraer a archivos .md, mantener contenido |
| SII Monitoring | ✅ SIN CAMBIOS | Módulo independiente |
| Anthropic Client validate_dte() | ✅ EXTENDIDO | Agregar métodos, no modificar existentes |

---

## 📅 PLAN EN 4 FASES (4-6 semanas)

### **FASE 0: PREPARACIÓN** (1 semana)
**Objetivo:** Asegurar que podemos hacer rollback seguro

**Tareas:**
1. ✅ Crear suite de tests de regresión DTE
2. ✅ Documentar contratos API existentes
3. ✅ Setup feature flags
4. ✅ Backup y branching

**Entregables:**
- Tests con >80% coverage
- Contratos API documentados
- Feature flags configurados
- Tag git `v1.0.0-dte-only`

---

### **FASE 1: REFACTORING CORE** (2 semanas)
**Objetivo:** Preparar infraestructura sin romper DTE

**Semana 1: Knowledge Base Multi-Módulo**
```python
# ANTES (hardcoded)
documents = [
    {'id': 'dte_doc_1', 'module': 'l10n_cl_dte', 'content': '...'},
    # ... 10+ docs hardcoded
]

# DESPUÉS (archivos + backward compatible)
knowledge/
├── l10n_cl_dte/
│   ├── generation_wizard.md
│   ├── caf_management.md
│   └── certificates.md
├── stock/
│   └── inventory_basics.md
└── general/
    └── odoo_basics.md

# Feature flag: enable_multi_module_kb
# Si False → usa docs hardcoded (backward compatible)
# Si True → carga desde archivos
```

**Semana 2: Sistema de Prompts Dinámicos**
```python
# ANTES (hardcoded en ChatEngine)
SYSTEM_PROMPT_BASE = """Eres experto en DTEs..."""

# DESPUÉS (registry + backward compatible)
class DTEPrompt:
    def get_system_prompt(self):
        return """Eres experto en DTEs..."""  # MISMO TEXTO

class PromptRegistry:
    prompts = {
        'l10n_cl_dte': DTEPrompt(),
        'stock': InventoryPrompt(),  # Nuevo
    }

# Feature flag: enable_dynamic_prompts
# Si False → usa prompt hardcoded
# Si True → usa registry
```

**Entregables:**
- ✅ Knowledge Base con archivos Markdown
- ✅ Sistema de prompts dinámicos
- ✅ Tests de regresión pasando
- ✅ DTE funcionando 100%

---

### **FASE 2: PLUGIN SYSTEM** (2 semanas)
**Objetivo:** Migrar DTE a plugin, agregar extensibilidad

**Semana 3: Base de Plugins**
```python
# plugins/base.py
class AIPlugin(ABC):
    @abstractmethod
    def get_module_name(self) -> str: pass
    
    @abstractmethod
    def validate(self, data: Dict) -> Dict: pass
    
    @abstractmethod
    def get_system_prompt(self) -> str: pass

# plugins/dte/plugin.py
class DTEPlugin(AIPlugin):
    def get_module_name(self):
        return "l10n_cl_dte"
    
    def validate(self, data, context):
        # MIGRADO desde main.py validate_dte()
        # MISMA LÓGICA, nuevo wrapper
        client = get_anthropic_client()
        return client.validate_dte(data, context.get('history', []))
    
    def get_system_prompt(self):
        # MIGRADO desde ChatEngine.SYSTEM_PROMPT_BASE
        return """Eres experto en DTEs..."""
```

**Semana 4: Endpoints Genéricos**
```python
# main.py - NUEVO endpoint genérico
@app.post("/api/ai/validate/{module}")
async def validate_document(module: str, request: GenericRequest):
    plugin = plugin_registry.get_plugin(module)
    return await plugin.validate(request.data, request.context)

# main.py - MANTENER endpoint legacy (backward compatible)
@app.post("/api/ai/validate")
async def validate_dte(request: DTEValidationRequest):
    # Wrapper que llama al nuevo sistema
    plugin = plugin_registry.get_plugin('l10n_cl_dte')
    return await plugin.validate(request.dte_data, {'history': request.history})
```

**Entregables:**
- ✅ DTEPlugin funcionando
- ✅ Endpoints legacy funcionando
- ✅ Nuevo endpoint genérico
- ✅ Tests pasando

---

### **FASE 3: VALIDACIÓN Y DEPLOYMENT** (1 semana)
**Objetivo:** Asegurar calidad antes de producción

**Tareas:**
1. ✅ Tests end-to-end completos
2. ✅ Load testing
3. ✅ Documentación actualizada
4. ✅ Deployment staging
5. ✅ Validación con usuarios

**Criterios de Aceptación:**
- Todos los tests pasando (100%)
- Performance igual o mejor
- Endpoints DTE funcionando idéntico
- Documentación completa

---

## 🛡️ ESTRATEGIA DE MITIGACIÓN DE RIESGOS

### Feature Flags (Rollback Instantáneo)

```python
# config.py
class Settings:
    # Si algo falla, cambiar a False
    enable_plugin_system: bool = False
    enable_multi_module_kb: bool = False
    enable_dynamic_prompts: bool = False
    
    # Siempre True en producción (garantía)
    force_dte_compatibility_mode: bool = True
```

**Ventaja:** Rollback sin redesplegar, solo cambiar variable de entorno

### Tests de Regresión Automáticos

```python
# tests/test_dte_regression.py
def test_validate_dte_endpoint():
    """Verificar que endpoint DTE funciona igual"""
    response = client.post("/api/ai/validate", json={...})
    assert response.status_code == 200
    assert "confidence" in response.json()

def test_chat_dte_knowledge():
    """Verificar que chat responde sobre DTEs"""
    response = client.post("/api/chat/message", json={
        "message": "¿Cómo genero un DTE 33?"
    })
    assert "dte" in response.json()["message"].lower()
```

**Ventaja:** Detectar regresiones antes de deployment

### Deployment Gradual

```
1. Staging → Tests completos
2. Canary → 5% tráfico producción
3. Blue-Green → 50% tráfico
4. Full → 100% tráfico
```

**Ventaja:** Detectar problemas con tráfico real mínimo

---

## 📊 COMPARACIÓN: ANTES vs DESPUÉS

### **ANTES (Estado Actual)**
```
✅ Funcionalidad DTE: 100%
❌ Extensibilidad: 30%
❌ Agregar módulo: 2-3 días modificando core
❌ Mantenibilidad: Media
```

### **DESPUÉS (Post-Upgrade)**
```
✅ Funcionalidad DTE: 100% (PRESERVADA)
✅ Extensibilidad: 95%
✅ Agregar módulo: 2-3 horas creando plugin
✅ Mantenibilidad: Alta
```

**Mejora:** 10x más rápido agregar módulos, sin perder DTE

---

## ✅ GARANTÍAS DE SEGURIDAD

### 1. **Backward Compatibility 100%**
- Todos los endpoints existentes funcionan igual
- Mismas URLs, mismos contratos
- Mismos modelos Pydantic

### 2. **Rollback Instantáneo**
- Feature flags permiten volver atrás sin redesplegar
- Backup de código en tag git
- Tests de regresión detectan problemas

### 3. **Testing Exhaustivo**
- >80% code coverage
- Tests unitarios, integración, end-to-end
- Load testing para performance

### 4. **Deployment Gradual**
- Staging → Canary → Blue-Green → Full
- Monitoreo en cada fase
- Rollback automático si métricas fallan

---

## 🎯 RECOMENDACIÓN FINAL

**✅ PROCEDER CON UPGRADE**

**Justificación:**
1. Plan de mitigación robusto (feature flags + tests + deployment gradual)
2. Funcionalidad DTE 100% preservada (verificable con tests)
3. ROI alto (10x más rápido agregar módulos)
4. Riesgo controlado (rollback instantáneo)

**Timing recomendado:**
- Iniciar en sprint tranquilo (no antes de releases críticos)
- Duración: 4-6 semanas
- Deployment: Viernes tarde (menos tráfico)

**Equipo necesario:**
- 1 desarrollador senior (full-time)
- 1 QA (part-time para tests)
- 1 DevOps (part-time para deployment)

---

## 📋 CHECKLIST DE EJECUCIÓN

### Fase 0: Preparación
- [ ] Tests de regresión DTE creados
- [ ] Contratos API documentados
- [ ] Feature flags configurados
- [ ] Branch `feature/multi-module-upgrade` creado
- [ ] Tag `v1.0.0-dte-only` creado

### Fase 1: Refactoring Core
- [ ] Knowledge Base extraída a archivos .md
- [ ] Loader de Markdown funcionando
- [ ] Sistema de prompts dinámicos implementado
- [ ] Tests de regresión pasando
- [ ] Feature flags testeados

### Fase 2: Plugin System
- [ ] Plugin base creado
- [ ] DTEPlugin implementado
- [ ] Endpoints genéricos funcionando
- [ ] Endpoints legacy funcionando
- [ ] Tests end-to-end pasando

### Fase 3: Validación
- [ ] Load testing completado
- [ ] Documentación actualizada
- [ ] Deployment staging exitoso
- [ ] Validación con usuarios
- [ ] Aprobación para producción

---

**Documento generado:** 2025-10-22  
**Autor:** Plan de Upgrade AI Service  
**Versión:** 1.0 - Executive Summary
