# Estrategia de Prompting de Alta Precisión - Odoo 19 CE EERGYGROUP

**Versión:** 2.0.0  
**Fecha:** 2025-11-11  
**Autores:** Pedro Troncoso (arquitectura) + Claude Sonnet 4.5 (validación metodológica)  
**Status:** ✅ Validado en producción (experimento P1-P4, microservicio AI)

---

## 🎯 Objetivo de esta Estrategia

Proporcionar **prompts de alta precisión** para:

1. **Investigar** módulos del stack Odoo 19 CE (DTE, Payroll, Financial Reports)
2. **Auditar** arquitectura, integraciones, seguridad, compliance
3. **Desarrollar** con evidencia verificable y recomendaciones priorizadas
4. **Integrar** suite base Odoo 19 CE + módulos custom + microservicio AI

**Resultado esperado:**  
Análisis reproducibles con métricas medibles (especificidad ≥0.85, referencias ≥30, verificaciones ≥6).

---

## 📊 Niveles de Prompting (P1-P4)

### Tabla Comparativa de Niveles

| Nivel | Palabras | Especificidad | File Refs | Use Case | Tiempo |
|-------|----------|---------------|-----------|----------|--------|
| **P1** | 50-100 | 0.45-0.60 | 0-2 | Pregunta simple, consulta rápida | 30s |
| **P2** | 150-300 | 0.60-0.75 | 3-8 | Investigación inicial, exploración | 2-5min |
| **P3** | 400-700 | 0.75-0.85 | 10-20 | Análisis técnico específico | 5-10min |
| **P4-Lite** | 900-1,200 | 0.80-0.88 | 10-15 | Auditoría ejecutiva, compliance | 3-5min |
| **P4-Deep** | 1,200-1,500 | 0.85-0.95 | 30-50 | Auditoría arquitectónica, roadmap | 5-10min |

### Escalamiento Validado

**Experimento P1→P4 (2025-11-09):**
- P1 (100 palabras) → P4 (1,303 palabras) = **13x escalamiento**
- Especificidad: 0.62 → 0.95 = **+53% mejora**
- Referencias: 2 → 31 = **15.5x densidad**

**Conclusión:** P4-Deep genera análisis 13x más denso y 53% más específico que P1.

---

## 🏗️ Arquitectura Completa de Prompts

### Estructura de Directorios Actual

```
docs/prompts_desarrollo/
├── README.md (este archivo)               # Estrategia completa
├── ESTRATEGIA_PROMPTING_EFECTIVO.md      # Plan propagación CLIs (existente)
├── MAXIMAS_DESARROLLO.md                 # Estándares desarrollo
├── MAXIMAS_AUDITORIA.md                  # Estándares auditoría
├── CONTEXTO_GLOBAL_MODULOS.md            # Integración módulos
│
├── templates/                            # Templates P4 (NUEVO)
│   ├── prompt_p4_lite_template.md        # Auditoría ejecutiva
│   ├── prompt_p4_deep_template.md        # Auditoría arquitectónica
│   └── checklist_calidad_p4.md           # Validación formato + profundidad
│
├── modulos/                              # Prompts especializados por módulo
│   ├── prompt_auditoria_dte.md           # DTE (existente)
│   ├── prompt_desarrollo_dte.md          # DTE desarrollo
│   ├── prompt_auditoria_nomina.md        # Payroll (existente)
│   ├── prompt_desarrollo_nomina.md       # Payroll desarrollo
│   ├── prompt_auditoria_reportes_financieros.md  # Financial Reports
│   ├── p4_deep_l10n_cl_dte.md           # DTE P4-Deep (NUEVO)
│   ├── p4_deep_l10n_cl_hr_payroll.md    # Payroll P4-Deep (NUEVO)
│   ├── p4_deep_ai_service.md            # Microservicio AI P4-Deep (NUEVO)
│   └── p4_deep_financial_reports.md     # Reports P4-Deep (NUEVO)
│
├── integraciones/                        # Prompts de integración (NUEVO)
│   ├── p4_deep_odoo_ai_integration.md   # Odoo ↔ AI Service
│   ├── p4_deep_dte_sii_integration.md   # DTE ↔ SII Webservices
│   └── p4_deep_payroll_previred.md      # Payroll ↔ Previred
│
├── cierre/                               # Prompts orquestación cierre (existente)
│   ├── prompt_cierre_total_definitivo_brechas_global_sii_nomina_reportes.md
│   ├── prompt_seleccion_accion_cierre_total_definitivo.md
│   └── prompt_cierre_P0_cross_modulos_sii_nomina_reportes.md
│
├── plantillas/                           # Plantillas generales (existente)
│   ├── plantilla_prompt_auditoria.md
│   └── plantilla_prompt_cierre_brechas.md
│
└── ejemplos/                             # Outputs de referencia (NUEVO)
    ├── output_p4_deep_ai_service.md     # Ejemplo auditoría microservicio
    └── metricas_validadas.json          # Métricas analyze_response.py
```

---

## 🎓 Guía de Uso por Caso de Uso

### 1. Investigación Inicial de Módulo (P2)

**Objetivo:** Entender arquitectura básica, archivos clave, dependencias.

**Nivel recomendado:** P2 (150-300 palabras)

**Prompt rápido:**
```markdown
# Contexto
Módulo: l10n_cl_dte (Facturación Electrónica Chilena)
Stack: Odoo 19 CE + Python 3.11 + PostgreSQL 16

# Objetivo
Investigar arquitectura del módulo l10n_cl_dte:
- Modelos principales (herencia de account.move)
- Integraciones externas (SII webservices)
- Dependencias críticas (xmlsec, zeep, cryptography)

# Output esperado
- Lista de 5-8 archivos clave con propósito
- Diagrama de dependencias básico
- 3-5 integraciones identificadas
```

**Tiempo:** 2-5 minutos generación

---

### 2. Auditoría de Compliance (P4-Lite)

**Objetivo:** Validar cumplimiento normativo con evidencia reproducible.

**Nivel recomendado:** P4-Lite (900-1,200 palabras)

**Template:** `templates/prompt_p4_lite_template.md` (a crear)

**Áreas foco (A-F):**
- A) Arquitectura y modularidad
- B) Validaciones SII/Previred
- C) Seguridad y protección de datos
- D) Testing de compliance
- E) Observabilidad de auditoría
- F) Documentación y trazabilidad

**Métricas:**
- ≥10 referencias a código (validaciones, constraints)
- ≥3 verificaciones reproducibles (grep, pytest)
- ≥1 verificación P0 (seguridad/data loss)

**Ejemplo uso:**
```bash
copilot -p "$(cat templates/prompt_p4_lite_template.md | sed 's/MODULE_NAME/l10n_cl_dte/g')"
```

**Tiempo:** 3-5 minutos generación

---

### 3. Auditoría Arquitectónica Profunda (P4-Deep)

**Objetivo:** Evaluar diseño, deuda técnica, roadmap priorizado.

**Nivel recomendado:** P4-Deep (1,200-1,500 palabras)

**Template:** `templates/prompt_p4_deep_template.md` (a crear)

**Dimensiones (A-J):**
- A) Arquitectura y modularidad
- B) Patrones de diseño (herencia, mixins, decorators)
- C) Integraciones externas (SII, Previred, APIs)
- D) Seguridad multicapa
- E) Observabilidad
- F) Testing y cobertura
- G) Performance y escalabilidad
- H) Dependencias y CVEs
- I) Configuración y deployment
- J) Deuda técnica y mejoras críticas

**Métricas:**
- ≥30 referencias a código (cobertura ~30% archivos)
- ≥6 verificaciones reproducibles (1 por área A-F)
- ≥3 trade-offs evaluados
- ≥5 tablas comparativas

**Ejemplo uso:**
```bash
copilot -p "$(cat modulos/p4_deep_l10n_cl_dte.md)" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_l10n_cl_dte_$(date +%Y%m%d_%H%M%S).md
```

**Tiempo:** 5-10 minutos generación

---

### 4. Auditoría de Integraciones (P4-Deep Especializado)

**Objetivo:** Validar comunicación entre módulos Odoo, microservicio AI, servicios externos.

**Nivel recomendado:** P4-Deep especializado

**Templates:**
- `integraciones/p4_deep_odoo_ai_integration.md`
- `integraciones/p4_deep_dte_sii_integration.md`
- `integraciones/p4_deep_payroll_previred.md`

**Foco:**
- Contratos de API (endpoints, payloads, autenticación)
- Manejo de errores y reintentos
- Circuit breakers y fallbacks
- Timeouts y degradación
- Logging y trazabilidad distribuida

**Métricas:**
- ≥20 referencias a endpoints/handlers
- ≥4 verificaciones de integración (curl, pytest)
- ≥2 diagramas de secuencia
- ≥3 escenarios de fallo evaluados

**Tiempo:** 8-12 minutos generación

---

### 5. Desarrollo con Cierre de Brechas (Prompts Existentes)

**Objetivo:** Orquestar cierre total de brechas P0/P1/P2 con KPIs y DoD.

**Nivel recomendado:** Prompts especializados existentes

**Archivos clave:**
- `cierre/prompt_cierre_total_definitivo_brechas_global_sii_nomina_reportes.md`
- `cierre/prompt_seleccion_accion_cierre_total_definitivo.md`
- `cierre/prompt_cierre_P0_cross_modulos_sii_nomina_reportes.md`

**Flujo:**
1. Ejecutar `prompt_seleccion_accion_cierre_total_definitivo.md`
2. Confirmar acción (Fase 1, Matriz global, Pre-ejecución, Dominio específico)
3. Proceder con plan operativo por dominio
4. Actualizar `AUDITORIA_MATRIZ_BRECHAS_YYYY-MM-DD.csv`
5. Crear PRs con plantilla completa y métricas

**Referencias:**
- `MAXIMAS_DESARROLLO.md` - Estándares desarrollo
- `MAXIMAS_AUDITORIA.md` - Estándares auditoría
- `CONTEXTO_GLOBAL_MODULOS.md` - Integración módulos

---

## 📋 Checklist de Calidad (P4-Lite y P4-Deep)

### Formato (Obligatorio)

- [ ] **Progreso visible**: Plan + "Paso i/N" + cierres de sección
- [ ] **Cobertura completa**: A-F (Lite) / A-J (Deep)
- [ ] **Referencias válidas**: ≥10 (Lite) / ≥30 (Deep) con `ruta.py:línea`
- [ ] **Verificaciones reproducibles**: ≥3 (Lite) / ≥6 (Deep)
  - P4-Lite: ≥1 P0 (crítica) + ≥1 P1 (alta) + ≥1 P2 (media)
  - P4-Deep: ≥1 por área (A-F)
- [ ] **Clasificación P0/P1/P2**: Riesgos priorizados con justificación
- [ ] **Recomendaciones accionables**: Snippet + impacto esperado

### Profundidad (Calidad Técnica)

- [ ] **Términos técnicos**: ≥60 (Lite) / ≥80 (Deep)
- [ ] **Snippets de código**: ≥8 (Lite) / ≥15 (Deep) - código real del proyecto
- [ ] **Trade-offs evaluados**: ≥2 (Lite) / ≥3 (Deep)
- [ ] **Tablas comparativas**: ≥2 (Lite) / ≥5 (Deep) - antes/después, opción A vs B
- [ ] **Anti-patterns identificados**: ≥2 (Lite) / ≥3 (Deep) - con evidencia file:line
- [ ] **Especificidad**: ≥0.80 (Lite) / ≥0.85 (Deep) - calculado con analyze_response.py
- [ ] **Best practices reconocidas**: ≥3 (Lite) / ≥5 (Deep)

---

## 🎯 Casos de Uso Específicos - Stack EERGYGROUP

### Caso 1: Auditoría Módulo DTE (Facturación Electrónica)

**Prompts disponibles:**
- `modulos/prompt_auditoria_dte.md` (existente)
- `modulos/p4_deep_l10n_cl_dte.md` (a crear - P4-Deep)

**Foco:**
- Validación XML SII (esquema, firma digital xmlsec)
- Gestión de CAF (folios autorizados)
- Estados DTE (draft, validated, accepted, rejected)
- Integración SOAP con SII webservices
- TED barcode (PDF417) en PDFs

**Verificaciones clave:**
```bash
# P0: Validación firma digital
grep -rn "xmlsec" addons/localization/l10n_cl_dte/

# P1: Manejo de errores SII
grep -rn "except.*SOAPFault" addons/localization/l10n_cl_dte/

# P2: Coverage tests DTE
pytest addons/localization/l10n_cl_dte/tests/ --cov --cov-report=term-missing
```

---

### Caso 2: Auditoría Módulo Payroll (Nóminas Chilenas)

**Prompts disponibles:**
- `modulos/prompt_auditoria_nomina.md` (existente)
- `modulos/p4_deep_l10n_cl_hr_payroll.md` (a crear - P4-Deep)

**Foco:**
- Indicadores económicos (UF, UTM, IPC, salario mínimo)
- Cálculos AFP (10% tope 90.3 UF)
- Cálculos ISAPRE (7% mínimo tope 90.3 UF)
- Impuesto único segunda categoría (tramos progresivos)
- Exportación Previred (formato TXT)

**Verificaciones clave:**
```bash
# P0: Cálculo AFP con tope correcto
grep -rn "tope_imponible_afp" addons/localization/l10n_cl_hr_payroll/

# P1: Validación indicadores económicos
pytest addons/localization/l10n_cl_hr_payroll/tests/test_economic_indicators.py -v

# P2: Formato Previred exportado
cat addons/localization/l10n_cl_hr_payroll/wizards/previred_export.py | grep "def _format"
```

---

### Caso 3: Auditoría Microservicio AI

**Prompts disponibles:**
- `modulos/p4_deep_ai_service.md` (a crear - P4-Deep)

**Foco:**
- Cliente Anthropic (caching, tokens, circuit breaker)
- Chat engine (plugins, context manager, streaming SSE)
- Seguridad (API keys, rate limiting, validación Pydantic)
- Observabilidad (structlog, Prometheus, health checks)
- Integraciones (Odoo XML-RPC, Previred scraping, SII monitoring)

**Verificaciones clave:**
```bash
# P0: API keys no hardcoded
grep -rn "api_key.*=.*\"" ai-service/ --exclude-dir=tests

# P1: Circuit breaker configurado
grep -rn "CircuitBreaker" ai-service/utils/circuit_breaker.py

# P2: Coverage tests
pytest ai-service/tests/ --cov=ai-service --cov-report=html
```

---

### Caso 4: Auditoría Integración Odoo ↔ AI Service

**Prompts disponibles:**
- `integraciones/p4_deep_odoo_ai_integration.md` (a crear)

**Foco:**
- Comunicación HTTP (FastAPI endpoints ↔ Odoo controllers)
- Autenticación (API keys, tokens, CORS)
- Manejo de errores (timeouts, reintentos, fallbacks)
- Contexto conversacional (Redis sessions)
- Plugin selection (keywords en español/técnico)

**Verificaciones clave:**
```bash
# P0: Autenticación en endpoints
grep -rn "@app.post" ai-service/main.py | xargs grep -l "api_key"

# P1: Timeouts configurados
grep -rn "timeout=" ai-service/clients/

# P2: Tests de integración
pytest ai-service/tests/integration/ -v -m integration
```

---

## 📈 Métricas de Éxito

### KPIs de Calidad de Prompts

| Métrica | Target P4-Lite | Target P4-Deep | Cómo Medir |
|---------|----------------|----------------|------------|
| **Especificidad** | ≥0.80 | ≥0.85 | `analyze_response.py` |
| **File references** | ≥10 | ≥30 | Contar `ruta.py:línea` |
| **Verificaciones** | ≥3 (P0+P1+P2) | ≥6 (1 por área) | Contar comandos grep/pytest/curl |
| **Términos técnicos** | ≥60 | ≥80 | `analyze_response.py` |
| **Snippets código** | ≥8 | ≥15 | Contar bloques ```python |
| **Tablas comparativas** | ≥2 | ≥5 | Contar tablas markdown |
| **Trade-offs** | ≥2 | ≥3 | Buscar "vs", "trade-off", "opción A/B" |

### Validación Automática

```bash
# Script de validación completa (a crear)
.venv/bin/python3 scripts/validate_prompt_output.py \
  --input experimentos/outputs/audit_*.md \
  --level P4-Deep \
  --checklist docs/prompts_desarrollo/templates/checklist_calidad_p4.md \
  --metrics-json experimentos/outputs/metricas.json
```

---

## 🚀 Roadmap de Implementación

### Fase 1: Templates Base (PRÓXIMO PASO INMEDIATO)

**Tareas:**
- [ ] Crear `templates/prompt_p4_lite_template.md`
- [ ] Crear `templates/prompt_p4_deep_template.md`
- [ ] Crear `templates/checklist_calidad_p4.md`
- [ ] Crear `templates/GUIA_USO_POR_CASO.md`

**Estimación:** 2-3 horas

**Prioridad:** 🔴 ALTA (bloqueante para Fase 2)

---

### Fase 2: Prompts Especializados por Módulo

**Tareas:**
- [ ] Crear `modulos/p4_deep_l10n_cl_dte.md`
- [ ] Crear `modulos/p4_deep_l10n_cl_hr_payroll.md`
- [ ] Crear `modulos/p4_deep_ai_service.md`
- [ ] Crear `modulos/p4_deep_financial_reports.md`

**Estimación:** 4-6 horas

**Prioridad:** 🟡 MEDIA (depende de Fase 1)

---

### Fase 3: Prompts de Integraciones

**Tareas:**
- [ ] Crear `integraciones/p4_deep_odoo_ai_integration.md`
- [ ] Crear `integraciones/p4_deep_dte_sii_integration.md`
- [ ] Crear `integraciones/p4_deep_payroll_previred.md`

**Estimación:** 3-4 horas

**Prioridad:** 🟢 BAJA (complementario)

---

### Fase 4: Validación en Producción

**Tareas:**
- [ ] Ejecutar P4-Deep en 4 módulos principales
- [ ] Capturar outputs en `ejemplos/`
- [ ] Medir métricas con `analyze_response.py`
- [ ] Validar checklist de calidad
- [ ] Documentar hallazgos y mejoras

**Estimación:** 6-8 horas

**Prioridad:** 🟡 MEDIA (validación empírica)

---

### Fase 5: Propagación a CLIs

**Tareas:**
- [ ] Actualizar `.github/copilot-instructions.md`
- [ ] Crear `.claude/project/PROMPTING_BEST_PRACTICES.md`
- [ ] Crear `.codex/prompting_guidelines.md`
- [ ] Crear `.gemini/prompt_optimization.md`

**Estimación:** 2-3 horas

**Prioridad:** 🟢 BAJA (propagación)

**Referencia:** Ya existe plan en `ESTRATEGIA_PROMPTING_EFECTIVO.md`

---

## 🔧 Cómo Ejecutar los Prompts

### Opción 1: Copilot CLI (Recomendado)

```bash
# P4-Deep para módulo específico
copilot -p "$(cat docs/prompts_desarrollo/modulos/p4_deep_l10n_cl_dte.md)" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_dte_$(date +%Y%m%d_%H%M%S).md

# Capturar en background y monitorear
copilot -p "$(cat modulos/p4_deep_ai_service.md)" \
  --allow-all-tools \
  2>&1 | tee experimentos/outputs/audit_ai_live.md &

# Ver proceso
ps aux | grep copilot
```

### Opción 2: Claude Code (Modo Conversacional)

1. Abrir archivo prompt: `modulos/p4_deep_l10n_cl_dte.md`
2. Copiar contenido completo
3. Pegar en chat de Claude Code
4. Esperar análisis completo (5-10 min)
5. Copiar output a `experimentos/outputs/`

### Opción 3: Codex CLI

```bash
# Requiere configuración previa
codex --prompt-file modulos/p4_deep_l10n_cl_dte.md \
  --model gpt-4-turbo \
  --max-tokens 4000 \
  > experimentos/outputs/audit_dte_codex.md
```

---

## 📖 Referencias y Documentación

### Documentación Interna del Proyecto

- `experimentos/INVESTIGACION_PROMPT_P4_2_MICROSERVICIO_AI.md` - Metodología investigación
- `experimentos/RESUMEN_EJECUTIVO_P4_2.md` - Experimento P1→P4 validado
- `experimentos/FEEDBACK_AGENTE_MEJORADOR_PROMPTS.txt` - Feedback comparativo
- `MAXIMAS_DESARROLLO.md` - Estándares desarrollo Odoo 19 CE
- `MAXIMAS_AUDITORIA.md` - Estándares auditoría y compliance
- `CONTEXTO_GLOBAL_MODULOS.md` - Integración módulos del stack

### Herramientas de Análisis

- `experimentos/analysis/analyze_response.py` - Cálculo especificidad y métricas
- `scripts/validate_prompt_output.py` - Validación checklist (TODO - Fase 4)
- `scripts/compliance_check.py` - Validación lint, tests, seguridad

### Normativa y Compliance

- **SII Resolution 80/2014** - DTE XML schema validation
- **Previred Circular 1/2018** - Formato TXT nóminas
- **Chilean Labor Code Art. 42** - Cálculos payroll obligatorios
- **OWASP Top 10 2023** - Seguridad aplicaciones web
- **GDPR Art. 32** - Medidas de seguridad técnica (si aplicable)

### Referencias Externas

- **Odoo 19 Docs:** https://www.odoo.com/documentation/19.0/
- **Anthropic Claude API:** https://docs.anthropic.com/claude/docs
- **SII Chile:** https://www.sii.cl/servicios_online/1039-.html
- **Previred:** https://www.previred.com/web/previred/documentacion-tecnica

---

## 🤝 Contribución y Mejora Continua

### Para Mejorar esta Estrategia

1. **Probar prompts** en módulos reales del stack
2. **Medir métricas** con `analyze_response.py`
3. **Documentar hallazgos** en `experimentos/outputs/`
4. **Proponer mejoras** via PR o issue en GitHub
5. **Actualizar templates** basado en feedback empírico

### Flujo de Contribución

```bash
# 1. Crear branch
git checkout -b feature/improve-p4-prompts

# 2. Hacer cambios en templates/modulos/integraciones/

# 3. Validar con checklist
cat templates/checklist_calidad_p4.md

# 4. Ejecutar prompt y medir
copilot -p "$(cat modulos/p4_deep_l10n_cl_dte.md)" > output.md
.venv/bin/python3 experimentos/analysis/analyze_response.py output.md test P4-Deep

# 5. Commit y PR
git add docs/prompts_desarrollo/
git commit -m "feat: improve P4-Deep template for DTE module"
git push origin feature/improve-p4-prompts
```

---

## 💡 Próximos Pasos Inmediatos (Acción)

### Opción A: Crear Templates Base (RECOMENDADO)

**Acción:**
```bash
# Crear Fase 1 completa
copilot -p "Crear templates P4-Lite y P4-Deep en docs/prompts_desarrollo/templates/ \
basado en análisis de experimentos/FEEDBACK_AGENTE_MEJORADOR_PROMPTS.txt"
```

**Tiempo estimado:** 30-45 minutos  
**Bloquea:** Fase 2 (prompts especializados)

---

### Opción B: Validar P4-Deep Existente

**Acción:**
```bash
# Ejecutar P4-Deep en microservicio AI
copilot -p "$(cat experimentos/prompts/prompt_p4_2_auditoria_microservicio_ai.txt)" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_ai_p4_$(date +%Y%m%d_%H%M%S).md

# Medir métricas
.venv/bin/python3 experimentos/analysis/analyze_response.py \
  experimentos/outputs/audit_ai_p4_*.md \
  audit_ai_p4 \
  P4-Deep
```

**Tiempo estimado:** 15-20 minutos  
**Valida:** Metodología P4-Deep en producción

---

### Opción C: Ejecutar Cierre de Brechas (DESARROLLO)

**Acción:**
```bash
# Usar prompts existentes de cierre
copilot -p "$(cat docs/prompts_desarrollo/cierre/prompt_seleccion_accion_cierre_total_definitivo.md)"
```

**Tiempo estimado:** Variable (según dominio)  
**Requiere:** Decisión de acción (Fase 1, Matriz, Dominio)

---

## ❓ Preguntas Frecuentes

### ¿Cuándo usar P4-Lite vs P4-Deep?

- **P4-Lite:** Auditorías de compliance, reviews ejecutivas, seguimiento semanal
- **P4-Deep:** Auditorías arquitectónicas, diseño de roadmap, evaluación deuda técnica

### ¿Los prompts P4 reemplazan los existentes?

**NO.** Los prompts P4 son **complementarios**:
- Prompts existentes: desarrollo, cierre de brechas, orquestación
- Prompts P4: auditoría arquitectónica con métricas medibles

### ¿Cómo sé si mi prompt es P4-Deep válido?

Ejecuta checklist:
```bash
cat templates/checklist_calidad_p4.md
```

Valida con script (Fase 4):
```bash
.venv/bin/python3 scripts/validate_prompt_output.py \
  --input output.md \
  --level P4-Deep
```

### ¿Qué hacer si métricas no cumplen targets?

1. Revisar contexto: ¿suficiente información en prompt?
2. Ajustar template: ¿instrucciones claras?
3. Verificar modelo: ¿Claude Sonnet 4.5 o superior?
4. Iterar: ejecutar nuevamente con prompt mejorado

---

## 📝 Changelog

### [2.0.0] - 2025-11-11

**Added:**
- Estrategia completa de prompting P1-P4
- Roadmap de implementación (5 fases)
- Checklist de calidad dual (formato + profundidad)
- Casos de uso específicos por módulo del stack
- Métricas de éxito con targets cuantitativos
- Guía de ejecución multi-CLI (Copilot, Claude, Codex)

**Integrated:**
- Prompts existentes de cierre de brechas
- Templates de auditoría y desarrollo por módulo
- Máximas de desarrollo y auditoría
- Contexto global de módulos

**Next:**
- Fase 1: Crear templates base P4-Lite y P4-Deep
- Fase 2: Prompts especializados por módulo
- Fase 4: Validación empírica en producción

---

**Mantenedor:** Pedro Troncoso (@pwills85)  
**Última actualización:** 2025-11-11  
**Versión:** 2.0.0  
**License:** LGPL-3 (Odoo modules) + MIT (documentation)
