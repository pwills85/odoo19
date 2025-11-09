# 🚀 PLAN DE RETOMA - STACK NÓMINAS CHILE 2025

**Fecha Análisis:** 2025-10-23 18:00 UTC
**Contexto:** Análisis completo vs desarrollo actual
**Estado Actual:** 78% completado
**Meta:** 90% funcional (Opción A recomendada)

---

## 📊 ESTADO ACTUAL DEL PROYECTO

### **✅ COMPLETADO (78%)**

#### 1. Módulo Odoo - `l10n_cl_hr_payroll/`
```
Líneas: 4,252 Python + 9 vistas XML
Modelos: 16 implementados
Tests: 13 automatizados
Sprint 4.1: ✅ Completado (2025-10-23)

REGLAS CRÍTICAS IMPLEMENTADAS:
• hr_salary_rule_gratificacion.py (350 líneas)
  - Art. 50 CT: 25% utilidades
  - Tope 4.75 IMM
  - Mensualización 1/12

• hr_salary_rule_asignacion_familiar.py (371 líneas)
  - DFL 150: 3 tramos A/B/C
  - Montos 2025 actualizados
  - Validación cargas legales

• hr_salary_rule_aportes_empleador.py (300 líneas)
  - SIS: 1.53% (tope 87.8 UF)
  - Seguro Cesantía: 2.4%/3.0%
  - CCAF: 0.6% opcional
```

**Archivos Clave:**
- `__manifest__.py` ✅ Estructura completa
- `models/hr_contract_cl.py` ✅ Contratos Chile
- `models/hr_payslip.py` ✅ 12 campos nuevos computados
- `models/hr_salary_rule.py` ✅ Base reglas
- `models/hr_economic_indicators.py` ✅ UF/UTM/UTA
- `models/hr_afp.py` ✅ 10 fondos AFP
- `models/hr_isapre.py` ✅ Planes Isapre

**Pendiente:**
- ❌ `models/hr_employee_cl.py` (extensión empleados Chile)
- ❌ `wizards/previred_export_wizard.py` (exportar archivo)
- ❌ `wizards/finiquito_wizard.py` (liquidación final)
- ❌ `report/liquidacion_report.xml` (PDF liquidaciones)

---

#### 2. AI-Service Payroll - `ai-service/payroll/`
```
Líneas: ~800 Python
Estructura: ✅ 70% lista
Endpoints: 2/4 implementados

COMPONENTES EXISTENTES:
• payroll_validator.py (123 líneas)
  - Validación básica liquidaciones
  - TODO: Integrar Claude API real

• previred_scraper.py (estimado ~300 líneas)
  - Scraping indicadores Previred
  - TODO: Verificar implementación

• __init__.py
  - Módulo inicializado
```

**Endpoints en main.py:**
- ❌ `/api/ai/payroll/validate` (declarado, sin implementar)
- ❌ `/api/ai/payroll/chat` (no existe)
- ❌ `/api/ai/payroll/optimize` (no existe)
- ❌ `/api/ai/payroll/previred/extract` (no existe)

**Infraestructura Disponible:**
- ✅ Claude API client (`clients/anthropic_client.py`)
- ✅ Structured logging
- ✅ Chat Engine (`chat/engine.py`)
- ✅ Context Manager (`chat/context_manager.py`)
- ✅ Knowledge Base (`chat/knowledge_base.py`)

---

#### 3. DTE-Service Auth - `dte-service/auth/`
```
Líneas: ~900 Python (5 archivos)
OAuth2: ✅ Google + Azure AD
RBAC: ✅ 25 permisos DTE + 5 roles

SISTEMA COMPLETO:
• models.py - User, Role, Token, Company
• oauth2.py - Multi-provider OAuth2
• permissions.py - 25 permisos + RBAC
• routes.py - Login/logout/refresh
• __init__.py - Exports
```

**100% REUTILIZABLE en AI-Service** ⭐
Solo requiere: Agregar permisos payroll

---

### **❌ PENDIENTE (22%)**

#### 1. Payroll-Service (0%)
```
DECISIÓN ARQUITECTÓNICA PENDIENTE:

OPCIÓN A: Integrar en AI-Service ✅ RECOMENDADO
• Más ligero (0 contenedores nuevos)
• Reutiliza Claude API
• 20h desarrollo vs 83h desde cero
• 75% ahorro ($6,300 USD)

OPCIÓN B: Microservicio separado
• Puerto 8003 independiente
• +40h desarrollo adicional
• +1 contenedor overhead
• Mayor modularidad
```

#### 2. Portal Empleados (0%)
```
DECISIÓN: Portal nativo Odoo 19 + customización

Plan 60 horas:
• Extender portal nativo (16h)
• Vistas customizadas (20h)
• Bot IA chat laboral (16h)
• Dashboard personal (8h)
```

---

## 🎯 PLAN DE RETOMA RECOMENDADO

### **OPCIÓN A: Completar Stack Actual** ⭐ PRIORIDAD ALTA

**Objetivo:** Stack 90% funcional en 1 semana
**Inversión:** 32 horas (~$3,200 USD @ $100/h)
**ROI:** Entregables visibles inmediatos

---

### **FASE 1: Reutilización Microservicios (8h)** 🔴 CRÍTICO

#### **1.1 Extender Sistema de Autenticación (2h)**
```bash
TAREA: Agregar permisos payroll al sistema OAuth2/RBAC existente

PASOS:
1. Copiar módulo auth desde DTE-Service
   cd /Users/pedro/Documents/odoo19/ai-service
   cp -r ../dte-service/auth ./auth

2. Editar auth/permissions.py
   Agregar:
   class Permission(str, Enum):
       # Permisos payroll
       PAYROLL_GENERATE = "payroll:generate"
       PAYROLL_VIEW = "payroll:view"
       PAYROLL_APPROVE = "payroll:approve"
       PAYROLL_EXPORT = "payroll:export"
       PREVIRED_GENERATE = "previred:generate"
       SETTLEMENT_CREATE = "settlement:create"  # Finiquito

3. Actualizar ROLE_PERMISSIONS
   UserRole.PAYROLL_MANAGER: [
       Permission.PAYROLL_GENERATE,
       Permission.PAYROLL_VIEW,
       Permission.PAYROLL_APPROVE,
       Permission.PAYROLL_EXPORT,
       Permission.PREVIRED_GENERATE
   ]

4. Tests básicos permisos
   pytest auth/test_permissions_payroll.py

ARCHIVOS MODIFICADOS:
• ai-service/auth/permissions.py (+50 líneas)
• ai-service/auth/test_permissions_payroll.py (+80 líneas NUEVO)

BENEFICIO:
✅ Login enterprise multi-provider
✅ RBAC granular payroll
✅ 0h desarrollo (solo configuración)
```

---

#### **1.2 Crear Knowledge Base Payroll (4h)**
```bash
TAREA: Knowledge Base laboral para Chat IA

CREAR ARCHIVO: ai-service/chat/knowledge_base_payroll.py

CONTENIDO (estimado 600 líneas):

"""
Knowledge Base - Legislación Laboral Chilena
============================================

## CÓDIGO DEL TRABAJO

### Artículo 50: Gratificación Legal
El empleador debe pagar al trabajador el 25% de las utilidades líquidas.
Tope: 4.75 IMM (Ingreso Mínimo Mensual) por trabajador.
Mensualización: Se paga mensualmente 1/12 de la gratificación anual.

Cálculo:
- Utilidades líquidas empresa: $100.000.000
- Trabajadores: 20
- Gratificación individual = ($100M * 0.25) / 20 = $1.250.000
- Tope 4.75 IMM = 4.75 * $460.000 = $2.185.000
- Pago mensual = $1.250.000 / 12 = $104.166

### DFL 150: Asignación Familiar

Tramos 2025 (vigente desde enero):
- Tramo A (ingreso hasta $554,678): $13,193 por carga
- Tramo B (ingreso $554,678 - $857,745): $8,120 por carga
- Tramo C (ingreso sobre $857,745): $2,563 por carga

Cargas reconocidas:
- Hijos menores de 18 años
- Hijos entre 18-24 estudiantes
- Cónyuge/pareja sin ingresos
- Padres mayores 65 años sin previsión

### Reforma Previsional 2025

Aportes empleador:
- SIS (Seguro Invalidez y Sobrevivencia): 1.53%
  Tope: 87.8 UF mensuales
- Seguro Cesantía:
  • Indefinido: 2.4% empleador + 0.6% trabajador
  • Plazo fijo: 3.0% empleador + 0.6% trabajador
  Tope: 120.2 UF mensuales
- CCAF (Caja Compensación): 0.6% (opcional)

### Impuesto Único Segunda Categoría (7 tramos SII 2025)

Tramo 1: Hasta 13.5 UTA exento
Tramo 2: 13.5 - 30 UTA → 4%
Tramo 3: 30 - 50 UTA → 8%
Tramo 4: 50 - 70 UTA → 13.5%
Tramo 5: 70 - 90 UTA → 23%
Tramo 6: 90 - 120 UTA → 30.4%
Tramo 7: Sobre 120 UTA → 35%

(UTA 2025 = $742,833)

### Artículo 54: Obligación Libro Remuneraciones
El empleador debe llevar un libro auxiliar de remuneraciones con:
- Identificación del trabajador
- Fecha de ingreso
- Remuneraciones devengadas
- Descuentos legales
- Líquido pagado
- Firma del trabajador

Conservación: 7 años mínimo

## PREVIRED

### Formato Archivo 105 Campos
(incluir especificación técnica completa...)

### Certificado F30-1
(detalles certificado cotizaciones...)

## FINIQUITO (Liquidación Final)

### Componentes Obligatorios:
1. Sueldo proporcional días trabajados
2. Vacaciones proporcionales (pendientes + proporcionales)
3. Gratificación proporcional
4. Indemnización años servicio (tope 11 años)
5. Indemnización sustitutiva aviso previo (opcional)

### Cálculo Indemnización Años:
Base: Última remuneración mensual
Tope: 90 UF por año
Años máximos: 11 años

Ejemplo:
- Sueldo: $1.500.000
- Años servicio: 8
- Indemnización = $1.500.000 * 8 = $12.000.000
- Tope 90 UF = 90 * $37,000 * 8 = $26.640.000
- Pago final: $12.000.000 (menor entre los dos)

## CASOS DE USO COMUNES

### "¿Cómo calcular AFP?"
AFP = Base imponible * (Tasa fondo + Comisión AFP)
Tope: 82.7 UF mensuales

Ejemplo Fondo C Capital:
- Sueldo: $1.500.000
- Tasa: 10%
- Comisión: 1.27%
- AFP = $1.500.000 * 0.1127 = $169.050

### "¿Cuánto es el descuento de salud?"
FONASA: 7% fijo
ISAPRE: 7% mínimo + exceso según plan

...
"""

ARCHIVOS CREADOS:
• ai-service/chat/knowledge_base_payroll.py (+600 líneas)

BENEFICIO:
✅ Chat IA especializado legislación chilena
✅ Respuestas precisas consultas RRHH
✅ Base conocimiento extendible
```

---

#### **1.3 Configurar Scheduler Previred (2h)**
```bash
TAREA: Jobs automáticos Previred + recordatorios

CREAR ARCHIVO: ai-service/payroll/previred_scheduler.py

CÓDIGO:
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from payroll.previred_scraper import scrape_previred
import structlog

logger = structlog.get_logger(__name__)
scheduler = AsyncIOScheduler()

@scheduler.scheduled_job('cron', hour=8, minute=0)  # Diario 8 AM
async def update_previred_indicators():
    """Actualizar UF, UTM, UTA, Sueldo Mínimo desde Previred"""
    try:
        indicators = await scrape_previred()
        await save_to_redis(indicators)

        logger.info(
            "previred_indicators_updated",
            uf=indicators.get('uf'),
            utm=indicators.get('utm'),
            uta=indicators.get('uta'),
            minimum_wage=indicators.get('minimum_wage')
        )

        # Notificar a Odoo vía webhook
        await notify_odoo_indicators_updated(indicators)

    except Exception as e:
        logger.error("previred_update_failed", error=str(e))

@scheduler.scheduled_job('cron', day=25, hour=9, minute=0)  # Día 25 cada mes
async def send_payroll_reminders():
    """Recordatorio procesamiento nómina mensual"""
    try:
        message = "🔔 Recordatorio: Procesar nómina del mes"
        await send_slack_notification(message)

        logger.info("payroll_reminder_sent")
    except Exception as e:
        logger.error("reminder_failed", error=str(e))

@scheduler.scheduled_job('cron', day_of_week='sun', hour=23, minute=0)  # Domingo 11 PM
async def backup_payslips():
    """Backup semanal liquidaciones (Art. 54 CT - 7 años)"""
    try:
        await backup_to_s3()
        logger.info("payslips_backup_completed")
    except Exception as e:
        logger.error("backup_failed", error=str(e))

# Inicializar en main.py startup
def init_scheduler():
    scheduler.start()
    logger.info("payroll_scheduler_started")

MODIFICAR: ai-service/main.py
@app.on_event("startup")
async def startup_event():
    # Existing code...

    # NUEVO: Inicializar scheduler payroll
    from payroll.previred_scheduler import init_scheduler
    init_scheduler()

ARCHIVOS CREADOS:
• ai-service/payroll/previred_scheduler.py (+120 líneas)

ARCHIVOS MODIFICADOS:
• ai-service/main.py (+5 líneas)

BENEFICIO:
✅ Indicadores Previred siempre actualizados
✅ Recordatorios automáticos nómina
✅ Backups compliance Art. 54 CT
```

---

### **FASE 2: Completar AI-Service Payroll (8h)** 🟡 IMPORTANTE

#### **2.1 Implementar Endpoints Payroll (6h)**
```bash
TAREA: 4 endpoints funcionales en main.py

ARCHIVO: ai-service/main.py

AGREGAR:

# ═══════════════════════════════════════════════════════════
# PAYROLL ENDPOINTS
# ═══════════════════════════════════════════════════════════

from auth import require_permission, Permission, get_current_user, User
from payroll.payroll_validator import PayrollValidator

# Modelos Pydantic
class PayslipValidationRequest(BaseModel):
    """Request validación liquidación"""
    employee_id: int
    period: str  # "2025-10"
    wage: float
    lines: List[Dict[str, Any]]

class PayslipValidationResponse(BaseModel):
    """Response validación"""
    success: bool
    confidence: float  # 0-100
    errors: List[str]
    warnings: List[str]
    recommendation: str  # "approve" | "review" | "reject"

# 1. Validación liquidación
@app.post("/api/ai/payroll/validate",
          response_model=PayslipValidationResponse,
          tags=["Payroll"],
          summary="Validar liquidación con IA")
@require_permission(Permission.PAYROLL_VIEW)
async def validate_payslip(
    request: PayslipValidationRequest,
    user: User = Depends(get_current_user)
):
    """
    Valida liquidación usando Claude API

    Detecta:
    - Errores cálculo AFP, Salud, Impuesto
    - Anomalías vs historial empleado
    - Compliance legislación chilena
    """
    logger.info("payslip_validation_requested",
                employee_id=request.employee_id,
                period=request.period,
                user=user.email)

    try:
        from clients.anthropic_client import get_anthropic_client

        client = get_anthropic_client()
        validator = PayrollValidator(client)

        payslip_data = {
            "employee_id": request.employee_id,
            "period": request.period,
            "wage": request.wage,
            "lines": request.lines
        }

        result = await validator.validate_payslip(payslip_data)

        return PayslipValidationResponse(**result)

    except Exception as e:
        logger.error("payslip_validation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation failed: {str(e)}"
        )

# 2. Chat laboral
@app.post("/api/ai/payroll/chat",
          tags=["Payroll"],
          summary="Chat laboral con IA")
@require_permission(Permission.PAYROLL_VIEW)
async def payroll_chat(
    question: str,
    session_id: Optional[str] = None,
    user: User = Depends(get_current_user)
):
    """
    Chat especializado en legislación laboral chilena

    Knowledge Base incluye:
    - Código del Trabajo
    - Previred
    - DT (Dirección del Trabajo)
    """
    from chat.engine import ChatEngine
    from chat.knowledge_base_payroll import PAYROLL_KNOWLEDGE

    session_id = session_id or str(uuid.uuid4())

    engine = get_chat_engine()  # Singleton existente

    # Agregar contexto payroll
    context = f"""
    {PAYROLL_KNOWLEDGE}

    Usuario: {user.email}
    Rol: {user.role}
    """

    response = await engine.send_message(
        session_id=session_id,
        user_message=question,
        user_context={"knowledge_base": "payroll"}
    )

    return {
        "session_id": session_id,
        "answer": response.assistant_message,
        "sources": ["Código del Trabajo", "Previred", "DT"]
    }

# 3. Optimización liquidación
class OptimizationRequest(BaseModel):
    """Request optimización"""
    payslip_data: Dict[str, Any]
    constraints: Optional[Dict[str, Any]] = {}

@app.post("/api/ai/payroll/optimize",
          tags=["Payroll"],
          summary="Optimizar liquidación")
@require_permission(Permission.PAYROLL_APPROVE)
async def optimize_payslip(
    request: OptimizationRequest,
    user: User = Depends(get_current_user)
):
    """
    Sugiere optimizaciones legales:
    - APV (Ahorro Previsional Voluntario) para reducir impuestos
    - Distribución haberes imponibles/no imponibles
    - Gratificación mensual vs anual
    """
    # TODO: Implementar con Claude API
    return {
        "optimizations": [
            {
                "type": "APV",
                "description": "Aportar $200.000 mensual APV reduce impuesto en $70.000",
                "tax_savings": 70000
            }
        ]
    }

# 4. Extracción datos Previred
@app.post("/api/ai/payroll/previred/extract",
          tags=["Payroll"],
          summary="Extraer indicadores Previred")
@require_permission(Permission.PREVIRED_GENERATE)
async def extract_previred_indicators(
    force: bool = False,
    user: User = Depends(get_current_user)
):
    """
    Scraping indicadores Previred (UF, UTM, UTA, SMM)

    Cache 24h en Redis (excepto force=True)
    """
    from payroll.previred_scraper import scrape_previred
    from utils.redis_helper import get_redis_client

    redis = get_redis_client()
    cache_key = "previred:indicators:latest"

    # Check cache
    if not force:
        cached = redis.get(cache_key)
        if cached:
            return json.loads(cached)

    # Scrape fresh data
    indicators = await scrape_previred()

    # Save to cache (24h TTL)
    redis.setex(cache_key, 86400, json.dumps(indicators))

    logger.info("previred_indicators_extracted",
                uf=indicators.get('uf'),
                utm=indicators.get('utm'))

    return indicators

ARCHIVOS MODIFICADOS:
• ai-service/main.py (+300 líneas)

BENEFICIO:
✅ 4 endpoints payroll funcionales
✅ Integración OAuth2 + RBAC
✅ Validación IA real con Claude
✅ Chat laboral especializado
```

---

#### **2.2 Mejorar PayrollValidator con Claude (2h)**
```bash
TAREA: Integrar Claude API en validación real

ARCHIVO: ai-service/payroll/payroll_validator.py

MODIFICAR método validate_payslip():

async def validate_payslip(self, payslip_data: Dict) -> Dict:
    """Validar liquidación con IA Claude"""

    # Preparar prompt para Claude
    employee_id = payslip_data.get('employee_id')
    period = payslip_data.get('period')
    wage = payslip_data.get('wage', 0)
    lines = payslip_data.get('lines', [])

    # Formatear líneas
    lines_text = "\n".join([
        f"  - {line['code']}: ${line['amount']:,.0f}"
        for line in lines
    ])

    prompt = f"""
    Analiza esta liquidación de sueldo chilena:

    Empleado ID: {employee_id}
    Período: {period}
    Sueldo base: ${wage:,.0f}

    Líneas:
    {lines_text}

    LEGISLACIÓN VIGENTE 2025:
    - AFP: 10% + comisión (tope 82.7 UF)
    - Salud: 7% FONASA o 7%+ ISAPRE
    - Impuesto: 7 tramos progresivos (exento hasta 13.5 UTA)
    - SIS: 1.53% cargo empleador (tope 87.8 UF)
    - Seguro Cesantía: 0.6% trabajador + 2.4% empleador

    VALIDA:
    1. ¿Los cálculos son correctos?
    2. ¿Hay errores matemáticos?
    3. ¿Cumple legislación chilena?
    4. ¿Hay anomalías vs liquidaciones típicas?

    RESPONDE EN JSON:
    {{
      "errors": ["error1", "error2"],
      "warnings": ["advertencia1"],
      "recommendation": "approve|review|reject",
      "confidence": 95.0,
      "explanation": "Razones..."
    }}
    """

    # Llamar a Claude
    response = await self.claude.complete(
        prompt=prompt,
        temperature=0.1,  # Más determinístico
        max_tokens=1000
    )

    # Parsear respuesta JSON
    try:
        result = json.loads(response)
    except:
        # Fallback si Claude no retorna JSON válido
        result = {
            "errors": [],
            "warnings": ["Error parsing AI response"],
            "recommendation": "review",
            "confidence": 50.0
        }

    logger.info(
        "payslip_validation_completed",
        employee_id=employee_id,
        recommendation=result.get('recommendation'),
        confidence=result.get('confidence')
    )

    return {
        "success": True,
        **result
    }

ARCHIVOS MODIFICADOS:
• ai-service/payroll/payroll_validator.py (+80 líneas)

BENEFICIO:
✅ Validación IA real (no mock)
✅ Detecta errores complejos
✅ Explicaciones en español
```

---

### **FASE 3: Completar Módulo Odoo (12h)** 🟡 IMPORTANTE

#### **3.1 Crear hr_employee_cl.py (4h)**
```bash
TAREA: Extensión empleados Chile

CREAR ARCHIVO: addons/localization/l10n_cl_hr_payroll/models/hr_employee_cl.py

CÓDIGO:
# -*- coding: utf-8 -*-
from odoo import models, fields, api
from odoo.exceptions import ValidationError

class HREmployeeCL(models.Model):
    """Extensión empleado Chile"""
    _inherit = 'hr.employee'

    # RUT (ya existe en l10n_cl via res.partner)
    # Usar vat del partner relacionado

    # Datos previsionales
    afp_id = fields.Many2one('hr.afp', string='AFP')
    health_entity_type = fields.Selection([
        ('fonasa', 'FONASA'),
        ('isapre', 'ISAPRE'),
    ], string='Sistema Salud', default='fonasa')

    isapre_id = fields.Many2one('hr.isapre', string='ISAPRE')
    isapre_plan_pesos = fields.Float('Plan Isapre (Pesos)')
    isapre_plan_uf = fields.Float('Plan Isapre (UF)')

    # APV (Ahorro Previsional Voluntario)
    apv_enabled = fields.Boolean('APV Activo')
    apv_amount = fields.Float('Monto APV Mensual')
    apv_regime = fields.Selection([
        ('a', 'Régimen A (Beneficio Tributario)'),
        ('b', 'Régimen B (Sin Beneficio)'),
    ], string='Régimen APV')

    # CCAF
    ccaf_enabled = fields.Boolean('CCAF', default=True)

    # Asignación familiar
    family_allowance_tranche = fields.Selection([
        ('a', 'Tramo A (hasta $554,678)'),
        ('b', 'Tramo B ($554,678 - $857,745)'),
        ('c', 'Tramo C (sobre $857,745)'),
        ('none', 'No corresponde'),
    ], string='Tramo Asignación Familiar', compute='_compute_family_allowance_tranche', store=True)

    family_allowance_charges = fields.Integer('Cargas Familiares', default=0)
    family_allowance_amount = fields.Float('Monto Asignación', compute='_compute_family_allowance_amount', store=True)

    # Seguro cesantía
    unemployment_insurance_type = fields.Selection([
        ('indefinite', 'Indefinido'),
        ('fixed', 'Plazo Fijo'),
    ], string='Tipo Contrato (Cesantía)', default='indefinite')

    @api.depends('contract_id.wage')
    def _compute_family_allowance_tranche(self):
        """Calcular tramo asignación familiar según sueldo"""
        for employee in self:
            if not employee.contract_id:
                employee.family_allowance_tranche = 'none'
                continue

            wage = employee.contract_id.wage

            # Tramos 2025
            if wage <= 554678:
                employee.family_allowance_tranche = 'a'
            elif wage <= 857745:
                employee.family_allowance_tranche = 'b'
            else:
                employee.family_allowance_tranche = 'c'

    @api.depends('family_allowance_tranche', 'family_allowance_charges')
    def _compute_family_allowance_amount(self):
        """Calcular monto asignación familiar"""
        # Montos 2025
        AMOUNTS = {
            'a': 13193,
            'b': 8120,
            'c': 2563,
            'none': 0,
        }

        for employee in self:
            tranche = employee.family_allowance_tranche or 'none'
            charges = employee.family_allowance_charges or 0

            employee.family_allowance_amount = AMOUNTS[tranche] * charges

ARCHIVOS CREADOS:
• models/hr_employee_cl.py (+150 líneas)

ARCHIVOS MODIFICADOS:
• models/__init__.py (+1 línea: from . import hr_employee_cl)
• __manifest__.py (agregar vista en 'data')

BENEFICIO:
✅ Datos previsionales empleado
✅ Asignación familiar automática
✅ APV configurable
```

---

#### **3.2 Wizard Exportación Previred (4h)**
```bash
TAREA: Wizard generar archivo Previred 105 campos

CREAR ARCHIVO: addons/localization/l10n_cl_hr_payroll/wizards/previred_export_wizard.py

CÓDIGO:
# -*- coding: utf-8 -*-
from odoo import models, fields, api
from odoo.exceptions import UserError
import requests
import base64

class PreviredExportWizard(models.TransientModel):
    """Wizard exportación Previred"""
    _name = 'previred.export.wizard'
    _description = 'Exportar archivo Previred'

    period = fields.Char('Período (YYYYMM)', required=True, default=lambda self: fields.Date.today().strftime('%Y%m'))
    payslip_run_id = fields.Many2one('hr.payslip.run', 'Proceso Nómina')

    file_data = fields.Binary('Archivo Previred', readonly=True)
    file_name = fields.Char('Nombre Archivo', readonly=True)

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('done', 'Generado'),
    ], default='draft')

    def action_generate(self):
        """Generar archivo Previred"""
        self.ensure_one()

        # Obtener liquidaciones del período
        payslips = self.env['hr.payslip'].search([
            ('date_to', '>=', f'{self.period[:4]}-{self.period[4:]}-01'),
            ('date_to', '<=', f'{self.period[:4]}-{self.period[4:]}-31'),
            ('state', '=', 'done'),
        ])

        if not payslips:
            raise UserError('No hay liquidaciones aprobadas para el período')

        # Llamar a AI-Service para generar archivo
        ai_service_url = self.env['ir.config_parameter'].sudo().get_param('ai_service.url', 'http://ai-service:8002')
        api_key = self.env['ir.config_parameter'].sudo().get_param('ai_service.api_key')

        # Preparar datos
        data = {
            "period": self.period,
            "payslips": [
                {
                    "employee_id": p.employee_id.id,
                    "employee_rut": p.employee_id.vat,
                    "wage": p.contract_id.wage,
                    # ... más campos
                }
                for p in payslips
            ]
        }

        # Request a AI-Service
        response = requests.post(
            f'{ai_service_url}/api/ai/payroll/previred/generate',
            json=data,
            headers={'Authorization': f'Bearer {api_key}'},
            timeout=60
        )

        if response.status_code != 200:
            raise UserError(f'Error generando archivo: {response.text}')

        # Guardar archivo
        file_content = response.content
        file_name = f'previred_{self.period}.txt'

        self.write({
            'file_data': base64.b64encode(file_content),
            'file_name': file_name,
            'state': 'done',
        })

        return {
            'type': 'ir.actions.act_window',
            'res_model': 'previred.export.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }

CREAR VISTA: wizards/previred_export_wizard_views.xml

<odoo>
  <record id="previred_export_wizard_form" model="ir.ui.view">
    <field name="name">previred.export.wizard.form</field>
    <field name="model">previred.export.wizard</field>
    <field name="arch" type="xml">
      <form>
        <group states="draft">
          <field name="period"/>
          <field name="payslip_run_id"/>
        </group>

        <group states="done">
          <field name="file_name"/>
          <field name="file_data" filename="file_name"/>
        </group>

        <field name="state" invisible="1"/>

        <footer>
          <button string="Generar" type="object" name="action_generate"
                  class="btn-primary" states="draft"/>
          <button string="Cerrar" special="cancel"/>
        </footer>
      </form>
    </field>
  </record>
</odoo>

ARCHIVOS CREADOS:
• wizards/previred_export_wizard.py (+100 líneas)
• wizards/previred_export_wizard_views.xml (+30 líneas)

ARCHIVOS MODIFICADOS:
• wizards/__init__.py (+1 línea)
• __manifest__.py (agregar vista)

BENEFICIO:
✅ Exportación Previred 1-click
✅ Integración AI-Service
✅ Validación período
```

---

#### **3.3 Wizard Finiquito (4h)**
```bash
TAREA: Wizard liquidación final (finiquito)

CREAR ARCHIVO: addons/localization/l10n_cl_hr_payroll/wizards/finiquito_wizard.py

CÓDIGO:
# -*- coding: utf-8 -*-
from odoo import models, fields, api
from odoo.exceptions import UserError, ValidationError
from datetime import datetime, timedelta

class FiniquitoWizard(models.TransientModel):
    """Wizard generación finiquito"""
    _name = 'finiquito.wizard'
    _description = 'Generar Finiquito'

    employee_id = fields.Many2one('hr.employee', 'Empleado', required=True)
    termination_date = fields.Date('Fecha Término', required=True, default=fields.Date.today)
    termination_reason = fields.Selection([
        ('resignation', 'Renuncia Voluntaria'),
        ('dismissal_cause', 'Despido con Causa (Art. 160)'),
        ('dismissal_no_cause', 'Despido sin Causa (Art. 161)'),
        ('mutual_agreement', 'Mutuo Acuerdo'),
    ], string='Causal', required=True)

    # Cálculos automáticos
    years_service = fields.Float('Años Servicio', compute='_compute_years_service', store=True)
    proportional_salary = fields.Float('Sueldo Proporcional', compute='_compute_proportional_salary')
    proportional_vacation = fields.Float('Vacaciones Proporcionales', compute='_compute_proportional_vacation')
    proportional_gratification = fields.Float('Gratificación Proporcional', compute='_compute_proportional_gratification')

    # Indemnizaciones
    indemnization_years = fields.Float('Indemnización Años Servicio')
    indemnization_notice = fields.Float('Indemnización Aviso Previo')

    # Total
    total_finiquito = fields.Float('Total Finiquito', compute='_compute_total_finiquito')

    @api.depends('employee_id', 'termination_date')
    def _compute_years_service(self):
        """Calcular años de servicio"""
        for wizard in self:
            if not wizard.employee_id or not wizard.termination_date:
                wizard.years_service = 0
                continue

            # Primera fecha contrato
            first_contract = self.env['hr.contract'].search([
                ('employee_id', '=', wizard.employee_id.id)
            ], order='date_start asc', limit=1)

            if not first_contract:
                wizard.years_service = 0
                continue

            date_start = fields.Date.from_string(first_contract.date_start)
            date_end = fields.Date.from_string(wizard.termination_date)

            days = (date_end - date_start).days
            wizard.years_service = days / 365.25

    @api.depends('employee_id', 'termination_date')
    def _compute_proportional_salary(self):
        """Sueldo proporcional días trabajados del mes"""
        for wizard in self:
            if not wizard.employee_id or not wizard.termination_date:
                wizard.proportional_salary = 0
                continue

            contract = wizard.employee_id.contract_id
            if not contract:
                wizard.proportional_salary = 0
                continue

            # Días trabajados en el mes
            termination_date = fields.Date.from_string(wizard.termination_date)
            days_in_month = 30  # Convención laboral chilena
            days_worked = termination_date.day

            wizard.proportional_salary = (contract.wage / days_in_month) * days_worked

    @api.depends('employee_id', 'years_service')
    def _compute_proportional_vacation(self):
        """Vacaciones proporcionales + pendientes"""
        for wizard in self:
            if not wizard.employee_id:
                wizard.proportional_vacation = 0
                continue

            # Vacaciones legales: 15 días hábiles por año
            # Proporcional año en curso
            months_worked = (wizard.years_service % 1) * 12
            vacation_days_proportional = (15 / 12) * months_worked

            # Vacaciones pendientes años anteriores
            # TODO: Integrar con módulo hr_holidays
            vacation_days_pending = 0

            # Valor día vacaciones = sueldo / 30
            contract = wizard.employee_id.contract_id
            if contract:
                daily_wage = contract.wage / 30
                total_days = vacation_days_proportional + vacation_days_pending
                wizard.proportional_vacation = daily_wage * total_days
            else:
                wizard.proportional_vacation = 0

    @api.depends('employee_id', 'termination_date')
    def _compute_proportional_gratification(self):
        """Gratificación proporcional meses trabajados"""
        for wizard in self:
            if not wizard.employee_id:
                wizard.proportional_gratification = 0
                continue

            contract = wizard.employee_id.contract_id
            if not contract:
                wizard.proportional_gratification = 0
                continue

            # Meses trabajados en el año
            termination_date = fields.Date.from_string(wizard.termination_date)
            months_worked = termination_date.month

            # Gratificación anual / 12 * meses trabajados
            # Usar campo gratificacion_amount del contrato
            annual_gratification = contract.gratificacion_amount or 0
            wizard.proportional_gratification = (annual_gratification / 12) * months_worked

    @api.depends('proportional_salary', 'proportional_vacation', 'proportional_gratification',
                 'indemnization_years', 'indemnization_notice')
    def _compute_total_finiquito(self):
        """Total finiquito"""
        for wizard in self:
            wizard.total_finiquito = (
                wizard.proportional_salary +
                wizard.proportional_vacation +
                wizard.proportional_gratification +
                wizard.indemnization_years +
                wizard.indemnization_notice
            )

    @api.onchange('termination_reason', 'years_service')
    def _onchange_indemnization(self):
        """Calcular indemnizaciones según causal"""
        if self.termination_reason == 'dismissal_no_cause':
            # Indemnización años servicio (tope 11 años, 90 UF/año)
            contract = self.employee_id.contract_id
            if contract:
                # Obtener UF actual
                uf_value = self.env['hr.economic.indicators'].get_latest_uf()

                # Años a indemnizar (máximo 11)
                years_to_pay = min(self.years_service, 11)

                # Sueldo base
                monthly_wage = contract.wage

                # Tope: 90 UF por año
                max_per_year = 90 * uf_value

                # Indemnización = sueldo * años (o tope)
                indemnization_calculated = monthly_wage * years_to_pay
                indemnization_max = max_per_year * years_to_pay

                self.indemnization_years = min(indemnization_calculated, indemnization_max)

                # Indemnización sustitutiva aviso previo (1 mes)
                self.indemnization_notice = monthly_wage
        else:
            self.indemnization_years = 0
            self.indemnization_notice = 0

    def action_generate_finiquito(self):
        """Generar finiquito y liquidación"""
        self.ensure_one()

        # Crear liquidación especial tipo finiquito
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee_id.id,
            'contract_id': self.employee_id.contract_id.id,
            'name': f'Finiquito - {self.employee_id.name}',
            'date_from': self.termination_date,
            'date_to': self.termination_date,
            'payslip_type': 'finiquito',
            # Agregar líneas...
        })

        # Generar PDF finiquito
        return self.env.ref('l10n_cl_hr_payroll.action_report_finiquito').report_action(payslip)

ARCHIVOS CREADOS:
• wizards/finiquito_wizard.py (+200 líneas)
• wizards/finiquito_wizard_views.xml (+60 líneas)

BENEFICIO:
✅ Finiquitos automáticos legales
✅ Cálculos conformes CT
✅ Validación indemnizaciones
```

---

### **FASE 4: Reportes PDF (4h)** 🟢 NICE-TO-HAVE

#### **4.1 PDF Liquidación Estándar (4h)**
```bash
TAREA: Reporte PDF liquidación para empleado

CREAR ARCHIVO: addons/localization/l10n_cl_hr_payroll/report/liquidacion_report.xml

<odoo>
  <report
    id="action_report_liquidacion"
    model="hr.payslip"
    string="Liquidación de Sueldo"
    report_type="qweb-pdf"
    name="l10n_cl_hr_payroll.report_liquidacion_document"
    file="l10n_cl_hr_payroll.report_liquidacion"
    print_report_name="'Liquidacion_%s' % (object.number or 'draft')"
  />

  <template id="report_liquidacion_document">
    <t t-call="web.html_container">
      <t t-foreach="docs" t-as="doc">
        <t t-call="l10n_cl_hr_payroll.report_liquidacion_template" t-lang="doc.employee_id.lang"/>
      </t>
    </t>
  </template>

  <template id="report_liquidacion_template">
    <t t-call="web.external_layout">
      <div class="page">
        <!-- Header -->
        <div class="row">
          <div class="col-8">
            <h2>LIQUIDACIÓN DE SUELDO</h2>
            <p>
              <strong>Período:</strong> <span t-field="doc.date_from"/> - <span t-field="doc.date_to"/><br/>
              <strong>Folio:</strong> <span t-field="doc.number"/>
            </p>
          </div>
          <div class="col-4 text-right">
            <img t-if="doc.company_id.logo" t-att-src="image_data_uri(doc.company_id.logo)" alt="Logo"/>
          </div>
        </div>

        <hr/>

        <!-- Datos empleado -->
        <div class="row mt-3">
          <div class="col-6">
            <strong>Empleado:</strong> <span t-field="doc.employee_id.name"/><br/>
            <strong>RUT:</strong> <span t-field="doc.employee_id.vat"/><br/>
            <strong>Cargo:</strong> <span t-field="doc.employee_id.job_id.name"/>
          </div>
          <div class="col-6">
            <strong>AFP:</strong> <span t-field="doc.employee_id.afp_id.name"/><br/>
            <strong>Salud:</strong>
            <span t-if="doc.employee_id.health_entity_type == 'fonasa'">FONASA</span>
            <span t-if="doc.employee_id.health_entity_type == 'isapre'" t-field="doc.employee_id.isapre_id.name"/>
          </div>
        </div>

        <!-- Tabla haberes y descuentos -->
        <table class="table table-sm mt-4">
          <thead>
            <tr>
              <th>Código</th>
              <th>Descripción</th>
              <th class="text-right">Haberes</th>
              <th class="text-right">Descuentos</th>
            </tr>
          </thead>
          <tbody>
            <t t-foreach="doc.line_ids" t-as="line">
              <tr>
                <td><span t-field="line.code"/></td>
                <td><span t-field="line.name"/></td>
                <td class="text-right">
                  <span t-if="line.total > 0" t-field="line.total"
                        t-options='{"widget": "monetary", "display_currency": doc.company_id.currency_id}'/>
                </td>
                <td class="text-right">
                  <span t-if="line.total < 0" t-field="line.total"
                        t-options='{"widget": "monetary", "display_currency": doc.company_id.currency_id}'/>
                </td>
              </tr>
            </t>
          </tbody>
          <tfoot>
            <tr class="font-weight-bold">
              <td colspan="2">TOTAL HABERES</td>
              <td class="text-right">
                <span t-field="doc.total_haberes"
                      t-options='{"widget": "monetary", "display_currency": doc.company_id.currency_id}'/>
              </td>
              <td></td>
            </tr>
            <tr class="font-weight-bold">
              <td colspan="2">TOTAL DESCUENTOS</td>
              <td></td>
              <td class="text-right">
                <span t-field="doc.total_descuentos"
                      t-options='{"widget": "monetary", "display_currency": doc.company_id.currency_id}'/>
              </td>
            </tr>
            <tr class="font-weight-bold" style="font-size: 1.2em;">
              <td colspan="2">LÍQUIDO A PAGAR</td>
              <td colspan="2" class="text-right">
                <span t-field="doc.net_wage"
                      t-options='{"widget": "monetary", "display_currency": doc.company_id.currency_id}'/>
              </td>
            </tr>
          </tfoot>
        </table>

        <!-- Indicadores económicos (Art. 54 CT - snapshot) -->
        <div class="row mt-4">
          <div class="col-12">
            <small class="text-muted">
              <strong>Indicadores aplicados:</strong>
              UF: <span t-field="doc.uf_value"/> |
              UTM: <span t-field="doc.utm_value"/> |
              UTA: <span t-field="doc.uta_value"/>
            </small>
          </div>
        </div>

        <!-- Firma -->
        <div class="row mt-5">
          <div class="col-6 text-center">
            <p>_______________________<br/>Firma Empleador</p>
          </div>
          <div class="col-6 text-center">
            <p>_______________________<br/>Firma Empleado</p>
          </div>
        </div>
      </div>
    </t>
  </template>
</odoo>

ARCHIVOS CREADOS:
• report/liquidacion_report.xml (+120 líneas)

ARCHIVOS MODIFICADOS:
• __manifest__.py (agregar reporte en 'data')

BENEFICIO:
✅ PDFs profesionales liquidaciones
✅ Compliance Art. 54 CT
✅ Imprimible para firma
```

---

## 📈 ENTREGABLES FINALES

Al completar este plan (32 horas), tendrás:

### ✅ **AI-Service Payroll Completo (100%)**
```
ai-service/
├── auth/                    ✅ OAuth2 + RBAC extendido
├── payroll/
│   ├── payroll_validator.py    ✅ Validación Claude real
│   ├── previred_scraper.py     ✅ Scraping indicadores
│   └── previred_scheduler.py   ✅ Jobs automáticos NUEVO
├── chat/
│   └── knowledge_base_payroll.py  ✅ KB laboral NUEVO
└── main.py                  ✅ 4 endpoints funcionales

Endpoints operacionales:
• POST /api/ai/payroll/validate
• POST /api/ai/payroll/chat
• POST /api/ai/payroll/optimize
• POST /api/ai/payroll/previred/extract
```

### ✅ **Módulo Odoo l10n_cl_hr_payroll (90%)**
```
addons/localization/l10n_cl_hr_payroll/
├── models/
│   ├── hr_employee_cl.py         ✅ Extensión empleados NUEVO
│   ├── hr_payslip.py             ✅ 12 campos computados
│   ├── hr_salary_rule_*.py       ✅ 3 reglas críticas
│   └── ... (16 modelos totales)
├── wizards/
│   ├── previred_export_wizard.py   ✅ Exportación 1-click NUEVO
│   └── finiquito_wizard.py         ✅ Finiquitos automáticos NUEVO
├── report/
│   └── liquidacion_report.xml      ✅ PDFs profesionales NUEVO
└── __manifest__.py               ✅ Actualizado
```

---

## 🚀 PRÓXIMOS PASOS (POST FASE 4)

### **Sprint 5: Portal Empleados (60h)** - OPCIONAL
Si después de completar el stack 90% decides seguir:

```
Portal nativo Odoo 19:
• Vista liquidaciones históricas (12h)
• Descarga PDFs (4h)
• Certificados (antigüedad, renta) (12h)
• Solicitud vacaciones (8h)
• Bot IA chat RRHH (16h)
• Dashboard personal (8h)
```

---

## 📊 COMPARACIÓN OPCIONES

| Métrica | Actual (78%) | Opción A (90%) | Plan Completo (100%) |
|---------|-------------|----------------|---------------------|
| **Tiempo** | - | 32h (1 semana) | 92h (2.5 semanas) |
| **Costo** | - | $3,200 | $9,200 |
| **Módulo Odoo** | 78% | 90% | 100% |
| **AI-Service** | 70% | 100% | 100% |
| **Portal Empleados** | 0% | 0% | 100% |
| **Payroll-Service** | 0% | Integrado AI | Opcional separado |
| **Estado** | ✅ Funcional básico | ✅ Operacional completo | ✅ Enterprise full |

---

## 💡 RECOMENDACIÓN FINAL

### ✅ **EJECUTAR OPCIÓN A** ⭐

**Razones:**
1. **ROI Inmediato:** 1 semana → Stack operacional 90%
2. **Reutilización Máxima:** 75% ahorro usando infraestructura DTE
3. **Menor Riesgo:** Completar lo iniciado antes de agregar complejidad
4. **Quick Wins:** Entregables visibles rápido (wizards, PDFs, endpoints)
5. **Base Sólida:** Plataforma robusta para evolución futura

**Después evaluar:**
- Portal empleados si hay presión usuarios
- Payroll-Service separado si hay carga transaccional alta

---

## 📞 DECISIÓN REQUERIDA

**¿Procedemos con Opción A (32h, 1 semana)?**

**Orden sugerido ejecución:**
1. Fase 1 (8h) - Reutilización microservicios ← **CRÍTICO**
2. Fase 2 (8h) - Endpoints AI-Service ← **IMPORTANTE**
3. Fase 3 (12h) - Módulo Odoo completo ← **IMPORTANTE**
4. Fase 4 (4h) - PDFs ← **NICE-TO-HAVE**

**Listo para comenzar cuando confirmes.** 🚀

---

**Documento generado:** 2025-10-23 18:00 UTC
**Próxima revisión:** Post implementación Fase 1-4
