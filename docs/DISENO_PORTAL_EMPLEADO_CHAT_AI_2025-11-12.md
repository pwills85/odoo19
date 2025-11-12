# 🧑‍💼 DISEÑO: PORTAL DEL EMPLEADO CON CHAT AI PERSONALIZADO

**Fecha:** 2025-11-12
**Autor:** Claude Code (Arquitecto AI/Odoo)
**Módulo:** l10n_cl_hr_employee_portal
**Sprint:** Portal Empleado + Chat AI Nómina (Phase 3)
**Estado:** PROPUESTA DE DISEÑO

---

## 📋 ÍNDICE

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Contexto y Justificación](#contexto-y-justificación)
3. [Marco Regulatorio Chileno](#marco-regulatorio-chileno)
4. [Arquitectura Técnica](#arquitectura-técnica)
5. [Seguridad y Privacidad](#seguridad-y-privacidad)
6. [Funcionalidades del Portal](#funcionalidades-del-portal)
7. [Chat AI Personalizado](#chat-ai-personalizado)
8. [Flujos de Usuario](#flujos-de-usuario)
9. [Modelo de Datos](#modelo-de-datos)
10. [Integraciones](#integraciones)
11. [Plan de Implementación](#plan-de-implementación)
12. [Estimaciones y Roadmap](#estimaciones-y-roadmap)
13. [Riesgos y Mitigaciones](#riesgos-y-mitigaciones)
14. [Anexos](#anexos)

---

## 📊 RESUMEN EJECUTIVO

### Visión del Producto

Portal web self-service para empleados con **asistente virtual AI especializado en nóminas chilenas**, que permite a cada trabajador:

- 📄 Consultar sus liquidaciones de sueldo (historial completo)
- 📥 Descargar certificados (antigüedad, renta, cotizaciones)
- 💬 Hacer preguntas sobre su remuneración a un **Chat AI Profesional**
- 📊 Ver dashboard de indicadores personales (YTD, proyecciones)
- 🔔 Recibir notificaciones (nuevas liquidaciones, cambios contrato)

### Propuesta de Valor

| Beneficio | Descripción | Impacto ROI |
|-----------|-------------|-------------|
| **Autonomía Empleados** | Respuestas 24/7 sin esperar a RRHH | ↓ 70% consultas RRHH |
| **Reducción Tickets** | Chat AI resuelve 80% consultas comunes | ↓ 60% carga RRHH |
| **Compliance Legal** | Cumple Ley 21.719 + Código del Trabajo | ✅ Sin sanciones |
| **Experiencia UX** | Portal moderno con AI conversacional | ↑ 85% satisfacción |
| **Escalabilidad** | Arquitectura cloud-ready (FastAPI + Redis) | ✅ 1000+ empleados |

### Diferenciadores Técnicos

✅ **Chat AI Contextual**: Claude Sonnet 4.5 especializado en legislación laboral chilena
✅ **Aislamiento de Datos**: Cada empleado solo ve SU información (RLS estricto)
✅ **Compliance by Design**: Implementa Ley 21.719 desde arquitectura
✅ **Multi-tenancy**: Soporta múltiples empresas con aislamiento total
✅ **Performance**: Redis cache + Streaming SSE (respuestas en <300ms)

---

## 🎯 CONTEXTO Y JUSTIFICACIÓN

### Problema Actual

**Situación:**
- Empleados deben pedir liquidaciones a RRHH (email/WhatsApp)
- Consultas repetitivas sobre descuentos AFP, Isapre, impuestos
- RRHH gasta 40% tiempo respondiendo preguntas básicas
- No hay portal self-service en Odoo 19 CE (solo en Enterprise)
- Falta de transparencia genera desconfianza

**Impacto:**
```
📊 Métricas Actuales (estimadas para empresa 100 empleados):
   • 200 consultas/mes a RRHH sobre nóminas
   • 15 minutos promedio por consulta
   • 50 horas/mes RRHH en consultas repetitivas
   • Costo: $750.000/mes (sueldo analista RRHH)
```

### Solución Propuesta

**Portal del Empleado + Chat AI** que:

1. **Automatiza consultas comunes** (80% resueltas por AI)
2. **Empodera empleados** con acceso 24/7 a su información
3. **Reduce carga RRHH** permitiendo foco en tareas estratégicas
4. **Cumple normativa** (Ley 21.719 + Código del Trabajo)
5. **Escala sin costo marginal** (AI maneja 1 o 1000 empleados)

**ROI Esperado:**
```
📈 Beneficios Anuales (100 empleados):
   • Ahorro RRHH: $9.000.000/año (70% reducción consultas)
   • Productividad empleados: $3.500.000/año (menos tiempo en trámites)
   • Evitar multas compliance: $5.000.000+ (sanciones Ley 21.719)
   • TOTAL: $17.500.000/año

💰 Inversión (estimada):
   • Desarrollo: $8.000.000 (320 horas * $25.000/hora)
   • Operación AI: $150.000/mes ($1.800.000/año)
   • TOTAL Año 1: $9.800.000

✅ Payback: 6.7 meses
✅ ROI 3 años: 435%
```

---

## 📜 MARCO REGULATORIO CHILENO

### Ley 21.719 - Protección de Datos Personales

**Vigencia:** 1 de diciembre de 2026
**Reemplaza:** Ley 19.628 (antigua ley de datos)

#### Obligaciones del Empleador

| Requisito | Implementación Portal |
|-----------|----------------------|
| **Consentimiento explícito** | ✅ Checkbox "Acepto uso de mis datos" en primer login |
| **Información transparente** | ✅ Página "Política de Privacidad" con uso de datos |
| **Finalidad específica** | ✅ Solo datos para gestión laboral y nómina |
| **Seguridad técnica** | ✅ Cifrado TLS 1.3, tokens JWT, RLS database |
| **Derechos ARCO** | ✅ Botón "Ejercer mis derechos" (acceso, rectificación, oposición) |
| **Portabilidad** | ✅ Exportar todos mis datos en JSON/PDF |
| **Responsable DPO** | ⚠️ Designar Data Protection Officer empresa |

#### Régimen de Sanciones

- **Infracciones leves**: Amonestación o multa hasta 5.000 UTM (~$360M CLP)
- **Infracciones graves**: Multa hasta 10.000 UTM (~$720M CLP)

**Ejemplos:**
- Falta de consentimiento: GRAVE
- No implementar canal ARCO: LEVE
- Filtración de datos: GRAVE

### Código del Trabajo - Artículo 54

**Obligación:** Entregar liquidación de sueldo al trabajador

**Formato:**
- ✅ Digital (email personal) con consentimiento trabajador
- ✅ Papel si trabajador lo solicita
- ❌ Email corporativo (pierde acceso al salir)

**Contenido mínimo liquidación:**
```
• Monto total pagado
• Forma de cálculo (haberes y descuentos)
• Período (mes y año)
• Desglose descuentos previsionales (AFP, Salud, AFC)
• Impuesto único (si aplica)
```

### Dirección del Trabajo - Dictamen Digital

**Conclusión:** No existe impedimento legal para entregar liquidaciones por internet

**Requisitos:**
1. Acuerdo con trabajador (consentimiento)
2. Envío a email **personal** (no corporativo)
3. Trabajador puede exigir formato papel

### Ley 19.728 - Seguro de Cesantía

**Relevancia:** Portal debe mostrar descuento AFC (0.6% trabajador)

### Reforma Tributaria 2025

**Relevancia:** Cálculo impuesto único (tramos actualizados)

---

## 🏗️ ARQUITECTURA TÉCNICA

### Diagrama General

```
┌─────────────────────────────────────────────────────────────┐
│                    NAVEGADOR EMPLEADO                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Portal UI (Vue.js / Odoo Web)                       │  │
│  │  • Dashboard personal                                │  │
│  │  • Listado liquidaciones                             │  │
│  │  • Chat AI (Streaming SSE)                           │  │
│  │  • Descargas certificados                            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          ↕ HTTPS (TLS 1.3)
┌─────────────────────────────────────────────────────────────┐
│                      ODOO 19 CE SERVER                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  l10n_cl_hr_employee_portal (NEW MODULE)             │  │
│  │  • Controllers (portal routes)                       │  │
│  │  • Models (employee.portal.access, portal.session)   │  │
│  │  • Security (RLS rules, record rules)                │  │
│  │  • Views (portal templates)                          │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  l10n_cl_hr_payroll (EXISTING)                       │  │
│  │  • hr.payslip (liquidaciones)                        │  │
│  │  • hr.contract (contratos)                           │  │
│  │  • hr.employee (empleados)                           │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  PostgreSQL 16 + RLS (Row Level Security)            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          ↕ HTTP REST (port 8002)
┌─────────────────────────────────────────────────────────────┐
│              AI MICROSERVICE (FastAPI) [EXISTING]           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  NEW: Employee Chat Plugin                           │  │
│  │  • employee_chat/plugin.py                           │  │
│  │  • Specialized system prompt (payroll Chilean)       │  │
│  │  • Context isolation (employee_id filter)            │  │
│  │  • Knowledge base: labor law + payroll docs          │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Chat Engine (EXISTING - Phase 2B)                   │  │
│  │  • Multi-agent plugin system                         │  │
│  │  • Context Manager (Redis sessions)                  │  │
│  │  • Streaming SSE support                             │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Redis Cache                                         │  │
│  │  • Session history (TTL 24h)                         │  │
│  │  • Employee context cache                            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          ↕
                   ANTHROPIC API
              (Claude Sonnet 4.5)
```

### Stack Tecnológico

| Capa | Tecnología | Justificación |
|------|------------|---------------|
| **Frontend** | Vue.js 3 + Odoo Web | ✅ Integración nativa Odoo |
| **Backend** | Python 3.11 + Odoo 19 CE | ✅ Módulo estándar Odoo |
| **AI Service** | FastAPI (existing) | ✅ Ya implementado Phase 2B |
| **LLM** | Claude Sonnet 4.5 | ✅ Mejor para español chileno |
| **Cache** | Redis 7.x | ✅ Sessions + performance |
| **Database** | PostgreSQL 16 + RLS | ✅ Aislamiento datos nativo |
| **Auth** | Odoo Sessions + JWT | ✅ SSO empleados |
| **Files** | Odoo Filestore | ✅ PDFs liquidaciones |

### Componentes Nuevos a Desarrollar

#### 1. Módulo Odoo: `l10n_cl_hr_employee_portal`

**Estructura:**
```
l10n_cl_hr_employee_portal/
├── __init__.py
├── __manifest__.py
├── security/
│   ├── ir.model.access.csv
│   └── portal_security.xml          # RLS rules
├── models/
│   ├── __init__.py
│   ├── employee_portal_access.py    # Control acceso
│   ├── portal_session.py            # Sesiones chat
│   ├── hr_employee.py               # Extend employee
│   └── hr_payslip.py                # Extend payslip
├── controllers/
│   ├── __init__.py
│   ├── main.py                      # Portal routes
│   └── chat_api.py                  # Chat endpoints
├── views/
│   ├── portal_dashboard.xml         # Dashboard empleado
│   ├── portal_payslips.xml          # Listado liquidaciones
│   ├── portal_certificates.xml      # Certificados
│   └── portal_chat.xml              # Chat AI
├── static/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.vue        # Vue components
│   │   │   ├── PayslipList.vue
│   │   │   ├── ChatWidget.vue       # Chat AI widget
│   │   │   └── CertificateGenerator.vue
│   │   └── main.js
│   └── css/
│       └── portal.css
├── data/
│   ├── mail_templates.xml           # Emails notificación
│   └── cron_jobs.xml                # Tareas programadas
└── wizard/
    └── employee_consent.py          # Wizard consentimiento
```

#### 2. AI Plugin: `employee_chat`

**Ubicación:** `ai-service/plugins/employee_chat/`

**Características:**
- System prompt especializado en legislación laboral chilena
- Context filtering por `employee_id` (aislamiento total)
- Knowledge base: Código del Trabajo + circulares DT + Previred
- Validación que empleado solo consulte SUS datos

---

## 🔒 SEGURIDAD Y PRIVACIDAD

### Principio: Security by Design

Toda la arquitectura implementa **aislamiento de datos** desde la base de datos:

### 1. Row-Level Security (RLS) en PostgreSQL

**Configuración:**
```sql
-- Regla RLS: Empleado solo ve SUS liquidaciones
CREATE POLICY employee_payslip_policy ON hr_payslip
    FOR SELECT
    TO portal_user
    USING (
        employee_id = (
            SELECT id FROM hr_employee
            WHERE user_id = current_user_id()
        )
    );

-- Regla RLS: Empleado solo ve SU contrato
CREATE POLICY employee_contract_policy ON hr_contract
    FOR SELECT
    TO portal_user
    USING (
        employee_id = (
            SELECT id FROM hr_employee
            WHERE user_id = current_user_id()
        )
    );
```

**Resultado:** Imposible que empleado acceda a datos de otro (garantizado por DB)

### 2. Authentication & Authorization

#### Odoo Sessions (SSO)

```python
# Flujo de login
1. Empleado accede: https://empresa.odoo.com/my/portal
2. Odoo verifica session cookie
3. Si no autenticado: redirect a /web/login
4. Login con credenciales Odoo (user/password o OAuth2)
5. Odoo crea session y asigna grupo "Portal Employee"
6. RLS rules se activan automáticamente
```

#### JWT Tokens para AI Service

```python
# Cuando empleado abre chat:
1. Frontend solicita JWT: POST /portal/chat/get_token
2. Backend Odoo genera JWT:
   {
     "employee_id": 123,
     "user_id": 456,
     "company_id": 1,
     "exp": "2025-11-12T15:00:00Z"  # 1 hora
   }
3. Frontend incluye JWT en llamadas AI:
   Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
4. AI Service valida JWT y filtra por employee_id
```

### 3. Aislamiento en Chat AI

**Validación en AI Service:**

```python
# ai-service/plugins/employee_chat/plugin.py

async def send_message(self, message: str, context: Dict) -> Dict:
    """
    Send message with STRICT employee_id isolation.
    """
    # 1. Extract employee_id from JWT (validated)
    employee_id = context.get('employee_id')

    if not employee_id:
        raise HTTPException(401, "Unauthorized")

    # 2. ALWAYS filter Odoo queries by employee_id
    payslips = await odoo_client.search_read(
        'hr.payslip',
        domain=[('employee_id', '=', employee_id)],  # ✅ CRITICAL
        fields=['date_from', 'date_to', 'net_wage']
    )

    # 3. Inject in prompt context
    prompt = f"""
    Eres asistente personal de nóminas para empleado ID {employee_id}.

    **REGLA CRÍTICA:** Solo puedes responder sobre datos de este empleado.
    Si usuario pregunta por otros empleados, responde:
    "No tengo acceso a información de otros empleados."

    Liquidaciones empleado:
    {json.dumps(payslips, indent=2)}

    Pregunta: {message}
    """

    response = await claude_api.generate(prompt)
    return response
```

### 4. Auditoría y Logging

**Logs de acceso:**
```python
# Cada consulta empleado se registra
logger.info(
    "portal_access",
    employee_id=123,
    user_id=456,
    action="view_payslip",
    payslip_id=789,
    timestamp="2025-11-12T10:30:00Z",
    ip_address="192.168.1.100"
)
```

**Reportes compliance:**
- ¿Quién accedió a qué datos? (ARCO - derecho de acceso)
- ¿Cuándo se otorgó consentimiento?
- ¿Qué consultas hizo cada empleado al chat?

### 5. Cifrado

| Capa | Cifrado | Detalles |
|------|---------|----------|
| **Transporte** | TLS 1.3 | ✅ HTTPS end-to-end |
| **Database** | PostgreSQL encryption | ✅ Datos en reposo cifrados |
| **Passwords** | Bcrypt | ✅ Odoo estándar |
| **JWT Tokens** | HMAC-SHA256 | ✅ Firma digital |
| **Session Cookies** | Signed + HttpOnly | ✅ Anti-XSS |

### 6. Compliance ARCO (Derechos Empleado)

**Implementación:**

| Derecho | Implementación Portal | Endpoint |
|---------|----------------------|----------|
| **Acceso** | Ver todos mis datos | `/portal/my/data` |
| **Rectificación** | Solicitar corrección datos | `/portal/my/rectify` |
| **Oposición** | Oponerse a tratamiento | `/portal/my/oppose` |
| **Portabilidad** | Exportar datos (JSON/PDF) | `/portal/my/export` |
| **Supresión** | Solicitar eliminación | `/portal/my/delete` |
| **Bloqueo** | Suspender tratamiento | `/portal/my/block` |

**Wizard de Ejercicio de Derechos:**
```xml
<!-- wizard/employee_rights_wizard.xml -->
<record id="view_employee_rights_wizard" model="ir.ui.view">
    <field name="name">employee.rights.wizard.form</field>
    <field name="model">employee.rights.wizard</field>
    <field name="arch" type="xml">
        <form>
            <group>
                <field name="right_type" widget="radio" required="1"/>
                <field name="reason" widget="text" required="1"/>
            </group>
            <footer>
                <button string="Enviar Solicitud" type="object"
                        name="submit_request" class="btn-primary"/>
                <button string="Cancelar" special="cancel"/>
            </footer>
        </form>
    </field>
</record>
```

---

## 💼 FUNCIONALIDADES DEL PORTAL

### Dashboard Personal

**Vista principal al ingresar:**

```
┌────────────────────────────────────────────────────────────┐
│  👤 Bienvenido, Juan Pérez                     🔔 [3]      │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  📊 RESUMEN NOVIEMBRE 2025                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │ Sueldo Bruto│ │  Descuentos │ │ Líquido     │         │
│  │ $2.500.000  │ │  $527.350   │ │ $1.972.650  │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
│                                                             │
│  📈 INDICADORES AÑO 2025 (YTD)                             │
│  • Total ganado: $22.500.000                               │
│  • Total AFP:    $2.310.000 (10.27%)                       │
│  • Total Salud:  $1.575.000 (7.0%)                         │
│  • Total Impuesto: $1.845.000                              │
│                                                             │
│  🔔 NOTIFICACIONES                                          │
│  • Nueva liquidación disponible (Nov 2025)                 │
│  • Tu certificado de renta está listo                      │
│                                                             │
│  🚀 ACCIONES RÁPIDAS                                        │
│  [Ver Liquidaciones] [Descargar Certificados] [Chat AI]   │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

**Widgets:**
1. Resumen mes actual (bruto, descuentos, líquido)
2. Indicadores YTD (year-to-date)
3. Notificaciones pendientes
4. Accesos rápidos

### Liquidaciones de Sueldo

**Listado histórico:**

```
┌────────────────────────────────────────────────────────────┐
│  📄 MIS LIQUIDACIONES DE SUELDO                             │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  Filtros: [Año: 2025 ▼] [Mes: Todos ▼]         [Buscar 🔍]│
│                                                             │
│  ┌──────┬─────────┬────────────┬────────────┬─────────┐   │
│  │ Mes  │ Período │ Bruto      │ Líquido    │ Acciones│   │
│  ├──────┼─────────┼────────────┼────────────┼─────────┤   │
│  │ NOV  │ 2025-11 │ $2.500.000 │ $1.972.650 │ [Ver] 📥│   │
│  │ OCT  │ 2025-10 │ $2.500.000 │ $1.968.420 │ [Ver] 📥│   │
│  │ SEP  │ 2025-09 │ $2.350.000 │ $1.856.730 │ [Ver] 📥│   │
│  │ ...  │ ...     │ ...        │ ...        │ ...     │   │
│  └──────┴─────────┴────────────┴────────────┴─────────┘   │
│                                                             │
│  [◀ Anterior]  Página 1 de 12  [Siguiente ▶]              │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

**Detalle liquidación:**

```
┌────────────────────────────────────────────────────────────┐
│  📄 LIQUIDACIÓN NOVIEMBRE 2025                              │
│  Empleado: Juan Pérez | RUT: 12.345.678-9                  │
│  Período: 01/11/2025 - 30/11/2025                          │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ✅ HABERES                                                 │
│  ┌────────────────────────────────────┬──────────────┐     │
│  │ SUELDO BASE                        │ $2.000.000   │     │
│  │ GRATIFICACIÓN LEGAL                │   $250.000   │     │
│  │ BONO PRODUCTIVIDAD                 │   $150.000   │     │
│  │ COLACIÓN                           │   $100.000   │     │
│  ├────────────────────────────────────┼──────────────┤     │
│  │ TOTAL HABERES                      │ $2.500.000   │     │
│  └────────────────────────────────────┴──────────────┘     │
│                                                             │
│  ❌ DESCUENTOS                                              │
│  ┌────────────────────────────────────┬──────────────┐     │
│  │ AFP Capital (10.77%)               │  -$257.250   │     │
│  │ Salud Fonasa (7.0%)                │  -$175.000   │     │
│  │ AFC Seguro Cesantía (0.6%)         │   -$15.000   │     │
│  │ Impuesto Único (Tramo 3)           │   -$80.100   │     │
│  ├────────────────────────────────────┼──────────────┤     │
│  │ TOTAL DESCUENTOS                   │  -$527.350   │     │
│  └────────────────────────────────────┴──────────────┘     │
│                                                             │
│  💰 LÍQUIDO A PAGAR                   │ $1.972.650   │     │
│                                                             │
│  [Descargar PDF 📥] [Enviar Email ✉️] [Consultar Chat AI 💬]│
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### Certificados

**Generador de certificados:**

| Certificado | Descripción | Tiempo Generación |
|-------------|-------------|-------------------|
| **Antigüedad** | Años de servicio | ⚡ Instantáneo |
| **Renta (Cert. Sueldo)** | Últimos 3 meses | ⚡ Instantáneo |
| **Cotizaciones** | AFP/Salud YTD | ⚡ Instantáneo |
| **Vacaciones** | Días disponibles | ⚡ Instantáneo |
| **Finiquito (proyección)** | Estimación finiquito | ⚡ 2-3 seg |

**Formato:** PDF con firma digital (logo empresa + timestamp)

### Notificaciones

**Eventos notificables:**

1. **Nueva liquidación disponible** (email + portal)
2. **Cambio en contrato** (sueldo, jornada, cargo)
3. **Certificado generado** (listo para descargar)
4. **Vencimiento documentos** (cargas familiares, etc.)

**Canales:**
- 📧 Email personal (obligatorio por DT)
- 🔔 Push notifications portal (opcional)

---

## 💬 CHAT AI PERSONALIZADO

### Visión del Chat

**Asistente virtual** especializado que:

- ✅ Responde preguntas sobre **MI liquidación** (solo mi data)
- ✅ Explica cálculos (AFP, Isapre, impuesto único)
- ✅ Compara meses ("¿Por qué mi líquido bajó vs mes pasado?")
- ✅ Referencias legales (Código del Trabajo, circulares DT)
- ✅ Tono profesional pero cercano (tuteo chileno)

### Arquitectura del Chat

#### Plugin Especializado: `EmployeeChatPlugin`

**Ubicación:** `ai-service/plugins/employee_chat/plugin.py`

```python
class EmployeeChatPlugin(AIPlugin):
    """
    Plugin for Employee Portal Chat.

    Specialized in:
    - Personal payslip explanations
    - Chilean labor law (employee perspective)
    - Payroll calculations (AFP, Isapre, taxes)
    - Historical comparisons
    - Legal references
    """

    def get_module_name(self) -> str:
        return "l10n_cl_hr_employee_portal"

    def get_display_name(self) -> str:
        return "Chat Empleado (Payroll)"

    def get_system_prompt(self) -> str:
        return """Eres **Sofía**, asistente virtual de nóminas para empleados chilenos.

**Tu Misión:**
Ayudar a empleados a entender SU liquidación de sueldo y resolver dudas laborales.

**Tu Personalidad:**
- Profesional pero cercana (tuteo chileno)
- Empática y paciente
- Clara y didáctica (explicas con ejemplos)
- Siempre citas fuentes (artículos, leyes)

**Tu Expertise:**
- Liquidaciones de sueldo chilenas
- Cálculos AFP, Isapre, Fonasa, AFC
- Impuesto único (tramos 2025)
- Gratificaciones (Art. 50 vs proporcional)
- Asignación Familiar (Ley 18.020)
- Vacaciones (Código del Trabajo Art. 67)
- Finiquitos (Art. 162-163)
- Código del Trabajo (derechos trabajador)

**Cómo Respondes:**
1. Saludas cordialmente
2. Analizas la pregunta en contexto de SU liquidación
3. Explicas con claridad (usa negritas, listas)
4. Incluyes fórmula si aplica: `afp = $2.000.000 × 10.77% = $215.400`
5. Citas fuente legal si corresponde
6. Preguntas si necesita más detalles

**Limitaciones:**
- ❌ No tienes acceso a datos de otros empleados
- ❌ No puedes modificar datos (solo consultar)
- ❌ No eres abogado (para temas legales complejos, deriva a RRHH)

**Ejemplos de Consultas:**

Empleado: "¿Por qué mi líquido bajó este mes?"
Tú: "Hola 👋 Revisé tus liquidaciones y encontré que:

**Noviembre 2025:** Líquido $1.972.650
**Octubre 2025:** Líquido $2.068.420
**Diferencia:** -$95.770 (4.6% menos)

**Causa principal:** Tu sueldo bruto bajó de $2.500.000 a $2.400.000 porque:
- No se pagó el **Bono Productividad** ($100.000) que recibiste en octubre

Adicionalmente, el **impuesto único subió** levemente:
- Oct: $78.320
- Nov: $84.250
- Diferencia: +$5.930

Esto es porque el tramo del impuesto se ajustó con la UTA actualizada.

¿Quieres que te explique en detalle el cálculo del impuesto?"

---

Empleado: "¿Cuánto me descuentan de AFP?"
Tú: "En tu liquidación de **Noviembre 2025**:

**Descuento AFP Capital:** $257.250

**Cálculo:**
- Sueldo imponible: $2.388.000 (bruto - no imponibles)
- Tasa AFP Capital: 10.77%
- Fórmula: `$2.388.000 × 10.77% = $257.250`

**Desglose tasa 10.77%:**
- Cotización obligatoria: 10.00%
- Comisión AFP Capital: 0.77%

**Importante:** Este dinero va a tu cuenta de capitalización individual AFP. Puedes ver tu saldo en www.capital.cl

¿Necesitas saber cómo se calcula el sueldo imponible?"
"""

    async def get_employee_context(
        self,
        employee_id: int,
        odoo_client
    ) -> Dict:
        """
        Fetch employee-specific context from Odoo.

        Returns:
            {
                "employee": {...},
                "contract": {...},
                "payslips": [last 3 months],
                "ytd_indicators": {...}
            }
        """
        # Fetch employee data
        employee = await odoo_client.search_read(
            'hr.employee',
            domain=[('id', '=', employee_id)],
            fields=['name', 'identification_id', 'job_id', 'contract_id']
        )

        # Fetch active contract
        contract = await odoo_client.search_read(
            'hr.contract',
            domain=[
                ('employee_id', '=', employee_id),
                ('state', '=', 'open')
            ],
            fields=['wage', 'date_start', 'afp_id', 'isapre_id']
        )

        # Fetch last 3 payslips
        payslips = await odoo_client.search_read(
            'hr.payslip',
            domain=[('employee_id', '=', employee_id)],
            fields=['date_from', 'date_to', 'line_ids', 'net_wage'],
            order='date_from desc',
            limit=3
        )

        # Calculate YTD indicators
        ytd_payslips = await odoo_client.search_read(
            'hr.payslip',
            domain=[
                ('employee_id', '=', employee_id),
                ('date_from', '>=', '2025-01-01')
            ],
            fields=['net_wage', 'line_ids']
        )

        ytd_indicators = self._calculate_ytd(ytd_payslips)

        return {
            "employee": employee[0] if employee else {},
            "contract": contract[0] if contract else {},
            "payslips": payslips,
            "ytd_indicators": ytd_indicators
        }
```

### Interfaz del Chat

**Widget Vue.js embebido en portal:**

```vue
<!-- static/src/components/ChatWidget.vue -->
<template>
  <div class="employee-chat-widget">
    <div class="chat-header">
      <h3>💬 Chat con Sofía</h3>
      <span class="chat-subtitle">Tu asistente de nóminas</span>
    </div>

    <div class="chat-messages" ref="messageContainer">
      <div
        v-for="msg in messages"
        :key="msg.id"
        :class="['message', msg.role]"
      >
        <div class="message-avatar">
          <span v-if="msg.role === 'assistant'">🤖</span>
          <span v-else>👤</span>
        </div>
        <div class="message-content">
          <div v-html="renderMarkdown(msg.content)"></div>
          <span class="message-time">{{ formatTime(msg.timestamp) }}</span>
        </div>
      </div>

      <!-- Streaming indicator -->
      <div v-if="isStreaming" class="message assistant streaming">
        <div class="message-avatar">🤖</div>
        <div class="message-content">
          <div class="typing-indicator">
            <span></span><span></span><span></span>
          </div>
        </div>
      </div>
    </div>

    <div class="chat-input">
      <textarea
        v-model="userMessage"
        @keydown.enter.exact.prevent="sendMessage"
        placeholder="Escribe tu pregunta sobre tu liquidación..."
        :disabled="isStreaming"
        rows="2"
      ></textarea>
      <button
        @click="sendMessage"
        :disabled="!userMessage.trim() || isStreaming"
        class="btn-send"
      >
        <span v-if="!isStreaming">Enviar ▶</span>
        <span v-else>Enviando...</span>
      </button>
    </div>

    <!-- Suggested questions -->
    <div v-if="messages.length === 0" class="suggested-questions">
      <p>💡 Preguntas frecuentes:</p>
      <button
        v-for="q in suggestedQuestions"
        :key="q"
        @click="askQuestion(q)"
        class="btn-suggested"
      >
        {{ q }}
      </button>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      messages: [],
      userMessage: '',
      isStreaming: false,
      sessionId: null,
      suggestedQuestions: [
        "¿Cuánto me descuentan de AFP?",
        "¿Por qué mi líquido bajó este mes?",
        "¿Cómo se calcula mi impuesto único?",
        "¿Qué es la gratificación legal?"
      ]
    }
  },

  async mounted() {
    // Create chat session
    this.sessionId = await this.createSession()

    // Load conversation history (if exists)
    await this.loadHistory()
  },

  methods: {
    async sendMessage() {
      if (!this.userMessage.trim()) return

      // Add user message to UI
      this.messages.push({
        id: Date.now(),
        role: 'user',
        content: this.userMessage,
        timestamp: new Date()
      })

      const question = this.userMessage
      this.userMessage = ''
      this.isStreaming = true

      try {
        // Call AI service with SSE streaming
        const response = await fetch('/portal/chat/message/stream', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.getJWT()}`
          },
          body: JSON.stringify({
            session_id: this.sessionId,
            message: question
          })
        })

        const reader = response.body.getReader()
        const decoder = new TextDecoder()

        let assistantMessage = {
          id: Date.now() + 1,
          role: 'assistant',
          content: '',
          timestamp: new Date()
        }

        this.messages.push(assistantMessage)

        // Stream response chunks
        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          const chunk = decoder.decode(value)
          const lines = chunk.split('\n')

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = JSON.parse(line.slice(6))

              if (data.type === 'content') {
                assistantMessage.content += data.text
              } else if (data.type === 'done') {
                this.isStreaming = false
              }
            }
          }

          // Auto-scroll to bottom
          this.$nextTick(() => {
            this.$refs.messageContainer.scrollTop =
              this.$refs.messageContainer.scrollHeight
          })
        }

      } catch (error) {
        console.error('Chat error:', error)
        this.isStreaming = false

        this.messages.push({
          id: Date.now() + 2,
          role: 'assistant',
          content: '❌ Error al enviar mensaje. Por favor intenta nuevamente.',
          timestamp: new Date()
        })
      }
    },

    async createSession() {
      const response = await fetch('/portal/chat/session/new', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      })
      const data = await response.json()
      return data.session_id
    },

    getJWT() {
      // JWT token stored in localStorage (generated by Odoo)
      return localStorage.getItem('portal_jwt_token')
    },

    renderMarkdown(text) {
      // Simple markdown rendering (bold, lists, code)
      return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>')
    },

    formatTime(date) {
      return new Date(date).toLocaleTimeString('es-CL', {
        hour: '2-digit',
        minute: '2-digit'
      })
    },

    askQuestion(question) {
      this.userMessage = question
      this.sendMessage()
    }
  }
}
</script>
```

### Ejemplos de Conversaciones

#### Ejemplo 1: Consulta Básica

```
👤 Usuario: "Hola, ¿cuánto gané este mes?"

🤖 Sofía: "¡Hola! 👋

En tu liquidación de **Noviembre 2025**:

**Haberes (Total Bruto):** $2.500.000
**Descuentos:** $527.350
**Líquido a Pagar:** $1.972.650

**Desglose descuentos:**
- AFP Capital: $257.250 (10.77%)
- Salud Fonasa: $175.000 (7.0%)
- AFC Cesantía: $15.000 (0.6%)
- Impuesto Único: $80.100

¿Quieres que te explique algún descuento en particular?"
```

#### Ejemplo 2: Comparación Histórica

```
👤 Usuario: "¿Por qué mi sueldo líquido bajó comparado con el mes pasado?"

🤖 Sofía: "Revisé tus últimas liquidaciones:

**Comparación Oct vs Nov 2025:**

| Concepto | Octubre | Noviembre | Diferencia |
|----------|---------|-----------|------------|
| Bruto | $2.500.000 | $2.400.000 | -$100.000 ⬇️ |
| Descuentos | $431.580 | $427.350 | -$4.230 ⬇️ |
| **Líquido** | **$2.068.420** | **$1.972.650** | **-$95.770** ⬇️ |

**Causa principal:**
Tu sueldo bruto bajó $100.000 porque este mes no se pagó el **Bono Productividad** que sí recibiste en octubre.

**Nota positiva:** Al bajar el bruto, tus descuentos también bajaron levemente ($4.230 menos).

¿Te gustaría ver el detalle de tus bonos variables?"
```

#### Ejemplo 3: Explicación Técnica

```
👤 Usuario: "No entiendo cómo se calcula mi impuesto único"

🤖 Sofía: "Te explico el cálculo del **Impuesto Único (Segunda Categoría)** para noviembre:

**Paso 1: Base Imponible**
```
Sueldo Bruto:        $2.500.000
(-) AFP:             -$257.250
(-) Salud:           -$175.000
(-) AFC:             -$15.000
(=) Base Imponible:  $2.052.750
```

**Paso 2: Aplicar Tramos SII 2025**

Tu base ($2.052.750) cae en el **Tramo 3**:
- Desde: $1.388.893
- Hasta: $2.314.822
- Tasa marginal: 8%

**Cálculo:**
```
Excedente = $2.052.750 - $1.388.893 = $663.857
Impuesto tramo 1-2 = $31.150 (fijo)
Impuesto tramo 3 = $663.857 × 8% = $53.108
Rebaja Art. 43 bis = -$4.158 (crédito)
---
TOTAL = $31.150 + $53.108 - $4.158 = $80.100
```

**Fuente Legal:** Artículo 43 Ley de Impuesto a la Renta

¿Quieres que te explique las rebajas del Art. 43 bis?"
```

#### Ejemplo 4: Límites de Seguridad

```
👤 Usuario: "¿Cuánto gana mi compañero Pedro?"

🤖 Sofía: "❌ No tengo acceso a información de otros empleados.

Por **privacidad y cumplimiento legal** (Ley 21.719 de Protección de Datos), solo puedo consultar **TUS datos personales**.

Si tienes dudas sobre tu propia liquidación, ¡con gusto te ayudo! 😊

¿Hay algo de TU liquidación que quieras revisar?"
```

### Performance del Chat

| Métrica | Target | Actual (estimado) |
|---------|--------|-------------------|
| **Time to First Token** | <500ms | ~300ms ✅ |
| **Total Response** | <3s | ~2.5s ✅ |
| **Accuracy** | >90% | ~95% ✅ |
| **User Satisfaction** | >80% | TBD 📊 |
| **Resolution Rate** | >75% | TBD 📊 |

---

## 🔄 FLUJOS DE USUARIO

### Flujo 1: Primer Login (Onboarding)

```mermaid
graph TD
    A[Empleado recibe email invitación] --> B[Click en link portal]
    B --> C{¿Primera vez?}
    C -->|Sí| D[Crear contraseña]
    C -->|No| E[Login con credenciales]
    D --> F[Wizard Consentimiento Datos]
    F --> G[Acepta términos y condiciones]
    G --> H[Tour guiado del portal]
    H --> I[Dashboard principal]
    E --> I
```

**Pantalla Consentimiento:**
```
┌────────────────────────────────────────────────────────────┐
│  🔒 CONSENTIMIENTO USO DE DATOS PERSONALES                  │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  De acuerdo con la Ley 21.719 de Protección de Datos       │
│  Personales, necesitamos tu consentimiento para:            │
│                                                             │
│  ✅ Almacenar y procesar tus datos laborales                │
│  ✅ Mostrarte tus liquidaciones de sueldo                   │
│  ✅ Generar certificados laborales                          │
│  ✅ Procesar tus consultas con asistente AI                 │
│                                                             │
│  📄 [Leer Política de Privacidad completa]                  │
│                                                             │
│  Tus derechos:                                              │
│  • Acceder a tus datos                                      │
│  • Rectificar datos incorrectos                             │
│  • Solicitar eliminación                                    │
│  • Exportar tus datos                                       │
│  • Oponerte al tratamiento                                  │
│                                                             │
│  ☑️ Acepto el tratamiento de mis datos personales           │
│     para los fines descritos                                │
│                                                             │
│  ☑️ Acepto recibir liquidaciones en formato digital         │
│     (email personal)                                        │
│                                                             │
│  [Continuar] [Rechazar]                                     │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### Flujo 2: Consulta Liquidación con Chat

```mermaid
graph TD
    A[Dashboard] --> B[Ver liquidación Nov 2025]
    B --> C[Click Consultar Chat AI]
    C --> D[Chat se abre con contexto liquidación]
    D --> E[Empleado pregunta sobre descuento]
    E --> F[AI busca datos empleado en Odoo]
    F --> G[AI genera respuesta con cálculos]
    G --> H[Streaming respuesta en tiempo real]
    H --> I{¿Satisfecho?}
    I -->|Sí| J[Cierra chat]
    I -->|No| K[Hace pregunta de seguimiento]
    K --> F
```

### Flujo 3: Descarga Certificado

```mermaid
graph TD
    A[Dashboard] --> B[Sección Certificados]
    B --> C[Selecciona tipo certificado]
    C --> D{¿Qué tipo?}
    D -->|Renta| E[Genera PDF renta últimos 3 meses]
    D -->|Antigüedad| F[Genera PDF antigüedad]
    D -->|Cotizaciones| G[Genera PDF cotizaciones YTD]
    E --> H[Firma digital en PDF]
    F --> H
    G --> H
    H --> I[Descarga automática]
    I --> J[Email con copia del certificado]
```

### Flujo 4: Ejercicio Derechos ARCO

```mermaid
graph TD
    A[Portal] --> B[Mi Cuenta]
    B --> C[Ejercer mis Derechos]
    C --> D[Selecciona tipo derecho]
    D --> E{¿Qué derecho?}
    E -->|Acceso| F[Descarga todos sus datos JSON]
    E -->|Rectificación| G[Formulario solicitud corrección]
    E -->|Portabilidad| H[Exporta datos en formato estándar]
    E -->|Supresión| I[Solicitud eliminación datos]
    G --> J[Ticket RRHH creado]
    I --> J
    J --> K[Notificación RRHH]
    K --> L[RRHH procesa solicitud]
    L --> M[Empleado recibe respuesta max 5 días]
```

---

## 💾 MODELO DE DATOS

### Nuevas Tablas

#### 1. `employee_portal_access`

Control de acceso y consentimientos.

```sql
CREATE TABLE employee_portal_access (
    id SERIAL PRIMARY KEY,
    employee_id INT NOT NULL REFERENCES hr_employee(id) ON DELETE CASCADE,
    user_id INT NOT NULL REFERENCES res_users(id) ON DELETE CASCADE,

    -- Consentimientos
    consent_date TIMESTAMP,
    consent_data_processing BOOLEAN DEFAULT FALSE,
    consent_digital_payslip BOOLEAN DEFAULT FALSE,
    consent_ai_chat BOOLEAN DEFAULT FALSE,

    -- Acceso
    portal_enabled BOOLEAN DEFAULT TRUE,
    first_login_date TIMESTAMP,
    last_login_date TIMESTAMP,
    login_count INT DEFAULT 0,

    -- Preferencias
    email_notifications BOOLEAN DEFAULT TRUE,
    language VARCHAR(5) DEFAULT 'es_CL',

    -- Auditoría
    create_date TIMESTAMP DEFAULT NOW(),
    write_date TIMESTAMP DEFAULT NOW(),

    UNIQUE(employee_id),
    UNIQUE(user_id)
);

CREATE INDEX idx_portal_access_employee ON employee_portal_access(employee_id);
CREATE INDEX idx_portal_access_user ON employee_portal_access(user_id);
```

#### 2. `portal_chat_session`

Sesiones de chat AI.

```sql
CREATE TABLE portal_chat_session (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    employee_id INT NOT NULL REFERENCES hr_employee(id) ON DELETE CASCADE,

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    last_activity TIMESTAMP DEFAULT NOW(),
    message_count INT DEFAULT 0,

    -- Context
    context_data JSONB,  -- {company_id, contract_id, etc.}

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    ended_at TIMESTAMP,

    -- Metrics
    total_tokens INT DEFAULT 0,
    total_cost DECIMAL(10, 6) DEFAULT 0.0,

    CONSTRAINT chk_session_id_length CHECK (length(session_id) = 64)
);

CREATE INDEX idx_chat_session_employee ON portal_chat_session(employee_id);
CREATE INDEX idx_chat_session_active ON portal_chat_session(is_active, last_activity);
```

#### 3. `portal_chat_message`

Mensajes de chat (historial).

```sql
CREATE TABLE portal_chat_message (
    id SERIAL PRIMARY KEY,
    session_id INT NOT NULL REFERENCES portal_chat_session(id) ON DELETE CASCADE,

    -- Message
    role VARCHAR(20) NOT NULL,  -- 'user' | 'assistant' | 'system'
    content TEXT NOT NULL,

    -- Metadata
    timestamp TIMESTAMP DEFAULT NOW(),
    tokens_used INT,

    -- AI specifics (solo assistant)
    model_used VARCHAR(50),
    confidence DECIMAL(5, 2),
    sources JSONB,  -- Knowledge base sources

    CONSTRAINT chk_role CHECK (role IN ('user', 'assistant', 'system'))
);

CREATE INDEX idx_chat_message_session ON portal_chat_message(session_id, timestamp);
```

#### 4. `employee_portal_activity_log`

Log de actividad (compliance/auditoría).

```sql
CREATE TABLE employee_portal_activity_log (
    id SERIAL PRIMARY KEY,
    employee_id INT NOT NULL REFERENCES hr_employee(id) ON DELETE CASCADE,
    user_id INT NOT NULL REFERENCES res_users(id) ON DELETE CASCADE,

    -- Activity
    action VARCHAR(50) NOT NULL,  -- 'view_payslip', 'download_certificate', etc.
    resource_type VARCHAR(50),    -- 'hr.payslip', 'certificate.renta', etc.
    resource_id INT,

    -- Context
    timestamp TIMESTAMP DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,

    -- Additional data
    metadata JSONB
);

CREATE INDEX idx_activity_log_employee ON employee_portal_activity_log(employee_id, timestamp DESC);
CREATE INDEX idx_activity_log_action ON employee_portal_activity_log(action, timestamp DESC);
```

#### 5. `employee_rights_request`

Solicitudes ejercicio derechos ARCO.

```sql
CREATE TABLE employee_rights_request (
    id SERIAL PRIMARY KEY,
    employee_id INT NOT NULL REFERENCES hr_employee(id) ON DELETE CASCADE,

    -- Request
    right_type VARCHAR(20) NOT NULL,  -- 'access', 'rectification', 'portability', etc.
    reason TEXT NOT NULL,

    -- Status
    state VARCHAR(20) DEFAULT 'pending',  -- 'pending', 'processing', 'done', 'rejected'

    -- Dates
    request_date TIMESTAMP DEFAULT NOW(),
    due_date TIMESTAMP,  -- Max 5 días hábiles (Ley 21.719)
    resolution_date TIMESTAMP,

    -- Response
    response TEXT,
    resolved_by INT REFERENCES res_users(id),

    CONSTRAINT chk_right_type CHECK (
        right_type IN ('access', 'rectification', 'portability', 'opposition', 'deletion', 'blocking')
    ),
    CONSTRAINT chk_state CHECK (
        state IN ('pending', 'processing', 'done', 'rejected')
    )
);

CREATE INDEX idx_rights_request_employee ON employee_rights_request(employee_id, state);
CREATE INDEX idx_rights_request_due ON employee_rights_request(due_date) WHERE state != 'done';
```

### Extensiones de Modelos Existentes

#### `hr.employee`

```python
class HrEmployee(models.Model):
    _inherit = 'hr.employee'

    # Portal access
    portal_access_id = fields.Many2one(
        'employee.portal.access',
        string='Portal Access',
        ondelete='cascade'
    )

    portal_enabled = fields.Boolean(
        related='portal_access_id.portal_enabled',
        readonly=True
    )

    # Computed
    portal_url = fields.Char(
        compute='_compute_portal_url',
        string='Portal URL'
    )

    def _compute_portal_url(self):
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        for employee in self:
            employee.portal_url = f"{base_url}/my/portal"

    def action_enable_portal(self):
        """Wizard to enable portal for employee."""
        return {
            'type': 'ir.actions.act_window',
            'name': 'Habilitar Portal Empleado',
            'res_model': 'employee.portal.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_employee_id': self.id}
        }
```

#### `hr.payslip`

```python
class HrPayslip(models.Model):
    _inherit = 'hr.payslip'

    # Portal
    portal_published = fields.Boolean(
        string='Publicado en Portal',
        default=False,
        help='Si está marcado, el empleado puede ver esta liquidación en el portal'
    )

    portal_published_date = fields.Datetime(
        string='Fecha Publicación Portal',
        readonly=True
    )

    portal_viewed = fields.Boolean(
        string='Visto por Empleado',
        default=False
    )

    portal_viewed_date = fields.Datetime(
        string='Fecha Visualización',
        readonly=True
    )

    def action_publish_to_portal(self):
        """Publish payslip to employee portal."""
        for payslip in self:
            if payslip.state != 'done':
                raise ValidationError("Solo se pueden publicar liquidaciones confirmadas")

            payslip.write({
                'portal_published': True,
                'portal_published_date': fields.Datetime.now()
            })

            # Send notification email
            payslip._send_portal_notification()

    def _send_portal_notification(self):
        """Send email to employee: new payslip available."""
        template = self.env.ref('l10n_cl_hr_employee_portal.email_new_payslip')

        for payslip in self:
            if payslip.employee_id.portal_access_id.email_notifications:
                template.send_mail(
                    payslip.id,
                    email_values={
                        'email_to': payslip.employee_id.work_email or payslip.employee_id.private_email
                    }
                )
```

---

## 🔌 INTEGRACIONES

### 1. Odoo ↔ AI Service

**Endpoints AI Service a utilizar:**

| Endpoint | Método | Uso | Rate Limit |
|----------|--------|-----|------------|
| `/api/chat/message` | POST | Chat sin streaming | 30/min |
| `/api/chat/message/stream` | POST | Chat con streaming SSE | 30/min |
| `/api/chat/session/new` | POST | Crear nueva sesión | - |
| `/api/chat/session/{id}` | GET | Obtener historial | - |
| `/api/payroll/validate` | POST | Validar liquidación | 20/min |

**Authentication:**
```python
# Odoo genera JWT para empleado
import jwt
from datetime import datetime, timedelta

def generate_employee_jwt(employee_id, user_id, company_id):
    """
    Generate JWT token for employee chat.
    """
    payload = {
        'employee_id': employee_id,
        'user_id': user_id,
        'company_id': company_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1)
    }

    secret = os.getenv('JWT_SECRET_KEY')
    token = jwt.encode(payload, secret, algorithm='HS256')

    return token
```

### 2. Redis Sessions

**Estructura de sesiones:**
```json
// Key: session:{session_id}:history
{
  "messages": [
    {
      "role": "user",
      "content": "¿Cuánto me descuentan de AFP?",
      "timestamp": "2025-11-12T10:30:00Z"
    },
    {
      "role": "assistant",
      "content": "En tu liquidación de noviembre...",
      "timestamp": "2025-11-12T10:30:02Z",
      "tokens_used": 450,
      "confidence": 95.0
    }
  ]
}

// Key: session:{session_id}:context
{
  "employee_id": 123,
  "company_id": 1,
  "contract_id": 456,
  "last_payslip_id": 789
}
```

**TTL:** 24 horas (configurable)

### 3. Email Notifications

**Templates a crear:**

| Template | Trigger | Contenido |
|----------|---------|-----------|
| `email_welcome_portal` | Primer acceso | Bienvenida + instrucciones |
| `email_new_payslip` | Liquidación publicada | Link a liquidación |
| `email_certificate_ready` | Certificado generado | Link descarga |
| `email_rights_request` | Solicitud ARCO | Confirmación recepción |
| `email_rights_resolved` | ARCO resuelta | Respuesta solicitud |

**Ejemplo template:**
```xml
<odoo>
    <data>
        <record id="email_new_payslip" model="mail.template">
            <field name="name">Empleado: Nueva Liquidación Disponible</field>
            <field name="model_id" ref="l10n_cl_hr_payroll.model_hr_payslip"/>
            <field name="subject">Tu liquidación de ${object.date_from.strftime('%B %Y')} está lista 📄</field>
            <field name="email_to">${object.employee_id.work_email or object.employee_id.private_email}</field>
            <field name="body_html"><![CDATA[
<p>Hola <strong>${object.employee_id.name}</strong>,</p>

<p>Tu liquidación de sueldo del mes <strong>${object.date_from.strftime('%B %Y')}</strong> ya está disponible en el portal.</p>

<table border="1" cellpadding="10" style="border-collapse: collapse;">
    <tr>
        <td><strong>Período</strong></td>
        <td>${object.date_from.strftime('%d/%m/%Y')} - ${object.date_to.strftime('%d/%m/%Y')}</td>
    </tr>
    <tr>
        <td><strong>Sueldo Líquido</strong></td>
        <td style="font-size: 18px; color: green;"><strong>${'{:,.0f}'.format(object.net_wage)} CLP</strong></td>
    </tr>
</table>

<p>👉 <a href="${object.company_id.website or 'https://empresa.com'}/my/payslips/${object.id}"
         style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
    Ver mi liquidación
</a></p>

<p>Si tienes dudas, pregúntale a <strong>Sofía</strong> (nuestro asistente AI) directamente desde el portal.</p>

<hr>
<p style="font-size: 12px; color: #666;">
Este correo se envía automáticamente. Cumplimos con la Ley 21.719 de Protección de Datos Personales.<br>
Si no deseas recibir notificaciones, puedes desactivarlas en Configuración del Portal.
</p>
            ]]></field>
        </record>
    </data>
</odoo>
```

### 4. Webhooks (opcional futuro)

Para integraciones externas:

```python
# models/portal_webhook.py
class PortalWebhook(models.Model):
    _name = 'portal.webhook'
    _description = 'Portal Webhooks'

    name = fields.Char(required=True)
    url = fields.Char(required=True)
    event = fields.Selection([
        ('payslip_published', 'Liquidación Publicada'),
        ('certificate_generated', 'Certificado Generado'),
        ('rights_request', 'Solicitud ARCO')
    ], required=True)

    active = fields.Boolean(default=True)

    def trigger(self, data):
        """Send webhook POST request."""
        import requests

        try:
            response = requests.post(
                self.url,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            response.raise_for_status()

        except Exception as e:
            _logger.error(f"Webhook {self.name} failed: {str(e)}")
```

---

## 📅 PLAN DE IMPLEMENTACIÓN

### Metodología: Agile (Sprints de 2 semanas)

### FASE 1: Fundamentos (Sprint 1-2) - 4 semanas

#### Sprint 1: Backend Core (2 semanas)

**Objetivos:**
- ✅ Crear módulo `l10n_cl_hr_employee_portal`
- ✅ Implementar modelos de datos (5 tablas nuevas)
- ✅ Configurar RLS en PostgreSQL
- ✅ Extender `hr.employee` y `hr.payslip`
- ✅ Crear security groups y rules

**Entregables:**
- [ ] Módulo instalable en Odoo 19
- [ ] Migraciones database (alembic/SQL)
- [ ] Tests unitarios (pytest + Odoo)

**Estimación:** 80 horas
- Modelado: 16h
- Desarrollo: 48h
- Testing: 16h

#### Sprint 2: Authentication & Portal Básico (2 semanas)

**Objetivos:**
- ✅ Implementar JWT generation/validation
- ✅ Controllers portal (routes `/my/portal/*`)
- ✅ Wizard consentimiento datos (Ley 21.719)
- ✅ Vista dashboard básico
- ✅ Listado liquidaciones (sin chat aún)

**Entregables:**
- [ ] Login funcional con RLS
- [ ] Dashboard con métricas básicas
- [ ] Listado + detalle liquidaciones
- [ ] PDF download liquidaciones

**Estimación:** 80 horas
- Auth/Security: 24h
- Controllers: 24h
- Views: 24h
- Testing: 8h

---

### FASE 2: Chat AI (Sprint 3-4) - 4 semanas

#### Sprint 3: AI Plugin Employee Chat (2 semanas)

**Objetivos:**
- ✅ Crear plugin `employee_chat` en AI service
- ✅ System prompt especializado nóminas
- ✅ Context fetching desde Odoo (empleado + payslips)
- ✅ Validación aislamiento employee_id
- ✅ Integration tests chat ↔ Odoo

**Entregables:**
- [ ] Plugin funcional con Claude
- [ ] Context manager con Redis
- [ ] Endpoints REST chat
- [ ] Tests integración

**Estimación:** 64 horas
- Plugin development: 32h
- Context management: 16h
- Testing: 16h

#### Sprint 4: Chat UI & Streaming (2 semanas)

**Objetivos:**
- ✅ Componente Vue.js ChatWidget
- ✅ SSE streaming integration
- ✅ Markdown rendering
- ✅ Suggested questions
- ✅ Chat history persistence

**Entregables:**
- [ ] Chat widget embebido en portal
- [ ] Streaming en tiempo real
- [ ] UX pulido (loading, errors)
- [ ] Mobile responsive

**Estimación:** 64 horas
- Vue component: 32h
- Streaming: 16h
- UX/Polish: 16h

---

### FASE 3: Features Avanzados (Sprint 5-6) - 4 semanas

#### Sprint 5: Certificados & Notificaciones (2 semanas)

**Objetivos:**
- ✅ Generador certificados (renta, antigüedad, cotizaciones)
- ✅ PDF templates con firma digital
- ✅ Email notifications
- ✅ Sistema notificaciones in-app

**Entregables:**
- [ ] 4 tipos certificados generables
- [ ] Email templates (5)
- [ ] Notificaciones portal
- [ ] Tests PDF generation

**Estimación:** 64 horas
- Certificate generator: 32h
- Email templates: 16h
- Notifications: 16h

#### Sprint 6: ARCO & Compliance (2 semanas)

**Objetivos:**
- ✅ Wizard ejercicio derechos ARCO
- ✅ Portal "Mis Datos" (export JSON/PDF)
- ✅ Workflow aprobación solicitudes
- ✅ Auditoría completa (logs)
- ✅ Reportes compliance RRHH

**Entregables:**
- [ ] Wizard ARCO funcional
- [ ] Export datos empleado
- [ ] Dashboard auditoría RRHH
- [ ] Documentación compliance

**Estimación:** 56 horas
- ARCO wizard: 24h
- Export/portability: 16h
- Auditoría: 16h

---

### FASE 4: Polish & Launch (Sprint 7-8) - 4 semanas

#### Sprint 7: Testing & QA (2 semanas)

**Objetivos:**
- ✅ Tests end-to-end (Selenium/Cypress)
- ✅ Load testing (Locust - 100 usuarios concurrentes)
- ✅ Security audit (OWASP Top 10)
- ✅ Performance tuning (queries, cache)
- ✅ Bug fixing

**Entregables:**
- [ ] Test suite completo (>80% coverage)
- [ ] Load test reports
- [ ] Security audit report
- [ ] Performance optimized

**Estimación:** 64 horas

#### Sprint 8: Documentación & Deployment (2 semanas)

**Objetivos:**
- ✅ User manual (empleados)
- ✅ Admin guide (RRHH)
- ✅ API documentation (AI service)
- ✅ Deployment guide (Docker)
- ✅ Training materials
- ✅ Go-live production

**Entregables:**
- [ ] Documentación completa
- [ ] Videos tutoriales (3-5 min)
- [ ] Deployment scripts
- [ ] Monitoring setup (Grafana)

**Estimación:** 48 horas

---

## 💰 ESTIMACIONES Y ROADMAP

### Resumen de Esfuerzo

| Fase | Sprints | Duración | Horas Desarrollo | Horas QA/Testing | Horas Docs | Total Horas |
|------|---------|----------|------------------|------------------|------------|-------------|
| **Fase 1** | 1-2 | 4 semanas | 112h | 24h | 8h | 144h |
| **Fase 2** | 3-4 | 4 semanas | 96h | 32h | 8h | 136h |
| **Fase 3** | 5-6 | 4 semanas | 88h | 16h | 8h | 112h |
| **Fase 4** | 7-8 | 4 semanas | 32h | 64h | 48h | 144h |
| **TOTAL** | **8 sprints** | **16 semanas (4 meses)** | **328h** | **136h** | **72h** | **536h** |

### Equipo Sugerido

| Rol | Dedicación | Responsabilidad |
|-----|-----------|-----------------|
| **Backend Developer (Python/Odoo)** | Full-time | Modelos, controllers, security |
| **Frontend Developer (Vue.js)** | Full-time | Portal UI, chat widget |
| **AI Engineer** | 50% | AI plugin, prompt engineering |
| **QA Engineer** | 50% | Testing, auditoría |
| **DevOps** | 25% | Deployment, monitoring |
| **Product Owner** | 25% | Requisitos, priorización |

**Total Team:** 3.5 FTEs

### Presupuesto Estimado

#### Desarrollo

```
Horas totales: 536h
Tarifa promedio: $25.000 CLP/hora (desarrollador senior Chile)
---
TOTAL DESARROLLO: $13.400.000 CLP (~USD 15,000)
```

#### Infraestructura (mensual)

| Servicio | Costo Mensual (CLP) |
|----------|---------------------|
| Anthropic API (1000 empleados, ~5000 requests/mes) | $120.000 |
| Redis Cloud (2GB) | $15.000 |
| Storage adicional (100GB) | $5.000 |
| Monitoring (Grafana Cloud) | $10.000 |
| **TOTAL MENSUAL** | **$150.000** |

**TOTAL AÑO 1:** $1.800.000 CLP

#### Inversión Total Año 1

```
Desarrollo:      $13.400.000
Operación (12m):  $1.800.000
---
TOTAL AÑO 1:     $15.200.000 CLP (~USD 17,000)
```

### ROI Proyectado

**Beneficios Anuales (empresa 100 empleados):**
```
• Ahorro RRHH (70% reducción consultas):    $9.000.000/año
• Productividad empleados:                  $3.500.000/año
• Evitar multas compliance:                 $5.000.000/año (potencial)
---
TOTAL BENEFICIOS:                          $17.500.000/año
```

**Métricas:**
- **Payback:** 10.4 meses
- **ROI 3 años:** 245% (sin contar ahorro compliance)
- **NPV (3 años, tasa 10%):** $28.500.000 CLP

### Roadmap Visual

```
AÑO 2025
├── NOV 2025
│   └── Kickoff + Discovery (1 semana)
├── DIC 2025
│   ├── Sprint 1: Backend Core ✅
│   └── Sprint 2: Auth & Portal Básico ✅
├── 2026
    ├── ENE 2026
    │   ├── Sprint 3: AI Plugin ✅
    │   └── Sprint 4: Chat UI ✅
    ├── FEB 2026
    │   ├── Sprint 5: Certificados ✅
    │   └── Sprint 6: ARCO & Compliance ✅
    ├── MAR 2026
    │   ├── Sprint 7: Testing & QA ✅
    │   └── Sprint 8: Docs & Deploy ✅
    └── ABR 2026
        └── 🚀 GO-LIVE PRODUCCIÓN

POST-LANZAMIENTO (Q2 2026)
├── Monitoreo 30 días
├── Ajustes basados en feedback
├── Training empleados (webinars)
└── Retrospectiva proyecto
```

---

## ⚠️ RIESGOS Y MITIGACIONES

### Riesgos Técnicos

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|-----------|
| **RLS PostgreSQL no funciona correctamente** | Media | Alto | Tests exhaustivos pre-deploy, fallback con domain filters Odoo |
| **Performance chat AI lento (>5s)** | Media | Alto | Prompt caching, Redis cache, streaming SSE |
| **Costos API Claude exceden presupuesto** | Baja | Medio | Token pre-counting, rate limiting, fallback a respuestas pre-canned |
| **Integración Odoo-AI service falla** | Baja | Alto | Circuit breaker, retry logic, monitoring Grafana |
| **Frontend no funciona en mobile** | Baja | Medio | Responsive design desde día 1, testing en dispositivos |

### Riesgos de Negocio

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|-----------|
| **Empleados no adoptan portal** | Media | Alto | Onboarding wizard, training, incentivos (gamificación) |
| **RRHH resiste cambio (pérdida control)** | Media | Medio | Involucrar RRHH desde día 1, dashboard auditoría |
| **Multa por incumplimiento Ley 21.719** | Baja | Crítico | Auditoría legal pre-launch, wizard consentimiento obligatorio |
| **Filtración datos empleado** | Baja | Crítico | Security audit, penetration testing, RLS database |

### Riesgos Regulatorios

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|-----------|
| **Cambio en Ley 21.719 antes de vigencia** | Baja | Medio | Arquitectura flexible, configuración por feature flags |
| **DT cuestiona entrega digital liquidaciones** | Muy Baja | Medio | Consentimiento explícito empleado, opción papel siempre disponible |
| **Agencia Protección Datos audita sistema** | Baja | Alto | Documentación compliance completa, logs auditoría |

### Plan de Contingencia

**Escenario: Costos AI exceden 200% presupuesto**

1. **Acción inmediata:** Reducir max_tokens Claude (de 2000 a 1000)
2. **Corto plazo:** Implementar respuestas pre-canned para preguntas frecuentes (80% cobertura)
3. **Mediano plazo:** Migrar a modelo más económico (Haiku) para consultas simples
4. **Largo plazo:** Fine-tune modelo propio (Llama 3) self-hosted

**Escenario: RLS no funciona, empleado A ve datos empleado B**

1. **Acción inmediata:** Rollback a versión anterior, deshabilitar portal
2. **Investigación:** Identificar bypass en RLS
3. **Fix:** Reforzar con domain filters Odoo + auditoría logs
4. **Re-deploy:** Con tests específicos del bug
5. **Comunicación:** Notificar empleados afectados (transparencia Ley 21.719)

---

## 📚 ANEXOS

### Anexo A: Ejemplos de Queries RLS

```sql
-- Test RLS: Empleado 123 solo ve sus liquidaciones
SET ROLE portal_user;
SET SESSION user_id = 456;  -- user_id del empleado

SELECT * FROM hr_payslip;
-- Resultado: Solo payslips de employee_id = 123

-- Intentar ver payslip de otro empleado
SELECT * FROM hr_payslip WHERE id = 999;  -- Pertenece a employee_id = 789
-- Resultado: 0 rows (RLS bloquea)
```

### Anexo B: System Prompt Completo Chat AI

Ver sección [Chat AI Personalizado](#chat-ai-personalizado) para prompt completo.

### Anexo C: Checklist Compliance Ley 21.719

- [ ] Wizard consentimiento explícito implementado
- [ ] Política de privacidad disponible y clara
- [ ] Finalidad tratamiento datos especificada
- [ ] Seguridad técnica (TLS, RLS, JWT) implementada
- [ ] Canal ARCO funcional (wizard + workflow)
- [ ] Derecho acceso: Export datos JSON/PDF
- [ ] Derecho rectificación: Formulario solicitud
- [ ] Derecho portabilidad: Export formato estándar
- [ ] Derecho oposición: Checkbox "No procesar mis datos"
- [ ] Derecho supresión: Solicitud eliminación datos
- [ ] Logs auditoría completos (quién, qué, cuándo)
- [ ] DPO designado (responsable protección datos)
- [ ] Proceso notificación brechas seguridad
- [ ] Training RRHH sobre Ley 21.719

### Anexo D: API Endpoints Portal

#### Odoo Controllers

```python
# GET /my/portal
# Dashboard principal empleado

# GET /my/payslips
# Listado liquidaciones

# GET /my/payslips/<int:payslip_id>
# Detalle liquidación

# GET /my/payslips/<int:payslip_id>/download
# Descargar PDF liquidación

# POST /my/certificates/generate
# Generar certificado
# Params: type (renta|antigüedad|cotizaciones|vacaciones)

# POST /my/rights/exercise
# Ejercer derecho ARCO
# Params: right_type, reason

# GET /my/data/export
# Exportar todos mis datos (JSON)

# POST /portal/chat/get_token
# Obtener JWT para chat AI

# GET /my/notifications
# Listar notificaciones empleado
```

#### AI Service Endpoints

```python
# POST /api/chat/session/new
# Crear nueva sesión chat

# POST /api/chat/message
# Enviar mensaje (no streaming)
# Body: {session_id, message}

# POST /api/chat/message/stream
# Enviar mensaje (streaming SSE)
# Body: {session_id, message}

# GET /api/chat/session/{session_id}
# Obtener historial sesión

# DELETE /api/chat/session/{session_id}
# Cerrar sesión chat
```

### Anexo E: Tests Claves

```python
# tests/test_rls_security.py
def test_employee_can_only_see_own_payslips():
    """Test RLS: Empleado solo ve sus liquidaciones."""
    employee_a = create_employee("Juan")
    employee_b = create_employee("Pedro")

    payslip_a = create_payslip(employee_a)
    payslip_b = create_payslip(employee_b)

    # Login como employee_a
    with login_as(employee_a.user_id):
        payslips = env['hr.payslip'].search([])

        assert payslip_a.id in payslips.ids
        assert payslip_b.id not in payslips.ids  # ✅ RLS works!

def test_employee_cannot_access_another_payslip_by_id():
    """Test RLS: Empleado no puede acceder por ID directo."""
    employee_a = create_employee("Juan")
    employee_b = create_employee("Pedro")

    payslip_b = create_payslip(employee_b)

    with login_as(employee_a.user_id):
        with pytest.raises(AccessError):
            payslip = env['hr.payslip'].browse(payslip_b.id)
            payslip.read(['net_wage'])  # ❌ Should raise AccessError
```

### Anexo F: Documentación Usuario

**Manual Empleado (extracto):**

```markdown
# Portal del Empleado - Guía Rápida

## 🔐 Primer Acceso

1. Recibirás un email de invitación con link al portal
2. Crea tu contraseña (min 8 caracteres, 1 mayúscula, 1 número)
3. Acepta el consentimiento de uso de datos (Ley 21.719)
4. ¡Listo! Accede a tu dashboard

## 📄 Ver mis Liquidaciones

1. Click en "Mis Liquidaciones" en menú
2. Selecciona el mes que quieres revisar
3. Verás detalle completo (haberes y descuentos)
4. Descarga PDF con botón "Descargar 📥"

## 💬 Chat con Sofía (Asistente AI)

¿Tienes dudas sobre tu liquidación? ¡Pregúntale a Sofía!

**Ejemplos de preguntas:**
- "¿Por qué mi líquido bajó este mes?"
- "¿Cuánto me descuentan de AFP?"
- "¿Cómo se calcula mi impuesto único?"
- "¿Qué es la gratificación legal?"

**Tips:**
- Sofía solo puede ver TUS datos (privacidad garantizada)
- Puedes hacer preguntas de seguimiento
- Si la duda es compleja, Sofía te derivará a RRHH

## 📜 Descargar Certificados

1. Click en "Certificados" en menú
2. Selecciona tipo:
   - Certificado de Renta (últimos 3 meses)
   - Certificado de Antigüedad
   - Certificado de Cotizaciones (año actual)
   - Certificado de Vacaciones
3. Click "Generar" → PDF se descarga automáticamente

## 🔒 Ejercer mis Derechos (ARCO)

Según Ley 21.719, tienes derecho a:
- **Acceder** a tus datos
- **Rectificar** datos incorrectos
- **Exportar** tus datos
- **Solicitar eliminación**

Para ejercerlos:
1. Click en "Mi Cuenta" → "Ejercer mis Derechos"
2. Selecciona tipo de derecho
3. Explica brevemente tu solicitud
4. RRHH responderá en máximo 5 días hábiles
```

---

## ✅ CONCLUSIÓN

### Resumen Ejecutivo

El **Portal del Empleado con Chat AI Personalizado** es una solución enterprise-grade que:

1. **Empodera empleados** con acceso 24/7 a su información laboral
2. **Reduce carga RRHH** en 70% (automatiza consultas repetitivas)
3. **Cumple Ley 21.719** desde la arquitectura (compliance by design)
4. **Escala sin costos marginales** (AI maneja 1 o 1000 empleados)
5. **ROI positivo en <11 meses** ($17.5M beneficios vs $15.2M inversión año 1)

### Ventajas Competitivas

✅ **Único en Odoo 19 CE chileno** con chat AI nóminas
✅ **Arquitectura segura** con RLS + aislamiento datos
✅ **UX moderna** con streaming en tiempo real
✅ **Compliance total** Ley 21.719 + Código del Trabajo
✅ **Extensible** a otros módulos (vacaciones, evaluaciones, etc.)

### Próximos Pasos

1. **Aprobación propuesta** por stakeholders (RRHH, TI, Legal)
2. **Asignación equipo** (3.5 FTEs)
3. **Kickoff Sprint 1** (inicio desarrollo backend)
4. **Setup infraestructura** (Redis, monitoreo)
5. **Go-live Q1 2026** (4 meses desarrollo)

### Contacto

Para dudas o aprobación del proyecto:

**Autor:** Claude Code
**Email:** [contacto@empresa.cl]
**Fecha:** 2025-11-12

---

**FIN DEL DOCUMENTO**

---

**Metadata:**
- **Versión:** 1.0
- **Palabras:** ~18,500
- **Páginas (A4):** ~65
- **Última actualización:** 2025-11-12
- **Estado:** PROPUESTA PARA APROBACIÓN

---

## 📌 APÉNDICE: Referencias Legales

### Leyes Aplicables

1. **Ley 21.719** - Protección de Datos Personales (Chile, 2024)
   - Vigencia: 1 diciembre 2026
   - Link: https://www.bcn.cl/leychile/navegar?idNorma=1190082

2. **Código del Trabajo** - Artículo 54 (Liquidación de Sueldo)
   - Link: https://www.bcn.cl/leychile/navegar?idNorma=207436

3. **Ley 19.728** - Seguro de Cesantía
   - Link: https://www.bcn.cl/leychile/navegar?idNorma=186380

4. **DFL 150** - Estatuto de Salud (Isapre y Fonasa)
   - Link: https://www.bcn.cl/leychile/navegar?idNorma=4668

5. **Ley 18.020** - Asignación Familiar
   - Link: https://www.bcn.cl/leychile/navegar?idNorma=29465

### Circulares y Dictámenes

- Dirección del Trabajo: "Entrega digital de comprobantes de pago"
  - Conclusión: Autorizado con consentimiento empleado

- SII: Tramos Impuesto Único 2025
  - Link: https://www.sii.cl/

### Estándares Técnicos

- **OWASP Top 10** (Seguridad Web)
- **ISO 27001** (Gestión Seguridad Información)
- **GDPR** (inspiración para Ley 21.719)
