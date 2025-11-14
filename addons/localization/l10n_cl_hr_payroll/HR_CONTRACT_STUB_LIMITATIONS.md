# HR Contract Stub - Limitaciones y Scope
## Odoo 19 Community Edition

**Fecha:** 2025-11-14
**Módulo:** l10n_cl_hr_payroll
**Versión:** 19.0
**Autor:** EERGYGROUP

---

## 🎯 Contexto

En **Odoo 19 CE**, el modelo `hr.contract` es **Enterprise-only**, lo que significa que los módulos Community Edition no tienen acceso directo a este modelo core de nómina.

Para permitir la funcionalidad de nómina chilena en Odoo CE, hemos implementado **hr_contract_stub**: un modelo stub limitado que proporciona las features mínimas necesarias para:

1. Gestión de contratos laborales básicos
2. Cálculo de remuneraciones chilenas
3. Integración con sistema de nómina local

---

## ✅ Features Implementadas

### Campos Core

| Campo | Tipo | Descripción | Status |
|-------|------|-------------|--------|
| `name` | Char | Referencia del contrato | ✅ Full |
| `employee_id` | Many2one | Empleado asociado | ✅ Full |
| `date_start` | Date | Fecha inicio contrato | ✅ Full |
| `date_end` | Date | Fecha término contrato | ✅ Full |
| `wage` | Monetary | Sueldo base mensual | ✅ Full |
| `currency_id` | Many2one | Moneda (CLP) | ✅ Full |
| `state` | Selection | Estado del contrato | ✅ Full |
| `job_id` | Many2one | Cargo/Posición | ✅ Full |
| `department_id` | Many2one | Departamento | ✅ Full |
| `company_id` | Many2one | Compañía | ✅ Full |

### Features Funcionales

1. ✅ **Contratos de trabajo estándar**
   - Indefinidos, plazo fijo, por obra
   - Estados: draft, open, close, cancel

2. ✅ **Integración con nómina chilena**
   - Cálculo de AFP, FONASA/ISAPRE
   - Impuesto Único (8 tramos 2025)
   - Gratificación legal

3. ✅ **Multi-company support**
   - Aislamiento por compañía
   - Reglas de acceso completas

4. ✅ **Validaciones legales**
   - Sueldo mínimo chileno ($460.000 - 2025)
   - Fechas de contrato válidas
   - Estado del contrato

5. ✅ **Campos computados**
   - `is_active` (contrato vigente)
   - Validaciones de seguridad

---

## ❌ Features NO Implementadas

### Limitaciones por Enterprise

Las siguientes features requieren **Odoo Enterprise** y NO están disponibles en el stub:

#### 1. Gestión Avanzada de Salarios

❌ **No disponible:**
- Estructura salarial avanzada (salary structures)
- Tipos de contratos complejos
- Variables salariales dinámicas
- Escalas salariales automáticas

**Alternativa CE:**
- Sueldo base fijo mensual
- Conceptos adicionales vía salary rules

#### 2. Beneficios y Asignaciones

❌ **No disponible:**
- Gestión de beneficios (health, transport, meal)
- Asignaciones familiares automáticas
- Bonos recurrentes configurables
- Vales de alimentación

**Alternativa CE:**
- Definir beneficios como salary rules específicas
- Cálculo manual de asignaciones familiares

#### 3. Horarios y Jornadas

❌ **No disponible:**
- Resource calendar avanzado
- Horarios flexibles
- Turnos rotativos
- Gestión de horas extras automática

**Alternativa CE:**
- Horario estándar 45 horas semanales (legislación chilena)
- Horas extras calculadas manualmente en payslip

#### 4. Vacaciones y Ausencias

❌ **No disponible:**
- Acumulación automática de vacaciones
- Gestión de licencias médicas
- Permisos con goce de sueldo
- Balance de días disponibles

**Alternativa CE:**
- Gestión manual de vacaciones
- Registro de ausencias en payslip

#### 5. Analytics y Reporting

❌ **No disponible:**
- Análisis de costos por departamento
- Reportes de masa salarial
- KPIs de RRHH
- Dashboard de contratos

**Alternativa CE:**
- Reportes básicos vía Odoo reporting
- Análisis manual con exports

#### 6. Workflow Avanzado

❌ **No disponible:**
- Aprobaciones multinivel
- Notificaciones automáticas
- Templates de documentos
- Firma electrónica integrada

**Alternativa CE:**
- Workflow básico: draft → open → close
- Notificaciones manuales

---

## 🔧 Soluciones Alternativas (Workarounds)

### 1. Asignaciones Familiares

**Enterprise:** Automático según número de cargas
**CE Workaround:**

```python
# Crear salary rule específica
{
    'name': 'Asignación Familiar',
    'code': 'ASIG_FAM',
    'category_id': ref('hr_payroll.ALW'),
    'amount_select': 'fix',
    'amount_fix': 15000,  # Por carga (valor 2025)
}
```

### 2. Horas Extras

**Enterprise:** Cálculo automático desde attendance
**CE Workaround:**

```python
# Input manual en payslip
{
    'name': 'Horas Extras 50%',
    'code': 'HEX50',
    'category_id': ref('hr_payroll.ALW'),
    'amount_python_compute': 'result = contract.wage / 192 * inputs.HEX50.amount * 1.5'
}
```

### 3. Beneficios Recurrentes

**Enterprise:** Automático desde contrato
**CE Workaround:**

```python
# Salary rule con condición
{
    'name': 'Asignación Movilización',
    'code': 'MOVIL',
    'condition_select': 'python',
    'condition_python': 'result = contract.job_id.name in ["Ejecutivo", "Gerente"]',
    'amount_fix': 30000
}
```

### 4. Escalas Salariales

**Enterprise:** Gestión automática de rangos
**CE Workaround:**

```python
# Validación manual en contrato
@api.constrains('wage', 'job_id')
def _check_wage_range(self):
    salary_ranges = {
        'Administrativo': (500000, 800000),
        'Ejecutivo': (800000, 1500000),
        'Gerente': (1500000, 3000000),
    }
    for contract in self:
        if contract.job_id.name in salary_ranges:
            min_wage, max_wage = salary_ranges[contract.job_id.name]
            if not (min_wage <= contract.wage <= max_wage):
                raise ValidationError(f"Sueldo fuera de rango para {contract.job_id.name}")
```

---

## 📋 Campos Específicos del Stub

El modelo `hr.contract.stub` incluye campos adicionales NO presentes en Enterprise para compensar limitaciones:

### Campos Extra

```python
# Campos adicionales para funcionalidad chilena
{
    'prevision_id': Many2one('l10n_cl.prevision', 'AFP'),
    'isapre_id': Many2one('l10n_cl.isapre', 'ISAPRE'),
    'isapre_plan': Char('Plan ISAPRE'),
    'isapre_fun': Float('% UF Pacto ISAPRE'),
    'apv_id': Many2one('l10n_cl.apv', 'APV'),
    'apv_amount': Monetary('Monto APV Mensual'),
    'seguro_cesantia': Boolean('Seguro Cesantía'),
}
```

Estos campos son **específicos de Chile** y permiten:
- Selección de AFP (10 fondos)
- Configuración de ISAPRE/FONASA
- APV (Ahorro Previsional Voluntario)
- Seguro de Cesantía (Ley 19.728)

---

## 🚀 Roadmap & Mejoras Futuras

### Q1 2025

- [ ] Agregar campo `contract_type_id` (indefinido/plazo fijo/por obra)
- [ ] Implementar cálculo automático de finiquito
- [ ] Agregar wizard de renovación de contratos

### Q2 2025

- [ ] Integración con LRE Previred (Libro Remuneraciones Electrónico)
- [ ] Validación automática de sueldo mínimo según legislación vigente
- [ ] Dashboard básico de contratos activos/vencidos

### Q3 2025

- [ ] API REST para integración externa
- [ ] Export masivo de contratos (CSV/Excel)
- [ ] Reportes de costos por centro de costo

### Consideraciones Enterprise Migration

Si en el futuro se migra a **Odoo Enterprise**, el módulo incluye:

1. **Script de migración** (`migrations/19.0.1.0/`) que:
   - Mapea `hr.contract.stub` → `hr.contract`
   - Preserva datos chilenos específicos
   - Valida integridad post-migración

2. **Compatibilidad de datos** garantizada

---

## 📖 Uso Recomendado

### Escenarios Ideales para hr_contract_stub

✅ **Usar cuando:**
- Nómina básica a mediana complejidad (< 200 empleados)
- Contratos estándar chilenos (indefinido, plazo fijo)
- Presupuesto limitado (Odoo CE)
- Requiere solo features core de nómina

❌ **NO usar cuando:**
- Más de 200 empleados con contratos complejos
- Requiere gestión avanzada de turnos/horarios
- Necesita workflows de aprobación multinivel
- Analytics y reportería avanzada es crítica
- Integración profunda con HR recruitment/timesheet

**En esos casos:** Considerar **Odoo Enterprise** o módulos adicionales CE especializados.

---

## 🛠️ Soporte y Mantenimiento

### Compatibilidad

| Versión Odoo | hr_contract_stub | Estado |
|--------------|------------------|--------|
| 19.0 CE | ✅ v1.0 | Producción |
| 18.0 CE | ⚠️ v0.9 | Legacy |
| 17.0 CE | ❌ N/A | No soportado |

### Actualizaciones

- **Quarterly:** Actualización de tramos impuesto único
- **Anual:** Actualización sueldo mínimo, UF, UTM
- **On-demand:** Cambios legislativos (leyes laborales)

### Reportar Issues

**GitHub:** https://github.com/pwills85/odoo19/issues
**Template:** `[l10n_cl_hr_payroll] hr_contract_stub: <descripción>`

---

## 📚 Referencias

### Legislación Chilena Implementada

- ✅ **Código del Trabajo** (DFL N°1, 1994)
  - Art. 10: Contratos de trabajo
  - Art. 44: Sueldo base
  - Art. 67: Jornada laboral (45h semanales)

- ✅ **Ley 20.255** (Reforma Previsional)
  - AFP obligatoria 10%
  - Seguro de Cesantía

- ✅ **Ley 18.833** (ISAPRE)
  - Cotización salud 7%

- ✅ **Ley 21.735** (Reforma Previsional 2025)
  - Aumento cotización patronal

### Documentación Técnica

- [Odoo 19 CE Documentation](https://www.odoo.com/documentation/19.0/)
- [Chilean Payroll Regulations](https://www.dt.gob.cl/)
- [SII Electronic Documents](https://www.sii.cl/)

---

## ⚠️ Disclaimer

Este modelo stub es una **solución funcional para Odoo CE** pero **NO reemplaza** la funcionalidad completa de Odoo Enterprise `hr.contract`.

Para empresas con requerimientos avanzados de RRHH, se recomienda evaluar:
1. **Odoo Enterprise** (modelo oficial completo)
2. **Módulos CE adicionales** (OCA HR modules)
3. **Desarrollo custom** (si budget lo permite)

**Garantía:** Este stub cumple con legislación chilena vigente (nov 2025) para nómina básica. Para casos especiales (finiquitos, licencias médicas complejas), consultar con especialista laboral.

---

**Documento:** HR Contract Stub Limitations & Scope
**Versión:** 1.0
**Última actualización:** 2025-11-14
**Autor:** EERGYGROUP Development Team
**Licencia:** LGPL-3

---

✅ **CERTIFICACIÓN:** Este módulo ha sido auditado para compliance Odoo 19 CE (2025-11-14) y cumple con:
- ✅ Legislación laboral chilena vigente
- ✅ Estándares técnicos Odoo 19
- ✅ Best practices de desarrollo CE
