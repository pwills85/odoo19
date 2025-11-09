# Auditoría Exhaustiva – Nómina Chilena Odoo 19 CE-Pro

## 1. Executive Summary
- **Estado general**: ⚠️ Riesgos altos detectados.
- **Fecha**: 09-11-2025.
- **Alcance**: Revisión legal, funcional, técnica y de integración IA del módulo `l10n_cl_hr_payroll` y componentes asociados a indicadores económicos.
- **Hallazgos críticos**:
  1. Fórmula de salud hace referencia a un campo inexistente (`contract.isapre_plan_id`), provocando fallo en contratos ISAPRE. `hr_salary_rules_p1.xml:L70-L103`.
  2. Manejo de errores del microservicio IA lanza `UserError` sin importar la clase, generando `NameError` y dejando el cron sin fallback real. `hr_economic_indicators.py:L3-L235`.
  3. Reportería tributaria (F29/F22) y conciliación Previred no están implementadas; solo existe LRE parcial. `hr_lre_wizard.py:L59-L557`.

## 2. Alcance y metodología
- Revisión de modelos clave (`hr_contract_cl`, `hr_payslip`, `hr_payslip_run`, reglas salariales y wizards). `hr_contract_cl.py:L7-L168`, `hr_payslip.py:L649-L755`, `hr_payslip_run.py:L35-L220`.
- Evaluación de configuraciones de seguridad y multi-compañía. `multi_company_rules.xml:L13-L61`, `ir.model.access.csv:L1-L34`.
- Auditoría de integración con `ai-service`. `hr_economic_indicators.py:L158-L323`, `test_indicator_automation.py:L45-L207`.
- Revisión de pruebas funcionales disponibles (LRE, Ley 21.735, multi-compañía). `test_lre_generation.py:L200-L285`, `test_ley21735_reforma_pensiones.py:L41-L200`, `test_p0_multi_company.py:L31-L220`.

## 3. Cumplimiento legal y regulatorio

### 3.1 Remuneraciones y cotizaciones
- **AFP y SIS**: Regla `rule_afp` considera 10% + comisión desde `hr.afp`, pero no contempla SIS separado ni tope dinámico para contratos con jornada parcial. `hr_salary_rules_p1.xml:L70-L119`.
- **Salud**: Uso de `contract.isapre_plan_id` detiene cálculo para planes ISAPRE; debe consumirse `isapre_plan_uf` y convertir a CLP/UF según contrato. `hr_salary_rules_p1.xml:L96-L103`, `hr_contract_cl.py:L36-L101`.
- **Seguro de cesantía**: Regla fija 0.6% sin discriminar contrato plazo fijo (debiera usar 0% trabajador, 3% empleador). `hr_salary_rules_p1.xml:L108-L119`, `hr_salary_rule_aportes_empleador.py:L260-L334`.
- **Asignaciones familiares y zona extrema**: Campos presentes en contrato, pero falta enlace directo con reglas que calculen tramos. `hr_contract_cl.py:L92-L139`.
- **Reforma pensiones Ley 21.735**: Tests validan cálculo 0.1% + 0.9%, sin embargo los asientos contables asociados no están cubiertos por reglas de provisiones. `test_ley21735_reforma_pensiones.py:L41-L200`, `hr_salary_rule_aportes_empleador.py:L271-L349`.

### 3.2 Prestaciones especiales
- Horas extras, aguinaldos y licencias se esperan como inputs manuales; no existe lógica automatizada ni parametrización de recargos. `hr_payslip.py:L712-L755`, `hr_salary_rules_p1.xml:L30-L89`.
- Ausencias/licencias no integran `hr_work_entry` para prorratear días; cálculo de días trabajados usa diferencia simple de fechas. `hr_lre_wizard.py:L549-L578`.

### 3.3 Reportes regulatorios
- **LRE**: Wizard genera CSV con 105 columnas, pero múltiples columnas toman valores hardcodeados (ej. aportes empleador 2.4%, 0.93%) y no validan códigos SII. `hr_lre_wizard.py:L226-L544`.
- **SII (F29/F22) y declaraciones juradas**: No se encontraron wizards ni reportes; representa brecha de cumplimiento tributario.
- **Previred**: Integración sólo está en pruebas del microservicio AI; módulo Odoo no genera archivo `.txt` estándar.

## 4. Revisión funcional y de procesos
- **Ciclo de nómina**: `hr_payslip_run` controla generación masiva y bloquea estados incorrectos, pero no soporta recalculo retroactivo ni cierres parciales. `hr_payslip_run.py:L175-L220`.
- **Validaciones pre-nómina**: `hr_payslip.action_compute_sheet` limpia líneas y recalcula, pero no ejecuta conciliación contable ni prepara asientos automáticos. `hr_payslip.py:L649-L697`.
- **Contabilización**: Sólo `_generate_accounting_entries_aportes` crea asiento manual si cuentas configuradas; falta automatización para haberes/descuentos. `hr_salary_rule_aportes_empleador.py:L271-L349`.
- **UX**: Vistas de LRE y lotes usan filtros estándar, pero wizard LRE no guía sobre columnas faltantes. `hr_payslip_views.xml:L169-L202`, `hr_lre_wizard_views.xml:L18-L40`.

## 5. Arquitectura y calidad de código
- Buen uso de `_inherit` y `@api.constrains` para contratos y lotes. `hr_contract_cl.py:L64-L168`, `hr_payslip_run.py:L162-L220`.
- **Defecto crítico**: `UserError` no importado en `hr_economic_indicators.py`, ocasiona `NameError` en cualquier excepción del microservicio. `hr_economic_indicators.py:L3-L235`.
- **Consistencia ORM**: `hr_payslip` elimina líneas dos veces (antes de `_compute_basic_lines` y dentro); riesgo de performance y pérdida de auditoría. `hr_payslip.py:L681-L755`.
- **Mantenibilidad**: LRE define 105 columnas en código, sin configuración externa; actualización normativa implicará modificar código. `hr_lre_wizard.py:L226-L544`.

## 6. Integración con microservicio de IA
- `fetch_from_ai_service` consume `GET /api/payroll/indicators/{YYYY-MM}` con timeout 60s y bearer token. `hr_economic_indicators.py:L172-L205`.
- Cron `_run_fetch_indicators_cron` implementa reintentos con backoff y notificación vía `mail.activity`. `hr_economic_indicators.py:L244-L359`.
- Tests cubren éxito, reintentos e idempotencia. `test_indicator_automation.py:L45-L207`.
- **Brechas**:
  - `res_id=0` en actividades impide vínculo con un registro real. `hr_economic_indicators.py:L345-L360`.
  - No existe anonimización de datos enviados al microservicio cuando se extienda a liquidaciones; actualmente sólo indicadores (sin datos personales) viajan.
  - `hr_payslip.action_compute_sheet` no integra realmente el microservicio; se queda en `_compute_basic_lines`. `hr_payslip.py:L649-L686`.

## 7. Seguridad y privacidad de datos
- Record rules multi-compañía restringen acceso por `company_id`. `multi_company_rules.xml:L13-L61`.
- Accesos conceden permisos de borrado a `group_hr_payroll_user` en líneas, lo cual expone riesgo de eliminación inadvertida de historia de nómina. `ir.model.access.csv:L1-L34`.
- No hay cifrado específico para RUT/salarios; se confía en niveles estándar de Odoo. No se detectaron logs sensibles, pero se recomienda revisar `_logger.info` en integraciones.

## 8. Matriz de riesgos

| Id | Hallazgo | Severidad | Impacto | Recomendación | Responsable sugerido |
|----|----------|-----------|---------|---------------|----------------------|
| R1 | Regla de salud usa campo inexistente → cálculo falla para ISAPRE | 🔴 Alta | Nómina no calculable para afiliados Isapre | Reemplazar por cálculo basado en `isapre_plan_uf` y validar conversión UF/CLP | Equipo nómina técnico |
| R2 | `UserError` sin importar en integración IA | 🔴 Alta | Cron e interfaz fallan con `NameError`, sin notificación | Importar `UserError` y devolver `False` en cron para fail-soft | Equipo plataforma IA |
| R3 | Falta reportes SII (F29/F22) | 🔴 Alta | Incumplimiento tributario mensual/anual | Implementar generadores y conciliaciones Previred/SII | Equipo fiscal |
| R4 | Valores hardcodeados en LRE (aportes empleador, topes) | 🟡 Media | Declaración puede no cuadrar con libros contables | Mapear columnas a reglas salariales y topes dinámicos | Equipo reporting |
| R5 | Permiso de borrado a usuarios nómina en líneas | 🟡 Media | Riesgo de pérdida de auditoría | Restringir `perm_unlink` y habilitar auditoría `mail.thread` | Seguridad TI |
| R6 | Falta integración real con microservicio en cálculo de liquidaciones | 🟡 Media | No se aprovecha validación IA y controles avanzados | Implementar llamado asíncrono a `PayrollValidator` con fallback | Equipo IA |
| R7 | Notificación cron con `res_id=0` | 🟢 Baja | Actividades sin contexto dificultan seguimiento | Crear registro dummy o usar `mail.activity.schedule` con modelo correcto | Equipo dev |

## 9. Plan de mejoras priorizado

### Quick wins (≤2 semanas)
- Corregir import `UserError` y ajustar manejo de excepciones IA. `hr_economic_indicators.py:L3-L235`.
- Sustituir referencia `contract.isapre_plan_id` por cálculo basado en `isapre_plan_uf` y validar casos Fonasa. `hr_salary_rules_p1.xml:L96-L103`, `hr_contract_cl.py:L36-L101`.
- Ajustar `res_id` en notificaciones cron y retirar `perm_unlink` para usuarios no administradores. `hr_economic_indicators.py:L345-L360`, `ir.model.access.csv:L1-L34`.

### Mediano plazo (≤1 trimestre)
- Implementar estructura de reglas para asignaciones familiares por tramo y zona extrema, integradas a indicadores mensuales. `hr_contract_cl.py:L92-L139`, `hr_salary_rules_p1.xml:L30-L89`.
- Automatizar generación de asientos contables completos (haberes, descuentos, provisiones) usando diarios configurables. `hr_salary_rule_aportes_empleador.py:L271-L349`.
- Completar integración microservicio IA en `_compute_basic_lines`, enviando datos anonimizados y manejando tiempos de respuesta. `hr_payslip.py:L649-L755`.

### Refactorizaciones profundas (>1 trimestre)
- Diseñar módulo de reportes SII (F29/F22, DDJJ) con parametrización de cuentas y conciliación Previred. `hr_lre_wizard.py:L226-L544`.
- Externalizar especificación de LRE y otras planillas en modelos parametrizables para adaptarse a cambios normativos sin tocar código. `hr_lre_wizard.py:L226-L544`.
- Integrar `hr_work_entry` y ausencias para cálculo proporcional de haberes y licencias, incluyendo validaciones de tope legal. `hr_payslip.py:L712-L755`.

## 10. Recomendaciones adicionales
- Documentar matrices de responsabilidad y flujos de aprobación en SharePoint para alinear RR.HH., contabilidad y TI.
- Incluir pruebas unitarias para retroactivos, aguinaldos, multi-contrato y topes de indemnización.
- Evaluar cifrado a nivel de base de datos (campo `vat`, montos) o al menos auditoría reforzada con `mail.thread` en `hr.payslip` y `hr.contract`.

