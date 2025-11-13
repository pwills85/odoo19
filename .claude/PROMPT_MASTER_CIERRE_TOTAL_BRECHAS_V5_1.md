  🚨 PROBLEMA CRÍTICO DETECTADO: API Antigua en Tests

  He analizado el estado actual y encontré un problema crítico NO contemplado en el 
  PROMPT MASTER V5:

  📊 Situación Actual

  Tests Esperados Fallando: ~14 (según PROMPT V5)
  Tests Realmente Fallando: ~30 (más del doble)

  Causa Raíz:
  Múltiples archivos de tests están usando API antigua (campos eliminados como 'year',
  'month', etc.) que NO EXISTE en los modelos actualizados.

  🔍 Modelos Afectados

  | Modelo                 | API Antigua (❌ NO EXISTE)
   | API Actual (✅ CORRECTA)
           |
  |------------------------|-----------------------------------------------------------
  |------------------------------------------------------------------------------------
  -------|
  | hr.economic.indicators | 'month': 1, 'year': 2025
  | 'period': date(2025, 1, 1)
         |
  | l10n_cl.legal.caps     | 'year': 2025, 'tope_imponible_afp_uf': 81.6
  | 'code': 'AFP_IMPONIBLE_CAP', 'amount': 81.6, 'unit': 'uf', 'valid_from': date(2025,
   1, 1) |
  | hr.tax.bracket         | 'year': 2025, 'from_amount': 0.00, 'to_amount': 916380.00
  | 'tramo': 1, 'desde': 0.0, 'hasta': 13.89, 'tasa': 0.0, 'vigencia_desde': date(2025,
   1, 1) |

  📂 Archivos Afectados

  - test_payroll_calculation_p1.py - setUpClass falla → todos los tests bloqueados (~15
   tests)
  - test_payroll_caps_dynamic.py - usa month/year (~3 tests)
  - fixtures_p0_p1.py - helpers compartidos
  - test_ley21735_reforma_pensiones.py - probablemente afectado (~6 tests)

  Impacto: Esto explica por qué tenemos ~30 errores en lugar de ~14.

  ✅ DECISIÓN REQUERIDA

  He generado un reporte completo en: CRITICAL_ISSUE_API_ANTIGUA.md

  Opciones:

  A) Corregir tests ahora (RECOMENDADO)
  - ✅ Solución arquitectónicamente correcta
  - ✅ Sigue principios "SIN PARCHES" y "SIN IMPROVISACIÓN"
  - ✅ Tests actualizados a API correcta
  - ⏱️ Tiempo adicional: +1.5h
  - 📊 Nuevo total: 4-5h (vs 2.5-3.5h original)

  B) Solicitar más información
  - Revisar historial de commits
  - Verificar si hay documentación de migración

  C) Otra estrategia
  - Especificar

  🎯 MI RECOMENDACIÓN

  Opción A - Corregir los tests ahora, siguiendo estos principios:

  1. ✅ SIN IMPROVISACIÓN: Usar API correcta validada (tengo ejemplos de
  test_apv_calculation.py)
  2. ✅ SIN PARCHES: Actualizar tests a API actual, no crear workarounds
  3. ✅ MÁXIMA PRECISIÓN: Validar cada cambio con tests
  4. ✅ TRABAJO PROFESIONAL: Commits estructurados y documentados

  Plan propuesto:
  1. Corregir test_payroll_calculation_p1.py (30min)
  2. Corregir test_payroll_caps_dynamic.py (15min)
  3. Corregir fixtures_p0_p1.py (20min)
  4. Validar y ajustar test_ley21735_reforma_pensiones.py (15min)
  5. Validación completa (10min)

  Total: 1.5h adicionales → Luego continuar con TASK 2.6B, 2.6C, 2.5, 2.7

  ---
  ¿Cómo deseas proceder?

  Todos
  ☒ Validar estado actual del branch y commits
  ☒ Ejecutar tests completos para ver estado actual exacto
  ☒ Analizar errores críticos encontrados (campo 'year' y otros)
  ☒ PROBLEMA CRÍTICO: Identificar todos los tests con API antigua
  ☒ Generar reporte del problema y propuesta de solución
  ☐ ESPERANDO DECISIÓN: Cómo proceder con API antigua
  ☐ TASK 2.6B Parte 2: Corregir test_calculations_sprint32 (45min)
  ☐ TASK 2.6C: Ajustar Validaciones/Mensajes (30min)
  ☐ TASK 2.5: Resolver Multi-Company (1-2h)
  ☐ TASK 2.7: Validación Final y DoD (30min)