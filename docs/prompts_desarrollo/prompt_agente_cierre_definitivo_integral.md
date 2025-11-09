# Agente de Cierre Definitivo Integral — Odoo 19 CE (CL)

Misión: Cerrar definitivamente las brechas del stack Odoo 19 CE (Localización Chilena) garantizando instalabilidad total, estabilidad sin warnings/errores, y calidad operativa bajo gates de CI, con evidencias reproducibles.

Fecha objetivo: hoy
Alcance módulos: l10n_cl_dte, l10n_cl_financial_reports, l10n_cl_hr_payroll, eergygroup_branding
Entorno: macOS dev + CI (contenedor Odoo 19, Postgres 15, Redis 7 opcional)
Restricción: No hacer push remoto hasta pasar todos los quality gates y consolidar evidencias.

---

## Objetivos (definición de DONE)

- Instalación por lotes de los 4 módulos sin errores y sin warnings bloqueantes.
- Sin inconsistencias de manifiestos, data XML, ACLs y assets; rutas y dependencias coherentes.
- Crons, menús, acciones y endpoints de salud operativos o correctamente desactivados por configuración.
- CI con job de “instalabilidad + smoke” que falla en condiciones inválidas y sube artefactos.
- Evidencias: matriz CSV consolidada, logs parseados, reporte ejecutivo final.

---

## Contexto y decisiones previas

- DTE (l10n_cl_dte): Redis es opcional (lazy import). Riesgo detectado: `except redis.RedisError` sin import a nivel módulo. Debe reemplazarse por manejo seguro que no requiera el paquete presente.
- Financial Reports (l10n_cl_financial_reports): Vista de wizard F22 vs F29 existe en `views/l10n_cl_report_comparison_wizard_views.xml` pero el manifest desactiva una ruta `wizards/...`. Por defecto, mantener desactivado (o corregir ruta y activar) según política definida abajo.
- HR Payroll: depende de `requests` y tiene cron de indicadores; debe funcionar en modo offline si falta microservicio.
- Branding: módulo auxiliar (assets CSS/QWeb) sin ACL propio.

Política por defecto (seguridad de instalación):

- FR wizard comparación: DESACTIVADO por ahora (evitar rutas inconsistentes). Activable luego con ruta correcta.
- DTE Redis: fail-open en rate limit y fail-secure en replay nonce, sin requerir `redis` instalado.
- HR: cron indicadores en modo offline si faltan parámetros.

---

## Fases y entregables

### Fase A — Fixes rápidos bloqueantes (máx. 45 min)

1. DTE: robustecer control de excepciones Redis

- Reemplazar `except redis.RedisError` por un alias seguro o por `except Exception:` con logs claros.
- Mantener: `get_redis_client()` con lazy import + ping; fail-open solo en rate limit; fail-secure en replay protection.

1. Financial Reports: coherencia wizard comparación

- Opción segura (por defecto): mantener desactivado el wizard y alinear el manifest a ese estado (sin referenciar rutas inexistentes).
- Opción alternativa: activar el wizard corrigiendo la ruta a `views/l10n_cl_report_comparison_wizard_views.xml` y verificando modelo/acciones/menú.

1. HR Payroll: requests + cron indicadores

- Verificar que `requests` esté disponible.
- Proteger cron: si no hay URLs/keys configuradas, log informativo y retorno limpio (sin traceback).

Entregables A:

- Commits locales con fixes mínimos.
- Notas de cambio en CHANGELOG / audit.


### Fase B — Validación estática pre-instalación (máx. 40 min)

Checklist B:

- Manifests: 4/4 válidos; sin referencias a archivos inexistentes; `installable=True` coherente.
- Data XML: todos los archivos listados existen y cargan en orden (security → data → views → menus → reports → assets).
- ACLs/seguridad: CSV con columnas estándar y `model_id:id` existentes; grupos válidos.
- Assets: rutas de CSS/JS/XML existen.
- Migraciones: no romperán upgrades; migraciones legacy (18.0) documentadas o desplazadas fuera de ruta si no se usarán.

Entregables B:

- Informe estático con listado de hallazgos y correcciones aplicadas.


### Fase C — Instalación incremental por lotes (con logs y métricas)

Orden de lotes (propuesto):

1. eergygroup_branding
1. l10n_cl_dte
1. l10n_cl_hr_payroll
1. l10n_cl_financial_reports

Ejecución por lote:

- Instalar lote → capturar stdout/stderr.
- Parsear “WARNING” y “ERROR” por módulo/archivo.
- Registrar tiempo de instalación por módulo.
- Criterio de éxito por lote: 0 errores y 0 warnings bloqueantes (warnings informativos documentados y justificados).

Entregables C:

- Logs por lote (archivos), JSON de parsing por módulo, matriz CSV actualizada con tiempos, warnings/errors y estado.


### Fase D — Verificación post-instalación (profunda, 45-60 min)

DTE:

- `/api/dte/health`: debe responder OK; si no hay Redis instalado, `redis: false` y sin traceback.
- Crons: no deben fallar por falta de configuración (usar defaults o desactivar por parámetro).

HR Payroll:

- Cron indicadores: modo offline tolerante, sin tracebacks.
- Prueba básica: crear entidades mínimas (empleado/contrato/payslip dummy) si el entorno lo permite.

Financial Reports:
- Vistas F29/F22 abren; acciones básicas (cálculo vacío) no generan traceback.
- Si se activó el wizard de comparación: abrirlo, validar acciones y menús.

Entregables D:
- Checklist de verificación por módulo, con capturas/logs si aplica.


### Fase E — Evidencias y consolidación

- Matriz CSV consolidada: columnas mínimas
  - modulo,tipo,depends,external_deps,migraciones,cron_jobs,access_csv,archivos_python,tiempo_instal_seg,warnings,errors,estado_final,post_init_hook,uninstall_hook,assets_ok,config_minima,observaciones
- Reporte Ejecutivo Final: semáforo por módulo (VERDE/AMARILLO/ROJO), resumen de desviaciones y medidas.
- Artefactos: logs por lote, JSON de parsing, baseline compliance actualizada.


### Fase F — Hardening CI + Smoke tests

- Job CI “instalabilidad”: levanta contenedor, instala lotes, parsea logs, sube artefactos y falla en errores/warnings críticos.
- Smoke tests (pytest-odoo mínimos):
  - DTE: health OK; crear factura dummy y ejecutar acción que no requiera envío real; crons no fallan al disparo.
  - HR: crear estructura mínima y generar payslip dummy.
  - FR: abrir vistas críticas y ejecutar acción de cálculo vacía.
- Gates: 
  - Lint sin tolerancias.
  - Instalabilidad 4/4.
  - Smoke tests ALL PASS.
  - Warnings críticos = 0.

Entregables F:
- Workflow CI ajustado; tests mínimos en `tests/` por módulo.

---

## Quality Gates (deben quedar en VERDE)

- Lint: 0 errores; estilos consolidados.
- Instalación: 4/4 módulos sin errores.
- Warnings: 0 críticos (solo informativos documentados).
- Post-instalación: crons, menús, vistas y endpoints verificados.
- CI: job de instalabilidad y smoke activo; artefactos subidos.
- Evidencias: matriz, logs, reporte final.

---

## Contrato operativo (inputs/outputs/errores)

Entradas:
- Repo actual, rama de trabajo local, entorno Docker/venv.
- Parametría mínima (si aplica) en `ir.config_parameter` para modo offline.

Salidas:
- Commits locales con fixes y ajustes.
- Instalación por lotes con artefactos.
- Matriz + reporte final.
- CI endurecido con job instalabilidad + smoke.

Errores esperables y manejo:
- Falta de redis: no debe romper import ni instalación.
- Wizard inconsistente: desactivar o corregir ruta antes de instalar.
- Microservicios ausentes: cron en modo offline, sin traceback.

---

## Checklists rápidas de aceptación por módulo

DTE
- [ ] Import de controladores no falla sin `redis` instalado
- [ ] Health `/api/dte/health` responde; `redis` false permitido
- [ ] Crons no fallan por configuración ausente
- [ ] Vistas/menús/reportes cargan sin warnings críticos

HR Payroll
- [ ] `requests` disponible
- [ ] Cron indicadores tolerante sin microservicios (offline)
- [ ] Payslip dummy posible sin traceback (si entorno lo permite)

Financial Reports
- [ ] Manifest sin referencias rotas (wizard comparación coherente)
- [ ] Vistas F29/F22 abren y acciones básicas no rompen
- [ ] Assets presentes (sin rutas huérfanas)

Branding
- [ ] Instalación sin warnings/errores
- [ ] Assets CSS/QWeb resuelven rutas

---

## Evidencias mínimas a entregar (estructura propuesta)

- `matrices/INSTALABILIDAD_MODULOS_YYYY-MM-DD.csv`
- `evidencias/instalacion/YYYY-MM-DD/lote-*/{stdout.log,stderr.log,parse.json}`
- `evidencias/post_instalacion/YYYY-MM-DD/{checklist.md,capturas/}`
- `reports/REPORTE_FINAL_INSTALABILIDAD_YYYY-MM-DD.md`
- `.compliance/baseline_installability_YYYYMMDD.json`

---

## Notas de implementación inmediatas (aplícalas antes de instalar)

1) l10n_cl_dte/controllers/dte_webhook.py
- Reemplazar `except redis.RedisError` por manejo que no dependa del import si `redis` no existe (alias seguro o `except Exception:`) en `rate_limit_redis` y `check_replay_attack`.

2) l10n_cl_financial_reports/__manifest__.py
- Alinear decisión del wizard comparación:
  - Opción por defecto: mantener desactivado (eliminar/ comentar referencia) y dejar nota en TODO para reactivación.
  - Opción alternativa: activar corrigiendo la ruta a `views/l10n_cl_report_comparison_wizard_views.xml` y verificar modelo/acciones/menú.

3) l10n_cl_hr_payroll
- Confirmar `external_dependencies` (requests) disponible.
- Endurecer cron indicadores: detectar ausencia de configuración y salir limpio.

---

## Cómo proceder (resumen operativo)

1) Aplicar fixes rápidos (Fase A) y documentarlos.
2) Ejecutar validación estática (Fase B) y corregir cualquier desvío.
3) Instalar por lotes (Fase C), capturar y parsear logs, actualizar matriz.
4) Verificación profunda (Fase D) con checklist por módulo.
5) Consolidar evidencias (Fase E) y ajustar CI + smoke (Fase F).
6) Entregar reporte final y dejar PR preparado localmente (sin push) hasta validación ejecutiva.

---

## Métricas y SLAs

- Tiempo total instalación < 12 min en entorno CI estándar.
- Warnings críticos = 0; errores = 0.
- Smoke tests: 100% PASS.
- Gate de instalabilidad en CI obligatoriamente en VERDE antes de publicar.

---

## Cierre

Cuando todas las fases y gates estén en VERDE, empaquetar evidencias y solicitar validación ejecutiva para el push remoto y la creación del PR oficial.
