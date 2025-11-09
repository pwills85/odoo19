---
id: seleccion-accion-cierre-total-definitivo
type: orquestacion-interactiva
module: global (DTE + Nómina + Reportes)
phase: seleccion_inicial
requires:
  - prompt_cierre_total_definitivo_brechas_global_sii_nomina_reportes.md
  - MAXIMAS_DESARROLLO.md
  - MAXIMAS_AUDITORIA.md
  - CONTEXTO_GLOBAL_MODULOS.md
context_branch: feat/p1_payroll_calculation_lre
default_action_timeout_minutes: 15
default_action: ejecutar_fase_1
---

# Prompt interactivo: Selección de acción inicial para cierre total definitivo

El objetivo es confirmar la primera acción operativa antes de ejecutar el plan integral de cierre total. Debes evaluar el estado actual del repositorio (branch activa, últimos commits, artefactos de auditoría) y solicitar confirmación explícita. Si no recibes respuesta en `default_action_timeout_minutes` aplica automáticamente la acción por defecto (Ejecutar Fase 1: Dashboard DTE + Tablas Nómina).

## Opciones disponibles (elige una)

1. Ejecutar Fase 1 (DTE dashboard + Tablas Nómina)
1. Generar matriz de brechas global actualizada
1. Análisis pre-ejecución (dependencias, riesgos, orden óptimo)
1. Enfoque específico (indicar dominio: DTE | Nómina | Reportes | Migración | QA/CI)

## Instrucciones de interacción

1. Presenta un resumen rápido (≤ 10 líneas) del estado: branch, últimos 5 commits relevantes del dominio Nómina y DTE, presencia de archivos de auditoría críticos.
1. Pregunta al usuario: "Confirma la acción (1=Fase1,2=Matriz,3=Pre,4=Dominio:`nombre` )".
1. Espera confirmación. Si no llega en el tiempo definido, registra en log la decisión automática y procede con acción por defecto.

## Contrato por acción

- ejecutar_fase_1:
  - Subtareas: (a) Consolidar KPIs y alertas pendientes dashboard DTE; (b) Normalizar y cargar tablas regulatorias Nómina con vigencias y constraints.
  - Entregables: PR DTE fase1-dashboard, PR nomina-tablas-vigencias; tests (unidad + rendimiento base); actualización matriz parcial.
- matriz_global:
  - Construir o actualizar CSV/MD con todos los dominios, severidades y estado actual; marcar dependencias cruzadas.
  - Entregables: AUDITORIA_MATRIZ_BRECHAS_YYYY-MM-DD.csv y enlace en README auditoría.
- analisis_pre_ejecucion:
  - Identificar riesgos (rendimiento, orden migración, dependencias de tablas), proponer secuencia optimizada y presupuesto temporal.
  - Entregables: documento ANALISIS_PRE_EJECUCION_CIERRE_TOTAL.md.
- dominio_especifico:
  - Foco exclusivo en dominio indicado: generar micro-plan y PR inicial.
  - Entregables: PR dominio y extracto de matriz solo para ese dominio.

## Procedimiento al ejecutar acción seleccionada

1. Crear branch específica si aplica: feature/`accion`-cierre-total.
1. Registrar punto de partida: listado de archivos tocados y métricas previas (tests, cobertura si disponible).
1. Ejecutar subtareas en orden y abrir PRs con plantilla completa.
1. Actualizar matriz de brechas tras cada PR (estado: cerrada/verificada).
1. Adjuntar evidencias (logs, capturas, salidas de tests) en directorio /evidencias/`fecha`/`accion`/.

## Reglas y validaciones mínimas

1. No continuar si hay tests rojos existentes en dominios afectados; reportar primero.
1. No introducir hardcode de valores regulatorios (usar modelos con vigencias).
1. Verificar i18n para nuevos strings (es_CL, en_US).
1. Añadir al menos 1 prueba negativa por cada nueva regla de negocio.

## Formato de log de interacción

Ejemplo:

```text
[HH:MM] Estado repo evaluado: branch=..., commits=[...]
[HH:MM] Solicitud de confirmación enviada.
[HH:MM] Timeout alcanzado, aplicando acción por defecto ejecutar_fase_1.
```

## Resultado esperado tras acción por defecto (ejecutar_fase_1)

1. Dashboard DTE con KPIs/alertas completados y tests verdes.
1. Tablas Nómina parametrizadas (UF/UTM/topes/SIS) con constraints sin solapes.
1. PRs abiertos con descripción y métricas iniciales.
1. Matriz global actualizada con estado de Fase 1.

## Próximo paso tras completar acción

1. Proponer automáticamente acción siguiente lógica (matriz_global si no existía o analisis_pre_ejecucion) y solicitar confirmación.

## Inicio

Procede ahora con la secuencia: resumen → solicitud → espera → decisión → ejecución.
