# Guía rápida de prompts de desarrollo

Este README te permite retomar la sesión como si no te hubieras ido: qué hay en esta carpeta, cómo usarlo hoy y cuál es el siguiente paso recomendado.

## Qué hay en esta carpeta

Prompts listos para orquestar el cierre total de brechas y arrancar la ejecución:

1. Cierre total definitivo (global)
    - Archivo: `prompt_cierre_total_definitivo_brechas_global_sii_nomina_reportes.md`
    - Propósito: orquesta DTE + Nómina + Reportes + Migración + QA/CI con KPIs, DoD y entregables por dominio.
    - Cuándo usarlo: cuando quieras ejecutar el plan integral con criterios de merge finales.

1. Selección de acción inicial (interactivo)
    - Archivo: `prompt_seleccion_accion_cierre_total_definitivo.md`
    - Propósito: pedir confirmación de la primera acción (Fase 1, Matriz global, Pre-ejecución, Dominio específico) y proceder con “Fase 1” por defecto si no hay respuesta.
    - Cuándo usarlo: para coordinar el arranque y evitar ambigüedades al iniciar una nueva sesión.

Notas:

- En la raíz del repositorio hay otros prompts y auditorías relevantes (por ejemplo, cierre de dashboard DTE, hardening de nómina, auditoría regulatoria y cierre P0 cross-módulos). Están enlazados desde el prompt integral.

## Cómo usarlos hoy (5 minutos)

1. Abre `prompt_seleccion_accion_cierre_total_definitivo.md` y confirma la acción a ejecutar.
1. Si eliges “Fase 1”, sigue el plan operativo dentro del prompt integral (`cierre_total_definitivo…`).
1. Abre branches por dominio y crea PRs con plantilla completa y métricas base (tiempos, QueryCounter, cobertura).
1. Actualiza la matriz global de brechas al cerrar cada PR (usa `AUDITORIA_MATRIZ_BRECHAS_YYYY-MM-DD.csv`).
1. Adjunta evidencias en `evidencias/<fecha>/<accion>/` y enlaza en los PRs.

## Estado actual mínimo para reanudar

- Los dos prompts clave de orquestación están listos y sin errores de lint.
- Existe una matriz de brechas de referencia en `AUDITORIA_MATRIZ_BRECHAS_2025-11-07.csv`.
- Hay abundante evidencia de auditoría y análisis en la raíz del repo (prefijo `AUDITORIA_*`, `RESUMEN_*`, etc.).

## Siguiente paso recomendado (por defecto)

1. Ejecutar “Fase 1”: completar dashboard DTE (KPIs/alertas/i18n/performance) + normalizar tablas de Nómina (UF/UTM/topes/SIS) con vigencias y constraints.
1. Abrir 2 PRs: DTE-dashboard y Nómina-tablas-vigencias, con tests (unidad, negativos, rendimiento base) y métricas.
1. Actualizar la matriz global marcando brechas cerradas/verificadas.

## Convenciones y documentos base

1. Máximas y estándares: `MAXIMAS_DESARROLLO.md`, `MAXIMAS_AUDITORIA.md`.
1. Contexto de integración: `CONTEXTO_GLOBAL_MODULOS.md`.
1. Knowledge base Nómina: `ai-service/knowledge/nomina/README.md`.

## Checklist de reanudación (rápido)

1. ¿Branch de trabajo? Confirma o crea `feature/<accion>-cierre-total`.
1. ¿Tests verdes? No avances si hay rojos en dominios afectados.
1. ¿i18n? Nuevos strings en es_CL y en_US.
1. ¿Rendimiento? Define presupuesto y enciende QueryCounter en tests.
1. ¿Evidencias? Prepara carpeta `evidencias/<fecha>/<accion>/`.

## Notas

- Si ya tienes decidido un dominio único (DTE | Nómina | Reportes | Migración | QA/CI), usa el prompt interactivo y selecciona “Dominio específico” para generar un micro-plan y su PR inicial.
- Cuando el script `compliance_check` esté disponible, ejecútalo antes de hacer merge para validar lint, tests, cobertura y checks básicos de seguridad/i18n.
