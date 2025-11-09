# Máximas de Auditoría – Odoo 19 CE (Localización Chile)

Estas máximas rigen todas las auditorías funcionales y técnicas (Nómina, DTE, Reportes).

## 1. Alcance y Trazabilidad

- Cada auditoría debe declarar objetivo, módulos, ramas, y dependencias previas.
- Todo hallazgo referencia archivo/línea o vista/acción y cómo reproducirlo.

## 2. Evidencia y Reproducibilidad

- Evidencia mínima: pasos, dataset usado, capturas/logs, y resultado esperado vs obtenido.
- Los escenarios deben ser reproducibles en ambiente limpio; evitar datos huérfanos.

## 3. Cobertura y Profundidad

- Incluir: happy path, bordes (saldos cero, sin movimientos, fechas límite), multi-compañía, i18n.
- Incluir performance y seguridad cuando aplique (no opcional en reportes y DTE).

## 4. Performance y Escalabilidad

- Definir umbrales por tipo: reportes (<3s, <50 queries en 10k-50k líneas), nómina masiva (<5m/1k empleados aprox.).
- Medición obligatoria con `QueryCounter` o registros temporizados y evidencia de tiempos.

## 5. Seguridad y Privacidad

- Revisar ACL por rol; probar acceso indebido entre compañías.
- Validar wizards y endpoints (parámetros maliciosos); no filtrar por nombre visible sino por id/permiso.

## 6. Correctitud Legal

- Ningún cálculo basado en campos obsoletos; usar vigencias (`valid_from`/`valid_until`).
- Verificar que los topes/tasas provienen de modelos paramétricos y no de constantes.

## 7. Matrices y Checklist

- Usar matrices de verificación claras por módulo/sprint.
- Cada ítem con estado (OK, Gap, N/A), severidad (P0-P3) y acción propuesta.

## 8. Reportería del Resultado

- Entregar informe con resumen ejecutivo, tabla de gaps, reproducibilidad y DoD de cierre.
- Adjuntar archivos `.md`/`.csv` con matrices o scripts si se usaron.

## 9. Definición de Hecho (DoD)

- Un gap P0/P1 no se considera cerrado sin test que pruebe el fix y documentación actualizada.
- Se exige validación por un segundo revisor cuando afecta cálculos o seguridad.

## 10. Estilo y Formato

- Estructura Markdown con front-matter consistente; headings y listas con espacios correctos.
- Idiomas: `es_CL` por defecto; aportar ejemplo/nota en inglés si es relevante.

## 11. Herramientas y Automatización

- Preferir `pytest` y fixtures para datasets; scripts utilitarios versionados.
- Registrar comandos ejecutados y versiones relevantes del entorno.

## 12. Priorización de Gaps

- P0: bloquea producción o incumple ley; P1: alto impacto o riesgo; P2: mejora; P3: cosmético.
- Orden de trabajo: P0 → P1 → preflight rendimiento/seguridad → P2/P3.
