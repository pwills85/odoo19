# Máximas de Desarrollo – Stack Odoo 19 CE (Localización Chile)

Estas directrices son **no negociables** y aplican a todos los prompts de desarrollo.


## 1. Plataforma y Versionado

- Usar exclusivamente APIs y patrones soportados por **Odoo 19 Community Edition**.
- Prohibido portar código legacy de versiones anteriores sin refactor.


## 2. Integración y Cohesión

- Respetar integraciones nativas (`account.report`, `account_edi`, `hr_payroll`).
- Evitar duplicar lógica existente del core; extender con herencia limpia.
- Asegurar compatibilidad entre módulos propios: Nómina, DTE, Reportes.


## 3. Datos Paramétricos y Legalidad

- Ningún valor legal hardcodeado (UF, UTM, topes imponibles, tasas). Deben centralizarse en modelos de indicadores con vigencias.
- Validaciones legales siempre con fecha efectiva (`valid_from`/`valid_until`).


## 4. Rendimiento y Escalabilidad

- Evitar N+1 queries (usar prefetch, `read_group`, mapeos en lote).
- Tests de rendimiento para escenarios ≥10k registros cuando aplique (reportes, nómina masiva, DTE masivo).
- Medir queries clave con `QueryCounter` en tests de performance.


## 5. Seguridad y Acceso

- Definir `ir.model.access.csv` mínimo, restringiendo creación/edición según roles.
- Revisar herencia de `ir.rule` en multi-compañía; nunca exponer datos de otra compañía.
- Inputs externos (webhooks, wizards) siempre validados y sanitizados.


## 6. Calidad de Código

- Estándares: `black`, `flake8`/`ruff`, `pylint` (sin W/R/E nuevos introducidos).
- Commits: Conventional Commits (feat, fix, refactor, perf, docs, test, chore, i18n).
- Tests ≥ 90% cobertura para lógica crítica; incluir casos de borde y regresión.


## 7. Pruebas y Fiabilidad

- Cada corrección de brecha incluye al menos un test que fallaría antes del cambio.
- Tests deterministas: sin dependencias de red externa ni fechas no controladas (usar `freeze_time` si aplica).
- Performance: definir umbrales razonables y documentar en README si se superan.


## 8. Internacionalización (i18n)

- Todos los textos visibles traducibles (`_()` o `t-esc` con `translate="yes"`).
- Priorizar `es_CL` y `en_US`. Proveer plantilla base para otros idiomas.


## 9. Documentación

- Cada Sprint/Fase: archivo de cierre en `docs/sprints_log/<modulo>/` con métricas, hallazgos y próximos pasos.
- README del módulo actualizado cuando se añadan parámetros, menús o dependencias.


## 10. Observabilidad y Métricas

- Decoradores o hooks ligeros para medir tiempo crítico (generación de reportes, procesamiento DTE, cálculo masivo nómina).
- Configurables vía `ir.config_parameter` (ej: `<module>.metrics_enabled`).


## 11. Diseño de Reportes

- Uso estricto de `account.report` salvo requisito funcional que lo impida justificadamente.
- PDF: QWeb dinámico (sin placeholders fijos). XLSX nativo cuando aplica.


## 12. Manejo de Errores

- Errores funcionales: `UserError` con mensaje accionable.
- Errores internos: log estructurado (si activado) + excepción clara.
- Nunca silenciar excepciones legales o de integridad.


## 13. Aislamiento y Reutilización

- Servicios (helpers) reutilizables para cálculo de indicadores, mapping de cuentas, validaciones de RUT.
- Evitar duplicar helpers entre módulos; centralizar cuando se identifique patrón transversal.


## 14. Estrategia de Refactor

- Cambios mayores: commits segmentados (infra → lógica → tests → docs).
- Deprecaciones: marcar en docstrings y abrir issue interno si retiro no inmediato.


## 15. Checklist de Pre-Commit (Resumen)

- [ ] Sin hardcoding legal.
- [ ] Sin N+1 evidente.
- [ ] Tests nuevos incluidos y pasando.
- [ ] Cobertura ≥ 90% mantenida/mejorada en área afectada.
- [ ] Security/ACL revisado.
- [ ] i18n aplicado.
- [ ] Documentación actualizada.
- [ ] Convención de commits respetada.

