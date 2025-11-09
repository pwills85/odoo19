# Evidencias

## 1. Comandos ejecutados
- `rg --files` y `ls addons/localization/l10n_cl_financial_reports` para inventario inicial.
- `sed -n / nl -ba` sobre modelos, vistas y datos para capturar líneas citables (ej. `nl -ba addons/.../models/l10n_cl_f29.py`).
- `scripts/validate_l10n_cl_financial_reports.sh` para automatizar verificaciones de imports y consistencia F29.

## 2. Salida de script de validación
```
$ scripts/validate_l10n_cl_financial_reports.sh
[1/3] Revisando sintaxis Python...
[P0] Falta importar el paquete core en models/__init__.py
[P0] Falta importar el paquete services en models/__init__.py

[2/3] Validando campos y métodos críticos de F29...
[P0] Campos faltantes en l10n_cl.f29: compras_exentas, compras_gravadas, compras_total, iva_credito, iva_debito, move_ids, period_string, provision_move_id, ventas_exentas, ventas_gravadas, ventas_total
[P0] Métodos faltantes en l10n_cl.f29: action_check_status, action_replace, action_send_sii, create_monthly_f29
```
La ejecución aborta antes del paso 3 confirmando las brechas FR-001, FR-002, FR-003 y FR-006.

## 3. Referencias de código clave
- `models/__init__.py:5-49` – sin imports de `core`/`services`.
- `views/l10n_cl_f29_views.xml:12-118` vs `models/l10n_cl_f29.py:28-197` – campos/botones inexistentes.
- `data/account_report_f29_cl_data.xml:23-194` – estructura inválida, fórmulas sin tax tags.
- `models/l10n_cl_f22.py:437-478` – dependencia de servicio SII no cargado.
- `controllers/__init__.py:2-7` – controladores omitidos.
- `.github/workflows/quality-gates.yml:35-95` – pipelines apuntan sólo a `l10n_cl_dte`.

## 4. Gaps sin evidencia operativa
- No existen métricas p95/p99 ni logs de performance: no se encontró instrumentación en el código ni en `docs/`.
- No hay resultados de pruebas de integración: la suite `tests/` no puede ejecutarse porque depende de modelos ausentes; se requiere reconstruirla tras cerrar los bloqueantes.

> Nota: la Matriz de Brechas detalla todas las referencias archivo:línea y debe usarse como tabla maestra de seguimiento.
