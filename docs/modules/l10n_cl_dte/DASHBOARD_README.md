# Dashboard Central de DTEs - Monitoreo SII

## Descripción

Dashboard operacional-regulatorio para monitoreo en tiempo real del estado de los DTEs y compliance con normativa SII.

## Características

### KPIs Operacionales
- DTEs Aceptados/Rechazados (últimos 30 días)
- DTEs Pendientes de envío
- Tasas de aceptación (regulatoria vs operacional)

### KPIs Regulatorios Críticos
- **Folios CAF**: Folios restantes con alerta <10%
- **Certificado Digital**: Días hasta expiración con alerta <30 días
- **DTEs Envejecidos**: Documentos enviados sin respuesta >6h
- **Pendientes Total**: Estados draft/to_send/sending/sent/contingency

### Métricas Financieras
- **Monto Bruto**: Sum(facturas aceptadas)
- **Monto Neto**: Sum(facturas - NC aceptadas)
- **Evolución Diaria**: Gráfico de línea por día del mes

### Alertas Automáticas
- ⚠️ CAF bajo (<10% folios)
- ⚠️ Certificado próximo a expirar (<30 días)
- ⚠️ DTEs envejecidos (>6h sin respuesta SII)

## Acceso

**Menú:** Facturación > Dashboard DTEs

**Permisos:**
- `account.group_account_user`: Visualización (read-only)
- `account.group_account_manager`: Gestión completa (CRUD)

## Vistas Disponibles

1. **Kanban**: Vista principal con KPIs en tarjetas
2. **Tree**: Lista con decoraciones de color
3. **Form**: Detalle completo con Smart Buttons
4. **Graph**: Gráficos de barras y línea

## Drill-Down (Smart Buttons)

- Ver DTEs Aceptados
- Ver DTEs Rechazados
- Ver DTEs Pendientes
- Ver DTEs con Reparos
- Ver DTEs Envejecidos (+6h)
- Ver CAFs Activos
- Ver Certificados Digitales

## Tasas de Aceptación

### Tasa Regulatoria (Métrica Oficial SII)
```
aceptados / (aceptados + rechazados) × 100
```
No incluye pendientes. Métrica de compliance regulatorio.

### Tasa Operacional (Métrica Gestión Interna)
```
aceptados / total_emitidos × 100
```
Incluye pendientes y errores. Métrica de eficiencia operacional.

## Optimizaciones de Performance

- **Query Consolidation**: Single `read_group` por estado DTE
- **Memoization**: Variables locales en compute
- **Objetivo**: <50 queries por dashboard compute

## Multi-Compañía

- Singleton por compañía (1 dashboard = 1 company)
- Aislamiento estricto de datos
- Tests de validación multi-compañía

## Internacionalización

- i18n completo en modelo y vistas
- Soporta: es_CL (español Chile), en_US (inglés)

## Testing

**Test Suite:** `test_dte_dashboard.py` + `test_dte_dashboard_enhanced.py`

**Cobertura:**
- 18 tests base + 13 tests enhanced = 31 tests totales
- KPIs operacionales y regulatorios
- Métricas netas y tasas
- Multi-compañía y drill-down
- Performance y optimización

**Ejecutar tests:**
```bash
pytest addons/localization/l10n_cl_dte/tests/test_dte_dashboard*.py -v
```

## Notas Técnicas

- Compatible con Odoo CE (no dependencia de tag `<dashboard>`)
- Usa `amount_total_signed` para cálculo neto correcto
- Filtro temporal write_date para DTEs envejecidos
- States pendientes: draft, to_send, sending, sent, contingency

## Autor

**EERGYGROUP** - Ing. Pedro Troncoso Willz
Contacto: contacto@eergygroup.cl
Website: https://www.eergygroup.com

## Licencia

LGPL-3 - Compatible con Odoo Community Edition
