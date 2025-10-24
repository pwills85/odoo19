# Modelo: financial.dashboard.service.optimized

**Clase**: `FinancialDashboardServiceOptimized`  
**Archivo**: `models/financial_dashboard_service_optimized.py`  
**Generado**: 2025-08-11 16:02:32

## Descripción

Servicio optimizado de dashboard financiero.
Hereda los mixins de performance y usa caché agresivamente.

## Información Técnica

| Atributo | Valor |
|----------|-------|
| `_name` | `financial.dashboard.service.optimized` |
| `_description` | `Financial Dashboard Service Optimized` |

## Restricciones

### Restricciones Python
- **`_check_missing_indexes`**: Verifica índices faltantes en tablas críticas.
- **`_check_large_tables`**: Identifica tablas grandes que podrían necesitar archivado.

## Ejemplos de Uso

### Crear registro
```python
record = self.env['financial.dashboard.service.optimized'].create({
    # Campos requeridos aquí
})
```

### Buscar registros
```python
records = self.env['financial.dashboard.service.optimized'].search([
    # Dominio de búsqueda
])
```

### Actualizar registro
```python
record.write({
    # Campos a actualizar
})
```

---

*Documentación generada automáticamente por Claude Code hooks*
