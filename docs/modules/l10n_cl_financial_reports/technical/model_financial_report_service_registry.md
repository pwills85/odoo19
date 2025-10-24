# Modelo: financial.report.service.registry

**Clase**: `FinancialReportServiceRegistry`  
**Archivo**: `models/service_registry.py`  
**Generado**: 2025-08-11 15:57:28

## Descripción

Universal service registry for dynamic service discovery and registration.

This registry allows any installed module to register KPI providers, widget providers,
export providers, and alert providers that can be consumed by the universal dashboard
engine without duplicating business logic or data.

All registrations are done through method calls and stored in memory during the
Odoo session lifecycle.

## Información Técnica

| Atributo | Valor |
|----------|-------|
| `_name` | `financial.report.service.registry` |
| `_description` | `Financial Report Service Registry` |

## Ejemplos de Uso

### Crear registro
```python
record = self.env['financial.report.service.registry'].create({
    # Campos requeridos aquí
})
```

### Buscar registros
```python
records = self.env['financial.report.service.registry'].search([
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
