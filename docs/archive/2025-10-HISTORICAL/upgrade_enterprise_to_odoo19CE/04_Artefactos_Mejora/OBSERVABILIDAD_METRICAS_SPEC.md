# Especificación Observabilidad y Métricas — Quantum Engine

**Fecha:** 2025-11-08 | **Versión:** 1.0 | **Autor:** DevOps + Backend

---

## 1. Propósito

Definir modelo de métricas, instrumentación y export para monitoreo operacional del motor reportes Quantum.

---

## 2. Modelo Métrica (Conceptual)

```python
# models/quantum_metric.py (NO usar código Enterprise)
from odoo import models, fields

class QuantumMetric(models.Model):
    _name = 'quantum.metric'
    _description = 'Métrica Operacional Reportes'

    name = fields.Char(required=True)  # ej. "report.render.time"
    value = fields.Float(required=True)
    unit = fields.Selection([
        ('ms', 'Milisegundos'),
        ('count', 'Conteo'),
        ('bytes', 'Bytes')
    ])
    timestamp = fields.Datetime(default=fields.Datetime.now, index=True)
    report_id = fields.Many2one('account.report', index=True)
    user_id = fields.Many2one('res.users', index=True)
    dimension_json = fields.Json()  # Contexto: {level, account_id, ...}
```

---

## 3. Métricas Clave (Catálogo)

### 3.1 Performance

| Métrica | Tipo | Descripción | SLA Target |
|---------|------|-------------|------------|
| `report.render.time_ms` | Histogram | Tiempo generación reporte | p95 < 3000ms |
| `drill.level[1-7].time_ms` | Histogram | Latencia por nivel drill-down | p95 < 1000ms |
| `export.pdf.time_ms` | Histogram | Tiempo export PDF | p95 < 8000ms |
| `export.xlsx.time_ms` | Histogram | Tiempo export XLSX | p95 < 5000ms |

### 3.2 Volumetría

| Métrica | Tipo | Descripción |
|---------|------|-------------|
| `report.lines.count` | Gauge | Líneas en reporte |
| `cache.hit.count` | Counter | Cache hits |
| `cache.miss.count` | Counter | Cache misses |
| `db.queries.count` | Counter | Queries SQL ejecutadas |

### 3.3 Errores

| Métrica | Tipo | Descripción |
|---------|------|-------------|
| `report.error.count` | Counter | Errores generación |
| `export.error.count` | Counter | Errores export |
| `validation.failed.count` | Counter | Validaciones fallidas (balance != 0) |

---

## 4. Agregaciones (Ventanas Tiempo)

| Ventana | Agregaciones | Retención |
|---------|-------------|-----------|
| **5 minutos** | p50, p95, max, count | 24 horas |
| **1 hora** | p50, p95, max, count | 7 días |
| **1 día** | p50, p95, max, count | 90 días |

**Storage:** PostgreSQL (tabla `quantum_metric` particionada por mes) + Redis cache 1h

---

## 5. Export Prometheus

### 5.1 Endpoint

**URL:** `/quantum/metrics` (protegido: IP whitelist interna)

**Formato:** Prometheus text format

**Ejemplo:**

```
# HELP report_render_time_ms Tiempo generación reportes en ms
# TYPE report_render_time_ms histogram
report_render_time_ms_bucket{report="ledger",le="1000"} 42
report_render_time_ms_bucket{report="ledger",le="3000"} 89
report_render_time_ms_bucket{report="ledger",le="+Inf"} 100
report_render_time_ms_sum{report="ledger"} 185000
report_render_time_ms_count{report="ledger"} 100

# HELP drill_latency_ms Latencia drill-down por nivel
# TYPE drill_latency_ms histogram
drill_latency_ms{level="1"} 450
drill_latency_ms{level="7"} 1200

# HELP cache_hit_rate Tasa acierto cache
# TYPE cache_hit_rate gauge
cache_hit_rate 0.85
```

### 5.2 Instrumentación (Ejemplo)

```python
# addons/financial_reports_dynamic/models/account_report.py
import time
from odoo import models

class AccountReport(models.Model):
    _inherit = 'account.report'

    def generate_report(self, options):
        start = time.time()
        try:
            result = super().generate_report(options)
            latency_ms = (time.time() - start) * 1000

            # Registrar métrica
            self.env['quantum.metric'].create({
                'name': 'report.render.time_ms',
                'value': latency_ms,
                'unit': 'ms',
                'report_id': self.id,
                'dimension_json': {'options': options}
            })

            return result
        except Exception as e:
            self.env['quantum.metric'].create({
                'name': 'report.error.count',
                'value': 1,
                'unit': 'count'
            })
            raise
```

---

## 6. Dashboards Grafana

### 6.1 Dashboard "Quantum Performance"

**Paneles:**

1. **Latencia p95 Reportes (24h)**
   - Query: `histogram_quantile(0.95, rate(report_render_time_ms_bucket[5m]))`
   - Alert: p95 > 5000ms → Slack #alerts

2. **Throughput Reportes**
   - Query: `rate(report_render_time_ms_count[5m])`
   - Unidad: reports/min

3. **Cache Hit Rate**
   - Query: `cache_hit_count / (cache_hit_count + cache_miss_count)`
   - Target: ≥ 0.80

4. **Errores por Hora**
   - Query: `sum(rate(report_error_count[1h]))`
   - Alert: > 10 errores/h

---

## 7. Alertas (Ejemplo)

```yaml
# prometheus/alerts/quantum.yml
groups:
  - name: quantum_performance
    interval: 1m
    rules:
      - alert: ReportLatencyHigh
        expr: histogram_quantile(0.95, rate(report_render_time_ms_bucket[5m])) > 5000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Latencia reportes p95 > 5s"
          description: "p95 = {{ $value }}ms en últimos 10min"

      - alert: CacheHitRateLow
        expr: cache_hit_count / (cache_hit_count + cache_miss_count) < 0.70
        for: 15m
        labels:
          severity: info
        annotations:
          summary: "Cache hit rate < 70%"
          description: "Revisar TTL y keys invalidación"
```

---

## 8. Implementación Roadmap

| Fase | Entregable | Duración | Responsable |
|------|------------|----------|-------------|
| **Fase 1** | Modelo `quantum.metric` + instrumentación básica (render_time) | 1 semana | Backend Sr |
| **Fase 2** | Export Prometheus + dashboard Grafana básico | 1 semana | DevOps |
| **Fase 3** | Alertas + instrumentación completa (drill, export, cache) | 1 semana | DevOps + Backend |

**Total:** 3 semanas, 40h × $85/h = $3,400 (incluido en baseline)

---

## 9. Aprobaciones

| Rol | Aprobación | Fecha | Firma |
|-----|------------|-------|-------|
| DevOps Lead | ✅ Spec Observabilidad | _______ | _______ |
| Backend Sr | ✅ Instrumentación | _______ | _______ |

**Versión:** 1.0 | **Contacto:** [devops@empresa.cl](mailto:devops@empresa.cl)
