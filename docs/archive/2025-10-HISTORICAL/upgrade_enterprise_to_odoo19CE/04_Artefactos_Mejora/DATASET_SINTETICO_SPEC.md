# Especificación Dataset Sintético — Performance Testing

**Fecha:** 2025-11-08 | **Versión:** 1.0 | **Autor:** QA + Backend

---

## 1. Propósito

Definir generador de datos financieros sintéticos reproducibles para tests de performance y validación Quantum (drill-down, reportes).

---

## 2. Especificación Datos

### 2.1 Volúmenes Target

| Entidad | Cantidad | Justificación |
|---------|----------|---------------|
| **Compañías** | 2 | Multi-company testing |
| **Períodos contables** | 24 meses | 2 años históricos |
| **Plan de cuentas** | 500 cuentas | Empresa mediana Chile |
| **Partners** | 2,000 | Mix B2B/B2C (70%/30%) |
| **Journals** | 10 | Ventas, Compras, Banco, Caja, Misc |
| **Account Moves** | 12,000 | ~500/mes (1 año) |
| **Account Move Lines** | 50,000 | ~4 líneas/move promedio |
| **Monedas** | 3 | CLP, USD, EUR |

### 2.2 Distribuciones Estadísticas

**Montos transacciones:**
- Media: CLP $500,000
- Std Dev: CLP $300,000
- Distribución: Log-normal (realista, evita negativos)
- Rango: CLP $1,000 - $50,000,000

**Fechas:**
- Inicio: 2023-01-01
- Fin: 2024-12-31
- Distribución: Uniforme con picos fin de mes (+20% días 28-31)

**Partners:**
- Pareto 80/20: 20% partners generan 80% transacciones
- Segmentos: Corporativo (10%), PYME (40%), Retail (50%)

---

## 3. Estructura Datos (Ejemplos)

### 3.1 Account (Plan de Cuentas)

```python
{
    "code": "1105001",
    "name": "Banco Santander CTA CTE 12345678",
    "account_type": "asset_current",
    "currency_id": CLP,
    "parent_id": "1105",  # Bancos
    "level": 3
}
```

### 3.2 Account Move (Factura)

```python
{
    "name": "FV202301001",
    "move_type": "out_invoice",
    "partner_id": random.choice(partners_b2b),
    "date": random_date("2023-01-01", "2023-12-31"),
    "journal_id": journal_ventas,
    "currency_id": CLP,
    "state": "posted",
    "lines": [...]  # Ver 3.3
}
```

### 3.3 Account Move Line (Línea Apunte)

```python
{
    "account_id": "1105001",  # Banco
    "debit": 1190000.0,  # Monto bruto con IVA
    "credit": 0.0,
    "currency_id": CLP,
    "partner_id": partner_abc,
    "name": "Pago Factura FV202301001",
    "date": "2023-01-15"
}
```

---

## 4. Generador (Pseudocódigo Python)

```python
import random
import numpy as np
from datetime import datetime, timedelta
from odoo import api, models

class DatasetGenerator:
    def __init__(self, seed=42, num_moves=12000):
        random.seed(seed)
        np.random.seed(seed)
        self.num_moves = num_moves

    def generate_accounts(self):
        """Genera plan de cuentas jerárquico."""
        accounts = [
            {"code": "1", "name": "ACTIVOS", "level": 1},
            {"code": "11", "name": "Activo Corriente", "level": 2, "parent": "1"},
            {"code": "1105", "name": "Bancos", "level": 3, "parent": "11"},
            # ... 500 cuentas total
        ]
        return accounts

    def generate_partners(self, count=2000):
        """Genera partners con distribución Pareto."""
        partners = []
        for i in range(count):
            segment = "corporate" if i < count * 0.1 else \
                     "sme" if i < count * 0.5 else "retail"
            partners.append({
                "name": f"Partner {i:04d}",
                "vat": f"CL{random.randint(10000000, 99999999)}",
                "segment": segment
            })
        return partners

    def generate_moves(self):
        """Genera account.move con distribución realista."""
        moves = []
        for month in range(24):  # 2 años
            date_start = datetime(2023, 1, 1) + timedelta(days=30 * month)
            num_moves_month = int(np.random.normal(500, 50))  # ~500±50/mes

            for _ in range(num_moves_month):
                move_date = self._random_date_weighted(date_start)
                move = {
                    "name": f"FV{move_date.strftime('%Y%m')}{_:04d}",
                    "date": move_date,
                    "journal_id": random.choice(journals),
                    "lines": self._generate_move_lines()
                }
                moves.append(move)
        return moves

    def _generate_move_lines(self):
        """Genera líneas balanceadas (debit = credit)."""
        amount = np.random.lognormal(mean=13.1, sigma=0.8)  # Media ~500k
        lines = [
            {"account": "4101", "credit": amount, "debit": 0},  # Ingreso
            {"account": "2108", "credit": amount * 0.19, "debit": 0},  # IVA
            {"account": "1105", "debit": amount * 1.19, "credit": 0}  # Banco
        ]
        return lines

    def _random_date_weighted(self, start_date):
        """Fechas con pico fin de mes."""
        day = random.randint(1, 30)
        if day > 27:
            day = random.choice([28, 29, 30, 31] * 3 + list(range(1, 28)))
        return start_date + timedelta(days=day - 1)

# Uso
generator = DatasetGenerator(seed=42)
accounts = generator.generate_accounts()
partners = generator.generate_partners(2000)
moves = generator.generate_moves()

# Insertar en Odoo via ORM
env['account.account'].create(accounts)
env['res.partner'].create(partners)
env['account.move'].create(moves)
```

---

## 5. Validaciones Dataset

| Validación | Método | Threshold |
|------------|--------|-----------|
| **Balance debit = credit** | SQL: SUM(debit) - SUM(credit) | = 0 |
| **Distribución montos** | Histograma | Log-normal μ=13.1, σ=0.8 |
| **Count moves por mes** | SQL GROUP BY month | 450-550/mes |
| **Partners top 20%** | SQL ORDER BY count(*) | ≥ 80% transacciones |
| **Sin duplicados** | SQL DISTINCT name | 100% unique |

---

## 6. Artefactos Generados

```
datasets/
├── synthetic_v1_seed42_50k_lines.sql     # Dump PostgreSQL
├── synthetic_v1_metadata.json            # Stats: counts, distribuciones
├── generate_dataset.py                   # Script generador
└── validate_dataset.py                   # Tests validación
```

---

## 7. Uso en PoCs

- **POC-2 (Drill-Down):** Dataset 10k líneas (20% del total)
- **POC-3 (Performance):** Dataset 50k líneas (100%)
- **POC-4 (Export):** Dataset 1k líneas (subset limpio para golden master)

---

## Aprobaciones

| Rol | Aprobación | Fecha | Firma |
|-----|------------|-------|-------|
| QA Lead | ✅ Spec Dataset | _______ | _______ |
| Backend Sr | ✅ Script Generador | _______ | _______ |

**Versión:** 1.0 | **Contacto:** [qa@empresa.cl](mailto:qa@empresa.cl)
