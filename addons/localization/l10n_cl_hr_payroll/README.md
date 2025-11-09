# Chilean Payroll & HR - Odoo 19 CE

**Version:** 19.0.1.0.0  
**License:** LGPL-3  
**Author:** Eergygroup

---

## Overview

Enterprise-grade Chilean payroll module for Odoo 19 CE, with 100% compliance to Chilean labor regulations (2025).

### Key Features

- **Chilean Payroll Calculations**
  - AFP (10 pension funds, variable commissions)
  - FONASA (7%) / ISAPRE (variable plans)
  - Income tax (7 progressive brackets)
  - Legal bonus (25% profits, 4.75 IMM cap)
  - 2025 Pension Reform (employer contributions)

- **Previred Integration**
  - 105-field export file
  - F30-1 certificate
  - Format validation

- **Severance Pay (Finiquito)**
  - Proportional salary
  - Proportional vacation
  - Years of service indemnity (11-year cap)
  - Prior notice indemnity

- **Microservices Integration**
  - Payroll Service (complex calculations)
  - AI Service (validations, optimization)

- **Complete Audit Trail (Art. 54 CT)**
  - 7-year audit trail
  - Economic indicators snapshot
  - Full traceability

---

## Architecture

### Design Pattern: EXTEND, DON'T DUPLICATE

```text
ODOO 19 CE BASE
├─ hr (employees) ✅ Use
├─ hr_contract ✅ Extend
└─ account ✅ Integrate

THIS MODULE
├─ Masters (AFP, ISAPRE, APV)
├─ Extended hr.contract (Chilean fields)
├─ hr.payslip (new model)
└─ Payroll-Service integration
```

---

## Installation

```bash
# 1. Module is already in correct location
# addons/localization/l10n_cl_hr_payroll/

# 2. Update module list
./odoo-bin -c odoo.conf -d your_db -u all

# 3. Install module
# Go to Apps → Search "Chilean Payroll" → Install
```

### Requirements

- Odoo 19.0 CE
- Python dependencies: `requests`
- Optional: Payroll Microservice (FastAPI)
- Optional: AI Service

---

## Module Structure

```
l10n_cl_hr_payroll/
├── __init__.py
├── __manifest__.py
├── README.md
├── data/                    # Base data (sequences, categories)
├── models/                  # Python models
├── security/                # Access rights & groups
├── tests/                   # Unit tests
└── views/                   # XML views
```

---

## Models

### Master Data
- `hr.afp` - 10 Chilean pension funds
- `hr.isapre` - Health insurance providers
- `hr.apv` - Voluntary pension savings
- `hr.economic.indicators` - UF, UTM, UTA monthly values

### Extended Models
- `hr.contract` - Chilean contract fields (AFP, health, allowances)

### Core Models
- `hr.payslip` - Payroll slips
- `hr.payslip.line` - Payslip lines
- `hr.payslip.run` - Payroll batches
- `hr.payroll.structure` - Payroll structures
- `hr.salary.rule` - Salary rules
- `hr.salary.rule.category` - Rule categories (SOPA 2025)

### Specialized Rules
- `hr.salary.rule.gratificacion` - Legal bonus (Art. 50 CT)
- `hr.salary.rule.asignacion.familiar` - Family allowance (DFL 150)
- `hr.salary.rule.aportes.empleador` - Employer contributions (2025 Reform)

---

## Documentation

For detailed documentation, see:
- `/docs/modules/l10n_cl_hr_payroll/development/` - Development docs
- Module docstrings in Python files
- Inline comments for complex logic

---

## Testing

```bash
# Run module tests
./odoo-bin -c odoo.conf -d test_db --test-enable --stop-after-init -i l10n_cl_hr_payroll
```

---

## Support

- **Website:** <https://www.eergygroup.com>
- **Issues:** Contact development team

---

## License

LGPL-3 - See LICENSE file for details
