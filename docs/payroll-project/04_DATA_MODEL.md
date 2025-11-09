# 🗄️ MODELO DE DATOS: Sistema Nóminas

**Proyecto:** l10n_cl_hr_payroll  
**Base de Datos:** PostgreSQL 15+

---

## 📊 ENTIDADES PRINCIPALES

### **MAESTROS**

#### hr_afp (10 registros)
```sql
CREATE TABLE hr_afp (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    rate NUMERIC(5,4) NOT NULL,  -- 0.1049 a 0.1154
    sis_rate NUMERIC(5,4),
    independent_rate NUMERIC(5,4),
    active BOOLEAN DEFAULT TRUE,
    create_date TIMESTAMP DEFAULT NOW(),
    write_date TIMESTAMP DEFAULT NOW(),
    create_uid INTEGER REFERENCES res_users,
    write_uid INTEGER REFERENCES res_users
);

-- Datos iniciales (Odoo 11 pattern)
INSERT INTO hr_afp (name, code, rate, sis_rate) VALUES
('AFP Capital', 'capital', 0.1144, 0.0157),
('AFP Cuprum', 'cuprum', 0.1144, 0.0157),
('AFP Habitat', 'habitat', 0.1127, 0.0157),
('AFP Modelo', 'modelo', 0.1077, 0.0157),
('AFP PlanVital', 'planvital', 0.1116, 0.0157),
('AFP Provida', 'provida', 0.1154, 0.0157),
('AFP Uno', 'uno', 0.1049, 0.0157);
```

#### hr_isapre (15 registros)
```sql
CREATE TABLE hr_isapre (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    active BOOLEAN DEFAULT TRUE
);
```

#### hr_economic_indicators (84 registros - 2018-2025)
```sql
CREATE TABLE hr_economic_indicators (
    id SERIAL PRIMARY KEY,
    period DATE UNIQUE NOT NULL,  -- Primer día del mes
    uf NUMERIC(10,2) NOT NULL,
    utm NUMERIC(10,2) NOT NULL,
    uta NUMERIC(10,2) NOT NULL,
    minimum_wage NUMERIC(10,2) NOT NULL,
    afp_limit NUMERIC(10,2) NOT NULL,  -- 83.1 UF
    ips_limit NUMERIC(10,2),
    unemployment_limit NUMERIC(10,2),
    family_allowance_t1 NUMERIC(10,2),
    family_allowance_t2 NUMERIC(10,2),
    family_allowance_t3 NUMERIC(10,2),
    maternal_allowance NUMERIC(10,2),
    invalid_allowance NUMERIC(10,2),
    -- ... 20+ campos más
    create_date TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_indicators_period ON hr_economic_indicators(period);
```

---

### **CORE**

#### hr_contract (300 registros)
```sql
-- Extiende tabla Odoo base
ALTER TABLE hr_contract ADD COLUMN IF NOT EXISTS
    afp_id INTEGER REFERENCES hr_afp,
    isapre_id INTEGER REFERENCES hr_isapre,
    isapre_plan_uf NUMERIC(6,4),
    isapre_fun VARCHAR(50),
    health_system VARCHAR(20) DEFAULT 'fonasa',
    is_fonasa BOOLEAN GENERATED ALWAYS AS (health_system = 'fonasa') STORED,
    apv_id INTEGER REFERENCES hr_apv,
    apv_amount_uf NUMERIC(6,4),
    apv_type VARCHAR(20) DEFAULT 'direct',
    colacion NUMERIC(10,2),
    movilizacion NUMERIC(10,2),
    family_allowance_simple INTEGER DEFAULT 0,
    family_allowance_maternal INTEGER DEFAULT 0,
    family_allowance_invalid INTEGER DEFAULT 0,
    gratification_type VARCHAR(20) DEFAULT 'legal',
    cost_center_id INTEGER REFERENCES hr_cost_center,
    weekly_hours INTEGER DEFAULT 44,
    extreme_zone BOOLEAN DEFAULT FALSE;

-- Índices (Odoo 11 pattern)
CREATE INDEX idx_contract_employee ON hr_contract(employee_id);
CREATE INDEX idx_contract_afp ON hr_contract(afp_id);
CREATE INDEX idx_contract_isapre ON hr_contract(isapre_id);

-- Constraint
ALTER TABLE hr_contract ADD CONSTRAINT chk_weekly_hours 
    CHECK (weekly_hours BETWEEN 1 AND 45);
```

#### hr_payslip (50,000 registros)
```sql
CREATE TABLE hr_payslip (
    id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES hr_employee NOT NULL,
    contract_id INTEGER REFERENCES hr_contract NOT NULL,
    date_from DATE NOT NULL,
    date_to DATE NOT NULL,
    name VARCHAR(200),
    number VARCHAR(50),
    state VARCHAR(20) DEFAULT 'draft',
    
    -- Indicadores (Odoo 11 pattern)
    indicator_id INTEGER REFERENCES hr_economic_indicators,
    indicators_snapshot TEXT,  -- JSON
    
    -- Previred
    previred_sent BOOLEAN DEFAULT FALSE,
    previred_date DATE,
    previred_file BYTEA,
    
    -- Movimientos personal
    movement_code VARCHAR(2) DEFAULT '0',
    movement_date_start DATE,
    movement_date_end DATE,
    
    -- IA
    ai_validated BOOLEAN DEFAULT FALSE,
    ai_warnings TEXT,
    
    -- Audit
    create_date TIMESTAMP DEFAULT NOW(),
    write_date TIMESTAMP DEFAULT NOW(),
    create_uid INTEGER REFERENCES res_users,
    write_uid INTEGER REFERENCES res_users,
    
    -- Constraint unicidad (Odoo 11 pattern)
    CONSTRAINT unique_payslip UNIQUE(employee_id, date_from)
);

-- Índices críticos (Odoo 11 pattern)
CREATE INDEX idx_payslip_employee_date ON hr_payslip(employee_id, date_from);
CREATE INDEX idx_payslip_state ON hr_payslip(state);
CREATE INDEX idx_payslip_indicator ON hr_payslip(indicator_id);
CREATE INDEX idx_payslip_previred ON hr_payslip(previred_sent, previred_date);
```

#### hr_payslip_line (500,000 registros)
```sql
CREATE TABLE hr_payslip_line (
    id SERIAL PRIMARY KEY,
    payslip_id INTEGER REFERENCES hr_payslip NOT NULL,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    category_code VARCHAR(50),
    sequence INTEGER DEFAULT 10,
    quantity NUMERIC(10,2) DEFAULT 1,
    rate NUMERIC(10,2) DEFAULT 100,
    amount NUMERIC(12,2) NOT NULL,
    total NUMERIC(12,2) NOT NULL,
    create_date TIMESTAMP DEFAULT NOW()
);

-- Índices performance
CREATE INDEX idx_payslip_line_payslip ON hr_payslip_line(payslip_id);
CREATE INDEX idx_payslip_line_code ON hr_payslip_line(code);
CREATE INDEX idx_payslip_line_category ON hr_payslip_line(category_code);
```

#### hr_settlement (finiquitos)
```sql
CREATE TABLE hr_settlement (
    id SERIAL PRIMARY KEY,
    employee_id INTEGER REFERENCES hr_employee NOT NULL,
    contract_id INTEGER REFERENCES hr_contract NOT NULL,
    date_start DATE NOT NULL,
    date_end DATE NOT NULL,
    termination_reason VARCHAR(50) NOT NULL,
    
    -- Componentes
    proportional_salary NUMERIC(12,2),
    proportional_vacation NUMERIC(12,2),
    years_of_service_indemnity NUMERIC(12,2),
    notice_indemnity NUMERIC(12,2),
    proportional_gratification NUMERIC(12,2),
    total_settlement NUMERIC(12,2),
    
    state VARCHAR(20) DEFAULT 'draft',
    create_date TIMESTAMP DEFAULT NOW(),
    write_date TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_settlement_employee ON hr_settlement(employee_id);
CREATE INDEX idx_settlement_date ON hr_settlement(date_end);
```

---

### **AUDIT TRAIL (Odoo 11 pattern)**

#### hr_payroll_audit (50,000 registros)
```sql
CREATE TABLE hr_payroll_audit (
    id SERIAL PRIMARY KEY,
    payslip_id INTEGER REFERENCES hr_payslip,
    action_type VARCHAR(50) NOT NULL,
    user_id INTEGER REFERENCES res_users NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    old_values_json TEXT,
    new_values_json TEXT,
    ip_address VARCHAR(45)
);

-- Índices audit
CREATE INDEX idx_audit_payslip ON hr_payroll_audit(payslip_id);
CREATE INDEX idx_audit_timestamp ON hr_payroll_audit(timestamp);
CREATE INDEX idx_audit_user ON hr_payroll_audit(user_id);

-- Retención 7 años (Art. 54 CT)
-- Implementar con particionado por año
```

---

## 📊 VOLÚMENES ESTIMADOS

| Tabla | Registros | Crecimiento Anual |
|-------|-----------|-------------------|
| hr_afp | 10 | Estable |
| hr_isapre | 15 | Estable |
| hr_economic_indicators | 84 | +12/año |
| hr_contract | 300 | +50/año |
| hr_payslip | 50,000 | +18,000/año |
| hr_payslip_line | 500,000 | +180,000/año |
| hr_settlement | 200 | +30/año |
| hr_payroll_audit | 50,000 | +18,000/año |

**Total:** ~600,000 registros iniciales

---

## 🔍 QUERIES CRÍTICOS

### **1. Liquidación del mes**
```sql
SELECT p.*, e.name as employee_name
FROM hr_payslip p
JOIN hr_employee e ON p.employee_id = e.id
WHERE p.date_from >= '2025-10-01'
  AND p.date_from < '2025-11-01'
  AND p.state = 'done'
ORDER BY e.name;
```

### **2. Previred del período**
```sql
SELECT p.*, c.*, e.*
FROM hr_payslip p
JOIN hr_contract c ON p.contract_id = c.id
JOIN hr_employee e ON p.employee_id = e.id
WHERE p.date_from = '2025-10-01'
  AND p.state = 'done'
ORDER BY e.identification_id;  -- RUT
```

### **3. Audit trail empleado**
```sql
SELECT a.*, u.name as user_name
FROM hr_payroll_audit a
JOIN res_users u ON a.user_id = u.id
JOIN hr_payslip p ON a.payslip_id = p.id
WHERE p.employee_id = 123
  AND a.timestamp >= NOW() - INTERVAL '7 years'
ORDER BY a.timestamp DESC;
```

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0
