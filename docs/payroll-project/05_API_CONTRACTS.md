# 🔌 CONTRATOS API: Microservicios

**Proyecto:** l10n_cl_hr_payroll  
**Formato:** OpenAPI 3.0

---

## 🎯 PAYROLL-SERVICE API

### **Base URL:** `http://payroll-service:8000`

### **1. Calcular Liquidación**

```yaml
POST /api/payroll/calculate

Request:
{
  "employee": {
    "id": 123,
    "name": "Juan Pérez",
    "rut": "12345678-9",
    "birthday": "1985-05-15"
  },
  "contract": {
    "wage": 1500000,
    "afp_id": "capital",
    "afp_rate": 0.1144,
    "health_system": "isapre",
    "isapre_plan_uf": 2.5,
    "apv_amount_uf": 1.0,
    "apv_type": "direct",
    "colacion": 50000,
    "movilizacion": 40000,
    "family_allowances": {
      "simple": 2,
      "maternal": 0,
      "invalid": 0
    },
    "gratification_type": "legal",
    "weekly_hours": 44,
    "extreme_zone": false
  },
  "period": {
    "date_from": "2025-10-01",
    "date_to": "2025-10-31"
  },
  "indicators": {
    "uf": 38000,
    "utm": 65000,
    "uta": 726000,
    "minimum_wage": 500000
  }
}

Response 200:
{
  "success": true,
  "gross_salary": 1500000,
  "taxable_income": 1500000,
  "afp": {
    "amount": 171600,
    "rate": 0.1144,
    "tope_applied": false
  },
  "health": {
    "amount": 95000,
    "system": "isapre",
    "plan_uf": 2.5,
    "excess": 0
  },
  "tax": {
    "amount": 45320,
    "bracket": 2,
    "rate": 0.08,
    "base_uta": 2.07
  },
  "gratification": {
    "amount": 125000,
    "type": "monthly",
    "tope_applied": false
  },
  "employer_contribution": {
    "amount": 7500,
    "rate": 0.005,
    "reform_2025": true
  },
  "net_salary": 1188080,
  "breakdown": {
    "total_haberes": 1625000,
    "total_descuentos": 311920,
    "liquido_pagar": 1313080
  }
}
```

---

### **2. Generar Previred**

```yaml
POST /api/previred/generate

Request:
{
  "period": "2025-10-01",
  "company_rut": "76123456-7",
  "company_name": "Empresa Demo SpA",
  "payslips": [
    {
      "employee_rut": "12345678-9",
      "employee_name": "Juan Pérez",
      "taxable_income": 1500000,
      "afp_code": "capital",
      "afp_amount": 171600,
      "health_system": "isapre",
      "health_amount": 95000,
      "isapre_code": "consalud",
      "unemployment_amount": 9000,
      "employer_contribution": 7500
    }
  ]
}

Response 200:
{
  "success": true,
  "file_content": "base64_encoded_string...",
  "format": "105_fields_fixed",
  "record_count": 1,
  "validation": {
    "valid": true,
    "errors": [],
    "warnings": []
  }
}
```

---

### **3. Calcular Finiquito**

```yaml
POST /api/settlement/calculate

Request:
{
  "employee": {
    "id": 123,
    "name": "Juan Pérez",
    "rut": "12345678-9"
  },
  "contract": {
    "date_start": "2015-01-15",
    "date_end": "2025-10-31",
    "last_salary": 1500000,
    "gratification_type": "monthly"
  },
  "termination": {
    "reason": "dismissal_no_cause",
    "vacation_days_pending": 10
  }
}

Response 200:
{
  "success": true,
  "proportional_salary": 500000,
  "proportional_vacation": 750000,
  "years_of_service_indemnity": 15000000,  # 10 años (tope 11)
  "notice_indemnity": 1500000,
  "proportional_gratification": 125000,
  "total_settlement": 17875000,
  "breakdown": {
    "years_worked": 10.79,
    "years_compensated": 10,  # Tope 11
    "vacation_days": 10,
    "worked_days_month": 15
  }
}
```

---

## 🤖 AI-SERVICE API (Extensión)

### **Base URL:** `http://ai-service:8000`

### **1. Validar Liquidación**

```yaml
POST /api/payroll/validate

Request:
{
  "payslip_data": {
    "employee_id": 123,
    "gross_salary": 1500000,
    "net_salary": 1188080,
    "afp_amount": 171600,
    "health_amount": 95000,
    "tax_amount": 45320
  },
  "context": {
    "company_id": 1,
    "period": "2025-10",
    "similar_positions": ["Analista", "Desarrollador"]
  }
}

Response 200:
{
  "valid": true,
  "confidence": 0.95,
  "warnings": [
    "Sueldo 15% superior al promedio del cargo",
    "Considerar APV para optimizar impuesto único"
  ],
  "anomalies_detected": [],
  "suggestions": [
    {
      "type": "tax_optimization",
      "description": "APV de 1.5 UF reduciría impuesto en $25,000",
      "savings": 25000
    }
  ]
}
```

---

### **2. Analizar Contrato**

```yaml
POST /api/contract/analyze

Request:
{
  "contract_data": {
    "wage": 1500000,
    "weekly_hours": 50,  # Excede 45h
    "colacion": 200000,  # Excede 5 UTM
    "termination_clause": "Sin indemnización"
  }
}

Response 200:
{
  "compliant": false,
  "issues": [
    {
      "severity": "high",
      "article": "Art. 22 Código del Trabajo",
      "description": "Jornada semanal excede máximo legal de 45 horas",
      "recommendation": "Reducir a 45 horas o pagar horas extras"
    },
    {
      "severity": "medium",
      "article": "Art. 41 Código del Trabajo",
      "description": "Colación excede límite exento (5 UTM = $325,000)",
      "recommendation": "Reducir a $325,000 o tributar exceso"
    },
    {
      "severity": "high",
      "article": "Art. 163 Código del Trabajo",
      "description": "Cláusula de indemnización ilegal",
      "recommendation": "Eliminar cláusula, indemnización es derecho legal"
    }
  ],
  "recommendations": [
    "Revisar contrato con abogado laboral",
    "Ajustar jornada a 44 horas (estándar 2024)",
    "Corregir cláusulas ilegales"
  ]
}
```

---

### **3. Optimizar Tributación**

```yaml
POST /api/payroll/optimize

Request:
{
  "employee_data": {
    "current_salary": 1500000,
    "current_net": 1188080,
    "current_tax": 45320,
    "family_allowances": 2
  },
  "optimization_goals": [
    "maximize_net",
    "minimize_tax"
  ]
}

Response 200:
{
  "current_net": 1188080,
  "optimized_net": 1213080,
  "savings": 25000,
  "suggestions": [
    {
      "type": "apv",
      "description": "APV Directo (Régimen A)",
      "amount_uf": 1.5,
      "amount_clp": 57000,
      "tax_savings": 25000,
      "net_cost": 32000,
      "roi": "78%"
    },
    {
      "type": "health_insurance",
      "description": "Seguro complementario deducible",
      "amount_uf": 0.5,
      "amount_clp": 19000,
      "tax_savings": 8000,
      "net_cost": 11000,
      "roi": "73%"
    }
  ],
  "implementation": {
    "steps": [
      "1. Contratar APV con institución autorizada",
      "2. Informar a empleador para descuento mensual",
      "3. Actualizar contrato de trabajo"
    ],
    "timeline": "1-2 meses"
  }
}
```

---

### **4. Chat Laboral**

```yaml
POST /api/chat/labor_query

Request:
{
  "session_id": "uuid-123",
  "query": "¿Cuántos días de vacaciones me corresponden?",
  "context": {
    "employee_id": 123,
    "years_worked": 3.5
  }
}

Response 200:
{
  "answer": "Según el Art. 67 del Código del Trabajo, te corresponden 15 días hábiles de vacaciones por cada año trabajado. Con 3.5 años de antigüedad, has acumulado aproximadamente 52.5 días hábiles de vacaciones (15 días × 3.5 años).\n\nAdemás, el Art. 68 establece que las vacaciones deben ser continuas, pero pueden fraccionarse de común acuerdo con el empleador.",
  "sources": [
    {
      "article": "Art. 67 Código del Trabajo",
      "text": "Todo trabajador con más de un año de servicio tendrá derecho a un feriado anual de quince días hábiles..."
    },
    {
      "article": "Art. 68 Código del Trabajo",
      "text": "El feriado será de preferencia continuo..."
    }
  ],
  "related_questions": [
    "¿Puedo vender días de vacaciones?",
    "¿Qué pasa con las vacaciones al terminar contrato?",
    "¿Cómo se calculan las vacaciones proporcionales?"
  ]
}
```

---

## 🔐 AUTENTICACIÓN

**Todas las APIs usan Bearer Token:**

```http
Authorization: Bearer {API_KEY}
Content-Type: application/json
```

---

## ⚡ RATE LIMITING

| Endpoint | Límite |
|----------|--------|
| /api/payroll/calculate | 100 req/min |
| /api/previred/generate | 10 req/min |
| /api/settlement/calculate | 50 req/min |
| /api/payroll/validate | 50 req/min |
| /api/chat/labor_query | 30 req/min |

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0
