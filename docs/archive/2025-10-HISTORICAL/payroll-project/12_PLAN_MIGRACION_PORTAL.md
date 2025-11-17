# 🚀 PLAN DE MIGRACIÓN: Employee Portal a Stack Odoo 19

**Fecha:** 2025-10-22  
**Objetivo:** Migrar microservicio employee-portal de Odoo 11 a Odoo 19 CE

---

## 📊 SITUACIÓN ACTUAL

### **Ubicación Origen**
```
/Users/pedro/Documents/oficina_server1/produccion/prod_odoo-11_eergygroup/
└── microservices/eergy-ai/
    ├── app/
    │   ├── routers/employee_portal.py (920 líneas)
    │   ├── models/odoo_hr.py
    │   ├── services/
    │   └── middleware/
    ├── frontend/ (React)
    ├── tests/ (14 archivos)
    ├── requirements.txt
    └── Dockerfile
```

### **Ubicación Destino**
```
/Users/pedro/Documents/odoo19/
└── employee-portal-service/  ← NUEVO
    ├── app/
    ├── frontend/
    ├── tests/
    ├── docker-compose.yml
    └── README.md
```

---

## 🎯 ESTRATEGIA DE MIGRACIÓN

### **FASE 1: Copiar y Adaptar (1 día)**

#### **Paso 1.1: Copiar Estructura Base**

```bash
# 1. Crear directorio en stack Odoo 19
cd /Users/pedro/Documents/odoo19
mkdir -p employee-portal-service

# 2. Copiar microservicio completo
cp -r /Users/pedro/Documents/oficina_server1/produccion/prod_odoo-11_eergygroup/microservices/eergy-ai/* \
   employee-portal-service/

# 3. Verificar estructura
tree employee-portal-service -L 2
```

**Resultado esperado:**
```
employee-portal-service/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── routers/
│   │   ├── employee_portal.py ✅
│   │   ├── auth.py ✅
│   │   └── __init__.py
│   ├── models/
│   │   └── odoo_hr.py ✅
│   ├── services/
│   │   ├── db_session.py ✅
│   │   ├── auth_service.py ✅
│   │   ├── payroll.py ✅
│   │   └── payslip_pdf_generator.py ✅
│   └── middleware/
├── frontend/
│   ├── src/
│   ├── package.json
│   └── README.md
├── tests/
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

#### **Paso 1.2: Actualizar Configuración de Base de Datos**

**Archivo:** `app/services/db_session.py`

```python
# ANTES (Odoo 11)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://odoo11:password@localhost:5432/odoo11_db"
)

# DESPUÉS (Odoo 19)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://odoo19:password@postgres:5432/odoo19_db"
)

# ✅ Usar variables de entorno
# ✅ Conectar a PostgreSQL del stack Odoo 19
```

**Archivo:** `.env` (nuevo)

```bash
# Database
DATABASE_URL=postgresql://odoo:odoo@postgres:5432/odoo19_db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# JWT
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8069

# Logging
LOG_LEVEL=INFO
```

---

#### **Paso 1.3: Verificar Compatibilidad Esquema**

**Archivo:** `app/models/odoo_hr.py`

```python
# ✅ VERIFICAR que estos modelos existen en Odoo 19

from sqlalchemy import Column, Integer, String, Date, Float, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class HrEmployee(Base):
    __tablename__ = 'hr_employee'
    
    id = Column(Integer, primary_key=True)
    name = Column(String)
    identification_id = Column(String)  # RUT
    job_id = Column(Integer)
    department_id = Column(Integer)
    # ✅ Verificar campos adicionales en Odoo 19

class HrPayslip(Base):
    __tablename__ = 'hr_payslip'
    
    id = Column(Integer, primary_key=True)
    employee_id = Column(Integer)
    date_from = Column(Date)
    date_to = Column(Date)
    name = Column(String)
    state = Column(String)
    # ✅ Agregar campos nuevos de Odoo 19 si existen

class HrPayslipLine(Base):
    __tablename__ = 'hr_payslip_line'
    
    id = Column(Integer, primary_key=True)
    slip_id = Column(Integer)
    code = Column(String)
    name = Column(String)
    amount = Column(Float)
    total = Column(Float)
    # ✅ Verificar estructura en Odoo 19
```

**Acción:** Comparar esquema Odoo 11 vs Odoo 19

```bash
# Conectar a Odoo 19 y verificar esquema
psql -h localhost -U odoo -d odoo19_db

\d hr_employee
\d hr_payslip
\d hr_payslip_line

# Comparar con esquema Odoo 11
# Identificar diferencias
# Actualizar modelos si necesario
```

---

#### **Paso 1.4: Adaptar Adapter Pattern**

**Archivo:** `app/services/payroll.py`

```python
# ANTES: Soporta Legacy + SOPA 2025 (Odoo 11)

class PayrollSystemFactory:
    @staticmethod
    def create_adapter(payslip_id: int, db: Session):
        """
        Detecta automáticamente si es Legacy o SOPA 2025
        """
        # Lógica de detección...

# DESPUÉS: Agregar soporte Odoo 19

class PayrollSystemFactory:
    @staticmethod
    def create_adapter(payslip_id: int, db: Session):
        """
        Detecta automáticamente:
        - Legacy (pre-agosto 2025)
        - SOPA 2025 (agosto 2025+)
        - Odoo 19 (nuevas liquidaciones)
        """
        payslip = db.query(HrPayslip).filter(
            HrPayslip.id == payslip_id
        ).first()
        
        if not payslip:
            raise ValueError(f"Payslip {payslip_id} not found")
        
        # Detectar sistema por fecha o campo específico
        if payslip.date_from < date(2025, 8, 1):
            return LegacyPayrollAdapter(db)
        elif hasattr(payslip, 'sistema_calculo') and payslip.sistema_calculo == 'SOPA2025':
            return SOPA2025Adapter(db)
        else:
            # Nuevas liquidaciones en Odoo 19
            return Odoo19PayrollAdapter(db)  # ✅ NUEVO
```

**Crear nuevo adapter:**

```python
# app/services/payroll_adapters.py

class Odoo19PayrollAdapter(BasePayrollAdapter):
    """
    Adapter para liquidaciones generadas en Odoo 19
    con nuestro módulo l10n_cl_hr_payroll
    """
    
    def calculate_totals(self, payslip_id: int) -> PayrollCalculation:
        """
        Calcula totales desde estructura Odoo 19
        """
        # Obtener líneas
        lines = self.db.query(HrPayslipLine).filter(
            HrPayslipLine.slip_id == payslip_id
        ).all()
        
        # Separar haberes y descuentos
        income_lines = [l for l in lines if l.total > 0]
        deduction_lines = [l for l in lines if l.total < 0]
        
        # Calcular totales
        gross_wage = sum(l.total for l in income_lines)
        total_deductions = abs(sum(l.total for l in deduction_lines))
        net_wage = gross_wage - total_deductions
        
        return PayrollCalculation(
            gross_wage=gross_wage,
            total_deductions=total_deductions,
            net_wage=net_wage,
            income_lines=income_lines,
            deduction_lines=deduction_lines,
            imponible=self._calculate_imponible(lines),
            system_name='Odoo 19'
        )
```

---

### **FASE 2: Integración con Stack Odoo 19 (1 día)**

#### **Paso 2.1: Crear docker-compose.yml**

**Archivo:** `employee-portal-service/docker-compose.yml`

```yaml
version: '3.8'

services:
  employee-portal-backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: employee-portal-backend
    ports:
      - "8001:8000"  # No conflicto con Odoo (8069)
    environment:
      - DATABASE_URL=postgresql://odoo:odoo@postgres:5432/odoo19_db
      - SECRET_KEY=${SECRET_KEY}
      - ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8069
    depends_on:
      - postgres
    networks:
      - odoo19_network
    volumes:
      - ./app:/app/app
      - ./logs:/app/logs
    restart: unless-stopped

  employee-portal-frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: employee-portal-frontend
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8001
    depends_on:
      - employee-portal-backend
    networks:
      - odoo19_network
    restart: unless-stopped

networks:
  odoo19_network:
    external: true  # Usar red del stack Odoo 19

# Nota: PostgreSQL ya existe en stack Odoo 19
```

---

#### **Paso 2.2: Actualizar docker-compose.yml Principal**

**Archivo:** `/Users/pedro/Documents/odoo19/docker-compose.yml`

```yaml
version: '3.8'

services:
  postgres:
    # ... (existente)
    networks:
      - odoo19_network

  odoo:
    # ... (existente)
    networks:
      - odoo19_network

  dte-service:
    # ... (existente)
    networks:
      - odoo19_network

  ai-service:
    # ... (existente)
    networks:
      - odoo19_network

  # ✅ NUEVO: Employee Portal
  employee-portal:
    build:
      context: ./employee-portal-service
      dockerfile: Dockerfile
    container_name: employee-portal
    ports:
      - "8001:8000"
    environment:
      - DATABASE_URL=postgresql://odoo:odoo@postgres:5432/odoo19_db
      - SECRET_KEY=${EMPLOYEE_PORTAL_SECRET_KEY}
    depends_on:
      - postgres
    networks:
      - odoo19_network
    volumes:
      - ./employee-portal-service/app:/app/app
    restart: unless-stopped

  employee-portal-frontend:
    build:
      context: ./employee-portal-service/frontend
      dockerfile: Dockerfile
    container_name: employee-portal-frontend
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8001
    depends_on:
      - employee-portal
    networks:
      - odoo19_network
    restart: unless-stopped

networks:
  odoo19_network:
    driver: bridge
```

---

#### **Paso 2.3: Actualizar Frontend (React)**

**Archivo:** `frontend/src/config.js`

```javascript
// ANTES (Odoo 11)
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// DESPUÉS (Odoo 19)
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8001';

export default {
  apiUrl: API_URL,
  endpoints: {
    login: `${API_URL}/auth/login`,
    me: `${API_URL}/employee/me`,
    payslips: `${API_URL}/employee/payslips`,
    payslipDetail: (id) => `${API_URL}/employee/payslips/${id}`,
    downloadPDF: (id) => `${API_URL}/employee/payslips/${id}/pdf`,
    statistics: `${API_URL}/employee/statistics`,
  }
};
```

---

### **FASE 3: Testing y Validación (1 día)**

#### **Paso 3.1: Tests Unitarios**

```bash
cd employee-portal-service

# Instalar dependencias de testing
pip install -r requirements-test.txt

# Ejecutar tests
pytest tests/ -v --cov=app --cov-report=html

# Verificar coverage
open htmlcov/index.html
```

**Actualizar tests para Odoo 19:**

```python
# tests/test_employee_portal.py

def test_get_payslips_odoo19(client, db_session):
    """
    Test que verifica compatibilidad con Odoo 19
    """
    # Crear datos de prueba en esquema Odoo 19
    employee = create_test_employee(db_session)
    payslip = create_test_payslip_odoo19(db_session, employee.id)
    
    # Autenticar
    token = get_test_token(employee.identification_id)
    
    # Llamar endpoint
    response = client.get(
        "/employee/payslips",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert data[0]['sistema_calculo'] == 'Odoo 19'
```

---

#### **Paso 3.2: Tests de Integración**

```bash
# Levantar stack completo
cd /Users/pedro/Documents/odoo19
docker-compose up -d

# Verificar servicios
docker-compose ps

# Verificar logs
docker-compose logs employee-portal -f

# Test manual de endpoints
curl http://localhost:8001/employee/health
```

---

#### **Paso 3.3: Tests E2E (Frontend)**

```bash
cd employee-portal-service/frontend

# Instalar dependencias
npm install

# Ejecutar tests E2E
npm run test:e2e

# Verificar en navegador
npm start
# Abrir http://localhost:3000
```

**Checklist de validación:**
- [ ] Login funciona
- [ ] Dashboard muestra datos
- [ ] Lista de liquidaciones carga
- [ ] Detalle de liquidación muestra correctamente
- [ ] Descarga PDF funciona
- [ ] Estadísticas se calculan correctamente
- [ ] Datos históricos (Legacy) se ven
- [ ] Datos SOPA 2025 se ven
- [ ] Datos nuevos Odoo 19 se ven

---

### **FASE 4: Migración de Datos (si necesario)**

#### **Paso 4.1: Migrar Usuarios**

```python
# scripts/migrate_portal_users.py

"""
Migrar usuarios del portal de Odoo 11 a Odoo 19
"""

def migrate_portal_users():
    # 1. Extraer usuarios de Odoo 11
    odoo11_users = extract_users_from_odoo11()
    
    # 2. Crear en Odoo 19
    for user in odoo11_users:
        create_portal_user_odoo19(
            rut=user['rut'],
            name=user['name'],
            email=user['email'],
            password_hash=user['password_hash']  # Mantener hash
        )
    
    # 3. Validar
    validate_user_migration()
```

---

#### **Paso 4.2: Migrar Sesiones (opcional)**

```python
# Si queremos mantener sesiones activas

def migrate_active_sessions():
    # 1. Extraer tokens JWT activos
    active_tokens = get_active_jwt_tokens()
    
    # 2. Re-firmar con nueva SECRET_KEY
    for token in active_tokens:
        payload = decode_token(token, old_secret_key)
        new_token = encode_token(payload, new_secret_key)
        store_new_token(new_token)
```

---

## 📋 CHECKLIST COMPLETO

### **Pre-Migración**
- [ ] Backup completo de Odoo 11
- [ ] Backup de microservicio actual
- [ ] Documentar configuración actual
- [ ] Identificar dependencias

### **Migración**
- [ ] Copiar código a stack Odoo 19
- [ ] Actualizar configuración DB
- [ ] Verificar esquema compatible
- [ ] Adaptar Adapter Pattern
- [ ] Actualizar docker-compose
- [ ] Actualizar frontend
- [ ] Configurar variables de entorno

### **Testing**
- [ ] Tests unitarios pasan
- [ ] Tests integración pasan
- [ ] Tests E2E pasan
- [ ] Performance aceptable
- [ ] Seguridad validada

### **Validación**
- [ ] Login funciona
- [ ] Datos históricos visibles
- [ ] Datos SOPA 2025 visibles
- [ ] Datos Odoo 19 visibles
- [ ] PDFs se generan
- [ ] Analytics funcionan

### **Deploy**
- [ ] Levantar en staging
- [ ] Pruebas con usuarios reales
- [ ] Monitoreo configurado
- [ ] Logs funcionando
- [ ] Backup automático

---

## 🚀 COMANDOS DE EJECUCIÓN

### **1. Copiar Microservicio**

```bash
#!/bin/bash
# migrate_portal.sh

# Crear directorio
cd /Users/pedro/Documents/odoo19
mkdir -p employee-portal-service

# Copiar código
cp -r /Users/pedro/Documents/oficina_server1/produccion/prod_odoo-11_eergygroup/microservices/eergy-ai/* \
   employee-portal-service/

# Limpiar archivos innecesarios
cd employee-portal-service
rm -rf __pycache__ .pytest_cache *.pyc

echo "✅ Microservicio copiado"
```

---

### **2. Configurar Entorno**

```bash
#!/bin/bash
# setup_portal.sh

cd employee-portal-service

# Crear .env
cat > .env << EOF
DATABASE_URL=postgresql://odoo:odoo@postgres:5432/odoo19_db
SECRET_KEY=$(openssl rand -hex 32)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8069
LOG_LEVEL=INFO
EOF

# Instalar dependencias
pip install -r requirements.txt

echo "✅ Entorno configurado"
```

---

### **3. Levantar Servicios**

```bash
#!/bin/bash
# start_portal.sh

cd /Users/pedro/Documents/odoo19

# Levantar stack completo
docker-compose up -d

# Verificar servicios
docker-compose ps

# Ver logs
docker-compose logs employee-portal -f
```

---

### **4. Testing**

```bash
#!/bin/bash
# test_portal.sh

cd employee-portal-service

# Tests unitarios
pytest tests/ -v --cov=app

# Tests integración
pytest tests/integration/ -v

# Health check
curl http://localhost:8001/employee/health

echo "✅ Tests completados"
```

---

## 📊 TIEMPO ESTIMADO

| Fase | Duración | Responsable |
|------|----------|-------------|
| **FASE 1: Copiar y Adaptar** | 1 día | Dev Backend |
| **FASE 2: Integración Stack** | 1 día | DevOps |
| **FASE 3: Testing** | 1 día | QA |
| **FASE 4: Migración Datos** | 0.5 día | Dev Backend |
| **TOTAL** | **3.5 días** | Equipo |

---

## ✅ RESULTADO ESPERADO

### **Stack Odoo 19 Completo**

```
/Users/pedro/Documents/odoo19/
├── addons/
│   └── localization/
│       └── l10n_cl_hr_payroll/  ← Módulo nóminas
├── dte-service/  ← Microservicio DTE
├── ai-service/  ← Microservicio IA
├── employee-portal-service/  ← ✅ NUEVO Portal empleados
│   ├── app/
│   ├── frontend/
│   ├── tests/
│   └── docker-compose.yml
├── docker-compose.yml  ← Stack completo
└── README.md
```

### **Servicios Corriendo**

```bash
docker-compose ps

NAME                    STATUS    PORTS
postgres                Up        5432
odoo                    Up        8069
dte-service             Up        8000
ai-service              Up        8002
employee-portal         Up        8001  ← ✅ NUEVO
employee-portal-frontend Up       3000  ← ✅ NUEVO
```

---

## 🎯 BENEFICIOS

1. **Portal Integrado** ✅
   - Mismo stack que Odoo 19
   - Red compartida
   - DB compartida

2. **Performance** ✅
   - SQL Direct mantiene velocidad
   - Sin cambios de arquitectura

3. **Funcionalidades** ✅
   - Todas las features existentes
   - Adapter Pattern funciona
   - Analytics mantienen

4. **Mantenimiento** ✅
   - Un solo stack
   - Deploy unificado
   - Monitoreo centralizado

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ PLAN COMPLETO
