# ⚡ QUICK START - Odoo 19 CE Chile (5 minutos)

**Objetivo:** Tener el stack corriendo en tu máquina en menos de 5 minutos.

---

## ✅ Prerrequisitos

```bash
docker --version        # Docker 24+
docker-compose --version # 2.20+
```

---

## 🚀 Pasos

### 1. Verificar Configuración

```bash
cd /Users/pedro/Documents/odoo19

# Verificar que .env existe y tiene API key
cat .env | grep ANTHROPIC_API_KEY
```

### 2. Iniciar Stack

```bash
# Iniciar todos los servicios (7 contenedores)
docker-compose up -d

# Esperar ~30 segundos para que inicien
```

### 3. Verificar Estado

```bash
# Todos deben estar "Up" y "healthy"
docker-compose ps

# Deberías ver:
# ✅ odoo19_db (PostgreSQL)
# ✅ odoo19_redis
# ✅ odoo19_rabbitmq
# ✅ odoo19_app (Odoo)
# ✅ odoo19_dte_service
# ✅ odoo19_ai_service
```

### 4. Acceder a Odoo

```
URL: http://localhost:8169
Usuario: admin
Password: (configurar en primer acceso)
```

### 5. Instalar Módulo DTE

```
1. Apps → Update Apps List
2. Buscar: "Chilean" o "DTE"
3. Click Install en "Chilean Localization - Electronic Invoicing (DTE)"
4. Esperar instalación (~2 minutos)
```

### 6. Configurar DTE

```
Settings → Accounting → Chilean Electronic Invoicing

Configurar:
- DTE Service URL: http://dte-service:8001
- AI Service URL: http://ai-service:8002
- Ambiente SII: Sandbox (Maullin)
- Test Connections (ambos deben pasar ✅)
```

---

## 🎯 ¡Listo!

**Servicios disponibles:**
- Odoo: http://localhost:8169
- DTE Service API: http://localhost:8001/docs (solo red interna)
- AI Service API: http://localhost:8002/docs (solo red interna)
- RabbitMQ Management: http://localhost:15772 (admin/RabbitMQ_Odoo19_Secure_2025)

**Próximos pasos:**
1. Lee `TEAM_ONBOARDING.md` para entender el proyecto
2. Lee `README.md` para documentación completa
3. Explora `/addons/localization/l10n_cl_dte/`

---

## 🐛 Problemas Comunes

### Servicios no inician
```bash
docker-compose logs odoo
docker-compose logs dte-service
docker-compose logs ai-service
```

### Rebuild después de cambios
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Ver logs en tiempo real
```bash
docker-compose logs -f odoo
```

---

**¿Dudas?** Lee `TEAM_ONBOARDING.md` o contacta al equipo.
