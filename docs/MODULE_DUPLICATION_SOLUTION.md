# 🔧 SOLUCIÓN: DUPLICACIÓN DE MÓDULOS DTE

**Problema:** Dos módulos `l10n_cl_dte` en ubicaciones diferentes  
**Fecha:** 2025-10-21 23:47 UTC-03:00

---

## 📂 SITUACIÓN ACTUAL

### Módulo 1: `/addons/localization/l10n_cl_dte/`
- **Contenido:** Módulo COMPLETO (8,000+ líneas)
- **Incluye:** CAF, certificados, validaciones, UI, seguridad, tests
- **Estado:** ✅ Funcional y completo

### Módulo 2: `/addons/l10n_cl_dte/`
- **Contenido:** Extensión RabbitMQ (650 líneas)
- **Incluye:** rabbitmq_helper, webhook, account_move_dte (async)
- **Estado:** ✅ Funcional pero duplicado

### Problema
❌ Mismo nombre técnico → Odoo no puede instalar ambos  
❌ Código duplicado en `account_move_dte.py`  
❌ Confusión sobre cuál usar

---

## ✅ SOLUCIÓN RECOMENDADA: MERGE

**Fusionar módulo 2 EN módulo 1**

### Ventajas
- ✅ Un solo módulo completo
- ✅ Sin duplicación
- ✅ Más fácil de mantener
- ✅ Best practice Odoo

### Plan de Acción (2-3 horas)

#### 1. Copiar archivos nuevos
```bash
# RabbitMQ Helper
cp addons/l10n_cl_dte/models/rabbitmq_helper.py \
   addons/localization/l10n_cl_dte/models/

# Webhook
mkdir -p addons/localization/l10n_cl_dte/controllers
cp addons/l10n_cl_dte/controllers/dte_webhook.py \
   addons/localization/l10n_cl_dte/controllers/
```

#### 2. Merge account_move_dte.py
Combinar funcionalidades de ambas versiones

#### 3. Actualizar __manifest__.py
Agregar `'pika'` en external_dependencies

#### 4. Eliminar módulo duplicado
```bash
rm -rf addons/l10n_cl_dte
```

---

## ⚡ ALTERNATIVA RÁPIDA: RENOMBRAR

**Si necesitas solución inmediata (30 min)**

```bash
# Renombrar módulo
mv addons/l10n_cl_dte addons/l10n_cl_dte_async

# Cambiar nombre en __manifest__.py
# 'name': 'l10n_cl_dte_async'
# 'depends': [..., 'l10n_cl_dte']
```

**Resultado:** Dos módulos separados, sin conflicto

---

## 🎯 RECOMENDACIÓN

**MERGE** es la mejor opción a largo plazo.  
**RENOMBRAR** si necesitas solución rápida ahora.

¿Cuál prefieres que implemente?
