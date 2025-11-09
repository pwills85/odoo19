# 🔓 DESBLOQUEO ODOO 12 ENTERPRISE - INICIO RÁPIDO

## 🎯 Resumen del Problema

Tu instancia de Odoo 12 Enterprise está **bloqueada** porque:
- ❌ La base de datos tiene fecha de expiración de 2019
- ❌ Se perdió el código de subscripción (`database.enterprise_code`)
- ❌ La interfaz web muestra bloqueo completo

## ✅ Soluciones Disponibles

### 🚀 **MÉTODO RÁPIDO (2 MINUTOS) - RECOMENDADO**

#### Opción A: Script Bash (Más Simple)

```bash
cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12

# 1. Editar configuración
nano desbloquear_odoo12_enterprise.sh
# Cambiar: DB_NAME y DB_PASSWORD

# 2. Ejecutar
./desbloquear_odoo12_enterprise.sh

# 3. Cerrar navegador y volver a entrar
```

#### Opción B: Script Python (Más Robusto)

```bash
cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12

# 1. Instalar dependencia
pip3 install psycopg2-binary

# 2. Editar configuración
nano desbloquear_odoo12_enterprise.py
# Cambiar: DB_CONFIG

# 3. Ejecutar
python3 desbloquear_odoo12_enterprise.py

# 4. Cerrar navegador y volver a entrar
```

#### Opción C: SQL Manual (Más Control)

```bash
# 1. Conectar a PostgreSQL
psql -U odoo -d nombre_base_datos

# 2. Ejecutar SQL
UPDATE ir_config_parameter 
SET value = '2035-12-31'
WHERE key = 'database.expiration_date';

UPDATE ir_config_parameter 
SET value = 'demo'
WHERE key = 'database.expiration_reason';

DELETE FROM ir_sessions;

# 3. Salir
\q

# 4. Cerrar navegador y volver a entrar
```

---

## 📚 Documentación Completa

Para métodos avanzados (modificar código JavaScript/Python), ver:

- **Guía Completa:** [`GUIA_DESBLOQUEO_ODOO12_ENTERPRISE.md`](./GUIA_DESBLOQUEO_ODOO12_ENTERPRISE.md)
  - 5 métodos diferentes explicados
  - Ventajas y desventajas de cada uno
  - Código fuente comentado
  - Troubleshooting

- **Análisis Técnico:** [`ANALISIS_PROFUNDO_MECANISMO_EXPIRACION_ODOO12_ENTERPRISE.md`](./ANALISIS_PROFUNDO_MECANISMO_EXPIRACION_ODOO12_ENTERPRISE.md)
  - Cómo funciona el sistema de licencias
  - Archivos involucrados
  - Flujo de verificación

---

## ⚠️ IMPORTANTE

### Después del Desbloqueo

1. **Cerrar navegador COMPLETAMENTE** (no solo la pestaña)
2. Volver a abrir el navegador
3. Ingresar a Odoo normalmente
4. ✅ La interfaz ya NO estará bloqueada

### Consideraciones Legales

- ⚠️ Este desbloqueo es para **recuperación de emergencia** de datos
- ⚠️ Odoo Enterprise requiere licencia válida para uso productivo
- ⚠️ Uso prolongado sin licencia puede violar términos de servicio

### Soluciones Permanentes

1. **Comprar nueva subscripción:**
   - https://www.odoo.com/pricing
   - Contactar soporte: support@odoo.com

2. **Migrar a Community Edition:**
   - Versión gratuita de Odoo
   - Pierdes algunas funcionalidades Enterprise

3. **Migrar a Odoo 18:**
   - Ya tienes proyecto Odoo 18 en este workspace
   - Considera migrar tus datos

---

## 🆘 Soporte

### Si algo sale mal:

```bash
# Ver logs de Odoo
tail -f /var/log/odoo/odoo-server.log

# Verificar PostgreSQL
psql -U odoo -d nombre_base_datos -c "SELECT value FROM ir_config_parameter WHERE key = 'database.expiration_date';"

# Verificar sesiones
psql -U odoo -d nombre_base_datos -c "SELECT COUNT(*) FROM ir_sessions;"
```

### Scripts Incluidos en este Directorio:

- ✅ `desbloquear_odoo12_enterprise.sh` - Script Bash (más simple)
- ✅ `desbloquear_odoo12_enterprise.py` - Script Python (más robusto)

### Documentación:

- 📖 [`GUIA_DESBLOQUEO_ODOO12_ENTERPRISE.md`](./GUIA_DESBLOQUEO_ODOO12_ENTERPRISE.md)
- 📖 [`ANALISIS_PROFUNDO_MECANISMO_EXPIRACION_ODOO12_ENTERPRISE.md`](./ANALISIS_PROFUNDO_MECANISMO_EXPIRACION_ODOO12_ENTERPRISE.md)

---

## 📊 Comparación Rápida

| Método | Tiempo | Dificultad | Requiere Código | Persistente |
|--------|--------|------------|-----------------|-------------|
| Script Bash | 2 min | ⭐ Fácil | ❌ No | ✅ Sí |
| Script Python | 3 min | ⭐ Fácil | ❌ No | ✅ Sí |
| SQL Manual | 2 min | ⭐⭐ Media | ❌ No | ✅ Sí |
| Modificar JS | 5 min | ⭐⭐ Media | ✅ Sí | ✅ Sí |
| Modificar Python | 10 min | ⭐⭐⭐ Avanzada | ✅ Sí | ✅ Sí |

---

**Fecha:** 4 de octubre de 2025  
**Versión:** 1.0  
**Autor:** Análisis Técnico Odoo 12
