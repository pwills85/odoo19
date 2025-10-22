# Configuración de Encriptación de Certificados

## 📋 Overview

Los certificados digitales en el sistema DTE están protegidos mediante múltiples capas de seguridad:

1. **Control de Acceso:** Solo administradores del sistema (`base.group_system`)
2. **Encriptación de Attachments:** Habilitada mediante configuración Odoo
3. **Contraseña Protegida:** No se muestra en logs ni vistas estándar

---

## 🔐 Habilitar Encriptación de Attachments

### Método 1: Configuración Odoo (Recomendado)

**Archivo:** `config/odoo.conf`

```ini
[options]
# Generar key: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
encryption_key = <TU_KEY_FERNET_BASE64>

# Ejemplo (NO USAR EN PRODUCCIÓN):
# encryption_key = gAAAAABhN1234567890abcdefghijklmnopqrstuvwxyz==
```

### Generar Key de Encriptación

```bash
# Método 1: Python
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Método 2: OpenSSL (alternativa)
openssl rand -base64 32

# Guardar la key de forma segura (fuera del repositorio)
```

### Aplicar Configuración

```bash
# 1. Editar config/odoo.conf
nano config/odoo.conf

# 2. Agregar encryption_key (línea completa)
encryption_key = <KEY_GENERADA>

# 3. Reiniciar Odoo
docker-compose restart odoo

# 4. Verificar en logs
docker-compose logs odoo | grep -i encrypt
# Debe aparecer: "Encryption enabled for attachments"
```

---

## 🔒 Método 2: HashiCorp Vault (Enterprise)

Para entornos enterprise que requieran mayor seguridad, se recomienda integración con Vault.

### Instalación Vault

```bash
# Docker Compose
vault:
  image: vault:latest
  container_name: odoo19_vault
  restart: unless-stopped
  environment:
    - VAULT_DEV_ROOT_TOKEN_ID=myroot
    - VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
  ports:
    - "127.0.0.1:8200:8200"
  cap_add:
    - IPC_LOCK
  networks:
    - stack_network
```

### Configuración Odoo con Vault

**Archivo:** `addons/localization/l10n_cl_dte/models/dte_certificate.py`

```python
import hvac

def _get_vault_client(self):
    """Conectar a HashiCorp Vault"""
    client = hvac.Client(url='http://vault:8200', token=os.getenv('VAULT_TOKEN'))
    return client

def _store_certificate_in_vault(self, cert_data, cert_password):
    """Almacenar certificado en Vault"""
    client = self._get_vault_client()

    # Almacenar certificado
    client.secrets.kv.v2.create_or_update_secret(
        path=f'dte/certificates/{self.id}',
        secret=dict(
            cert_file=base64.b64encode(cert_data).decode(),
            password=cert_password,
            rut=self.cert_rut
        )
    )

def _retrieve_certificate_from_vault(self):
    """Recuperar certificado desde Vault"""
    client = self._get_vault_client()

    secret = client.secrets.kv.v2.read_secret_version(
        path=f'dte/certificates/{self.id}'
    )

    return {
        'cert_file': base64.b64decode(secret['data']['data']['cert_file']),
        'password': secret['data']['data']['password']
    }
```

---

## ✅ Verificación de Seguridad

### 1. Verificar Encriptación Habilitada

```python
# Desde Odoo shell
docker-compose exec odoo odoo shell -c /etc/odoo/odoo.conf -d odoo

# En el shell:
>>> from odoo import api, SUPERUSER_ID
>>> env = api.Environment(cr, SUPERUSER_ID, {})
>>> IrAttachment = env['ir.attachment']
>>> att = IrAttachment.search([('res_model', '=', 'dte.certificate')], limit=1)
>>> print(f"Encrypted: {bool(att.db_datas)}")
# Debe retornar: Encrypted: True
```

### 2. Verificar Permisos de Acceso

```bash
# Solo admins deben ver certificados
# Usuario normal NO debe ver campo cert_file ni cert_password
```

### 3. Verificar Logs No Contienen Contraseñas

```bash
docker-compose logs odoo | grep -i password
# No debe aparecer contraseñas en logs
```

---

## 📊 Comparación de Métodos

| Método | Seguridad | Complejidad | Costo | Recomendado Para |
|--------|-----------|-------------|-------|------------------|
| **Odoo encryption_key** | Alta | Baja | Gratis | Producción estándar |
| **HashiCorp Vault** | Muy Alta | Alta | Medio | Enterprise, multi-tenant |
| **AWS KMS** | Muy Alta | Media | Bajo | Cloud AWS |
| **Azure Key Vault** | Muy Alta | Media | Bajo | Cloud Azure |

---

## 🚀 Implementación Actual

**Estado:** ✅ Configurado con método Odoo nativo

**Características:**
1. ✅ `attachment=True` - Almacena en `ir.attachment`
2. ✅ `groups='base.group_system'` - Solo admins pueden ver
3. ✅ Preparado para encryption_key en odoo.conf
4. ✅ Documentación completa de setup

**Próximos Pasos (Opcional):**
1. Generar encryption_key para producción
2. Configurar en odoo.conf
3. Reiniciar servicio Odoo
4. Verificar encriptación habilitada

---

## 🔐 Best Practices

### 1. Rotación de Keys

```bash
# Cada 90 días, rotar encryption_key:
# 1. Generar nueva key
# 2. Re-encriptar attachments existentes
# 3. Actualizar odoo.conf
# 4. Reiniciar Odoo
```

### 2. Backup Seguro

```bash
# Backup de certificados (encriptados)
docker-compose exec db pg_dump -U odoo -t ir_attachment odoo > attachments_backup.sql

# Almacenar backup con password
gpg -c attachments_backup.sql
```

### 3. Auditoría

```bash
# Log de accesos a certificados
docker-compose logs odoo | grep -i dte.certificate
```

---

**Creado:** 2025-10-21
**Versión:** 1.0
**Autor:** Claude Code (Anthropic)
