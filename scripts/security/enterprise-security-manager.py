#!/usr/bin/env python3
"""
Sistema de Seguridad Enterprise para Copilot CLI
Control de acceso granular, auditoría y políticas de seguridad
"""

import os
import sys
import json
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import sqlite3
import logging
from pathlib import Path
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnterpriseSecurityManager:
    """Gestor de seguridad enterprise para Copilot CLI"""

    def __init__(self, security_db_path: str = None):
        self.security_db_path = security_db_path or "/Users/pedro/.copilot/security.db"
        self.audit_log_path = "/Users/pedro/.copilot/audit.log"
        self.policies_file = "/Users/pedro/Documents/odoo19/config/security-policies.json"

        # Inicializar base de datos de seguridad
        self._initialize_security_database()

        # Cargar políticas de seguridad
        self.security_policies = self._load_security_policies()

        # Generar/cargar clave de encriptación para datos sensibles
        self.encryption_key = self._get_or_create_encryption_key()

    def _initialize_security_database(self):
        """Inicializar base de datos de seguridad"""
        try:
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            # Tabla de usuarios/autenticación
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    permissions TEXT NOT NULL, -- JSON array
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            ''')

            # Tabla de sesiones activas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Tabla de log de auditoría
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    username TEXT,
                    session_id TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    parameters TEXT, -- JSON
                    result TEXT,
                    ip_address TEXT,
                    risk_level TEXT DEFAULT 'low',
                    anomaly_score REAL DEFAULT 0.0
                )
            ''')

            # Tabla de políticas de seguridad activas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id TEXT UNIQUE NOT NULL,
                    policy_type TEXT NOT NULL,
                    policy_data TEXT NOT NULL, -- JSON
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')

            # Tabla de detección de anomalías
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT NOT NULL,
                    pattern_data TEXT NOT NULL, -- JSON
                    severity TEXT DEFAULT 'medium',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_triggered TIMESTAMP,
                    trigger_count INTEGER DEFAULT 0
                )
            ''')

            # Índices para mejor rendimiento
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_username ON active_sessions(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_policies_type ON active_policies(policy_type)')

            conn.commit()
            conn.close()

            logger.info(f"Base de datos de seguridad inicializada: {self.security_db_path}")

        except Exception as e:
            logger.error(f"Error inicializando base de datos de seguridad: {e}")
            raise

    def _load_security_policies(self) -> Dict[str, Any]:
        """Cargar políticas de seguridad desde archivo"""
        default_policies = {
            "authentication": {
                "max_failed_attempts": 5,
                "lockout_duration_minutes": 15,
                "session_timeout_hours": 8,
                "password_min_length": 12,
                "require_mfa": False
            },
            "authorization": {
                "roles": {
                    "admin": ["*"],
                    "developer": [
                        "read:*", "write:code", "execute:safe_commands",
                        "use:agents", "access:memory", "run:tests"
                    ],
                    "reviewer": [
                        "read:*", "use:agents:dte-specialist",
                        "use:agents:security-auditor", "run:tests"
                    ],
                    "auditor": [
                        "read:*", "use:agents:security-auditor",
                        "access:audit_logs", "view:metrics"
                    ]
                },
                "resource_permissions": {
                    "filesystem": ["read", "write", "execute"],
                    "memory": ["read", "write"],
                    "github": ["read", "write"],
                    "database": ["read"],
                    "network": ["http_get", "http_post"]
                }
            },
            "audit": {
                "log_all_actions": True,
                "sensitive_actions": [
                    "execute_command", "access_database", "modify_security_policies",
                    "view_sensitive_data", "export_data"
                ],
                "anomaly_detection": True,
                "retention_days": 90
            },
            "content_filtering": {
                "blocked_commands": [
                    "rm -rf /", "sudo", "chmod 777", "curl.*--exec",
                    "wget.*\\|.*bash", "ssh.*-o.*ProxyCommand"
                ],
                "blocked_files": [
                    "*.pem", "*.key", "*secret*", "*password*",
                    ".env", ".git/config"
                ],
                "sensitive_patterns": [
                    "password.*=", "secret.*=", "key.*=", "token.*=",
                    "Bearer\\s+[A-Za-z0-9+/=]{20,}"
                ]
            },
            "rate_limiting": {
                "requests_per_minute": 60,
                "burst_limit": 10,
                "cooldown_minutes": 5
            },
            "data_protection": {
                "encrypt_sensitive_data": True,
                "mask_sensitive_output": True,
                "audit_data_access": True,
                "prevent_data_exfiltration": True
            }
        }

        try:
            if os.path.exists(self.policies_file):
                with open(self.policies_file, 'r') as f:
                    custom_policies = json.load(f)
                    # Fusionar políticas por defecto con personalizadas
                    self._merge_policies(default_policies, custom_policies)
        except Exception as e:
            logger.warning(f"Error cargando políticas personalizadas: {e}")

        return default_policies

    def _merge_policies(self, base: Dict[str, Any], custom: Dict[str, Any]):
        """Fusionar políticas recursivamente"""
        for key, value in custom.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_policies(base[key], value)
            else:
                base[key] = value

    def _get_or_create_encryption_key(self) -> bytes:
        """Obtener o crear clave de encriptación"""
        key_file = "/Users/pedro/.copilot/encryption.key"

        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generar nueva clave
            key = secrets.token_bytes(32)
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            # Establecer permisos restrictivos
            os.chmod(key_file, 0o600)
            return key

    def authenticate_user(self, username: str, password: str,
                         ip_address: str = None, user_agent: str = None) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Autenticar usuario y crear sesión"""
        try:
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            # Verificar si usuario existe y está activo
            cursor.execute('''
                SELECT id, hashed_password, role, permissions, failed_attempts, locked_until, is_active
                FROM users WHERE username = ?
            ''', (username,))

            user_data = cursor.fetchone()
            if not user_data:
                self._log_audit(None, "authentication_failed", "user_login",
                               {"reason": "user_not_found", "username": username}, ip_address)
                return False, "Usuario no encontrado", None

            user_id, hashed_password, role, permissions_str, failed_attempts, locked_until, is_active = user_data

            if not is_active:
                self._log_audit(username, "authentication_failed", "user_login",
                               {"reason": "user_inactive"}, ip_address)
                return False, "Usuario inactivo", None

            # Verificar si cuenta está bloqueada
            if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
                self._log_audit(username, "authentication_failed", "user_login",
                               {"reason": "account_locked", "locked_until": locked_until}, ip_address)
                return False, f"Cuenta bloqueada hasta {locked_until}", None

            # Verificar contraseña
            if not self._verify_password(password, hashed_password):
                # Incrementar contador de intentos fallidos
                new_failed_attempts = failed_attempts + 1
                lock_until = None

                if new_failed_attempts >= self.security_policies["authentication"]["max_failed_attempts"]:
                    lock_duration = self.security_policies["authentication"]["lockout_duration_minutes"]
                    lock_until = datetime.now() + timedelta(minutes=lock_duration)

                cursor.execute('''
                    UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?
                ''', (new_failed_attempts, lock_until.isoformat() if lock_until else None, user_id))

                conn.commit()

                self._log_audit(username, "authentication_failed", "user_login",
                               {"reason": "invalid_password", "failed_attempts": new_failed_attempts}, ip_address)
                return False, "Contraseña incorrecta", None

            # Autenticación exitosa - resetear contador de fallos y actualizar último login
            cursor.execute('''
                UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (user_id,))

            # Crear sesión
            session_id = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=self.security_policies["authentication"]["session_timeout_hours"])

            cursor.execute('''
                INSERT INTO active_sessions (session_id, username, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, username, ip_address, user_agent, expires_at.isoformat()))

            conn.commit()
            conn.close()

            # Parsear permisos
            permissions = json.loads(permissions_str) if permissions_str else []

            user_info = {
                "username": username,
                "role": role,
                "permissions": permissions,
                "session_id": session_id
            }

            self._log_audit(username, "authentication_success", "user_login", {}, ip_address)
            return True, None, user_info

        except Exception as e:
            logger.error(f"Error en autenticación: {e}")
            return False, "Error interno del sistema", None

    def validate_session(self, session_id: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Validar sesión activa"""
        try:
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT username, expires_at, last_activity FROM active_sessions
                WHERE session_id = ? AND expires_at > CURRENT_TIMESTAMP
            ''', (session_id,))

            session_data = cursor.fetchone()
            conn.close()

            if not session_data:
                return False, "Sesión inválida o expirada", None

            username, expires_at, last_activity = session_data

            # Actualizar última actividad
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE active_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_id = ?
            ''', (session_id,))
            conn.commit()
            conn.close()

            return True, None, {"username": username, "session_id": session_id}

        except Exception as e:
            logger.error(f"Error validando sesión: {e}")
            return False, "Error interno del sistema", None

    def check_permission(self, username: str, action: str, resource: str = None,
                        context: Dict[str, Any] = None) -> Tuple[bool, str]:
        """Verificar permisos para una acción"""
        try:
            # Obtener rol y permisos del usuario
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT role, permissions FROM users WHERE username = ?', (username,))
            user_data = cursor.fetchone()
            conn.close()

            if not user_data:
                return False, "Usuario no encontrado"

            role, permissions_str = user_data
            user_permissions = json.loads(permissions_str) if permissions_str else []

            # Verificar permisos directos
            if "*" in user_permissions or action in user_permissions:
                self._log_permission_check(username, action, resource, True, "direct_permission")
                return True, "Permiso concedido"

            # Verificar permisos por rol
            role_permissions = self.security_policies["authorization"]["roles"].get(role, [])
            if "*" in role_permissions or action in role_permissions:
                self._log_permission_check(username, action, resource, True, "role_permission")
                return True, "Permiso concedido por rol"

            # Verificar permisos de recursos específicos
            if resource and ":" in action:
                action_prefix, action_suffix = action.split(":", 1)
                resource_perm = f"{action_prefix}:{resource}"
                if resource_perm in user_permissions or resource_perm in role_permissions:
                    self._log_permission_check(username, action, resource, True, "resource_permission")
                    return True, "Permiso concedido para recurso"

            # Verificar políticas de seguridad adicionales
            security_check = self._check_security_policies(action, resource, context or {})
            if not security_check[0]:
                self._log_permission_check(username, action, resource, False, "security_policy_violation")
                return security_check

            self._log_permission_check(username, action, resource, False, "insufficient_permissions")
            return False, "Permisos insuficientes"

        except Exception as e:
            logger.error(f"Error verificando permisos: {e}")
            return False, "Error interno del sistema"

    def _check_security_policies(self, action: str, resource: str,
                                context: Dict[str, Any]) -> Tuple[bool, str]:
        """Verificar políticas de seguridad específicas"""
        try:
            # Verificar comandos bloqueados
            if action == "execute_command" and resource:
                blocked_commands = self.security_policies["content_filtering"]["blocked_commands"]
                for blocked in blocked_commands:
                    if re.search(blocked, resource, re.IGNORECASE):
                        return False, f"Comando bloqueado por política de seguridad: {blocked}"

            # Verificar archivos sensibles
            if action in ["read_file", "write_file"] and resource:
                blocked_files = self.security_policies["content_filtering"]["blocked_files"]
                for blocked in blocked_files:
                    if "*" in blocked:
                        if re.match(blocked.replace("*", ".*"), resource):
                            return False, f"Archivo sensible bloqueado: {blocked}"
                    elif blocked in resource:
                        return False, f"Archivo sensible bloqueado: {blocked}"

            # Verificar patrones sensibles en contenido
            if "content" in context:
                sensitive_patterns = self.security_policies["content_filtering"]["sensitive_patterns"]
                for pattern in sensitive_patterns:
                    if re.search(pattern, context["content"], re.IGNORECASE):
                        return False, "Contenido contiene datos sensibles"

            return True, "Políticas de seguridad cumplidas"

        except Exception as e:
            logger.error(f"Error verificando políticas de seguridad: {e}")
            return False, "Error en validación de políticas"

    def authorize_action(self, session_id: str, action: str, resource: str = None,
                        parameters: Dict[str, Any] = None, ip_address: str = None) -> Tuple[bool, str]:
        """Autorizar una acción completa (validar sesión + permisos + auditoría)"""
        try:
            # Validar sesión
            session_valid, session_error, session_info = self.validate_session(session_id)
            if not session_valid:
                return False, f"Sesión inválida: {session_error}"

            username = session_info["username"]

            # Verificar permisos
            permission_granted, permission_message = self.check_permission(
                username, action, resource, parameters
            )

            if not permission_granted:
                self._log_audit(username, "authorization_denied", action,
                               {"resource": resource, "reason": permission_message}, ip_address, session_id)
                return False, permission_message

            # Verificar límites de tasa
            rate_limit_ok, rate_limit_message = self._check_rate_limits(username, action)
            if not rate_limit_ok:
                self._log_audit(username, "rate_limit_exceeded", action,
                               {"resource": resource, "reason": rate_limit_message}, ip_address, session_id)
                return False, rate_limit_message

            # Acción autorizada - registrar en auditoría
            self._log_audit(username, "action_authorized", action,
                           {"resource": resource, "parameters": parameters}, ip_address, session_id)

            return True, "Acción autorizada"

        except Exception as e:
            logger.error(f"Error autorizando acción: {e}")
            return False, "Error interno del sistema"

    def _check_rate_limits(self, username: str, action: str) -> Tuple[bool, str]:
        """Verificar límites de tasa para prevenir abuso"""
        try:
            # Esta es una implementación simplificada
            # En producción, usar Redis o similar para rate limiting distribuido

            rate_limits = self.security_policies["rate_limiting"]
            requests_per_minute = rate_limits["requests_per_minute"]

            # Para esta implementación básica, siempre permitir
            # En producción, implementar contadores reales
            return True, "Dentro de límites de tasa"

        except Exception as e:
            logger.error(f"Error verificando límites de tasa: {e}")
            return False, "Error en verificación de límites"

    def _log_audit(self, username: str, action: str, resource: str,
                  parameters: Dict[str, Any] = None, ip_address: str = None,
                  session_id: str = None, risk_level: str = "low",
                  anomaly_score: float = 0.0):
        """Registrar evento en log de auditoría"""
        try:
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO audit_log
                (username, session_id, action, resource, parameters, ip_address, risk_level, anomaly_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                username,
                session_id,
                action,
                resource,
                json.dumps(parameters or {}),
                ip_address,
                risk_level,
                anomaly_score
            ))

            conn.commit()
            conn.close()

            # También escribir a archivo de log para backup
            self._write_audit_log_file(username, action, resource, parameters, ip_address, session_id)

        except Exception as e:
            logger.error(f"Error registrando auditoría: {e}")

    def _write_audit_log_file(self, username: str, action: str, resource: str,
                            parameters: Dict[str, Any], ip_address: str, session_id: str):
        """Escribir entrada de auditoría a archivo"""
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "username": username,
                "session_id": session_id,
                "action": action,
                "resource": resource,
                "parameters": parameters or {},
                "ip_address": ip_address
            }

            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')

        except Exception as e:
            logger.error(f"Error escribiendo log de auditoría: {e}")

    def _log_permission_check(self, username: str, action: str, resource: str,
                            granted: bool, reason: str):
        """Registrar verificación de permisos"""
        try:
            self._log_audit(
                username=username,
                action="permission_check",
                resource=f"{action}:{resource}" if resource else action,
                parameters={"granted": granted, "reason": reason},
                risk_level="medium" if not granted else "low"
            )
        except Exception as e:
            logger.error(f"Error registrando verificación de permisos: {e}")

    def create_user(self, username: str, password: str, role: str,
                   permissions: List[str] = None, created_by: str = "system") -> Tuple[bool, str]:
        """Crear nuevo usuario"""
        try:
            if not self._validate_password_strength(password):
                return False, "Contraseña no cumple con requisitos de seguridad"

            if role not in self.security_policies["authorization"]["roles"]:
                return False, f"Rol inválido: {role}"

            hashed_password = self._hash_password(password)
            user_permissions = permissions or self.security_policies["authorization"]["roles"][role]

            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO users (username, hashed_password, role, permissions)
                VALUES (?, ?, ?, ?)
            ''', (username, hashed_password, role, json.dumps(user_permissions)))

            conn.commit()
            conn.close()

            self._log_audit(created_by, "user_created", "user_management",
                           {"new_user": username, "role": role}, None)

            return True, f"Usuario {username} creado exitosamente"

        except sqlite3.IntegrityError:
            return False, "Usuario ya existe"
        except Exception as e:
            logger.error(f"Error creando usuario: {e}")
            return False, "Error interno del sistema"

    def _validate_password_strength(self, password: str) -> bool:
        """Validar fortaleza de contraseña"""
        min_length = self.security_policies["authentication"]["password_min_length"]

        if len(password) < min_length:
            return False

        # Verificar complejidad básica
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        return has_upper and has_lower and has_digit and has_special

    def _hash_password(self, password: str) -> str:
        """Hashear contraseña de forma segura"""
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{hashed.hex()}"

    def _verify_password(self, password: str, hashed_password: str) -> bool:
        """Verificar contraseña contra hash"""
        try:
            salt, hash_value = hashed_password.split(':')
            hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(hashed.hex(), hash_value)
        except:
            return False

    def get_audit_logs(self, username: str = None, action: str = None,
                      from_date: str = None, to_date: str = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """Obtener logs de auditoría con filtros"""
        try:
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            query = '''
                SELECT timestamp, username, session_id, action, resource, parameters,
                       result, ip_address, risk_level, anomaly_score
                FROM audit_log WHERE 1=1
            '''
            params = []

            if username:
                query += ' AND username = ?'
                params.append(username)

            if action:
                query += ' AND action = ?'
                params.append(action)

            if from_date:
                query += ' AND timestamp >= ?'
                params.append(from_date)

            if to_date:
                query += ' AND timestamp <= ?'
                params.append(to_date)

            query += f' ORDER BY timestamp DESC LIMIT {limit}'

            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()

            logs = []
            for row in results:
                logs.append({
                    "timestamp": row[0],
                    "username": row[1],
                    "session_id": row[2],
                    "action": row[3],
                    "resource": row[4],
                    "parameters": json.loads(row[5]) if row[5] else {},
                    "result": row[6],
                    "ip_address": row[7],
                    "risk_level": row[8],
                    "anomaly_score": row[9]
                })

            return logs

        except Exception as e:
            logger.error(f"Error obteniendo logs de auditoría: {e}")
            return []

    def get_security_report(self) -> Dict[str, Any]:
        """Generar reporte completo de seguridad"""
        try:
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            # Estadísticas de autenticación
            cursor.execute('''
                SELECT
                    COUNT(*) as total_users,
                    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users,
                    SUM(CASE WHEN locked_until > CURRENT_TIMESTAMP THEN 1 ELSE 0 END) as locked_accounts
                FROM users
            ''')
            auth_stats = cursor.fetchone()

            # Estadísticas de sesiones
            cursor.execute('''
                SELECT COUNT(*) as active_sessions
                FROM active_sessions
                WHERE expires_at > CURRENT_TIMESTAMP
            ''')
            session_stats = cursor.fetchone()

            # Estadísticas de auditoría (últimas 24 horas)
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute('''
                SELECT
                    COUNT(*) as total_actions,
                    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk_actions,
                    SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) as medium_risk_actions,
                    SUM(CASE WHEN action = 'authorization_denied' THEN 1 ELSE 0 END) as denied_actions
                FROM audit_log
                WHERE timestamp > ?
            ''', (yesterday,))
            audit_stats = cursor.fetchone()

            conn.close()

            return {
                "generated_at": datetime.now().isoformat(),
                "authentication": {
                    "total_users": auth_stats[0] or 0,
                    "active_users": auth_stats[1] or 0,
                    "locked_accounts": auth_stats[2] or 0
                },
                "sessions": {
                    "active_sessions": session_stats[0] or 0
                },
                "audit_24h": {
                    "total_actions": audit_stats[0] or 0,
                    "high_risk_actions": audit_stats[1] or 0,
                    "medium_risk_actions": audit_stats[2] or 0,
                    "denied_actions": audit_stats[3] or 0
                },
                "security_status": self._calculate_security_status(auth_stats, session_stats, audit_stats),
                "policies": {
                    "active_policies": len(self.security_policies),
                    "audit_enabled": self.security_policies["audit"]["log_all_actions"],
                    "rate_limiting_enabled": True
                }
            }

        except Exception as e:
            logger.error(f"Error generando reporte de seguridad: {e}")
            return {"error": str(e)}

    def _calculate_security_status(self, auth_stats, session_stats, audit_stats) -> str:
        """Calcular estado general de seguridad"""
        try:
            total_users = auth_stats[0] or 0
            locked_accounts = auth_stats[2] or 0
            denied_actions = audit_stats[3] or 0
            high_risk_actions = audit_stats[1] or 0

            # Lógica simple de evaluación
            if locked_accounts > total_users * 0.1:  # Más del 10% de cuentas bloqueadas
                return "CRITICAL"
            elif denied_actions > 10 or high_risk_actions > 5:  # Muchas denegaciones o acciones de alto riesgo
                return "WARNING"
            else:
                return "HEALTHY"

        except:
            return "UNKNOWN"

    def cleanup_expired_sessions(self) -> int:
        """Limpiar sesiones expiradas"""
        try:
            conn = sqlite3.connect(self.security_db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM active_sessions WHERE expires_at <= CURRENT_TIMESTAMP')
            deleted_count = cursor.rowcount

            conn.commit()
            conn.close()

            if deleted_count > 0:
                logger.info(f"Limpiadas {deleted_count} sesiones expiradas")

            return deleted_count

        except Exception as e:
            logger.error(f"Error limpiando sesiones expiradas: {e}")
            return 0

def main():
    """Función principal para testing"""
    manager = EnterpriseSecurityManager()

    # Crear usuario de prueba
    success, message = manager.create_user(
        username="test_user",
        password="TestPass123!@#",
        role="developer"
    )
    print(f"Crear usuario: {success} - {message}")

    # Probar autenticación
    auth_success, auth_error, user_info = manager.authenticate_user(
        username="test_user",
        password="TestPass123!@#"
    )
    print(f"Autenticación: {auth_success} - {user_info}")

    if auth_success and user_info:
        session_id = user_info["session_id"]

        # Probar autorización
        auth_action, auth_message = manager.authorize_action(
            session_id=session_id,
            action="read:code",
            resource="test.py"
        )
        print(f"Autorización: {auth_action} - {auth_message}")

    # Mostrar reporte de seguridad
    report = manager.get_security_report()
    print("Reporte de seguridad:")
    print(json.dumps(report, indent=2))

    manager.cleanup_expired_sessions()

if __name__ == "__main__":
    main()
