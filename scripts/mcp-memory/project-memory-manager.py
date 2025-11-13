#!/usr/bin/env python3
"""
Sistema de Memoria Persistente para Copilot CLI - Odoo19 Chilean Localization
Gestiona conocimiento del proyecto, decisiones arquitectónicas y contexto entre sesiones
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
import hashlib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProjectMemoryManager:
    """Gestor de memoria persistente para el proyecto Odoo19"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or "/Users/pedro/.copilot/odoo19-knowledge.db"
        self.conn = None
        self._initialize_database()

    def _initialize_database(self):
        """Inicializar base de datos de memoria"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self._create_tables()
            self._seed_initial_knowledge()
            logger.info(f"Base de datos de memoria inicializada: {self.db_path}")
        except Exception as e:
            logger.error(f"Error inicializando base de datos: {e}")
            raise

    def _create_tables(self):
        """Crear tablas de la base de datos"""
        cursor = self.conn.cursor()

        # Tabla de conocimiento del proyecto
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS project_knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL,
                category TEXT NOT NULL,
                tags TEXT, -- JSON array
                source TEXT, -- Archivo o fuente de origen
                confidence REAL DEFAULT 1.0, -- 0.0 a 1.0
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                last_accessed TIMESTAMP
            )
        ''')

        # Tabla de decisiones arquitectónicas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS architectural_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                context TEXT,
                decision TEXT NOT NULL,
                alternatives TEXT, -- JSON array
                consequences TEXT,
                status TEXT DEFAULT 'active', -- active, deprecated, superseded
                superseded_by TEXT,
                tags TEXT, -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabla de patrones de código aprendidos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS code_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                language TEXT DEFAULT 'python',
                pattern TEXT NOT NULL, -- Código patrón
                anti_pattern TEXT, -- Qué evitar
                example_good TEXT,
                example_bad TEXT,
                tags TEXT, -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                last_used TIMESTAMP
            )
        ''')

        # Tabla de contexto de sesiones
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_context (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                context_data TEXT NOT NULL, -- JSON
                project_state TEXT, -- JSON con estado del proyecto
                active_tasks TEXT, -- JSON array
                recent_files TEXT, -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')

        # Tabla de métricas de uso
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                value REAL NOT NULL,
                tags TEXT, -- JSON
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Índices para mejor rendimiento
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_knowledge_key ON project_knowledge(key)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_knowledge_category ON project_knowledge(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_decisions_status ON architectural_decisions(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_patterns_category ON code_patterns(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_expires ON session_context(expires_at)')

        self.conn.commit()

    def _seed_initial_knowledge(self):
        """Cargar conocimiento inicial del proyecto"""
        initial_knowledge = [
            {
                "key": "project_scope",
                "value": "Odoo 19 Community Edition with Chilean localization for DTE electronic invoicing, payroll compliance, and financial reporting",
                "category": "project",
                "tags": ["scope", "odoo19", "chilean", "localization"]
            },
            {
                "key": "dte_types_supported",
                "value": "Document types 33,34,52,56,61 only. No boletas 39,41 support.",
                "category": "regulatory",
                "tags": ["dte", "sii", "compliance", "scope"]
            },
            {
                "key": "architecture_pattern",
                "value": "Pure Python validators in libs/ directory, no ORM dependencies. Extend existing Odoo models with _inherit.",
                "category": "architecture",
                "tags": ["architecture", "patterns", "libs", "odoo"]
            },
            {
                "key": "security_first",
                "value": "OWASP Top 10 compliance mandatory. XXE protection in XML parsers. No hardcoded credentials.",
                "category": "security",
                "tags": ["security", "owasp", "xxe", "credentials"]
            },
            {
                "key": "testing_standard",
                "value": "80% coverage for DTE, 100% for critical validators. TransactionCase for all tests.",
                "category": "testing",
                "tags": ["testing", "coverage", "transactioncase"]
            },
            {
                "key": "chilean_labor_code",
                "value": "Previred integration required. AFP 10%, ISAPRE 7%, APV calculations with tope imponible.",
                "category": "regulatory",
                "tags": ["payroll", "previred", "labor", "afp", "isapre"]
            }
        ]

        cursor = self.conn.cursor()
        for knowledge in initial_knowledge:
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO project_knowledge
                    (key, value, category, tags, confidence)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    knowledge["key"],
                    knowledge["value"],
                    knowledge["category"],
                    json.dumps(knowledge["tags"]),
                    1.0
                ))
            except Exception as e:
                logger.warning(f"Error insertando conocimiento inicial {knowledge['key']}: {e}")

        self.conn.commit()

    def remember_context(self, key: str, value: Any, category: str,
                        tags: List[str] = None, confidence: float = 1.0,
                        source: str = None, ttl_days: int = None) -> bool:
        """Recordar un nuevo elemento de conocimiento"""
        try:
            cursor = self.conn.cursor()
            expires_at = None
            if ttl_days:
                expires_at = datetime.now() + timedelta(days=ttl_days)

            cursor.execute('''
                INSERT OR REPLACE INTO project_knowledge
                (key, value, category, tags, confidence, source, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                key,
                json.dumps(value) if isinstance(value, (dict, list)) else str(value),
                category,
                json.dumps(tags or []),
                confidence,
                source,
                expires_at.isoformat() if expires_at else None
            ))

            self.conn.commit()
            logger.info(f"Conocimiento recordado: {key}")
            return True

        except Exception as e:
            logger.error(f"Error recordando contexto {key}: {e}")
            return False

    def recall_context(self, key: str = None, category: str = None,
                      tags: List[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Recordar elementos de conocimiento"""
        try:
            cursor = self.conn.cursor()

            query = '''
                SELECT key, value, category, tags, confidence, source,
                       created_at, updated_at, access_count, last_accessed
                FROM project_knowledge
                WHERE 1=1
            '''
            params = []

            if key:
                query += ' AND key = ?'
                params.append(key)

            if category:
                query += ' AND category = ?'
                params.append(category)

            if tags:
                tag_conditions = ' OR '.join(['tags LIKE ?'] * len(tags))
                query += f' AND ({tag_conditions})'
                for tag in tags:
                    params.append(f'%{tag}%')

            query += ' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)'
            query += f' ORDER BY confidence DESC, updated_at DESC LIMIT {limit}'

            cursor.execute(query, params)
            results = cursor.fetchall()

            # Actualizar contador de acceso
            if results:
                keys_to_update = [row[0] for row in results]
                cursor.execute(f'''
                    UPDATE project_knowledge
                    SET access_count = access_count + 1, last_accessed = CURRENT_TIMESTAMP
                    WHERE key IN ({",".join(["?"] * len(keys_to_update))})
                ''', keys_to_update)
                self.conn.commit()

            # Convertir resultados
            knowledge_items = []
            for row in results:
                try:
                    value = json.loads(row[1]) if row[1].startswith(('{', '[')) else row[1]
                except:
                    value = row[1]

                knowledge_items.append({
                    "key": row[0],
                    "value": value,
                    "category": row[2],
                    "tags": json.loads(row[3]) if row[3] else [],
                    "confidence": row[4],
                    "source": row[5],
                    "created_at": row[6],
                    "updated_at": row[7],
                    "access_count": row[8],
                    "last_accessed": row[9]
                })

            return knowledge_items

        except Exception as e:
            logger.error(f"Error recordando contexto: {e}")
            return []

    def add_architectural_decision(self, decision_id: str, title: str,
                                  description: str, decision: str,
                                  context: str = None, alternatives: List[str] = None,
                                  consequences: str = None, tags: List[str] = None) -> bool:
        """Agregar una decisión arquitectónica"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO architectural_decisions
                (decision_id, title, description, context, decision, alternatives,
                 consequences, tags, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                decision_id,
                title,
                description,
                context,
                decision,
                json.dumps(alternatives or []),
                consequences,
                json.dumps(tags or []),
            ))

            self.conn.commit()
            logger.info(f"Decisión arquitectónica agregada: {decision_id}")
            return True

        except Exception as e:
            logger.error(f"Error agregando decisión arquitectónica {decision_id}: {e}")
            return False

    def get_architectural_decisions(self, status: str = "active",
                                   tags: List[str] = None) -> List[Dict[str, Any]]:
        """Obtener decisiones arquitectónicas"""
        try:
            cursor = self.conn.cursor()

            query = '''
                SELECT decision_id, title, description, context, decision,
                       alternatives, consequences, status, tags, created_at, updated_at
                FROM architectural_decisions
                WHERE status = ?
            '''
            params = [status]

            if tags:
                tag_conditions = ' OR '.join(['tags LIKE ?'] * len(tags))
                query += f' AND ({tag_conditions})'
                for tag in tags:
                    params.append(f'%{tag}%')

            query += ' ORDER BY updated_at DESC'

            cursor.execute(query, params)
            results = cursor.fetchall()

            decisions = []
            for row in results:
                decisions.append({
                    "decision_id": row[0],
                    "title": row[1],
                    "description": row[2],
                    "context": row[3],
                    "decision": row[4],
                    "alternatives": json.loads(row[5]) if row[5] else [],
                    "consequences": row[6],
                    "status": row[7],
                    "tags": json.loads(row[8]) if row[8] else [],
                    "created_at": row[9],
                    "updated_at": row[10]
                })

            return decisions

        except Exception as e:
            logger.error(f"Error obteniendo decisiones arquitectónicas: {e}")
            return []

    def add_code_pattern(self, pattern_id: str, name: str, description: str,
                        category: str, pattern: str, anti_pattern: str = None,
                        example_good: str = None, example_bad: str = None,
                        tags: List[str] = None) -> bool:
        """Agregar un patrón de código aprendido"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO code_patterns
                (pattern_id, name, description, category, pattern, anti_pattern,
                 example_good, example_bad, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern_id,
                name,
                description,
                category,
                pattern,
                anti_pattern,
                example_good,
                example_bad,
                json.dumps(tags or [])
            ))

            self.conn.commit()
            logger.info(f"Patrón de código agregado: {pattern_id}")
            return True

        except Exception as e:
            logger.error(f"Error agregando patrón de código {pattern_id}: {e}")
            return False

    def get_code_patterns(self, category: str = None, tags: List[str] = None,
                         limit: int = 20) -> List[Dict[str, Any]]:
        """Obtener patrones de código"""
        try:
            cursor = self.conn.cursor()

            query = '''
                SELECT pattern_id, name, description, category, language, pattern,
                       anti_pattern, example_good, example_bad, tags, usage_count, last_used
                FROM code_patterns
                WHERE 1=1
            '''
            params = []

            if category:
                query += ' AND category = ?'
                params.append(category)

            if tags:
                tag_conditions = ' OR '.join(['tags LIKE ?'] * len(tags))
                query += f' AND ({tag_conditions})'
                for tag in tags:
                    params.append(f'%{tag}%')

            query += f' ORDER BY usage_count DESC, last_used DESC LIMIT {limit}'

            cursor.execute(query, params)
            results = cursor.fetchall()

            patterns = []
            for row in results:
                patterns.append({
                    "pattern_id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "category": row[3],
                    "language": row[4],
                    "pattern": row[5],
                    "anti_pattern": row[6],
                    "example_good": row[7],
                    "example_bad": row[8],
                    "tags": json.loads(row[9]) if row[9] else [],
                    "usage_count": row[10],
                    "last_used": row[11]
                })

            return patterns

        except Exception as e:
            logger.error(f"Error obteniendo patrones de código: {e}")
            return []

    def save_session_context(self, session_id: str, context_data: Dict[str, Any],
                           active_tasks: List[str] = None, recent_files: List[str] = None,
                           ttl_hours: int = 24) -> bool:
        """Guardar contexto de sesión"""
        try:
            cursor = self.conn.cursor()
            expires_at = datetime.now() + timedelta(hours=ttl_hours)

            session_data = {
                "context_data": context_data,
                "active_tasks": active_tasks or [],
                "recent_files": recent_files or [],
                "saved_at": datetime.now().isoformat()
            }

            cursor.execute('''
                INSERT OR REPLACE INTO session_context
                (session_id, context_data, active_tasks, recent_files, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                session_id,
                json.dumps(session_data),
                json.dumps(active_tasks or []),
                json.dumps(recent_files or []),
                expires_at.isoformat()
            ))

            self.conn.commit()
            logger.info(f"Contexto de sesión guardado: {session_id}")
            return True

        except Exception as e:
            logger.error(f"Error guardando contexto de sesión {session_id}: {e}")
            return False

    def load_session_context(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Cargar contexto de sesión"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT context_data, active_tasks, recent_files, expires_at
                FROM session_context
                WHERE session_id = ? AND expires_at > CURRENT_TIMESTAMP
            ''', (session_id,))

            result = cursor.fetchone()
            if result:
                return {
                    "session_data": json.loads(result[0]),
                    "active_tasks": json.loads(result[1]) if result[1] else [],
                    "recent_files": json.loads(result[2]) if result[2] else [],
                    "expires_at": result[3]
                }

            return None

        except Exception as e:
            logger.error(f"Error cargando contexto de sesión {session_id}: {e}")
            return None

    def record_metric(self, metric_type: str, metric_name: str, value: float,
                     tags: Dict[str, Any] = None) -> bool:
        """Registrar una métrica de uso"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO usage_metrics (metric_type, metric_name, value, tags)
                VALUES (?, ?, ?, ?)
            ''', (
                metric_type,
                metric_name,
                value,
                json.dumps(tags or {})
            ))

            self.conn.commit()
            return True

        except Exception as e:
            logger.error(f"Error registrando métrica {metric_type}.{metric_name}: {e}")
            return False

    def get_metrics(self, metric_type: str = None, hours: int = 24) -> List[Dict[str, Any]]:
        """Obtener métricas de uso"""
        try:
            cursor = self.conn.cursor()

            query = '''
                SELECT metric_type, metric_name, value, tags, timestamp
                FROM usage_metrics
                WHERE timestamp > datetime('now', '-{} hours')
            '''.format(hours)

            if metric_type:
                query += ' AND metric_type = ?'
                cursor.execute(query, (metric_type,))
            else:
                cursor.execute(query)

            results = cursor.fetchall()

            metrics = []
            for row in results:
                metrics.append({
                    "metric_type": row[0],
                    "metric_name": row[1],
                    "value": row[2],
                    "tags": json.loads(row[3]) if row[3] else {},
                    "timestamp": row[4]
                })

            return metrics

        except Exception as e:
            logger.error(f"Error obteniendo métricas: {e}")
            return []

    def cleanup_expired(self) -> int:
        """Limpiar elementos expirados"""
        try:
            cursor = self.conn.cursor()

            # Limpiar conocimiento expirado
            cursor.execute('DELETE FROM project_knowledge WHERE expires_at <= CURRENT_TIMESTAMP')
            knowledge_deleted = cursor.rowcount

            # Limpiar sesiones expiradas
            cursor.execute('DELETE FROM session_context WHERE expires_at <= CURRENT_TIMESTAMP')
            sessions_deleted = cursor.rowcount

            self.conn.commit()

            total_deleted = knowledge_deleted + sessions_deleted
            logger.info(f"Limpieza completada: {total_deleted} elementos expirados eliminados")
            return total_deleted

        except Exception as e:
            logger.error(f"Error en limpieza: {e}")
            return 0

    def get_memory_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas de la memoria"""
        try:
            cursor = self.conn.cursor()

            stats = {}

            # Estadísticas de conocimiento
            cursor.execute('SELECT COUNT(*), category FROM project_knowledge GROUP BY category')
            knowledge_by_category = {row[1]: row[0] for row in cursor.fetchall()}
            stats["knowledge_by_category"] = knowledge_by_category
            stats["total_knowledge_items"] = sum(knowledge_by_category.values())

            # Estadísticas de decisiones arquitectónicas
            cursor.execute('SELECT COUNT(*), status FROM architectural_decisions GROUP BY status')
            decisions_by_status = {row[1]: row[0] for row in cursor.fetchall()}
            stats["decisions_by_status"] = decisions_by_status
            stats["total_decisions"] = sum(decisions_by_status.values())

            # Estadísticas de patrones de código
            cursor.execute('SELECT COUNT(*), category FROM code_patterns GROUP BY category')
            patterns_by_category = {row[1]: row[0] for row in cursor.fetchall()}
            stats["patterns_by_category"] = patterns_by_category
            stats["total_patterns"] = sum(patterns_by_category.values())

            # Sesiones activas
            cursor.execute('SELECT COUNT(*) FROM session_context WHERE expires_at > CURRENT_TIMESTAMP')
            stats["active_sessions"] = cursor.fetchone()[0]

            # Tamaño de la base de datos
            db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
            stats["database_size_bytes"] = db_size
            stats["database_size_mb"] = round(db_size / (1024 * 1024), 2)

            return stats

        except Exception as e:
            logger.error(f"Error obteniendo estadísticas de memoria: {e}")
            return {}

    def close(self):
        """Cerrar conexión a la base de datos"""
        if self.conn:
            self.conn.close()
            self.conn = None

def main():
    """Función principal para testing"""
    manager = ProjectMemoryManager()

    # Agregar algunos conocimientos iniciales adicionales
    manager.add_architectural_decision(
        "libs-pattern",
        "Pure Python Validators in libs/",
        "All business logic validators must be in libs/ directory with no ORM dependencies",
        "Decision: Create pure Python classes for validators to ensure testability and reusability",
        "Need for better testability and separation of concerns",
        ["Alternative: Keep validators in models/", "Alternative: Mix ORM and pure Python"],
        "Better testability, cleaner architecture, easier maintenance",
        ["architecture", "testing", "patterns"]
    )

    manager.add_code_pattern(
        "dte_xml_validation",
        "DTE XML Validation Pattern",
        "Standard pattern for validating DTE XML against SII schemas",
        "validation",
        """def validate_dte_xml(xml_content: str, dte_type: str) -> Dict[str, Any]:
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    try:
        root = etree.fromstring(xml_content.encode(), parser)
        # Validation logic here
        return {"valid": True, "errors": []}
    except etree.XMLSyntaxError as e:
        return {"valid": False, "errors": [str(e)]}""",
        "Don't use lxml without XXE protection",
        "Use secure XML parser configuration",
        "Never parse XML without XXE protection",
        ["xml", "validation", "security", "dte"]
    )

    # Mostrar estadísticas
    stats = manager.get_memory_stats()
    print("Estadísticas de Memoria del Proyecto:")
    print(json.dumps(stats, indent=2))

    manager.close()

if __name__ == "__main__":
    main()
