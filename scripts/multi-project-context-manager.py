#!/usr/bin/env python3
"""
Sistema de Gestión de Contexto Multi-Proyecto para Copilot CLI
Permite a Copilot manejar múltiples proyectos relacionados, compartir conocimiento
y gestionar dependencias y contextos complejos de forma inteligente
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
import hashlib
import networkx as nx
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MultiProjectContextManager:
    """Gestor de contexto multi-proyecto para Copilot CLI"""

    def __init__(self, context_db_path: str = None):
        self.context_db_path = context_db_path or "/Users/pedro/.copilot/multi-project-context.db"
        self.projects_base_path = "/Users/pedro/Documents/odoo19"
        self._initialize_database()

        # Proyectos conocidos
        self.known_projects = self._load_known_projects()

        # Grafo de dependencias entre proyectos
        self.dependency_graph = self._build_dependency_graph()

    def _initialize_database(self):
        """Inicializar base de datos de contexto multi-proyecto"""
        try:
            conn = sqlite3.connect(self.context_db_path)
            cursor = conn.cursor()

            # Tabla de proyectos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    project_type TEXT NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Tabla de dependencias entre proyectos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS project_dependencies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_project TEXT NOT NULL,
                    to_project TEXT NOT NULL,
                    dependency_type TEXT NOT NULL,
                    strength REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(from_project, to_project, dependency_type)
                )
            ''')

            # Tabla de contexto compartido
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS shared_context (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    context_key TEXT NOT NULL,
                    context_value TEXT NOT NULL,
                    project_scope TEXT, -- 'global', 'regional', or specific project
                    context_type TEXT NOT NULL,
                    relevance_score REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            ''')

            # Tabla de sesiones multi-proyecto
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS multi_project_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    active_projects TEXT NOT NULL, -- JSON array
                    session_context TEXT NOT NULL, -- JSON
                    cross_project_queries TEXT, -- JSON array
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            ''')

            # Tabla de conocimiento cross-proyecto
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cross_project_knowledge (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    knowledge_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    relevant_projects TEXT NOT NULL, -- JSON array
                    knowledge_type TEXT NOT NULL,
                    author TEXT,
                    confidence REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Índices para mejor rendimiento
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_projects_type ON projects(project_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dependencies_from ON project_dependencies(from_project)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_context_type ON shared_context(context_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON multi_project_sessions(expires_at)')

            conn.commit()
            conn.close()

            logger.info(f"Base de datos multi-proyecto inicializada: {self.context_db_path}")

        except Exception as e:
            logger.error(f"Error inicializando base de datos multi-proyecto: {e}")
            raise

    def _load_known_projects(self) -> Dict[str, Dict[str, Any]]:
        """Cargar proyectos conocidos del sistema"""
        known_projects = {
            "odoo19-chilean-core": {
                "name": "Odoo19 Chilean Localization Core",
                "path": "/Users/pedro/Documents/odoo19",
                "type": "localization",
                "description": "Módulo principal de localización chilena para Odoo 19",
                "technologies": ["python", "odoo", "postgresql", "xml"],
                "domains": ["dte", "payroll", "tax", "accounting"]
            },
            "ai-service": {
                "name": "AI Microservice",
                "path": "/Users/pedro/Documents/odoo19/ai-service",
                "type": "microservice",
                "description": "Servicio de IA para procesamiento inteligente",
                "technologies": ["python", "fastapi", "claude", "docker"],
                "domains": ["ai", "nlp", "automation"]
            },
            "eergy-services": {
                "name": "EERGY Services",
                "path": "/Users/pedro/Documents/odoo19/odoo-eergy-services",
                "type": "integration",
                "description": "Servicios de integración para EERGYGROUP",
                "technologies": ["python", "rest", "graphql", "docker"],
                "domains": ["integration", "api", "business"]
            },
            "infrastructure": {
                "name": "Infrastructure & DevOps",
                "path": "/Users/pedro/Documents/odoo19",
                "type": "infrastructure",
                "description": "Infraestructura, Docker, CI/CD, monitoreo",
                "technologies": ["docker", "kubernetes", "terraform", "github-actions"],
                "domains": ["devops", "monitoring", "security"]
            }
        }

        # Registrar proyectos en la base de datos
        conn = sqlite3.connect(self.context_db_path)
        cursor = conn.cursor()

        for project_id, project_data in known_projects.items():
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO projects
                    (project_id, name, path, project_type, description, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    project_id,
                    project_data["name"],
                    project_data["path"],
                    project_data["type"],
                    project_data["description"]
                ))
            except Exception as e:
                logger.warning(f"Error registrando proyecto {project_id}: {e}")

        conn.commit()
        conn.close()

        return known_projects

    def _build_dependency_graph(self) -> nx.DiGraph:
        """Construir grafo de dependencias entre proyectos"""
        graph = nx.DiGraph()

        # Agregar nodos (proyectos)
        for project_id, project_data in self.known_projects.items():
            graph.add_node(project_id, **project_data)

        # Definir dependencias conocidas
        dependencies = [
            ("odoo19-chilean-core", "ai-service", "uses", 0.8),
            ("odoo19-chilean-core", "eergy-services", "integrates", 0.9),
            ("odoo19-chilean-core", "infrastructure", "depends", 1.0),
            ("ai-service", "infrastructure", "depends", 0.7),
            ("eergy-services", "infrastructure", "depends", 0.6),
            ("eergy-services", "odoo19-chilean-core", "extends", 0.5),
        ]

        # Agregar aristas (dependencias)
        for from_proj, to_proj, dep_type, strength in dependencies:
            if from_proj in self.known_projects and to_proj in self.known_projects:
                graph.add_edge(from_proj, to_proj,
                             dependency_type=dep_type,
                             strength=strength)

        # Registrar dependencias en base de datos
        conn = sqlite3.connect(self.context_db_path)
        cursor = conn.cursor()

        for from_proj, to_proj, dep_type, strength in dependencies:
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO project_dependencies
                    (from_project, to_project, dependency_type, strength)
                    VALUES (?, ?, ?, ?)
                ''', (from_proj, to_proj, dep_type, strength))
            except Exception as e:
                logger.warning(f"Error registrando dependencia {from_proj} -> {to_proj}: {e}")

        conn.commit()
        conn.close()

        return graph

    def get_relevant_context(self, query: str, current_project: str = None,
                           context_horizon: int = 2) -> Dict[str, Any]:
        """Obtener contexto relevante considerando múltiples proyectos"""
        try:
            relevant_projects = self._find_relevant_projects(query, current_project, context_horizon)

            context = {
                "query": query,
                "current_project": current_project,
                "relevant_projects": relevant_projects,
                "shared_knowledge": [],
                "cross_project_insights": [],
                "dependency_context": [],
                "recommendations": []
            }

            # Obtener conocimiento compartido relevante
            shared_knowledge = self._get_shared_knowledge(query, relevant_projects)
            context["shared_knowledge"] = shared_knowledge

            # Obtener insights cross-proyecto
            cross_insights = self._get_cross_project_insights(query, relevant_projects)
            context["cross_project_insights"] = cross_insights

            # Obtener contexto de dependencias
            dependency_context = self._get_dependency_context(current_project, relevant_projects)
            context["dependency_context"] = dependency_context

            # Generar recomendaciones
            recommendations = self._generate_recommendations(query, relevant_projects, context)
            context["recommendations"] = recommendations

            return context

        except Exception as e:
            logger.error(f"Error obteniendo contexto relevante: {e}")
            return {"error": str(e), "query": query}

    def _find_relevant_projects(self, query: str, current_project: str = None,
                              context_horizon: int = 2) -> List[Dict[str, Any]]:
        """Encontrar proyectos relevantes para la consulta"""
        relevant_projects = []

        # Siempre incluir el proyecto actual si está especificado
        if current_project and current_project in self.known_projects:
            relevant_projects.append({
                "project_id": current_project,
                "name": self.known_projects[current_project]["name"],
                "relevance_score": 1.0,
                "relationship": "current"
            })

        # Buscar proyectos relevantes por contenido de la consulta
        query_lower = query.lower()

        for project_id, project_data in self.known_projects.items():
            if project_id == current_project:
                continue  # Ya incluido arriba

            relevance_score = 0.0

            # Verificar si la consulta menciona tecnologías del proyecto
            for tech in project_data.get("technologies", []):
                if tech.lower() in query_lower:
                    relevance_score += 0.3

            # Verificar si la consulta menciona dominios del proyecto
            for domain in project_data.get("domains", []):
                if domain.lower() in query_lower:
                    relevance_score += 0.4

            # Verificar conexiones en el grafo de dependencias
            if current_project:
                try:
                    # Proyectos directamente conectados
                    if self.dependency_graph.has_edge(current_project, project_id):
                        relevance_score += 0.5 * self.dependency_graph[current_project][project_id]["strength"]
                    elif self.dependency_graph.has_edge(project_id, current_project):
                        relevance_score += 0.4 * self.dependency_graph[project_id][current_project]["strength"]

                    # Proyectos a distancia de contexto
                    if nx.has_path(self.dependency_graph, current_project, project_id):
                        distance = nx.shortest_path_length(self.dependency_graph, current_project, project_id)
                        if distance <= context_horizon:
                            relevance_score += 0.2 / (distance + 1)

                except nx.NetworkXNoPath:
                    pass

            if relevance_score > 0.1:  # Umbral mínimo de relevancia
                relevant_projects.append({
                    "project_id": project_id,
                    "name": project_data["name"],
                    "relevance_score": min(relevance_score, 1.0),  # Máximo 1.0
                    "relationship": self._determine_relationship(current_project, project_id),
                    "technologies": project_data.get("technologies", []),
                    "domains": project_data.get("domains", [])
                })

        # Ordenar por relevancia
        relevant_projects.sort(key=lambda x: x["relevance_score"], reverse=True)

        return relevant_projects

    def _determine_relationship(self, from_project: str, to_project: str) -> str:
        """Determinar el tipo de relación entre proyectos"""
        if not from_project or not self.dependency_graph.has_edge(from_project, to_project):
            return "related"

        edge_data = self.dependency_graph[from_project][to_project]
        dep_type = edge_data.get("dependency_type", "related")

        relationship_map = {
            "depends": "dependency",
            "uses": "consumer",
            "integrates": "integration",
            "extends": "extension"
        }

        return relationship_map.get(dep_type, "related")

    def _get_shared_knowledge(self, query: str, relevant_projects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Obtener conocimiento compartido relevante"""
        try:
            conn = sqlite3.connect(self.context_db_path)
            cursor = conn.cursor()

            # Buscar conocimiento relevante
            query_terms = query.lower().split()
            knowledge_items = []

            cursor.execute('''
                SELECT context_key, context_value, project_scope, context_type, relevance_score
                FROM shared_context
                WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP
                ORDER BY relevance_score DESC
                LIMIT 10
            ''')

            results = cursor.fetchall()
            conn.close()

            for row in results:
                context_key, context_value, project_scope, context_type, relevance_score = row

                # Calcular relevancia adicional basada en la consulta
                query_relevance = 0.0
                context_text = f"{context_key} {context_value}".lower()

                for term in query_terms:
                    if term in context_text:
                        query_relevance += 0.1

                final_relevance = min(relevance_score + query_relevance, 1.0)

                if final_relevance > 0.2:  # Umbral de relevancia
                    knowledge_items.append({
                        "key": context_key,
                        "value": context_value,
                        "scope": project_scope,
                        "type": context_type,
                        "relevance_score": final_relevance
                    })

            return knowledge_items[:5]  # Top 5 más relevantes

        except Exception as e:
            logger.error(f"Error obteniendo conocimiento compartido: {e}")
            return []

    def _get_cross_project_insights(self, query: str, relevant_projects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Obtener insights cross-proyecto"""
        insights = []

        # Analizar patrones en los proyectos relevantes
        project_types = {}
        technologies = set()
        domains = set()

        for project in relevant_projects:
            proj_data = self.known_projects.get(project["project_id"], {})
            proj_type = proj_data.get("type", "unknown")

            project_types[proj_type] = project_types.get(proj_type, 0) + 1
            technologies.update(proj_data.get("technologies", []))
            domains.update(proj_data.get("domains", []))

        # Generar insights basados en patrones
        if len(relevant_projects) > 1:
            insights.append({
                "type": "multi_project",
                "insight": f"Query spans {len(relevant_projects)} related projects",
                "details": [p["name"] for p in relevant_projects[:3]]
            })

        if len(technologies) > 3:
            insights.append({
                "type": "technology_stack",
                "insight": f"Cross-cutting concern across {len(technologies)} technologies",
                "details": list(technologies)[:5]
            })

        # Insights específicos para consultas chilenas
        query_lower = query.lower()
        if any(term in query_lower for term in ["dte", "sii", "factura", "boleta"]):
            insights.append({
                "type": "regulatory_compliance",
                "insight": "DTE-related query may require coordination between core localization and integration services",
                "affected_projects": ["odoo19-chilean-core", "eergy-services"]
            })

        if any(term in query_lower for term in ["payroll", "nomina", "afp", "isapre"]):
            insights.append({
                "type": "payroll_compliance",
                "insight": "Payroll query should consider Previred integration and labor law compliance",
                "affected_projects": ["odoo19-chilean-core", "ai-service"]
            })

        return insights

    def _get_dependency_context(self, current_project: str = None,
                              relevant_projects: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Obtener contexto de dependencias entre proyectos"""
        dependency_context = []

        if not current_project:
            return dependency_context

        try:
            # Obtener dependencias directas desde la base de datos
            conn = sqlite3.connect(self.context_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT from_project, to_project, dependency_type, strength
                FROM project_dependencies
                WHERE from_project = ? OR to_project = ?
                ORDER BY strength DESC
            ''', (current_project, current_project))

            dependencies = cursor.fetchall()
            conn.close()

            for from_proj, to_proj, dep_type, strength in dependencies:
                other_project = to_proj if from_proj == current_project else from_proj
                direction = "depends_on" if from_proj == current_project else "depended_by"

                if other_project in self.known_projects:
                    dependency_context.append({
                        "project": other_project,
                        "name": self.known_projects[other_project]["name"],
                        "relationship": direction,
                        "type": dep_type,
                        "strength": strength
                    })

        except Exception as e:
            logger.error(f"Error obteniendo contexto de dependencias: {e}")

        return dependency_context

    def _generate_recommendations(self, query: str, relevant_projects: List[Dict[str, Any]],
                                context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generar recomendaciones para consultas multi-proyecto"""
        recommendations = []

        # Recomendación de coordinación si hay múltiples proyectos relevantes
        if len(relevant_projects) > 1:
            recommendations.append({
                "type": "coordination",
                "priority": "high",
                "title": "Consider Cross-Project Coordination",
                "description": f"This query affects {len(relevant_projects)} projects. Consider using the Chilean Compliance Coordinator agent.",
                "action": "Use /agent chilean-compliance-coordinator for holistic analysis"
            })

        # Recomendación de agentes específicos
        query_lower = query.lower()

        if any(term in query_lower for term in ["dte", "sii", "factura"]):
            recommendations.append({
                "type": "specialized_agent",
                "priority": "high",
                "title": "Use DTE Specialist",
                "description": "DTE-related queries should use the specialized DTE agent for compliance accuracy.",
                "action": "Switch to /agent dte-specialist"
            })

        if any(term in query_lower for term in ["payroll", "nomina", "afp", "previred"]):
            recommendations.append({
                "type": "specialized_agent",
                "priority": "high",
                "title": "Use Payroll Compliance Agent",
                "description": "Payroll queries require specialized knowledge of Chilean labor regulations.",
                "action": "Switch to /agent payroll-compliance"
            })

        if any(term in query_lower for term in ["deploy", "release", "production"]):
            recommendations.append({
                "type": "specialized_agent",
                "priority": "high",
                "title": "Use Release Deployment Manager",
                "description": "Deployment queries should consider enterprise-grade release management.",
                "action": "Switch to /agent release-deployment-manager"
            })

        # Recomendación de contexto adicional
        if len(context.get("shared_knowledge", [])) > 0:
            recommendations.append({
                "type": "context_enrichment",
                "priority": "medium",
                "title": "Leverage Shared Knowledge",
                "description": f"Found {len(context['shared_knowledge'])} relevant knowledge items from other projects.",
                "action": "Review shared knowledge for additional context"
            })

        return recommendations

    def create_multi_project_session(self, session_id: str, initial_projects: List[str],
                                   session_context: Dict[str, Any] = None) -> bool:
        """Crear una sesión multi-proyecto"""
        try:
            conn = sqlite3.connect(self.context_db_path)
            cursor = conn.cursor()

            expires_at = datetime.now() + timedelta(hours=24)  # 24 horas

            cursor.execute('''
                INSERT OR REPLACE INTO multi_project_sessions
                (session_id, active_projects, session_context, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (
                session_id,
                json.dumps(initial_projects),
                json.dumps(session_context or {}),
                expires_at.isoformat()
            ))

            conn.commit()
            conn.close()

            logger.info(f"Sesión multi-proyecto creada: {session_id}")
            return True

        except Exception as e:
            logger.error(f"Error creando sesión multi-proyecto: {e}")
            return False

    def add_cross_project_knowledge(self, knowledge_id: str, title: str, content: str,
                                  relevant_projects: List[str], knowledge_type: str,
                                  author: str = None, confidence: float = 1.0) -> bool:
        """Agregar conocimiento cross-proyecto"""
        try:
            conn = sqlite3.connect(self.context_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO cross_project_knowledge
                (knowledge_id, title, content, relevant_projects, knowledge_type, author, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                knowledge_id,
                title,
                content,
                json.dumps(relevant_projects),
                knowledge_type,
                author,
                confidence
            ))

            conn.commit()
            conn.close()

            logger.info(f"Conocimiento cross-proyecto agregado: {knowledge_id}")
            return True

        except Exception as e:
            logger.error(f"Error agregando conocimiento cross-proyecto: {e}")
            return False

    def get_project_overview(self) -> Dict[str, Any]:
        """Obtener overview general de todos los proyectos"""
        try:
            conn = sqlite3.connect(self.context_db_path)
            cursor = conn.cursor()

            # Estadísticas generales
            cursor.execute('SELECT COUNT(*) FROM projects WHERE status = "active"')
            active_projects = cursor.fetchone()[0]

            cursor.execute('SELECT project_type, COUNT(*) FROM projects GROUP BY project_type')
            project_types = dict(cursor.fetchall())

            cursor.execute('SELECT COUNT(*) FROM project_dependencies')
            total_dependencies = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM cross_project_knowledge')
            shared_knowledge = cursor.fetchone()[0]

            conn.close()

            return {
                "total_projects": active_projects,
                "project_types": project_types,
                "total_dependencies": total_dependencies,
                "shared_knowledge_items": shared_knowledge,
                "projects": self.known_projects,
                "dependency_graph_stats": {
                    "nodes": len(self.dependency_graph.nodes),
                    "edges": len(self.dependency_graph.edges)
                }
            }

        except Exception as e:
            logger.error(f"Error obteniendo overview de proyectos: {e}")
            return {"error": str(e)}

    def cleanup_expired_sessions(self) -> int:
        """Limpiar sesiones multi-proyecto expiradas"""
        try:
            conn = sqlite3.connect(self.context_db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM multi_project_sessions WHERE expires_at <= CURRENT_TIMESTAMP')
            deleted_count = cursor.rowcount

            conn.commit()
            conn.close()

            if deleted_count > 0:
                logger.info(f"Limpiadas {deleted_count} sesiones multi-proyecto expiradas")

            return deleted_count

        except Exception as e:
            logger.error(f"Error limpiando sesiones expiradas: {e}")
            return 0

def main():
    """Función principal para testing"""
    manager = MultiProjectContextManager()

    # Probar obtención de contexto relevante
    context = manager.get_relevant_context(
        "How should I implement DTE validation in the AI service?",
        "odoo19-chilean-core"
    )

    print("Contexto relevante obtenido:")
    print(json.dumps(context, indent=2, ensure_ascii=False))

    # Crear sesión multi-proyecto
    session_created = manager.create_multi_project_session(
        "test-session-001",
        ["odoo19-chilean-core", "ai-service"],
        {"purpose": "DTE integration analysis"}
    )

    print(f"Sesión multi-proyecto creada: {session_created}")

    # Agregar conocimiento cross-proyecto
    knowledge_added = manager.add_cross_project_knowledge(
        "dte-ai-integration-pattern",
        "DTE Validation in AI Services",
        "Best practices for integrating DTE validation logic into AI-powered services",
        ["odoo19-chilean-core", "ai-service"],
        "integration_pattern",
        "Copilot CLI"
    )

    print(f"Conocimiento cross-proyecto agregado: {knowledge_added}")

    # Mostrar overview
    overview = manager.get_project_overview()
    print("Overview de proyectos:")
    print(json.dumps(overview, indent=2, ensure_ascii=False))

    manager.cleanup_expired_sessions()

if __name__ == "__main__":
    main()
