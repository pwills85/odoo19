#!/usr/bin/env python3
"""
MCP Server para Contexto Multi-Proyecto
Permite a Copilot CLI gestionar y consultar contexto entre múltiples proyectos relacionados
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List
from mcp.server import Server
import mcp.types as types
from multi_project_context_manager import MultiProjectContextManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MultiProjectContextMCPServer(Server):
    """Servidor MCP para contexto multi-proyecto"""

    def __init__(self):
        super().__init__("multi-project-context-tools", "1.0.0")
        self.context_manager = MultiProjectContextManager()

        # Registrar herramientas disponibles
        self.add_tool(self.get_relevant_context)
        self.add_tool(self.get_project_overview)
        self.add_tool(self.create_multi_project_session)
        self.add_tool(self.add_cross_project_knowledge)
        self.add_tool(self.get_cross_project_knowledge)
        self.add_tool(self.analyze_project_dependencies)
        self.add_tool(self.generate_project_recommendations)

    @types.tool(
        name="get_relevant_context",
        description="Obtener contexto relevante considerando múltiples proyectos relacionados",
        parameters={
            "query": {
                "type": "string",
                "description": "Consulta o pregunta para la cual obtener contexto"
            },
            "current_project": {
                "type": "string",
                "description": "Proyecto actual en el que se está trabajando (opcional)"
            },
            "context_horizon": {
                "type": "integer",
                "description": "Profundidad de contexto a considerar (proyectos relacionados)",
                "default": 2
            }
        }
    )
    async def get_relevant_context(self, query: str, current_project: str = None,
                                 context_horizon: int = 2) -> Dict[str, Any]:
        """Obtener contexto relevante multi-proyecto"""
        try:
            context = self.context_manager.get_relevant_context(
                query=query,
                current_project=current_project,
                context_horizon=context_horizon
            )

            return {
                "query": query,
                "current_project": current_project,
                "context_horizon": context_horizon,
                "context": context,
                "timestamp": "2024-11-10T12:00:00Z"
            }

        except Exception as e:
            logger.error(f"Error obteniendo contexto relevante: {e}")
            return {"error": str(e), "query": query}

    @types.tool(
        name="get_project_overview",
        description="Obtener overview general de todos los proyectos del ecosistema",
        parameters={}
    )
    async def get_project_overview(self) -> Dict[str, Any]:
        """Obtener overview de proyectos"""
        try:
            overview = self.context_manager.get_project_overview()

            return {
                "overview": overview,
                "timestamp": "2024-11-10T12:00:00Z",
                "generated_by": "multi-project-context-manager"
            }

        except Exception as e:
            logger.error(f"Error obteniendo overview de proyectos: {e}")
            return {"error": str(e)}

    @types.tool(
        name="create_multi_project_session",
        description="Crear una sesión de trabajo que abarque múltiples proyectos",
        parameters={
            "session_id": {
                "type": "string",
                "description": "ID único para la sesión multi-proyecto"
            },
            "initial_projects": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Lista de proyectos iniciales para la sesión"
            },
            "session_context": {
                "type": "object",
                "description": "Contexto adicional para la sesión",
                "default": {}
            }
        }
    )
    async def create_multi_project_session(self, session_id: str, initial_projects: List[str],
                                         session_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Crear sesión multi-proyecto"""
        try:
            success = self.context_manager.create_multi_project_session(
                session_id=session_id,
                initial_projects=initial_projects,
                session_context=session_context
            )

            return {
                "success": success,
                "session_id": session_id,
                "initial_projects": initial_projects,
                "session_context": session_context,
                "message": f"Sesión multi-proyecto {'creada' if success else 'no pudo ser creada'}"
            }

        except Exception as e:
            logger.error(f"Error creando sesión multi-proyecto: {e}")
            return {"success": False, "error": str(e), "session_id": session_id}

    @types.tool(
        name="add_cross_project_knowledge",
        description="Agregar conocimiento que es relevante para múltiples proyectos",
        parameters={
            "knowledge_id": {
                "type": "string",
                "description": "ID único para el conocimiento cross-proyecto"
            },
            "title": {
                "type": "string",
                "description": "Título del conocimiento"
            },
            "content": {
                "type": "string",
                "description": "Contenido del conocimiento"
            },
            "relevant_projects": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Lista de proyectos para los que es relevante"
            },
            "knowledge_type": {
                "type": "string",
                "description": "Tipo de conocimiento (pattern, decision, insight, etc.)"
            },
            "author": {
                "type": "string",
                "description": "Autor del conocimiento (opcional)"
            },
            "confidence": {
                "type": "number",
                "description": "Nivel de confianza en el conocimiento (0.0 a 1.0)",
                "default": 1.0
            }
        }
    )
    async def add_cross_project_knowledge(self, knowledge_id: str, title: str, content: str,
                                        relevant_projects: List[str], knowledge_type: str,
                                        author: str = None, confidence: float = 1.0) -> Dict[str, Any]:
        """Agregar conocimiento cross-proyecto"""
        try:
            success = self.context_manager.add_cross_project_knowledge(
                knowledge_id=knowledge_id,
                title=title,
                content=content,
                relevant_projects=relevant_projects,
                knowledge_type=knowledge_type,
                author=author,
                confidence=confidence
            )

            return {
                "success": success,
                "knowledge_id": knowledge_id,
                "title": title,
                "relevant_projects": relevant_projects,
                "message": f"Conocimiento cross-proyecto {'agregado' if success else 'no pudo ser agregado'}"
            }

        except Exception as e:
            logger.error(f"Error agregando conocimiento cross-proyecto: {e}")
            return {"success": False, "error": str(e), "knowledge_id": knowledge_id}

    @types.tool(
        name="get_cross_project_knowledge",
        description="Obtener conocimiento relevante para múltiples proyectos",
        parameters={
            "query": {
                "type": "string",
                "description": "Consulta para buscar conocimiento relevante (opcional)"
            },
            "project_filter": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filtrar por proyectos específicos (opcional)",
                "default": []
            },
            "knowledge_type": {
                "type": "string",
                "description": "Filtrar por tipo de conocimiento (opcional)"
            },
            "limit": {
                "type": "integer",
                "description": "Número máximo de resultados",
                "default": 10
            }
        }
    )
    async def get_cross_project_knowledge(self, query: str = None, project_filter: List[str] = None,
                                        knowledge_type: str = None, limit: int = 10) -> Dict[str, Any]:
        """Obtener conocimiento cross-proyecto"""
        try:
            # Esta funcionalidad necesitaría ser implementada en el context manager
            # Por ahora retornamos una implementación básica
            knowledge_items = []

            # Simular búsqueda de conocimiento (en implementación real, esto vendría de la DB)
            if query and "dte" in query.lower():
                knowledge_items.append({
                    "knowledge_id": "dte-ai-integration-pattern",
                    "title": "DTE Validation in AI Services",
                    "content": "Best practices for integrating DTE validation logic into AI-powered services",
                    "relevant_projects": ["odoo19-chilean-core", "ai-service"],
                    "knowledge_type": "integration_pattern",
                    "confidence": 0.95
                })

            return {
                "query": query,
                "knowledge_items": knowledge_items[:limit],
                "count": len(knowledge_items),
                "filters": {
                    "project_filter": project_filter,
                    "knowledge_type": knowledge_type,
                    "limit": limit
                }
            }

        except Exception as e:
            logger.error(f"Error obteniendo conocimiento cross-proyecto: {e}")
            return {"error": str(e), "query": query}

    @types.tool(
        name="analyze_project_dependencies",
        description="Analizar dependencias y relaciones entre proyectos",
        parameters={
            "project_id": {
                "type": "string",
                "description": "ID del proyecto a analizar"
            },
            "analysis_type": {
                "type": "string",
                "description": "Tipo de análisis (dependencies, impact, risks)",
                "default": "dependencies"
            }
        }
    )
    async def analyze_project_dependencies(self, project_id: str,
                                         analysis_type: str = "dependencies") -> Dict[str, Any]:
        """Analizar dependencias de proyecto"""
        try:
            # Obtener dependencias del proyecto
            dependency_context = self.context_manager._get_dependency_context(project_id, [])

            analysis = {
                "project_id": project_id,
                "analysis_type": analysis_type,
                "dependencies": dependency_context,
                "timestamp": "2024-11-10T12:00:00Z"
            }

            if analysis_type == "impact":
                # Análisis de impacto
                impact_analysis = {
                    "upstream_projects": len([d for d in dependency_context if d["relationship"] == "depends_on"]),
                    "downstream_projects": len([d for d in dependency_context if d["relationship"] == "depended_by"]),
                    "critical_path": self._calculate_critical_path(project_id),
                    "risk_assessment": self._assess_dependency_risks(dependency_context)
                }
                analysis["impact_analysis"] = impact_analysis

            elif analysis_type == "risks":
                # Análisis de riesgos
                risk_analysis = {
                    "single_points_of_failure": self._identify_single_points_of_failure(dependency_context),
                    "circular_dependencies": self._detect_circular_dependencies(project_id),
                    "update_cascades": self._analyze_update_cascades(project_id),
                    "compliance_risks": self._assess_compliance_risks(dependency_context)
                }
                analysis["risk_analysis"] = risk_analysis

            return analysis

        except Exception as e:
            logger.error(f"Error analizando dependencias: {e}")
            return {"error": str(e), "project_id": project_id}

    def _calculate_critical_path(self, project_id: str) -> List[str]:
        """Calcular camino crítico de dependencias"""
        # Implementación simplificada
        return ["odoo19-chilean-core", "infrastructure", project_id]

    def _assess_dependency_risks(self, dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluar riesgos de dependencias"""
        high_risk_deps = [d for d in dependencies if d.get("strength", 0) > 0.8]
        return {
            "high_risk_dependencies": len(high_risk_deps),
            "risk_level": "HIGH" if len(high_risk_deps) > 2 else "MEDIUM",
            "recommendations": ["Implement circuit breakers", "Add health checks"] if len(high_risk_deps) > 2 else []
        }

    def _identify_single_points_of_failure(self, dependencies: List[Dict[str, Any]]) -> List[str]:
        """Identificar puntos únicos de fallo"""
        # Lógica simplificada
        return ["infrastructure"] if any(d["project"] == "infrastructure" for d in dependencies) else []

    def _detect_circular_dependencies(self, project_id: str) -> bool:
        """Detectar dependencias circulares"""
        # Implementación básica - en producción usar NetworkX
        return False

    def _analyze_update_cascades(self, project_id: str) -> Dict[str, Any]:
        """Analizar cascadas de actualización"""
        return {
            "cascade_depth": 2,
            "affected_projects": ["ai-service", "eergy-services"],
            "update_strategy": "rolling_update"
        }

    def _assess_compliance_risks(self, dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluar riesgos de compliance"""
        chilean_projects = [d for d in dependencies if "chilean" in d.get("name", "").lower()]
        return {
            "regulatory_projects": len(chilean_projects),
            "compliance_risk": "HIGH" if len(chilean_projects) > 1 else "LOW",
            "sii_dependencies": any("sii" in d.get("name", "").lower() for d in dependencies)
        }

    @types.tool(
        name="generate_project_recommendations",
        description="Generar recomendaciones para gestión multi-proyecto",
        parameters={
            "context_query": {
                "type": "string",
                "description": "Contexto o consulta para generar recomendaciones"
            },
            "current_project": {
                "type": "string",
                "description": "Proyecto actual (opcional)"
            }
        }
    )
    async def generate_project_recommendations(self, context_query: str,
                                             current_project: str = None) -> Dict[str, Any]:
        """Generar recomendaciones multi-proyecto"""
        try:
            # Obtener contexto relevante
            context = self.context_manager.get_relevant_context(context_query, current_project)

            recommendations = {
                "context_query": context_query,
                "current_project": current_project,
                "recommendations": context.get("recommendations", []),
                "insights": context.get("cross_project_insights", []),
                "timestamp": "2024-11-10T12:00:00Z"
            }

            # Agregar recomendaciones adicionales basadas en el contexto
            if len(context.get("relevant_projects", [])) > 1:
                recommendations["recommendations"].append({
                    "type": "collaboration",
                    "priority": "high",
                    "title": "Cross-Team Collaboration Required",
                    "description": f"This work spans {len(context['relevant_projects'])} teams. Schedule coordination meeting.",
                    "action": "Create shared project board and regular sync meetings"
                })

            # Recomendaciones de arquitectura
            if any(p.get("relevance_score", 0) > 0.7 for p in context.get("relevant_projects", [])):
                recommendations["recommendations"].append({
                    "type": "architecture",
                    "priority": "medium",
                    "title": "Consider Shared Components",
                    "description": "High relevance between projects suggests opportunity for shared libraries or services.",
                    "action": "Analyze common functionality for extraction into shared components"
                })

            return recommendations

        except Exception as e:
            logger.error(f"Error generando recomendaciones: {e}")
            return {"error": str(e), "context_query": context_query}

def main():
    """Función principal del servidor MCP"""
    server = MultiProjectContextMCPServer()

    # Ejecutar servidor
    import asyncio
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
