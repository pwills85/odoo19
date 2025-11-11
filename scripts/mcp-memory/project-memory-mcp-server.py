#!/usr/bin/env python3
"""
MCP Server para Memoria Persistente del Proyecto Odoo19
Permite a Copilot CLI recordar y acceder al conocimiento del proyecto
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List
from mcp.server import Server
import mcp.types as types
from project_memory_manager import ProjectMemoryManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProjectMemoryMCPServer(Server):
    """Servidor MCP para memoria persistente del proyecto"""

    def __init__(self):
        super().__init__("project-memory-tools", "1.0.0")
        self.memory_manager = ProjectMemoryManager()

        # Registrar herramientas disponibles
        self.add_tool(self.remember_project_context)
        self.add_tool(self.recall_project_context)
        self.add_tool(self.get_architectural_decisions)
        self.add_tool(self.add_architectural_decision)
        self.add_tool(self.get_code_patterns)
        self.add_tool(self.add_code_pattern)
        self.add_tool(self.save_session_context)
        self.add_tool(self.load_session_context)
        self.add_tool(self.get_memory_stats)
        self.add_tool(self.record_usage_metric)
        self.add_tool(self.get_usage_metrics)

    @types.tool(
        name="remember_project_context",
        description="Recordar un nuevo elemento de conocimiento del proyecto",
        parameters={
            "key": {
                "type": "string",
                "description": "Clave única para el conocimiento"
            },
            "value": {
                "type": "string",
                "description": "Valor o información a recordar"
            },
            "category": {
                "type": "string",
                "description": "Categoría del conocimiento (project, regulatory, architecture, security, testing)"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Etiquetas para clasificación",
                "default": []
            },
            "confidence": {
                "type": "number",
                "description": "Nivel de confianza (0.0 a 1.0)",
                "default": 1.0
            },
            "source": {
                "type": "string",
                "description": "Fuente del conocimiento (archivo, decisión, etc.)"
            },
            "ttl_days": {
                "type": "integer",
                "description": "Días hasta expiración (opcional)"
            }
        }
    )
    async def remember_project_context(self, key: str, value: str, category: str,
                                     tags: List[str] = None, confidence: float = 1.0,
                                     source: str = None, ttl_days: int = None) -> Dict[str, Any]:
        """Recordar conocimiento del proyecto"""
        try:
            success = self.memory_manager.remember_context(
                key=key,
                value=value,
                category=category,
                tags=tags,
                confidence=confidence,
                source=source,
                ttl_days=ttl_days
            )

            return {
                "success": success,
                "key": key,
                "category": category,
                "message": f"Conocimiento {'recordado' if success else 'no pudo ser recordado'}"
            }

        except Exception as e:
            logger.error(f"Error recordando contexto: {e}")
            return {"success": False, "error": str(e), "key": key}

    @types.tool(
        name="recall_project_context",
        description="Recordar elementos de conocimiento del proyecto",
        parameters={
            "key": {
                "type": "string",
                "description": "Clave específica a recordar (opcional)"
            },
            "category": {
                "type": "string",
                "description": "Filtrar por categoría (opcional)"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filtrar por etiquetas (opcional)",
                "default": []
            },
            "limit": {
                "type": "integer",
                "description": "Número máximo de resultados",
                "default": 10
            }
        }
    )
    async def recall_project_context(self, key: str = None, category: str = None,
                                   tags: List[str] = None, limit: int = 10) -> Dict[str, Any]:
        """Recordar conocimiento del proyecto"""
        try:
            results = self.memory_manager.recall_context(
                key=key,
                category=category,
                tags=tags,
                limit=limit
            )

            return {
                "results": results,
                "count": len(results),
                "filters": {
                    "key": key,
                    "category": category,
                    "tags": tags
                }
            }

        except Exception as e:
            logger.error(f"Error recordando contexto: {e}")
            return {"error": str(e), "results": []}

    @types.tool(
        name="get_architectural_decisions",
        description="Obtener decisiones arquitectónicas del proyecto",
        parameters={
            "status": {
                "type": "string",
                "description": "Estado de las decisiones (active, deprecated, superseded)",
                "default": "active"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filtrar por etiquetas",
                "default": []
            }
        }
    )
    async def get_architectural_decisions(self, status: str = "active",
                                        tags: List[str] = None) -> Dict[str, Any]:
        """Obtener decisiones arquitectónicas"""
        try:
            decisions = self.memory_manager.get_architectural_decisions(
                status=status,
                tags=tags
            )

            return {
                "decisions": decisions,
                "count": len(decisions),
                "status_filter": status,
                "tags_filter": tags
            }

        except Exception as e:
            logger.error(f"Error obteniendo decisiones arquitectónicas: {e}")
            return {"error": str(e), "decisions": []}

    @types.tool(
        name="add_architectural_decision",
        description="Agregar una nueva decisión arquitectónica",
        parameters={
            "decision_id": {
                "type": "string",
                "description": "ID único de la decisión"
            },
            "title": {
                "type": "string",
                "description": "Título de la decisión"
            },
            "description": {
                "type": "string",
                "description": "Descripción del problema/contexto"
            },
            "decision": {
                "type": "string",
                "description": "La decisión tomada"
            },
            "context": {
                "type": "string",
                "description": "Contexto adicional (opcional)"
            },
            "alternatives": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Alternativas consideradas",
                "default": []
            },
            "consequences": {
                "type": "string",
                "description": "Consecuencias de la decisión"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Etiquetas para clasificación",
                "default": []
            }
        }
    )
    async def add_architectural_decision(self, decision_id: str, title: str,
                                       description: str, decision: str,
                                       context: str = None, alternatives: List[str] = None,
                                       consequences: str = None, tags: List[str] = None) -> Dict[str, Any]:
        """Agregar decisión arquitectónica"""
        try:
            success = self.memory_manager.add_architectural_decision(
                decision_id=decision_id,
                title=title,
                description=description,
                decision=decision,
                context=context,
                alternatives=alternatives,
                consequences=consequences,
                tags=tags
            )

            return {
                "success": success,
                "decision_id": decision_id,
                "message": f"Decisión arquitectónica {'agregada' if success else 'no pudo ser agregada'}"
            }

        except Exception as e:
            logger.error(f"Error agregando decisión arquitectónica: {e}")
            return {"success": False, "error": str(e), "decision_id": decision_id}

    @types.tool(
        name="get_code_patterns",
        description="Obtener patrones de código aprendidos",
        parameters={
            "category": {
                "type": "string",
                "description": "Categoría de patrones (validation, security, architecture, etc.)"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filtrar por etiquetas",
                "default": []
            },
            "limit": {
                "type": "integer",
                "description": "Número máximo de resultados",
                "default": 20
            }
        }
    )
    async def get_code_patterns(self, category: str = None, tags: List[str] = None,
                              limit: int = 20) -> Dict[str, Any]:
        """Obtener patrones de código"""
        try:
            patterns = self.memory_manager.get_code_patterns(
                category=category,
                tags=tags,
                limit=limit
            )

            return {
                "patterns": patterns,
                "count": len(patterns),
                "filters": {
                    "category": category,
                    "tags": tags,
                    "limit": limit
                }
            }

        except Exception as e:
            logger.error(f"Error obteniendo patrones de código: {e}")
            return {"error": str(e), "patterns": []}

    @types.tool(
        name="add_code_pattern",
        description="Agregar un nuevo patrón de código aprendido",
        parameters={
            "pattern_id": {
                "type": "string",
                "description": "ID único del patrón"
            },
            "name": {
                "type": "string",
                "description": "Nombre del patrón"
            },
            "description": {
                "type": "string",
                "description": "Descripción del patrón"
            },
            "category": {
                "type": "string",
                "description": "Categoría (validation, security, architecture, etc.)"
            },
            "pattern": {
                "type": "string",
                "description": "Código del patrón correcto"
            },
            "anti_pattern": {
                "type": "string",
                "description": "Qué evitar (anti-patrón)"
            },
            "example_good": {
                "type": "string",
                "description": "Ejemplo de implementación correcta"
            },
            "example_bad": {
                "type": "string",
                "description": "Ejemplo de lo que NO hacer"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Etiquetas para clasificación",
                "default": []
            }
        }
    )
    async def add_code_pattern(self, pattern_id: str, name: str, description: str,
                             category: str, pattern: str, anti_pattern: str = None,
                             example_good: str = None, example_bad: str = None,
                             tags: List[str] = None) -> Dict[str, Any]:
        """Agregar patrón de código"""
        try:
            success = self.memory_manager.add_code_pattern(
                pattern_id=pattern_id,
                name=name,
                description=description,
                category=category,
                pattern=pattern,
                anti_pattern=anti_pattern,
                example_good=example_good,
                example_bad=example_bad,
                tags=tags
            )

            return {
                "success": success,
                "pattern_id": pattern_id,
                "message": f"Patrón de código {'agregado' if success else 'no pudo ser agregado'}"
            }

        except Exception as e:
            logger.error(f"Error agregando patrón de código: {e}")
            return {"success": False, "error": str(e), "pattern_id": pattern_id}

    @types.tool(
        name="save_session_context",
        description="Guardar contexto de una sesión de trabajo",
        parameters={
            "session_id": {
                "type": "string",
                "description": "ID único de la sesión"
            },
            "context_data": {
                "type": "object",
                "description": "Datos de contexto a guardar"
            },
            "active_tasks": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tareas activas en la sesión",
                "default": []
            },
            "recent_files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Archivos trabajados recientemente",
                "default": []
            },
            "ttl_hours": {
                "type": "integer",
                "description": "Horas hasta expiración",
                "default": 24
            }
        }
    )
    async def save_session_context(self, session_id: str, context_data: Dict[str, Any],
                                 active_tasks: List[str] = None, recent_files: List[str] = None,
                                 ttl_hours: int = 24) -> Dict[str, Any]:
        """Guardar contexto de sesión"""
        try:
            success = self.memory_manager.save_session_context(
                session_id=session_id,
                context_data=context_data,
                active_tasks=active_tasks,
                recent_files=recent_files,
                ttl_hours=ttl_hours
            )

            return {
                "success": success,
                "session_id": session_id,
                "message": f"Contexto de sesión {'guardado' if success else 'no pudo ser guardado'}"
            }

        except Exception as e:
            logger.error(f"Error guardando contexto de sesión: {e}")
            return {"success": False, "error": str(e), "session_id": session_id}

    @types.tool(
        name="load_session_context",
        description="Cargar contexto de una sesión previa",
        parameters={
            "session_id": {
                "type": "string",
                "description": "ID de la sesión a cargar"
            }
        }
    )
    async def load_session_context(self, session_id: str) -> Dict[str, Any]:
        """Cargar contexto de sesión"""
        try:
            context = self.memory_manager.load_session_context(session_id)

            if context:
                return {
                    "found": True,
                    "session_id": session_id,
                    "context": context
                }
            else:
                return {
                    "found": False,
                    "session_id": session_id,
                    "message": "Sesión no encontrada o expirada"
                }

        except Exception as e:
            logger.error(f"Error cargando contexto de sesión: {e}")
            return {"found": False, "error": str(e), "session_id": session_id}

    @types.tool(
        name="get_memory_stats",
        description="Obtener estadísticas del sistema de memoria",
        parameters={}
    )
    async def get_memory_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas de memoria"""
        try:
            stats = self.memory_manager.get_memory_stats()

            # Agregar información adicional
            stats["memory_system"] = "project-knowledge"
            stats["timestamp"] = "2024-11-10T12:00:00Z"

            return stats

        except Exception as e:
            logger.error(f"Error obteniendo estadísticas de memoria: {e}")
            return {"error": str(e)}

    @types.tool(
        name="record_usage_metric",
        description="Registrar una métrica de uso del sistema",
        parameters={
            "metric_type": {
                "type": "string",
                "description": "Tipo de métrica (usage, performance, quality, etc.)"
            },
            "metric_name": {
                "type": "string",
                "description": "Nombre específico de la métrica"
            },
            "value": {
                "type": "number",
                "description": "Valor de la métrica"
            },
            "tags": {
                "type": "object",
                "description": "Etiquetas adicionales para la métrica",
                "default": {}
            }
        }
    )
    async def record_usage_metric(self, metric_type: str, metric_name: str, value: float,
                                tags: Dict[str, Any] = None) -> Dict[str, Any]:
        """Registrar métrica de uso"""
        try:
            success = self.memory_manager.record_metric(
                metric_type=metric_type,
                metric_name=metric_name,
                value=value,
                tags=tags
            )

            return {
                "success": success,
                "metric": f"{metric_type}.{metric_name}",
                "value": value,
                "message": f"Métrica {'registrada' if success else 'no pudo ser registrada'}"
            }

        except Exception as e:
            logger.error(f"Error registrando métrica: {e}")
            return {"success": False, "error": str(e)}

    @types.tool(
        name="get_usage_metrics",
        description="Obtener métricas de uso del sistema",
        parameters={
            "metric_type": {
                "type": "string",
                "description": "Tipo de métrica a filtrar (opcional)"
            },
            "hours": {
                "type": "integer",
                "description": "Horas hacia atrás para consultar",
                "default": 24
            }
        }
    )
    async def get_usage_metrics(self, metric_type: str = None, hours: int = 24) -> Dict[str, Any]:
        """Obtener métricas de uso"""
        try:
            metrics = self.memory_manager.get_usage_metrics(
                metric_type=metric_type,
                hours=hours
            )

            # Agrupar métricas por tipo
            grouped_metrics = {}
            for metric in metrics:
                key = f"{metric['metric_type']}.{metric['metric_name']}"
                if key not in grouped_metrics:
                    grouped_metrics[key] = []
                grouped_metrics[key].append({
                    "value": metric["value"],
                    "timestamp": metric["timestamp"],
                    "tags": metric["tags"]
                })

            return {
                "metrics": grouped_metrics,
                "total_records": len(metrics),
                "time_range_hours": hours,
                "metric_types": list(set(m["metric_type"] for m in metrics))
            }

        except Exception as e:
            logger.error(f"Error obteniendo métricas: {e}")
            return {"error": str(e), "metrics": {}}

def main():
    """Función principal del servidor MCP"""
    server = ProjectMemoryMCPServer()

    # Ejecutar servidor
    import asyncio
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
