# -*- coding: utf-8 -*-
"""
Stock Plugin Implementation
============================

Plugin for Inventory Management (Stock).

Specializes in:
- Inventory operations
- Warehouse management
- Product tracking
- Stock moves and pickings

Author: EERGYGROUP - Phase 2B Implementation 2025-10-24
"""

from typing import Dict, List, Optional, Any
import structlog
from plugins.base import AIPlugin

logger = structlog.get_logger(__name__)


class StockPlugin(AIPlugin):
    """
    Plugin for Inventory Management (stock module).

    Provides specialized assistance for:
    - Gestión de inventario
    - Operaciones de almacén
    - Transferencias y movimientos
    - Trazabilidad de productos
    - Valorización de inventario
    """

    def __init__(self):
        self.anthropic_client = None  # Lazy initialization
        logger.info("stock_plugin_initialized")

    def get_module_name(self) -> str:
        return "stock"

    def get_display_name(self) -> str:
        return "Gestión de Inventario (Stock)"

    def get_version(self) -> str:
        return "1.0.0"

    def get_system_prompt(self) -> str:
        """
        Specialized system prompt for inventory management.

        Focuses on stock operations, warehouse management, and traceability.
        """
        return """Eres un **experto en Gestión de Inventario** para Odoo 19.

**Tu Expertise:**
- Operaciones de inventario (entradas, salidas, ajustes)
- Gestión de almacenes y ubicaciones
- Transferencias internas y entre bodegas
- Pickings (recolección, empaque, despacho)
- Trazabilidad (lotes, números de serie)
- Valorización de inventario (FIFO, Average, Standard)
- Reglas de abastecimiento y reordenamiento
- Kits y paquetes

**Operaciones que Conoces:**
- Recepciones de compra
- Entregas de venta
- Ajustes de inventario
- Transferencias internas
- Backorders y reservas
- Routes y push/pull rules
- Operaciones multialmacén

**Tu Misión:**
Ayudar con operaciones de inventario de forma **clara**, **práctica** y **eficiente**.

**Cómo Respondes:**
1. **Paso a Paso:** Instrucciones concretas (menús, wizards, botones)
2. **Flujos Completos:** Describe procesos de inicio a fin
3. **Best Practices:** Sugiere mejores prácticas operativas
4. **Troubleshooting:** Explica errores comunes y soluciones
5. **Ejemplos Visuales:** Describe pantallas y campos de Odoo

**Formato:**
- Usa **negritas** para términos clave (Picking, Location, Quant)
- Usa listas numeradas para procesos paso a paso
- Usa ✅ ❌ ⚠️ para estados y validaciones
- Incluye rutas exactas en Odoo: Inventario > Operaciones > Transferencias

**Casos de Uso Comunes:**
- Realizar ajuste de inventario
- Procesar recepción de compra
- Preparar envío de venta
- Transferir entre ubicaciones
- Consultar stock disponible
- Resolver productos sin stock
- Configurar reordenamiento automático

**Terminología:**
- **Picking:** Operación de movimiento (receipt, delivery, internal)
- **Move:** Movimiento individual de producto
- **Quant:** Cantidad disponible en ubicación
- **Route:** Ruta de abastecimiento
- **Procure:** Método de aprovisionamiento (compra/fabricación)

**LÍMITE:** Solo responde sobre inventario en Odoo. Si la pregunta está fuera de tu expertise, indícalo claramente.
"""

    async def validate(
        self,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate stock operation.

        Note: Basic validation for stock operations.
        Future enhancement: Add specialized validations.

        Args:
            data: Stock operation data
            context: Additional context

        Returns:
            Dict with validation result
        """
        logger.info(
            "stock_validation_started",
            operation_type=data.get('operation_type'),
            product_id=data.get('product_id')
        )

        try:
            # Basic validation (can be enhanced in future)
            errors = []
            warnings = []

            # Check required fields
            if not data.get('product_id'):
                errors.append("Producto no especificado")

            if not data.get('quantity') or data.get('quantity') <= 0:
                errors.append("Cantidad debe ser mayor a 0")

            if not data.get('location_id'):
                errors.append("Ubicación de origen no especificada")

            if not data.get('location_dest_id'):
                warnings.append("Ubicación de destino no especificada")

            # Determine recommendation
            if errors:
                recommendation = "reject"
                confidence = 10.0
            elif warnings:
                recommendation = "review"
                confidence = 70.0
            else:
                recommendation = "approve"
                confidence = 95.0

            result = {
                "success": len(errors) == 0,
                "confidence": confidence,
                "errors": errors,
                "warnings": warnings,
                "recommendation": recommendation
            }

            logger.info(
                "stock_validation_completed",
                recommendation=recommendation,
                errors_count=len(errors)
            )

            return result

        except Exception as e:
            logger.error(
                "stock_validation_error",
                error=str(e),
                exc_info=True
            )

            # Graceful degradation
            return {
                "success": False,
                "confidence": 0.0,
                "errors": [f"Error en validación: {str(e)[:100]}"],
                "warnings": [],
                "recommendation": "review"
            }

    def get_supported_operations(self) -> List[str]:
        return ['validate', 'chat', 'inventory_check', 'traceability']

    def get_knowledge_base_path(self) -> str:
        return "stock"

    def get_tags(self) -> List[str]:
        return [
            'stock',
            'inventario',
            'almacen',
            'bodega',
            'warehouse',
            'picking',
            'transferencia',
            'producto',
            'ubicacion',
            'lote',
            'serie',
            'trazabilidad'
        ]
