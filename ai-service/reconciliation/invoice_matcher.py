# -*- coding: utf-8 -*-
"""
Invoice Matcher - Reconciliación inteligente con IA
Usa embeddings para matching semántico de facturas con POs
"""

from sentence_transformers import SentenceTransformer
import numpy as np
from typing import List, Dict, Optional
import structlog

logger = structlog.get_logger()


class InvoiceMatcher:
    """
    Matcher inteligente de facturas recibidas con órdenes de compra.
    
    Usa embeddings semánticos para encontrar la PO que mejor coincide
    con una factura recibida, incluso si los textos no son idénticos.
    """
    
    def __init__(self, model_name: str = None):
        """
        Inicializa el matcher.
        
        Args:
            model_name: Nombre del modelo de embeddings
        """
        # Modelo multilingüe optimizado para español
        self.model_name = model_name or 'paraphrase-multilingual-MiniLM-L12-v2'
        
        logger.info("loading_embedding_model", model=self.model_name)
        
        # Cargar modelo de sentence-transformers
        self.model = SentenceTransformer(self.model_name)
        
        logger.info("embedding_model_loaded")
    
    def match_invoice_to_po(
        self, 
        invoice_data: Dict, 
        pending_pos: List[Dict],
        threshold: float = 0.85
    ) -> Dict:
        """
        Encuentra la PO que mejor coincide con una factura recibida.
        
        Algoritmo:
        1. Crear embedding de la factura (líneas)
        2. Crear embeddings de cada PO pendiente
        3. Calcular similaridad coseno
        4. Retornar PO con mayor similaridad si > threshold
        
        Args:
            invoice_data: Datos de la factura recibida
            pending_pos: Lista de POs pendientes
            threshold: Umbral mínimo de similaridad (0-1)
        
        Returns:
            Dict con resultado del matching:
                - po_id: ID de la PO (o None)
                - confidence: Nivel de confianza (0-100)
                - line_matches: Detalle de coincidencias por línea
        """
        logger.info("matching_invoice_to_po",
                   invoice_folio=invoice_data.get('folio'),
                   pending_pos_count=len(pending_pos))
        
        if not pending_pos:
            logger.info("no_pending_pos")
            return {
                'po_id': None,
                'confidence': 0.0,
                'line_matches': [],
                'message': 'No hay órdenes de compra pendientes'
            }
        
        try:
            # 1. Crear texto representativo de la factura
            invoice_text = self._create_invoice_text(invoice_data)
            
            # 2. Crear embedding de la factura
            invoice_embedding = self.model.encode([invoice_text])[0]
            
            # 3. Crear embeddings de cada PO y calcular similaridad
            best_match = None
            best_similarity = 0.0
            
            for po in pending_pos:
                # Crear texto representativo de la PO
                po_text = self._create_po_text(po)
                
                # Crear embedding de la PO
                po_embedding = self.model.encode([po_text])[0]
                
                # Calcular similaridad coseno
                similarity = self._cosine_similarity(invoice_embedding, po_embedding)
                
                logger.debug("po_similarity_calculated",
                           po_id=po.get('id'),
                           similarity=similarity)
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = po
            
            # 4. Verificar si supera threshold
            if best_similarity >= threshold:
                # Matching exitoso
                confidence = best_similarity * 100  # Convertir a porcentaje
                
                logger.info("matching_successful",
                           po_id=best_match.get('id'),
                           confidence=confidence)
                
                # Matching detallado por líneas (opcional, para mejor precisión)
                line_matches = self._match_lines(
                    invoice_data.get('lineas', []),
                    best_match.get('lineas', [])
                )
                
                return {
                    'po_id': best_match.get('id'),
                    'confidence': round(confidence, 2),
                    'line_matches': line_matches,
                    'message': 'Matching exitoso'
                }
            else:
                # No hay match suficiente
                logger.info("no_match_found",
                           best_similarity=best_similarity,
                           threshold=threshold)
                
                return {
                    'po_id': None,
                    'confidence': round(best_similarity * 100, 2),
                    'line_matches': [],
                    'message': f'Mejor match: {best_similarity*100:.1f}% (umbral: {threshold*100}%)'
                }
                
        except Exception as e:
            logger.error("matching_error", error=str(e))
            return {
                'po_id': None,
                'confidence': 0.0,
                'line_matches': [],
                'message': f'Error: {str(e)}'
            }
    
    def _create_invoice_text(self, invoice_data: Dict) -> str:
        """
        Crea texto representativo de la factura para embedding.
        
        Concatena: proveedor + monto + descripción de productos
        """
        parts = []
        
        # Proveedor
        if invoice_data.get('razon_social_emisor'):
            parts.append(invoice_data['razon_social_emisor'])
        
        # Monto (importante para matching)
        if invoice_data.get('monto_total'):
            parts.append(f"Total: {invoice_data['monto_total']}")
        
        # Líneas de productos
        for linea in invoice_data.get('lineas', []):
            if linea.get('nombre'):
                parts.append(linea['nombre'])
            if linea.get('descripcion'):
                parts.append(linea['descripcion'])
        
        return ' '.join(parts)
    
    def _create_po_text(self, po_data: Dict) -> str:
        """Crea texto representativo de la PO para embedding"""
        parts = []
        
        # Proveedor
        if po_data.get('partner_name'):
            parts.append(po_data['partner_name'])
        
        # Monto
        if po_data.get('amount_total'):
            parts.append(f"Total: {po_data['amount_total']}")
        
        # Líneas
        for linea in po_data.get('lineas', []):
            if linea.get('product_name'):
                parts.append(linea['product_name'])
            if linea.get('description'):
                parts.append(linea['description'])
        
        return ' '.join(parts)
    
    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        Calcula similaridad coseno entre dos vectores.
        
        Returns:
            float: Similaridad (0-1)
        """
        # Normalizar vectores
        vec1_norm = vec1 / np.linalg.norm(vec1)
        vec2_norm = vec2 / np.linalg.norm(vec2)
        
        # Producto punto = cosine similarity
        similarity = np.dot(vec1_norm, vec2_norm)
        
        return float(similarity)
    
    def _match_lines(self, invoice_lines: List[Dict], po_lines: List[Dict]) -> List[Dict]:
        """
        Hace matching detallado línea por línea.
        
        Returns:
            List[Dict]: Coincidencias por línea
        """
        matches = []
        
        for inv_line in invoice_lines:
            inv_text = f"{inv_line.get('nombre', '')} {inv_line.get('descripcion', '')}"
            inv_embedding = self.model.encode([inv_text])[0]
            
            best_po_line = None
            best_similarity = 0.0
            
            for po_line in po_lines:
                po_text = f"{po_line.get('product_name', '')} {po_line.get('description', '')}"
                po_embedding = self.model.encode([po_text])[0]
                
                similarity = self._cosine_similarity(inv_embedding, po_embedding)
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_po_line = po_line
            
            if best_similarity > 0.7:  # Umbral para líneas
                matches.append({
                    'invoice_line': inv_line.get('nombre'),
                    'po_line': best_po_line.get('product_name') if best_po_line else None,
                    'similarity': round(best_similarity * 100, 2)
                })
        
        return matches

