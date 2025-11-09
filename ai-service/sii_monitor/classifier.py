"""
Impact Classifier

Clasifica impacto de cambios normativos en componentes del sistema.
"""

from datetime import datetime, date
from typing import Dict, List
import structlog

logger = structlog.get_logger()


class ImpactClassifier:
    """Clasifica y prioriza noticias del SII"""
    
    def calculate_priority(self, analysis: Dict) -> int:
        """
        Calcula prioridad 1-5 basado en múltiples factores.
        
        Args:
            analysis: Dict con análisis de la noticia
            
        Returns:
            Prioridad (1=bajo, 5=crítico)
        """
        score = 0
        impacto = analysis.get('impacto', {})
        
        # Breaking change = crítico
        if impacto.get('breaking_change'):
            score += 5
        
        # Requiere certificación = alto
        if impacto.get('requiere_certificacion'):
            score += 3
        
        # Nivel de impacto
        nivel_scores = {'alto': 3, 'medio': 2, 'bajo': 1}
        score += nivel_scores.get(impacto.get('nivel', 'medio'), 2)
        
        # Fecha vigencia cercana
        vigencia_str = analysis.get('vigencia')
        if vigencia_str:
            try:
                vigencia = datetime.fromisoformat(vigencia_str).date()
                days_until = (vigencia - date.today()).days
                
                if days_until < 30:
                    score += 2
                elif days_until < 90:
                    score += 1
            except:
                pass
        
        # Normalizar a 1-5
        priority = min(5, max(1, score // 2))
        
        logger.info("priority_calculated", 
                   score=score, 
                   priority=priority,
                   breaking=impacto.get('breaking_change'))
        
        return priority
    
    def determine_actions(self, analysis: Dict) -> List[str]:
        """Determina acciones concretas basadas en el análisis"""
        actions = analysis.get('acciones_requeridas', [])
        
        if not actions:
            impacto = analysis.get('impacto', {})
            
            if impacto.get('breaking_change'):
                actions.append("⚠️ URGENTE: Actualizar componentes afectados")
                actions.append("Certificar cambios en ambiente Maullin")
            
            if impacto.get('requiere_certificacion'):
                actions.append("Realizar certificación en Maullin (sandbox SII)")
            
            componentes = impacto.get('componentes_afectados', [])
            if componentes:
                actions.append(f"Revisar componentes: {', '.join(componentes)}")
        
        return actions if actions else ["Revisar y evaluar impacto"]
