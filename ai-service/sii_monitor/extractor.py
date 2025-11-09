"""
Document Extractor

Extrae texto limpio de HTML y PDFs del SII.
"""

import re
from typing import Dict, Optional
from datetime import datetime
import structlog
from bs4 import BeautifulSoup
import pdfplumber

logger = structlog.get_logger()


class DocumentExtractor:
    """Extractor de texto de documentos SII"""
    
    def extract_text_from_html(self, html: str) -> str:
        """
        Extrae texto limpio de HTML.
        
        Args:
            html: HTML crudo
            
        Returns:
            Texto limpio
        """
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remover scripts y estilos
        for script in soup(['script', 'style']):
            script.decompose()
        
        # Obtener texto
        text = soup.get_text()
        
        # Limpiar
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text
    
    def extract_text_from_pdf(self, pdf_bytes: bytes) -> str:
        """
        Extrae texto de PDF.
        
        Args:
            pdf_bytes: Contenido del PDF
            
        Returns:
            Texto extraído
        """
        try:
            import io
            pdf_file = io.BytesIO(pdf_bytes)
            
            text_parts = []
            with pdfplumber.open(pdf_file) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        text_parts.append(text)
            
            return '\n\n'.join(text_parts)
            
        except Exception as e:
            logger.error("pdf_extraction_error", error=str(e))
            return ""
    
    def extract_metadata(self, text: str, url: str) -> Dict:
        """
        Extrae metadatos del documento.
        
        Args:
            text: Texto del documento
            url: URL origen
            
        Returns:
            Dict con metadatos
        """
        metadata = {
            'tipo': self._detect_document_type(text, url),
            'numero': self._extract_number(text),
            'fecha': self._extract_date(text),
            'titulo': self._extract_title(text),
        }
        
        return metadata
    
    def _detect_document_type(self, text: str, url: str) -> str:
        """Detecta tipo de documento"""
        text_lower = text.lower()
        
        if 'circular' in text_lower:
            return 'circular'
        elif 'resolución' in text_lower or 'resolucion' in text_lower:
            return 'resolucion'
        elif 'xsd' in text_lower or 'schema' in text_lower:
            return 'xsd'
        elif 'pregunta' in text_lower:
            return 'faq'
        else:
            return 'otro'
    
    def _extract_number(self, text: str) -> Optional[str]:
        """Extrae número de circular/resolución"""
        # Buscar "Circular N° XX" o "Resolución N° XX"
        patterns = [
            r'Circular\s+N[°º]\s*(\d+)',
            r'Resolución\s+Exenta\s+N[°º]\s*(\d+)',
            r'Circular\s+(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_date(self, text: str) -> Optional[str]:
        """Extrae fecha del documento"""
        # Buscar fechas en formato dd/mm/yyyy o similar
        pattern = r'(\d{1,2})[/-](\d{1,2})[/-](\d{4})'
        match = re.search(pattern, text)
        
        if match:
            day, month, year = match.groups()
            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
        
        return None
    
    def _extract_title(self, text: str) -> str:
        """Extrae título del documento"""
        lines = text.split('\n')
        for line in lines[:10]:  # Primeras 10 líneas
            line = line.strip()
            if len(line) > 10 and len(line) < 200:
                return line
        
        return "Sin título"
    
    def clean_text(self, text: str) -> str:
        """Limpia y normaliza texto"""
        # Remover múltiples espacios
        text = re.sub(r'\s+', ' ', text)
        
        # Remover caracteres especiales problemáticos
        text = text.replace('\x00', '')
        
        # Normalizar saltos de línea
        text = re.sub(r'\n\s*\n', '\n\n', text)
        
        return text.strip()
