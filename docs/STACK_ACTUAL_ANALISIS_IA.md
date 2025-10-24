# ✅ ANÁLISIS: STACK ACTUAL CON OLLAMA

**Fecha:** 2025-10-22  
**Hallazgo:** YA TIENES Ollama + Claude configurados

---

## 🎯 ESTADO ACTUAL VERIFICADO

### **Docker Compose (líneas 162-204):**

```yaml
# ✅ YA TIENES OLLAMA
ollama:
  image: ollama/ollama:latest
  container_name: odoo19_ollama
  expose:
    - "11434"
  volumes:
    - ollama_data:/root/.ollama

# ✅ YA TIENES AI SERVICE
ai-service:
  depends_on:
    - ollama  # ← Depende de Ollama
  environment:
    - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}  # ← Claude
    - OLLAMA_URL=http://ollama:11434           # ← Ollama
```

### **AI Service Config (config.py líneas 29-41):**

```python
# ✅ CLAUDE CONFIGURADO
anthropic_api_key: str
anthropic_model: str = "claude-3-5-sonnet-20241022"

# ✅ OLLAMA CONFIGURADO
ollama_url: str = "http://ollama:11434"
ollama_model: str = "llama2"
```

---

## 🔍 ANÁLISIS: ¿QUÉ FALTA?

### **✅ LO QUE YA TIENES:**

1. ✅ **Ollama container** funcionando
2. ✅ **Claude API** configurado
3. ✅ **AI Service** con ambos
4. ✅ **Embeddings** configurados (sentence-transformers)
5. ✅ **ChromaDB** para vectores
6. ✅ **Redis** para cache

### **❌ LO QUE FALTA IMPLEMENTAR:**

1. ❌ **Lógica de routing** (decidir cuándo usar Ollama vs Claude)
2. ❌ **Matching inteligente** con OC (no implementado)
3. ❌ **Validación semántica** (no implementado)
4. ❌ **Detección anomalías** (no implementado)
5. ❌ **Inicialización Ollama** (descargar modelo al inicio)

---

## 💡 RECOMENDACIÓN ACTUALIZADA

### **TU STACK ES PERFECTO - Solo falta la lógica:**

```
Stack Actual:
✅ Ollama (container funcionando)
✅ Claude (API key configurada)
✅ AI Service (FastAPI listo)
✅ Embeddings (sentence-transformers)

Lo que falta:
❌ Código que USE Ollama y Claude inteligentemente
```

---

## 🚀 PLAN DE IMPLEMENTACIÓN ACTUALIZADO

### **NO necesitas cambiar infraestructura, solo agregar código:**

#### **1. Inicializar Ollama (5 min)**

```python
# ai-service/startup.py (NUEVO)
import httpx
import structlog
from config import settings

logger = structlog.get_logger()

async def initialize_ollama():
    """Descarga modelo Ollama al iniciar"""
    
    logger.info("initializing_ollama", model=settings.ollama_model)
    
    async with httpx.AsyncClient() as client:
        # Pull model si no existe
        response = await client.post(
            f"{settings.ollama_url}/api/pull",
            json={"name": settings.ollama_model},
            timeout=300.0  # 5 min timeout
        )
        
        if response.status_code == 200:
            logger.info("ollama_model_ready", model=settings.ollama_model)
        else:
            logger.error("ollama_pull_failed", error=response.text)
```

```python
# ai-service/main.py (MODIFICAR)
@app.on_event("startup")
async def startup_event():
    # Agregar inicialización Ollama
    await initialize_ollama()
    
    logger.info("ai_service_started",
                anthropic_model=settings.anthropic_model,
                ollama_model=settings.ollama_model)
```

---

#### **2. AI Router (30 min)**

```python
# ai-service/core/ai_router.py (NUEVO)
import httpx
import anthropic
from typing import Dict, Any
from config import settings
import structlog

logger = structlog.get_logger()

class AIRouter:
    """Decide qué modelo usar según complejidad"""
    
    def __init__(self):
        self.claude = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        self.ollama_url = settings.ollama_url
    
    async def complete(self, prompt: str, complexity: str = "auto") -> str:
        """
        Completa prompt con el modelo apropiado
        
        Args:
            prompt: Texto a completar
            complexity: auto|simple|complex
        """
        
        # Auto-detectar complejidad si no se especifica
        if complexity == "auto":
            complexity = self._assess_complexity(prompt)
        
        logger.info("ai_routing", complexity=complexity)
        
        if complexity == "simple":
            return await self._ollama_complete(prompt)
        else:
            return await self._claude_complete(prompt)
    
    async def embed(self, text: str) -> list[float]:
        """Genera embeddings con Ollama (siempre)"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.ollama_url}/api/embeddings",
                json={
                    "model": settings.ollama_model,
                    "prompt": text
                }
            )
            return response.json()["embedding"]
    
    async def _ollama_complete(self, prompt: str) -> str:
        """Completa con Ollama"""
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": settings.ollama_model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            return response.json()["response"]
    
    async def _claude_complete(self, prompt: str) -> str:
        """Completa con Claude"""
        message = self.claude.messages.create(
            model=settings.anthropic_model,
            max_tokens=settings.anthropic_max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    
    def _assess_complexity(self, prompt: str) -> str:
        """Evalúa complejidad del prompt"""
        
        # Heurísticas simples
        if len(prompt) < 500:
            return "simple"
        
        if any(word in prompt.lower() for word in [
            "analiza", "detecta", "explica", "razona", "compara"
        ]):
            return "complex"
        
        return "simple"
```

---

#### **3. Matching Inteligente con OC (2 horas)**

```python
# ai-service/matching/po_matcher.py (NUEVO)
from typing import Dict, List, Optional
from core.ai_router import AIRouter
import structlog
import json

logger = structlog.get_logger()

class PurchaseOrderMatcher:
    """Matching inteligente de DTEs con Purchase Orders"""
    
    def __init__(self):
        self.ai = AIRouter()
    
    async def find_matching_po(
        self,
        dte_data: Dict,
        open_pos: List[Dict]
    ) -> Dict:
        """
        Encuentra OC que corresponde al DTE
        
        Returns:
            {
                'po_id': int o None,
                'confidence': 0-100,
                'reasoning': str,
                'alternatives': List[Dict]
            }
        """
        
        # 1. Matching exacto (rápido)
        exact_match = self._exact_match(dte_data, open_pos)
        if exact_match and exact_match['confidence'] > 95:
            return exact_match
        
        # 2. Matching semántico con embeddings (Ollama)
        semantic_match = await self._semantic_match(dte_data, open_pos)
        if semantic_match and semantic_match['confidence'] > 85:
            return semantic_match
        
        # 3. Análisis profundo con Claude (casos complejos)
        deep_match = await self._deep_analysis(dte_data, open_pos)
        return deep_match
    
    def _exact_match(self, dte_data: Dict, open_pos: List[Dict]) -> Optional[Dict]:
        """Matching exacto por referencia"""
        
        refs = dte_data.get('references', [])
        
        for po in open_pos:
            if po['name'] in refs:
                return {
                    'po_id': po['id'],
                    'confidence': 100,
                    'reasoning': f"Referencia exacta: {po['name']}",
                    'alternatives': []
                }
        
        return None
    
    async def _semantic_match(
        self,
        dte_data: Dict,
        open_pos: List[Dict]
    ) -> Optional[Dict]:
        """Matching con embeddings (Ollama)"""
        
        # Generar embedding del DTE
        dte_text = f"{dte_data['supplier_name']} {dte_data['total_amount']}"
        dte_embedding = await self.ai.embed(dte_text)
        
        # Comparar con OCs
        matches = []
        for po in open_pos:
            po_text = f"{po['partner_name']} {po['amount_total']}"
            po_embedding = await self.ai.embed(po_text)
            
            # Similitud coseno
            similarity = self._cosine_similarity(dte_embedding, po_embedding)
            
            if similarity > 0.7:
                matches.append({
                    'po_id': po['id'],
                    'confidence': similarity * 100,
                    'reasoning': f"Similitud semántica: {similarity:.2%}"
                })
        
        if matches:
            best = max(matches, key=lambda x: x['confidence'])
            best['alternatives'] = [m for m in matches if m != best][:3]
            return best
        
        return None
    
    async def _deep_analysis(
        self,
        dte_data: Dict,
        open_pos: List[Dict]
    ) -> Dict:
        """Análisis profundo con Claude"""
        
        prompt = f"""
Encuentra la Orden de Compra que corresponde a esta factura:

FACTURA:
- Proveedor: {dte_data['supplier_name']}
- RUT: {dte_data['supplier_rut']}
- Monto: ${dte_data['total_amount']:,.2f}
- Items: {len(dte_data['items'])} productos
- Referencias: {', '.join(dte_data.get('references', []))}

ÓRDENES DE COMPRA ABIERTAS:
{json.dumps(open_pos[:10], indent=2)}

Analiza y determina cuál OC corresponde.
Considera:
- Referencias (pueden tener formato diferente)
- Proveedor (debe coincidir)
- Monto (puede variar ±10%)
- Productos (deben ser similares)

Responde en JSON:
{{
    "po_id": <id de la OC o null>,
    "confidence": <0-100>,
    "reasoning": "<explicación detallada>",
    "alternatives": [<otras OCs posibles>]
}}
"""
        
        response = await self.ai.complete(prompt, complexity="complex")
        
        try:
            result = json.loads(response)
            return result
        except json.JSONDecodeError:
            logger.error("claude_json_parse_error", response=response)
            return {
                'po_id': None,
                'confidence': 0,
                'reasoning': 'Error al parsear respuesta Claude',
                'alternatives': []
            }
    
    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calcula similitud coseno entre dos vectores"""
        import numpy as np
        return float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))
```

---

#### **4. Endpoint en AI Service (30 min)**

```python
# ai-service/main.py (AGREGAR)
from matching.po_matcher import PurchaseOrderMatcher

# Singleton
_po_matcher = None

def get_po_matcher():
    global _po_matcher
    if _po_matcher is None:
        _po_matcher = PurchaseOrderMatcher()
    return _po_matcher

@app.post("/api/ai/match-po")
async def match_purchase_order(
    request: Dict[str, Any],
    _: str = Depends(verify_api_key)
):
    """
    Encuentra OC que corresponde a un DTE recibido
    
    Request:
    {
        "dte_data": {...},
        "open_pos": [...]
    }
    
    Response:
    {
        "po_id": int o null,
        "confidence": 0-100,
        "reasoning": str,
        "alternatives": [...]
    }
    """
    
    matcher = get_po_matcher()
    
    result = await matcher.find_matching_po(
        dte_data=request['dte_data'],
        open_pos=request['open_pos']
    )
    
    logger.info("po_matching_completed",
                po_id=result['po_id'],
                confidence=result['confidence'])
    
    return result
```

---

## 📊 RESUMEN: QUÉ HACER

### **Tu infraestructura está LISTA:**

```yaml
✅ Ollama container: Funcionando
✅ Claude API: Configurada
✅ AI Service: Listo para recibir código
✅ Redis: Cache disponible
✅ ChromaDB: Vector DB lista
```

### **Solo necesitas AGREGAR código:**

| Archivo | Acción | Tiempo |
|---------|--------|--------|
| `ai-service/startup.py` | Crear (inicializar Ollama) | 5 min |
| `ai-service/core/ai_router.py` | Crear (routing inteligente) | 30 min |
| `ai-service/matching/po_matcher.py` | Crear (matching OC) | 2 horas |
| `ai-service/main.py` | Modificar (agregar endpoints) | 30 min |

**Total:** 3 horas de desarrollo

---

## ✅ CONCLUSIÓN

### **Mi análisis anterior estaba CORRECTO en concepto, pero:**

**❌ Asumí que NO tenías Ollama**  
**✅ TIENES Ollama + Claude configurados**

### **Nueva recomendación:**

✅ **USA tu stack actual (Ollama + Claude)**  
✅ **Solo agrega la lógica de routing**  
✅ **3 horas de desarrollo vs 2-3 días de setup**

### **Distribución óptima (ya tienes la infra):**

- **Ollama (30%):** Embeddings + matching simple
- **Claude (70%):** Análisis complejo + validación

**¿Procedemos con implementar la lógica en tu stack actual?** 🚀
