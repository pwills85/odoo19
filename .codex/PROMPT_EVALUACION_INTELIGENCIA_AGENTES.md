# 🧪 Prompt de Evaluación de Inteligencia y Agudeza - Auditoría Técnica Comparativa

**Propósito**: Evaluar capacidades de análisis técnico, agudeza y aplicación de máximas en agentes especializados  
**Formato**: Prompt único para múltiples agentes (comparación objetiva)  
**Duración Estimada**: 15-30 minutos por agente  
**Fecha**: 2025-11-08

---

## 🎯 INSTRUCCIONES PARA EL AGENTE

**IMPORTANTE**: Este es un ejercicio de evaluación de capacidades. Debes:
1. ✅ Registrar el tiempo total que te toma completar la tarea
2. ✅ Aplicar estrictamente las máximas establecidas en `docs/prompts_desarrollo/`
3. ✅ Proporcionar análisis técnico profundo con evidencia concreta
4. ✅ Distinguir claramente entre módulos custom y módulos base de Odoo 19 CE
5. ✅ Priorizar hallazgos según impacto real (P0-P3)

**CONTEXTO DEL PROYECTO**:
Estamos desarrollando MÓDULOS CUSTOM (ADDONS) que se integran con Odoo 19 CE base:
- `l10n_cl_dte`: Facturación electrónica chilena
- `l10n_cl_hr_payroll`: Nómina chilena
- `l10n_cl_financial_reports`: Reportes financieros chilenos

Estos módulos custom:
- ✅ Heredan de modelos base usando `_inherit`
- ✅ Extienden funcionalidad de módulos base (account, purchase, hr, etc.)
- ✅ Se instalan como addons adicionales sobre Odoo 19 CE
- ❌ NO modifican el código core de Odoo 19 CE

---

## 📋 TAREA DE AUDITORÍA TÉCNICA

### Objetivo

Realizar una auditoría técnica profunda del siguiente código y contexto, identificando:
1. **Problemas técnicos** (bugs, errores, inconsistencias)
2. **Violaciones de máximas** (MAXIMAS_AUDITORIA.md, MAXIMAS_DESARROLLO.md)
3. **Problemas de arquitectura** (integración con Odoo 19 CE base)
4. **Riesgos regulatorios** (correctitud legal, cumplimiento SII)
5. **Oportunidades de mejora** (performance, seguridad, calidad)

### Código a Auditar

```python
# Archivo: addons/localization/l10n_cl_dte/models/dte_validation_helper.py
# Contexto: Helper para validación de DTEs recibidos desde SII

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import re
from datetime import datetime

class DTEValidationHelper(models.Model):
    """
    Helper para validación de DTEs recibidos.
    
    Migrado desde Odoo 18 - Compatible con Odoo 18 y 19
    """
    _name = 'dte.validation.helper'
    _description = 'DTE Validation Helper'
    
    def validate_dte_received(self, dte_xml, company_id):
        """
        Valida un DTE recibido desde SII.
        
        Args:
            dte_xml: XML del DTE como string
            company_id: ID de la compañía receptora
        
        Returns:
            dict: {'valid': bool, 'errors': list, 'dte_data': dict}
        """
        errors = []
        dte_data = {}
        
        try:
            # Parse XML básico
            import xml.etree.ElementTree as ET
            root = ET.fromstring(dte_xml)
            
            # Extraer datos básicos
            dte_data['folio'] = root.find('.//Folio').text if root.find('.//Folio') is not None else None
            dte_data['rut_emisor'] = root.find('.//RUTEmisor').text if root.find('.//RUTEmisor') is not None else None
            dte_data['rut_receptor'] = root.find('.//RUTReceptor').text if root.find('.//RUTReceptor') is not None else None
            dte_data['tipo_dte'] = root.find('.//TipoDTE').text if root.find('.//TipoDTE') is not None else None
            dte_data['fecha_emision'] = root.find('.//FchEmis').text if root.find('.//FchEmis') is not None else None
            
            # Validación 1: Tipo DTE válido
            valid_types = ['33', '34', '39', '41', '52', '56', '61', '70']
            if dte_data['tipo_dte'] not in valid_types:
                errors.append(f"Tipo DTE {dte_data['tipo_dte']} no válido")
            
            # Validación 2: RUT emisor
            if dte_data['rut_emisor']:
                if not self._validate_rut(dte_data['rut_emisor']):
                    errors.append(f"RUT emisor inválido: {dte_data['rut_emisor']}")
            
            # Validación 3: RUT receptor debe coincidir con compañía
            company = self.env['res.company'].browse(company_id)
            if dte_data['rut_receptor']:
                company_rut = company.vat or ''
                if dte_data['rut_receptor'].replace('.', '').replace('-', '') != company_rut.replace('.', '').replace('-', ''):
                    errors.append(f"RUT receptor {dte_data['rut_receptor']} no coincide con compañía {company_rut}")
            
            # Validación 4: Fecha no futura
            if dte_data['fecha_emision']:
                fecha = datetime.strptime(dte_data['fecha_emision'], '%Y-%m-%d')
                if fecha > datetime.now():
                    errors.append(f"Fecha de emisión {dte_data['fecha_emision']} es futura")
            
            # Validación 5: Folio único por tipo
            if dte_data['folio'] and dte_data['tipo_dte']:
                existing = self.env['account.move'].search([
                    ('dte_folio', '=', dte_data['folio']),
                    ('dte_code', '=', dte_data['tipo_dte']),
                    ('company_id', '=', company_id)
                ], limit=1)
                if existing:
                    errors.append(f"DTE con folio {dte_data['folio']} ya existe")
            
            return {
                'valid': len(errors) == 0,
                'errors': errors,
                'dte_data': dte_data
            }
            
        except Exception as e:
            return {
                'valid': False,
                'errors': [f"Error al procesar XML: {str(e)}"],
                'dte_data': {}
            }
    
    def _validate_rut(self, rut_str):
        """
        Valida RUT chileno.
        
        Args:
            rut_str: RUT como string (ej: "12345678-5" o "CL12345678-5")
        
        Returns:
            bool: True si es válido
        """
        if not rut_str:
            return False
        
        # Limpiar espacios
        rut_clean = rut_str.strip()
        
        # Validar formato básico
        if '-' not in rut_clean:
            return False
        
        parts = rut_clean.split('-')
        if len(parts) != 2:
            return False
        
        rut_number = parts[0].replace('.', '')
        rut_dv = parts[1].upper()
        
        # Validar que número sea numérico
        if not rut_number.isdigit():
            return False
        
        # Validar dígito verificador
        if rut_dv not in '0123456789K':
            return False
        
        # Calcular módulo 11
        multiplier = [2, 3, 4, 5, 6, 7]
        sum_result = 0
        rut_reversed = rut_number[::-1]
        
        for i, digit in enumerate(rut_reversed):
            sum_result += int(digit) * multiplier[i % len(multiplier)]
        
        remainder = sum_result % 11
        calculated_dv = 11 - remainder
        
        if calculated_dv == 11:
            calculated_dv = 0
        elif calculated_dv == 10:
            calculated_dv = 'K'
        else:
            calculated_dv = str(calculated_dv)
        
        return calculated_dv == rut_dv
    
    @api.model
    def process_incoming_dte_batch(self, dte_list, company_id):
        """
        Procesa un lote de DTEs recibidos.
        
        Args:
            dte_list: Lista de XMLs de DTEs
            company_id: ID de la compañía
        
        Returns:
            dict: Estadísticas del procesamiento
        """
        stats = {
            'total': len(dte_list),
            'valid': 0,
            'invalid': 0,
            'errors': []
        }
        
        for dte_xml in dte_list:
            result = self.validate_dte_received(dte_xml, company_id)
            if result['valid']:
                stats['valid'] += 1
                # Crear registro en dte.inbox
                self.env['dte.inbox'].create({
                    'dte_type': result['dte_data']['tipo_dte'],
                    'folio': result['dte_data']['folio'],
                    'rut_emisor': result['dte_data']['rut_emisor'],
                    'fecha_recepcion': fields.Datetime.now(),
                    'company_id': company_id,
                    'xml_content': dte_xml,
                    'state': 'received'
                })
            else:
                stats['invalid'] += 1
                stats['errors'].extend(result['errors'])
        
        return stats
```

### Contexto Adicional

**Archivos Relacionados**:
- `addons/localization/l10n_cl_dte/models/dte_inbox.py`: Modelo que almacena DTEs recibidos
- `addons/localization/l10n_cl_dte/libs/dte_structure_validator.py`: Validador de estructura DTE
- `addons/localization/l10n_cl_dte/__manifest__.py`: Manifest del módulo

**Dependencias Declaradas**:
```python
'depends': [
    'base',
    'account',
    'l10n_latam_base',
    'l10n_latam_invoice_document',
    'l10n_cl',
    'purchase',
    'stock',
    'web',
]
```

**Alcance Regulatorio EERGYGROUP**:
- Solo DTE tipos: 33, 34, 52, 56, 61 (B2B)
- NO incluye: 39, 41, 46, 70 (BHE/Retail)

---

## 📊 FORMATO DEL REPORTE DE AUDITORÍA

### 1. Registro de Tiempo

**INICIO**: [Registra hora de inicio]  
**FIN**: [Registra hora de finalización]  
**DURACIÓN TOTAL**: [Calcula tiempo transcurrido en minutos]

### 2. Resumen Ejecutivo

- Total de hallazgos identificados
- Distribución por prioridad (P0, P1, P2, P3)
- Hallazgos críticos que requieren acción inmediata
- Impacto general estimado

### 3. Análisis Detallado por Hallazgo

Para cada hallazgo, proporciona:

#### 3.1 Identificación
- **ID**: `DTE-VALID-XXX` (identificador único)
- **Prioridad**: P0 / P1 / P2 / P3
- **Categoría**: Bug / Violación Máxima / Arquitectura / Regulatorio / Mejora
- **Archivo/Línea**: Referencia exacta

#### 3.2 Descripción
- Descripción clara y concisa del problema
- Contexto técnico relevante

#### 3.3 Justificación Técnica
- Evidencia concreta (código, referencias)
- Comparación con estándares Odoo 19 CE
- Comparación con máximas establecidas
- Distinción entre módulos custom vs módulos base

#### 3.4 Impacto
- Impacto funcional (¿bloquea producción?)
- Impacto regulatorio (¿incumple ley?)
- Impacto en calidad/desarrollo
- Riesgo estimado

#### 3.5 Solución Propuesta
- Código de ejemplo (antes/después)
- Tests requeridos
- DoD (Definition of Done)

### 4. Tabla Resumen de Hallazgos

| ID | Prioridad | Categoría | Archivo:Línea | Descripción Breve | Impacto |
|----|-----------|-----------|---------------|-------------------|---------|
| ... | ... | ... | ... | ... | ... |

### 5. Recomendaciones Prioritizadas

Ordenadas por P0 → P1 → P2 → P3:
1. [Acción inmediata P0]
2. [Acción alta prioridad P1]
3. [Mejora P2]
4. [Cosmético P3]

### 6. Métricas de Calidad

- **Cobertura de análisis**: ¿Qué aspectos cubriste? (funcionalidad, seguridad, performance, legalidad, arquitectura)
- **Profundidad**: ¿Qué tan profundo fue tu análisis?
- **Precisión**: ¿Qué tan precisa es tu evidencia?

---

## 🎯 CRITERIOS DE EVALUACIÓN

Tu análisis será evaluado según:

1. **Agudeza Técnica** (40%):
   - Identificación precisa de problemas técnicos
   - Detección de bugs y errores sutiles
   - Análisis de impacto real vs teórico

2. **Aplicación de Máximas** (30%):
   - Referencias explícitas a máximas establecidas
   - Verificación de cumplimiento con MAXIMAS_AUDITORIA.md y MAXIMAS_DESARROLLO.md
   - Distinción correcta entre módulos custom y módulos base

3. **Calidad del Análisis** (20%):
   - Evidencia técnica precisa (archivo:línea)
   - Justificación técnica sólida
   - Soluciones propuestas viables y completas

4. **Eficiencia** (10%):
   - Tiempo total de análisis
   - Completitud del reporte
   - Claridad y estructura

---

## ⚠️ RESTRICCIONES

- ❌ NO modifiques código (solo análisis)
- ❌ NO asumas funcionalidades que deben estar en módulos base
- ✅ SOLO analiza y reporta
- ✅ DISTINGUE entre código custom vs código base
- ✅ APLICA estrictamente las máximas establecidas

---

## 📝 INSTRUCCIONES FINALES

1. **Registra tu tiempo de inicio** antes de comenzar
2. **Realiza el análisis técnico** siguiendo el formato especificado
3. **Registra tu tiempo de finalización** al terminar
4. **Genera el reporte completo** en formato Markdown estructurado
5. **Guarda el reporte** como `AUDITORIA_EVALUACION_AGENTE_[NOMBRE_AGENTE]_[FECHA].md`

---

## 🚀 COMENZAR AUDITORÍA

**HORA DE INICIO**: [Registra aquí]

Procede con el análisis técnico del código proporcionado siguiendo todas las instrucciones y criterios establecidos.

---

**Nota**: Este prompt está diseñado para evaluar capacidades de análisis técnico, agudeza y aplicación de máximas. El mismo prompt será utilizado por múltiples agentes para permitir comparación objetiva de resultados.

