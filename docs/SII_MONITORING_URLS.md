# SII - URLs de Monitoreo Permanente

Documento con las URLs oficiales del SII de Chile para consulta permanente de actualizaciones normativas, circulares, resoluciones y aclaraciones relacionadas con facturación electrónica y DTE.

**Fecha de creación:** 2025-10-22  
**Propósito:** Mantener al proyecto actualizado con cambios normativos del SII

---

## 🎯 URLs Principales para Monitoreo

### 1. Normativa Factura Electrónica (PRINCIPAL)
**URL:** https://www.sii.cl/factura_electronica/normativa.htm

**Contenido:**
- Resoluciones vigentes sobre DTE
- Normas y procedimientos de emisión
- Cambios en esquemas XML
- Actualizaciones de tipos de documentos

**Frecuencia sugerida:** Semanal

---

### 2. Circulares del SII
**URL:** https://www.sii.cl/normativa_legislacion/circulares/

**Contenido:**
- Circulares anuales (2025, 2024, etc.)
- Interpretaciones oficiales de normativa
- Instrucciones para contribuyentes
- Aclaraciones sobre procedimientos

**Frecuencia sugerida:** Quincenal

**Ejemplo circulares recientes:**
- Circular N°35/2025 - Ley N° 21.713 (cumplimiento obligaciones tributarias)

---

### 3. Resoluciones Exentas
**URL:** https://www.sii.cl/normativa_legislacion/resoluciones/

**Contenido:**
- Resoluciones sobre facturación electrónica
- Cambios en requisitos técnicos
- Nuevas obligaciones para contribuyentes

**Frecuencia sugerida:** Quincenal

**Resoluciones críticas recientes:**
- **Resolución Exenta N° 121 (14/01/2025):** Refuerzo facturas/boletas en supermercados y restaurantes
- **Resolución Exenta N° 53 (vigencia 01/05/2025):** Representación impresa/virtual de boletas electrónicas B2C
- **Resolución Exenta N° 36 (15/03/2024):** Requisitos de descripción de productos/servicios en DTE

---

### 4. Preguntas Frecuentes (FAQ)
**URL:** https://www.sii.cl/preguntas_frecuentes/factura_electronica/arbol_factura_electronica_2349.htm

**Contenido:**
- Respuestas oficiales a consultas comunes
- Aclaraciones sobre procedimientos
- Casos de uso específicos
- Requisitos técnicos

**Frecuencia sugerida:** Mensual

**Temas clave:**
- Conservación de DTE (6 años mínimo)
- Información obligatoria en facturas
- Desafiliación del sistema
- Sistemas gratuitos del SII

---

### 5. Servicios Online - Factura Electrónica
**URL:** https://www.sii.cl/servicios_online/1039-normativa_fe-1184.html

**Contenido:**
- Portal de facturación electrónica
- Herramientas en línea
- Certificación de sistemas
- Actualizaciones de servicios

**Frecuencia sugerida:** Mensual

---

### 6. Ambiente de Certificación (Maullin)
**URL:** https://maullin.sii.cl/cvc/dte/certificacion_dte.html

**Contenido:**
- Requisitos de certificación
- Casos de prueba
- Ambiente de testing
- Documentación técnica para certificación

**Frecuencia sugerida:** Trimestral (o antes de certificar cambios)

---

### 7. Documentación Técnica DTE
**URL:** https://www.sii.cl/factura_electronica/factura_mercado/formato_dte.htm

**Contenido:**
- Esquemas XSD
- Formatos de documentos
- Especificaciones técnicas
- Ejemplos de XML

**Frecuencia sugerida:** Trimestral

---

## 📋 Checklist de Monitoreo

### Revisión Semanal
- [ ] Normativa Factura Electrónica
- [ ] Revisar noticias en portada SII: https://www.sii.cl/

### Revisión Quincenal
- [ ] Circulares nuevas
- [ ] Resoluciones exentas

### Revisión Mensual
- [ ] Preguntas frecuentes (actualizaciones)
- [ ] Servicios online
- [ ] Noticias y destacados: https://www.sii.cl/destacados/factura_electronica/

### Revisión Trimestral
- [ ] Documentación técnica DTE
- [ ] Ambiente de certificación
- [ ] Cambios en esquemas XSD

---

## 🚨 Alertas Críticas Actuales (2025)

### Resolución N° 53 - Mayo 2025
**Fecha vigencia:** 01/05/2025  
**Impacto:** ALTO  
**Descripción:** Boletas electrónicas B2C requieren representación impresa o virtual según método de pago

**Acción requerida:**
- Revisar generador DTE tipo 39/41 (boletas)
- Validar formato de impresión
- Actualizar documentación

### Resolución N° 36 - Julio 2024
**Fecha vigencia:** 01/07/2024  
**Impacto:** MEDIO  
**Descripción:** Requisitos de claridad y precisión en descripción de productos/servicios

**Acción requerida:**
- Validar campo descripción en generadores DTE
- Revisar límites de caracteres
- Actualizar validaciones

---

## 📊 Impacto en Nuestro Proyecto

### Componentes Afectados por Cambios Normativos

| Componente | Sección SII | Impacto |
|------------|-------------|---------|
| Generadores DTE (33,34,52,56,61) | Normativa FE | Alto |
| XSD Validators | Documentación Técnica | Alto |
| TED Generator | Formato DTE | Alto |
| Digital Signer | Normativa FE | Medio |
| SII SOAP Client | Ambiente Certificación | Medio |
| UI/UX Module | Resoluciones | Bajo-Medio |

---

## 🔄 Proceso de Actualización

### Cuando se detecta un cambio normativo:

1. **Evaluación (Día 1)**
   - Leer circular/resolución completa
   - Identificar impacto en componentes
   - Determinar fecha de vigencia

2. **Análisis Técnico (Días 2-3)**
   - Revisar cambios en XSD (si aplica)
   - Identificar cambios en generadores
   - Evaluar impacto en validaciones

3. **Planificación (Día 4)**
   - Crear issue en proyecto
   - Asignar prioridad según fecha vigencia
   - Definir alcance de cambios

4. **Implementación (Variable)**
   - Actualizar generadores DTE
   - Modificar validadores
   - Actualizar tests
   - Actualizar documentación

5. **Certificación (Antes de vigencia)**
   - Testing en ambiente Maullin
   - Validación con casos de prueba SII
   - Documentar compliance

6. **Despliegue (Antes de vigencia)**
   - Actualizar producción
   - Notificar usuarios
   - Monitorear errores

---

## 📞 Contactos SII

**Mesa de Ayuda Factura Electrónica:**
- Teléfono: 223951108
- Horario: Lunes a Viernes 9:00-18:00

**Correo consultas técnicas:**
- factura.electronica@sii.cl

**Portal de consultas:**
- https://www.sii.cl/servicios_online/

---

## 📚 Recursos Adicionales

### Legislación Base
- Resolución Ex. SII N° 4.576 (1998) - Autoriza uso de facturas electrónicas
- Resolución Ex. SII N° 45 (2003) - Procedimientos certificación
- Ley N° 19.983 (2004) - Regulación firma electrónica

### Guías y Manuales
- Guía de Certificación DTE: https://maullin.sii.cl/cvc/dte/
- Manual de Usuario Portal MIPYME: https://www4.sii.cl/mipymeinternetui/

---

## 🔖 Notas Importantes

1. **XSD Schemas:** Los esquemas XSD oficiales deben descargarse del SII, no de terceros
2. **Ambiente Sandbox:** Maullin puede tener cambios antes que Palena (producción)
3. **Retrocompatibilidad:** SII generalmente mantiene compatibilidad por 6 meses
4. **Certificación:** Cambios mayores requieren re-certificación en Maullin

---

## Historial de Actualizaciones

| Fecha | Cambio Detectado | Impacto | Estado |
|-------|------------------|---------|--------|
| 2025-10-22 | Documento creado | - | ✅ Completo |
| 2025-01-14 | Resolución N° 121 | Medio | 🔍 En revisión |
| 2024-03-15 | Resolución N° 36 | Alto | ✅ Implementado |

---

**Responsable de monitoreo:** Equipo desarrollo l10n_cl_dte  
**Última revisión:** 2025-10-22  
**Próxima revisión:** 2025-10-29
