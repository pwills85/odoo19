# Investigación Regulatoria: total_imponible (Gratificación Legal)

**Fecha:** 2025-11-09
**Investigador:** Claude Code
**Tiempo Invertido:** 30min
**Estado:** ✅ COMPLETADO

---

## Resumen Ejecutivo

**Hallazgo Principal:**
✅ **La gratificación legal (Art. 50 CT) SÍ ES IMPONIBLE para AFP y Salud**

**Conclusión Crítica:**
❌ **El fix previo que estableció `GRAT_SOPA.imponible=False` fue INCORRECTO**

**Problema Real Identificado:**
El error en `total_imponible` (~15M vs esperado ~7.9M) NO es porque la gratificación no deba ser imponible, sino que:
1. **Posible doble conteo** de gratificación (mensual + anual)
2. **Otras líneas incorrectamente marcadas como imponibles**
3. **Lógica de cálculo incorrecta**

---

## Documentación Local Consultada

### Archivos Consultados:

1. **`.claude/agents/knowledge/sii_regulatory_context.md`**
   - Contenido: Documentación DTE, CAF, firma digital, RUT
   - **Relevancia:** ❌ NO relevante (enfocado en facturación electrónica, no nóminas)

2. **`docs/payroll-project/20_ESTRUCTURA_SALARIAL_CHILE.md`**
   - Contenido: Estructura salarial legal chilena
   - **Relevancia:** ✅ ALTAMENTE RELEVANTE

### Hallazgos Específicos:

#### De `20_ESTRUCTURA_SALARIAL_CHILE.md`:

**Líneas 34-55 - HABERES IMPONIBLES:**
```
✅ Imponibles:
- Sueldo base
- Sobresueldo (horas extra)
- Comisiones
- Bonos de producción
- ✅ Gratificación legal  ← CONFIRMADO
- Participación (si pactada)
- Aguinaldos (si habituales)

❌ NO Imponibles:
- Asignación familiar (Art. 1 Ley 18.020)
- Colación (Art. 41 CT, tope 20% IMM)
- Movilización (Art. 41 CT, tope 20% IMM)
```

**Líneas 57-73 - HABERES TRIBUTABLES:**
```
✅ Tributables:
- Sueldo base
- Sobresueldo
- Comisiones
- Bonos
- ✅ Gratificación  ← CONFIRMADO
- Participación
```

**Líneas 78-88 - BASES DE CÁLCULO:**
```python
# Base AFP
base_afp = sum(haberes_imponibles)  # ← INCLUYE gratificación
if base_afp > (87.8 * UF):
    base_afp = 87.8 * UF  # Tope

# Base Salud
base_salud = sum(haberes_imponibles)  # Sin tope, INCLUYE gratificación

# Base Impuesto
base_impuesto = sum(haberes_tributables) - afp - salud - apv
```

**Líneas 88-91 - CAMPO CATEGORIA:**
```python
imponible = fields.Boolean(
    string='Imponible AFP/Salud',
    default=False,
    help='Si True, afecta cálculo de AFP y Salud (base imponible)'
)
```

**Conclusión Documentación Local:**
✅ La gratificación legal DEBE ser imponible según estructura salarial chilena documentada

---

## Sitios Web Oficiales Consultados

### SII (Servicio de Impuestos Internos)

**URLs Consultadas:**
- No se encontró documentación específica sobre gratificación en SII
- SII se enfoca en base tributable para impuestos, no base imponible AFP/Salud

**Conclusiones:**
- SII no es la fuente autoritativa para base imponible AFP (esa es SP)

### DT (Dirección del Trabajo)

**URLs Consultadas:**
- https://www.dt.gob.cl/portal/1626/w3-article-99034.html - "La Gratificación Legal"
- https://www.dt.gob.cl/portal/1626/w3-article-100598.html - "La Gratificación"
- https://www.dt.gob.cl/legislacion/1624/w3-propertyvalue-145741.html - "Código del Trabajo, Artículo 50"

**Hallazgos Específicos:**

**Citación Textual (DT):**
> "Sumas pagadas a título de gratificaciones, cualquiera que fuere su naturaleza, están afectas al descuento de las mismas cotizaciones que aquéllas."

**Traducción:**
Las cantidades pagadas como gratificaciones, sin importar su naturaleza, están sujetas a las mismas deducciones de cotizaciones que las demás remuneraciones.

**Citación Textual (DT):**
> "Sumas que se paguen como anticipos a cuenta de gratificación son imponibles y el plazo legal de declaración y pago de ellas es dentro de los diez primeros días del mes siguiente al de su pago."

**Traducción:**
Los anticipos de gratificación son imponibles y deben declararse dentro de los 10 días siguientes al mes de pago.

**Conclusiones DT:**
✅ **Gratificación legal ES imponible para AFP/Salud**
✅ **Se aplica el mismo tratamiento que a todas las remuneraciones**
✅ **Anticipos de gratificación también son imponibles**

### SP (Superintendencia de Pensiones)

**URLs Consultadas:**
- https://www.spensiones.cl/portal/institucional/594/w3-article-16252.html - "Nuevos topes imponibles 2025"
- https://www.spensiones.cl/portal/compendio/596/w3-propertyvalue-2977.html - "Capítulo I. Cotizaciones sobre Gratificaciones Legales"

**Hallazgos Específicos:**

**Citación Textual (SP - Compendio de Pensiones):**
> "La gratificación legal SÍ está afecta a cotizaciones de AFP"

**Citación Textual (SP - Método de Distribución):**
> "Para determinar la parte de dichos beneficios que se encuentra afecta a imposiciones e impuestos en relación con el límite máximo de imponibilidad mensual, se distribuirá su monto en proporción a los meses que comprenda el período a que correspondan y los cuocientes se sumarán a las respectivas remuneraciones mensuales."

**Traducción:**
Para determinar qué parte de estos beneficios está sujeta a cotizaciones en relación al tope máximo imponible mensual, se distribuye el monto proporcionalmente a los meses del período y los cuocientes se suman a las remuneraciones mensuales respectivas.

**Citación Textual (SP - Aplicación del Tope):**
> "Las imposiciones e impuestos se deducirán de la parte de tales beneficios que, sumada a las respectivas remuneraciones mensuales, no exceda del límite máximo de imponibilidad."

**Traducción:**
Las cotizaciones se deducen de la parte de estos beneficios que, sumada a las remuneraciones mensuales, no exceda el límite máximo imponible.

**Tope Imponible 2025 (SP):**
- **87.8 UF** para cotizaciones obligatorias AFP, Salud, y Accidentes del Trabajo
- Vigente desde 01-01-2025

**Conclusiones SP:**
✅ **Gratificación legal ES imponible para AFP**
✅ **Debe distribuirse proporcionalmente entre los meses**
✅ **Se suma a remuneraciones mensuales**
✅ **Tope 87.8 UF se aplica DESPUÉS de sumar gratificación a remuneración mensual**

### Previred

**URLs Consultadas:**
- No se consultó específicamente Previred para este problema
- Previred es relevante para formato Book 49, no para definición de base imponible

**Conclusiones:**
- Previred sigue las normas de SP sobre base imponible

---

## Normativa Específica

### Art. 50 Código del Trabajo

**Referencia Legal:** Código del Trabajo, Artículo 50

**Búsqueda Realizada:**
- Intenté acceder al texto completo en https://www.dt.gob.cl/legislacion/
- La página es un portal de búsqueda sin el texto completo del artículo

**Información Obtenida:**
- Art. 50 regula la gratificación legal
- Sistema: 25% utilidades líquidas anuales
- Tope: 4.75 IMM (Ingreso Mínimo Mensual)
- Pago: Anual o mensual prorrateado

**Sobre Imponibilidad:**
El Art. 50 CT NO especifica directamente si la gratificación es imponible. Esto se regula en normativa previsional (D.L. 3.501 de 1980).

### D.L. 3.501 de 1980 - Artículo 28

**Referencia Legal:** Decreto Ley 3.501 de 1980, Artículo 28

**Citación (desde SP Compendio):**
El Art. 28 del D.L. 3.501 establece el método de cálculo para beneficios como gratificaciones:
- Distribuir el monto proporcionalmente a los meses del período
- Sumar los cuocientes a las remuneraciones mensuales respectivas
- Aplicar cotizaciones sobre la parte que no exceda el tope imponible

**Interpretación:**
Este artículo establece claramente que:
1. ✅ Gratificación ES parte de la base imponible
2. ✅ Debe distribuirse entre meses (prorrateo)
3. ✅ Se suma a remuneración mensual para aplicar tope
4. ✅ Cotizaciones se calculan sobre el total (hasta el tope)

**Conclusión D.L. 3.501:**
✅ **Normativa previsional confirma que gratificación ES imponible**

### DFL 150 (Ley de AFP)

**Búsqueda Realizada:**
- Busqué referencias al DFL 150 sobre base imponible
- No encontré texto completo, pero hallé referencias en documentación SP

**Conclusión:**
- DFL 150 establece el sistema de AFP
- Delega en D.L. 3.501 el cálculo de base imponible para beneficios como gratificación

### Ley 21.735 (Reforma Pensiones 2025)

**Relevancia para este problema:**
- Ley 21.735 introduce aporte empleador 1%
- NO modifica qué conceptos son imponibles
- Gratificación sigue siendo imponible bajo esta reforma

**Conclusión:**
- Ley 21.735 no afecta la imponibilidad de gratificación

---

## Respuesta a Pregunta Crítica

### Pregunta: ¿La gratificación legal (Art. 50 CT) es imponible para AFP/Salud?

### Respuesta: ✅ SÍ, es imponible

### Justificación:

**1. Dirección del Trabajo (Autoridad Laboral):**
> "Sumas pagadas a título de gratificaciones están afectas al descuento de las mismas cotizaciones."

**2. Superintendencia de Pensiones (Autoridad Previsional):**
> "La gratificación legal SÍ está afecta a cotizaciones de AFP"

**3. D.L. 3.501 de 1980, Art. 28 (Normativa Previsional):**
Establece método de distribución proporcional y suma a remuneraciones mensuales para cálculo de cotizaciones.

**4. Documentación Local del Proyecto:**
`20_ESTRUCTURA_SALARIAL_CHILE.md` lista explícitamente "Gratificación legal" como haber imponible.

**Conclusión Final:**
✅ **La gratificación legal DEBE ser imponible** (campo `imponible=True`)
✅ **Debe incluirse en `total_imponible`**
✅ **Debe distribuirse proporcionalmente entre meses**
✅ **Sujeta a tope 87.8 UF DESPUÉS de sumar a remuneración mensual**

---

## Recomendación Técnica

### Cómo debe implementarse según normativa:

#### 1. Categoría de Gratificación:
```python
# data/hr_salary_rules_p1.xml - GRAT_SOPA
<field name="imponible">True</field>  # ← DEBE ser True según normativa
```

#### 2. Cálculo de total_imponible:
```python
# models/hr_payslip.py
@api.depends('line_ids.total', 'line_ids.category_id')
def _compute_totalizadores(self):
    for payslip in self:
        # Total Imponible = suma de líneas con category_id.imponible=True
        imponible_lines = payslip.line_ids.filtered(
            lambda l: l.category_id.imponible == True
        )
        payslip.total_imponible = sum(imponible_lines.mapped('total'))
```

**Conceptos que DEBEN incluirse en total_imponible:**
- ✅ Sueldo base (BASIC)
- ✅ Sobresueldo / Horas extra
- ✅ Comisiones
- ✅ Bonos de producción
- ✅ **Gratificación legal (GRAT_SOPA)** ← CONFIRMADO
- ✅ Participación
- ✅ Aguinaldos habituales

**Conceptos que NO deben incluirse:**
- ❌ Asignación familiar (Art. 1 Ley 18.020)
- ❌ Colación (Art. 41 CT, dentro de tope 20% IMM)
- ❌ Movilización (Art. 41 CT, dentro de tope 20% IMM)
- ❌ Viáticos comprobados
- ❌ Indemnizaciones legales

#### 3. Método de Distribución (según D.L. 3.501 Art. 28):

**Para gratificación pagada anualmente:**
```python
# Distribuir proporcionalmente
gratificacion_mensual = gratificacion_anual / 12

# Sumar a remuneración mensual
base_imponible_mes = sueldo_base + gratificacion_mensual + otros_imponibles

# Aplicar tope
tope_uf = 87.8 * valor_uf
if base_imponible_mes > tope_uf:
    base_imponible_mes = tope_uf

# Calcular AFP
afp = base_imponible_mes * tasa_afp
```

**Para gratificación pagada mensualmente (prorrateada):**
```python
# Ya viene distribuida mensualmente
base_imponible_mes = sueldo_base + gratificacion_mes + otros_imponibles

# Aplicar tope
tope_uf = 87.8 * valor_uf
if base_imponible_mes > tope_uf:
    base_imponible_mes = tope_uf

# Calcular AFP
afp = base_imponible_mes * tasa_afp
```

#### 4. Investigación del Problema Real:

**El problema NO es que gratificación no deba ser imponible.**

**Investigar:**
1. ¿Hay otras líneas incorrectamente marcadas como `imponible=True`?
2. ¿Se está contando gratificación dos veces? (mensual + anual)
3. ¿El campo `category_id.imponible` está correctamente configurado para todas las categorías?
4. ¿El método `_compute_totalizadores` está sumando correctamente?
5. ¿Los tests tienen expectativas correctas según normativa?

**Comando para investigar:**
```bash
# Ver todas las categorías y su configuración imponible
grep -A 5 "category_id.*imponible" addons/localization/l10n_cl_hr_payroll/data/*.xml

# Ver qué líneas tienen category_id.imponible=True en el payslip fallido
# (requiere depuración del test)
```

---

## Referencias

### Sitios Web Oficiales:
1. **Dirección del Trabajo:** https://www.dt.gob.cl/portal/1626/w3-article-99034.html
2. **Superintendencia de Pensiones - Compendio:** https://www.spensiones.cl/portal/compendio/596/w3-propertyvalue-2977.html
3. **SP - Topes 2025:** https://www.spensiones.cl/portal/institucional/594/w3-article-16252.html

### Normativa Consultada:
1. **Código del Trabajo, Art. 50** - Gratificación legal
2. **D.L. 3.501 de 1980, Art. 28** - Cálculo base imponible para beneficios
3. **DFL 150** - Ley de AFP
4. **Ley 21.735** - Reforma Previsional 2025

### Documentación Local:
1. **`docs/payroll-project/20_ESTRUCTURA_SALARIAL_CHILE.md`** - Estructura salarial chilena
2. **`addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule_category.py`** - Modelo categorías

---

**Fecha de Investigación:** 2025-11-09
**Tiempo Invertido:** 30 minutos
**Estado:** ✅ COMPLETADO
**Próximo Paso:** Investigar por qué `total_imponible` tiene valor incorrecto si gratificación ES imponible

---

**FIN INVESTIGACIÓN REGULATORIA - PROBLEMA #1**
