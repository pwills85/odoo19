# Prompt Perfecto: Auditoría Profunda Módulos Odoo 19 CE

## 🎯 Prompt Principal (Usar con `codex-odoo-dev`)

```bash
codex-odoo-dev "
Realiza una auditoría técnica completa y exhaustiva de los módulos de Odoo 19 CE en desarrollo del proyecto EERGYGROUP.

## CONTEXTO DEL PROYECTO
- Cliente: EERGYGROUP
- Framework: Odoo 19 Community Edition
- Módulos en desarrollo:
  * l10n_cl_dte (Documentos Tributarios Electrónicos)
  * l10n_cl_hr_payroll (Nómina chilena)
  * l10n_cl_financial_reports (Reportes financieros)

## CONOCIMIENTO CRÍTICO (CONSULTAR OBLIGATORIAMENTE)
Antes de auditar, revisa estos archivos de conocimiento:
1. .claude/agents/knowledge/sii_regulatory_context.md - Regulaciones SII y compliance DTE
2. .claude/agents/knowledge/odoo19_patterns.md - Patrones Odoo 19 (NO Odoo 11-16)
3. .claude/agents/knowledge/project_architecture.md - Arquitectura EERGYGROUP y decisiones

## ALCANCE DE LA AUDITORÍA

### 1. ARQUITECTURA Y PATRONES ODOO 19
- [ ] Verificar uso correcto de _inherit (NO duplicación de modelos)
- [ ] Validar que libs/ contiene solo Pure Python (NO AbstractModel)
- [ ] Revisar uso de @api.constrains (NO _sql_constraints deprecated)
- [ ] Verificar decoradores: @api.model, @api.depends, @api.onchange
- [ ] Validar estructura de módulos: models/, views/, security/, reports/
- [ ] Revisar manifest files: dependencias, versiones, datos

### 2. CÓDIGO Y CALIDAD
- [ ] Cumplimiento PEP8 estricto
- [ ] Docstrings completos y descriptivos
- [ ] Manejo de excepciones apropiado
- [ ] Logging con _logger para operaciones importantes
- [ ] Validación de datos de entrada
- [ ] Nomenclatura consistente (l10n_cl_* para módulos chilenos)

### 3. COMPLIANCE SII Y DTE
- [ ] Validación RUT modulo 11 correcta (3 formatos: DB, SII XML, Display)
- [ ] Estructura XML DTE conforme a esquemas XSD SII
- [ ] Firma digital XMLDSig (SHA1/SHA256) correcta
- [ ] CAF (Código Autorización Folios) validación y gestión
- [ ] TED (Timbre Electrónico) generación correcta
- [ ] Integración SII webservices (SOAP) correcta
- [ ] Alcance correcto: Solo DTEs 33,34,52,56,61 (NO boletas 39/41)
- [ ] Cumplimiento Res. 36/2024 (campos detalle productos)

### 4. SEGURIDAD Y PERMISOS
- [ ] Access rights (ir.model.access.csv) completos y correctos
- [ ] Record rules (ir.rule) apropiadas
- [ ] Field-level security implementada donde necesario
- [ ] Group-based permissions correctas
- [ ] Validación de permisos con @api.model decorator
- [ ] Protección contra SQL injection (queries parametrizadas)

### 5. PERFORMANCE Y OPTIMIZACIÓN
- [ ] ORM optimization (evitar loops, usar batch operations)
- [ ] Lazy evaluation y prefetch apropiados
- [ ] Índices de base de datos en campos críticos
- [ ] Cache usage (@tools.ormcache) donde aplica
- [ ] Computed fields: stored vs non-stored apropiado
- [ ] @api.depends correctamente configurado

### 6. TESTING Y COBERTURA
- [ ] Tests existentes: TransactionCase, @tagged decorators
- [ ] Coverage: 100% crítico, 90% lógica negocio, 70% UI
- [ ] Tests para validaciones DTE (RUT, CAF, XMLDSig)
- [ ] Tests para workflows completos
- [ ] Mocking de servicios externos (SII SOAP)
- [ ] Edge cases y error handling testeados

### 7. VIEWS Y UI
- [ ] XML views sintaxis correcta (sin version attribute en Odoo 19)
- [ ] View inheritance y XPath expressions correctas
- [ ] Form views: layouts, notebooks, groups apropiados
- [ ] Tree/List views con decorations y colores
- [ ] Kanban views y templates
- [ ] Search views y filters
- [ ] Menu items y actions correctos

### 8. INTEGRACIÓN Y DEPENDENCIAS
- [ ] Dependencias en __manifest__.py correctas
- [ ] Compatibilidad con módulos base Odoo 19
- [ ] Integración con módulos de localización chilena
- [ ] No dependencias circulares
- [ ] Versiones de módulos correctas

### 9. MIGRACIÓN Y COMPATIBILIDAD
- [ ] Compatibilidad con Odoo 19 (NO patrones Odoo 11-16)
- [ ] Scripts de migración si aplican
- [ ] Preservación de datos en upgrades
- [ ] Manejo de cambios breaking en Odoo 19

### 10. DOCUMENTACIÓN
- [ ] README.md actualizado
- [ ] Docstrings en modelos y métodos
- [ ] Comentarios explicativos en código complejo
- [ ] Documentación de workflows y procesos
- [ ] Ejemplos de uso donde aplica

## FORMATO DEL REPORTE

Genera un reporte estructurado con:

### Executive Summary
- Estado general (✅/⚠️/❌)
- Módulos auditados
- Hallazgos críticos (top 5)
- Score de calidad general (0-100)

### Análisis Detallado por Módulo
Para cada módulo (l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports):
- Estado de cada categoría (1-10)
- Issues encontrados con:
  * Prioridad (🔴 P0 Crítico, 🟡 P1 Alto, 🟢 P2 Medio)
  * Archivo y línea de código
  * Descripción del problema
  * Recomendación de solución
  * Código ejemplo de fix

### Hallazgos Críticos
- Issues que bloquean producción
- Problemas de compliance SII
- Vulnerabilidades de seguridad
- Performance críticos

### Recomendaciones Prioritizadas
- Acciones inmediatas (esta semana)
- Corto plazo (este mes)
- Largo plazo (mejoras continuas)

### Métricas y Scorecards
- Coverage de tests por módulo
- Compliance score por módulo
- Performance score
- Security score
- Code quality score

## CRITERIOS DE EVALUACIÓN

### Crítico (P0) - Bloquea Producción
- Errores de compliance SII
- Vulnerabilidades de seguridad
- Bugs que rompen funcionalidad core
- Patrones Odoo 11-16 en lugar de Odoo 19

### Alto (P1) - Impacta Calidad
- Performance issues significativos
- Falta de tests en código crítico
- Documentación incompleta
- Code smells importantes

### Medio (P2) - Mejoras
- Optimizaciones menores
- Mejoras de UX
- Refactoring sugerido
- Documentación adicional

## OUTPUT ESPERADO

1. Reporte completo en formato markdown estructurado
2. Tablas con métricas y scores
3. Lista priorizada de issues con referencias de código (file:line)
4. Código de ejemplo para fixes críticos
5. Roadmap de mejoras priorizado

Comienza la auditoría ahora, revisando primero los archivos de conocimiento crítico y luego analizando cada módulo sistemáticamente.
"
```

## 🎯 Prompt Alternativo (Más Conciso)

```bash
codex-odoo-dev "
Audita en profundidad los módulos Odoo 19 CE del proyecto EERGYGROUP (l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports).

CONSULTA OBLIGATORIA:
- .claude/agents/knowledge/sii_regulatory_context.md
- .claude/agents/knowledge/odoo19_patterns.md  
- .claude/agents/knowledge/project_architecture.md

AUDITA:
1. Arquitectura Odoo 19: _inherit correcto, libs/ Pure Python, @api.constrains
2. Compliance SII: RUT modulo 11, XML DTE, CAF, XMLDSig, TED
3. Seguridad: Permisos, access rights, record rules, SQL injection
4. Performance: ORM optimization, computed fields, índices
5. Testing: Coverage, TransactionCase, mocking SII
6. Código: PEP8, docstrings, manejo errores, logging
7. Views: XML correcto, inheritance, XPath
8. Documentación: README, docstrings, comentarios

FORMATO:
- Executive Summary con score (0-100)
- Issues por prioridad (🔴 P0, 🟡 P1, 🟢 P2)
- Referencias código (file:line)
- Código ejemplo fixes
- Roadmap priorizado

Comienza ahora.
"
```

## 🎯 Prompt para Auditoría Específica por Módulo

```bash
codex-odoo-dev "
Audita específicamente el módulo l10n_cl_dte con enfoque en:

1. COMPLIANCE SII CRÍTICO:
   - Validación RUT modulo 11 (3 formatos)
   - Estructura XML conforme XSD SII
   - Firma digital XMLDSig correcta
   - CAF validation y gestión
   - TED generación
   - Solo DTEs 33,34,52,56,61 (NO 39/41)

2. ARQUITECTURA ODOO 19:
   - libs/ Pure Python (NO AbstractModel)
   - _inherit correcto (NO duplicación)
   - @api.constrains (NO _sql_constraints)

3. SEGURIDAD Y PERFORMANCE:
   - Permisos y access rights
   - ORM optimization
   - Tests coverage crítico

Revisa primero: .claude/agents/knowledge/sii_regulatory_context.md

Genera reporte con issues priorizados y fixes.
"
```

## 📋 Uso Recomendado

### Opción 1: Auditoría Completa (Recomendada)
```bash
codex-odoo-dev "Realiza una auditoría técnica completa y exhaustiva de los módulos de Odoo 19 CE en desarrollo del proyecto EERGYGROUP. [usar prompt completo arriba]"
```

### Opción 2: Auditoría Rápida
```bash
codex-odoo-dev "Audita en profundidad los módulos Odoo 19 CE del proyecto EERGYGROUP. [usar prompt conciso arriba]"
```

### Opción 3: Auditoría por Módulo
```bash
codex-odoo-dev "Audita específicamente el módulo l10n_cl_dte con enfoque en compliance SII y arquitectura Odoo 19."
```

## 🔍 Perfiles Recomendados

- **`codex-odoo-dev`**: Para auditoría completa (recomendado)
- **`codex-dte-compliance`**: Para auditoría específica de compliance SII
- **`codex-test-automation`**: Para auditoría de testing y coverage

## 📊 Output Esperado

El agente generará:
1. ✅ Executive Summary con score general
2. 📋 Análisis detallado por módulo
3. 🔴 Issues críticos priorizados
4. 💡 Recomendaciones con código ejemplo
5. 📈 Métricas y scorecards
6. 🗺️ Roadmap de mejoras

---

**Nota**: El prompt completo incluye todas las categorías de auditoría y garantiza una revisión exhaustiva del código según estándares Odoo 19 CE y compliance SII.

