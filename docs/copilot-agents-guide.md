# 🤖 GitHub Copilot CLI - Guía de Agentes Especializados

**Proyecto**: Odoo19 Chilean Localization  
**Última actualización**: 2025-11-10  
**Versión**: 1.0.0

---

## 📋 Tabla de Contenidos

1. [Introducción](#introducción)
2. [Agentes Disponibles](#agentes-disponibles)
3. [Cómo Usar Agentes](#cómo-usar-agentes)
4. [Casos de Uso](#casos-de-uso)
5. [Troubleshooting](#troubleshooting)

---

## Introducción

Este proyecto tiene configurados **5 agentes especializados** de GitHub Copilot CLI para mejorar la productividad en el desarrollo de la localización chilena de Odoo 19.

### ¿Qué es un Agente Especializado?

Un agente especializado es una configuración personalizada de Copilot que:
- Tiene conocimiento específico del dominio (DTE, nóminas, testing, etc.)
- Referencia automáticamente la base de conocimiento del proyecto
- Aplica mejores prácticas y estándares específicos
- Proporciona respuestas más precisas y relevantes

---

## Agentes Disponibles

### 1. 🧾 `dte-specialist` - Especialista DTE/SII

**Especialización**: Facturación electrónica chilena y cumplimiento SII

**Cuándo usar**:
- Implementar o validar DTEs (33, 34, 52, 56, 61)
- Revisar integración con SII webservices
- Validar firmas digitales XML (XMLDSig)
- Gestionar CAF (Códigos de Autorización de Folios)
- Verificar cumplimiento regulatorio

**Comando**:
```bash
copilot /agent dte-specialist
```

**Ejemplo de uso**:
```bash
$ copilot /agent dte-specialist
> Review the DTE validation logic in models/account_move.py for SII compliance
```

---

### 2. 💰 `payroll-compliance` - Especialista Nómina Chilena

**Especialización**: Cálculos de nómina y cumplimiento laboral chileno

**Cuándo usar**:
- Implementar cálculos de AFP, ISAPRE, APV
- Validar indicadores económicos (UF, UTM, IPC)
- Generar archivos Previred (formato TXT)
- Revisar cumplimiento del Código del Trabajo
- Calcular Total Imponible y topes

**Comando**:
```bash
copilot /agent payroll-compliance
```

**Ejemplo de uso**:
```bash
$ copilot /agent payroll-compliance
> Validate AFP calculation logic for payslip with partial month
```

---

### 3. 🧪 `test-automation` - Especialista Testing

**Especialización**: Testing automatizado para módulos Odoo

**Cuándo usar**:
- Escribir tests unitarios con TransactionCase
- Configurar mocks para servicios externos (SII)
- Implementar tests de integración
- Configurar CI/CD con pytest
- Alcanzar objetivos de cobertura (80% DTE, 100% críticos)

**Comando**:
```bash
copilot /agent test-automation
```

**Ejemplo de uso**:
```bash
$ copilot /agent test-automation
> Write unit tests for RUT validator with edge cases
```

---

### 4. 🔒 `security-auditor` - Auditor de Seguridad

**Especialización**: Seguridad OWASP y auditoría de código

**Cuándo usar**:
- Auditar código para vulnerabilidades (SQL injection, XSS, XXE)
- Revisar seguridad de CAF (claves privadas)
- Validar autenticación SII
- Verificar permisos de acceso (@api.model)
- Revisar manejo de datos sensibles

**Comando**:
```bash
copilot /agent security-auditor
```

**Ejemplo de uso**:
```bash
$ copilot /agent security-auditor
> Audit XML parsing code for XXE vulnerabilities
```

---

### 5. 🏗️ `odoo-architect` - Arquitecto Odoo

**Especialización**: Arquitectura y patrones de diseño Odoo 19

**Cuándo usar**:
- Diseñar estructura de modelos
- Implementar herencia de modelos (_inherit, mixins)
- Optimizar rendimiento (índices, computed fields)
- Revisar arquitectura multi-empresa
- Refactorizar código a libs/ (Pure Python)

**Comando**:
```bash
copilot /agent odoo-architect
```

**Ejemplo de uso**:
```bash
$ copilot /agent odoo-architect
> Design model structure for DTE CAF management with multi-company support
```

---

## Cómo Usar Agentes

### Modo Interactivo

```bash
# Iniciar sesión con agente específico
copilot /agent dte-specialist

# Ahora todas las respuestas usan el contexto DTE
> How should I validate DTE folio sequence?
> Review the CAF expiration logic
> Generate example DTE XML for type 33
```

### Modo Programático (Una Sola Pregunta)

```bash
# Pregunta única con agente
copilot -p "Review AFP calculation logic" /agent payroll-compliance
```

### Cambiar de Agente

```bash
# Dentro de una sesión, cambiar de agente
> /agent test-automation
# Ahora el contexto cambia a testing
```

### Volver al Agente General

```bash
# Salir del agente especializado
> /agent general
```

---

## Casos de Uso

### Caso 1: Implementar Validación de DTE

```bash
$ copilot /agent dte-specialist

> I need to implement DTE XML validation against SII XSD schemas.
  Show me the pattern using lxml with XXE protection.

[Copilot responde con código seguro usando lxml parser configurado]

> Now review the existing DTE validation in libs/dte_validator.py
  for compliance with SII Resolution 80/2014

[Copilot analiza el código y sugiere mejoras regulatorias]
```

### Caso 2: Debugging Cálculo de Nómina

```bash
$ copilot /agent payroll-compliance

> The AFP calculation is incorrect for employees with salary > 90.3 UF.
  Help me debug the tope imponible logic in hr_payslip.py

[Copilot identifica el problema y sugiere corrección]

> Generate test cases for this edge case including partial months

[Copilot genera tests completos con setup, execution, assertions]
```

### Caso 3: Escribir Tests Completos

```bash
$ copilot /agent test-automation

> Write comprehensive tests for RUT validator including:
  - Valid RUTs
  - Invalid check digits
  - Edge cases (single digit, K check digit)
  - Format variations (with/without dots and hyphen)

[Copilot genera suite completa de tests con @tagged decorators]
```

### Caso 4: Auditoría de Seguridad

```bash
$ copilot /agent security-auditor

> Audit the SII webservice connector for security issues.
  Focus on: authentication, XXE, sensitive data exposure.

[Copilot analiza código y genera reporte con vulnerabilidades encontradas]

> Provide secure code examples for each vulnerability

[Copilot muestra código vulnerable vs seguro con explicaciones]
```

### Caso 5: Refactoring Arquitectónico

```bash
$ copilot /agent odoo-architect

> The DTE validation logic is currently in models/account_move.py.
  Help me refactor it to libs/ following pure Python pattern.

[Copilot propone estructura de clases en libs/ sin dependencias ORM]

> Review multi-company implications for this refactoring

[Copilot valida que la refactorización sea compatible con multi-empresa]
```

---

## Troubleshooting

### Problema: Agente no encuentra knowledge base

**Síntoma**: Agente no referencia archivos de `.github/agents/knowledge/`

**Solución**:
```bash
# Verificar que los archivos existen
ls -la .github/agents/knowledge/

# Deben estar presentes:
# - sii_regulatory_context.md
# - odoo19_patterns.md
# - project_architecture.md
```

### Problema: Agente responde con patrones antiguos (Odoo 11-16)

**Síntoma**: Usa `@api.one`, `@api.multi`, patrones deprecados

**Solución**:
```bash
# Recordar al agente explícitamente
> Use Odoo 19 patterns only. Check odoo19_patterns.md in knowledge base.
```

### Problema: No puedo cambiar de agente

**Síntoma**: `/agent <nombre>` no funciona

**Solución**:
```bash
# Salir y reiniciar sesión
> exit

# Iniciar con nuevo agente
copilot /agent <nombre-agente>
```

### Problema: Respuestas genéricas (no especializadas)

**Síntoma**: Agente no aplica conocimiento específico del proyecto

**Solución**:
```bash
# Verificar versión de Copilot CLI
gh copilot version

# Actualizar si es necesario
npm install -g @github/copilot@latest

# Verificar autenticación
gh auth status
```

---

## 📊 Matriz de Responsabilidades

| Tarea | Agente Recomendado | Alternativa |
|-------|-------------------|-------------|
| Validar DTE XML | `dte-specialist` | - |
| Implementar CAF | `dte-specialist` | `security-auditor` |
| Calcular AFP/ISAPRE | `payroll-compliance` | - |
| Generar archivo Previred | `payroll-compliance` | - |
| Escribir tests unitarios | `test-automation` | - |
| Configurar CI/CD | `test-automation` | - |
| Auditar SQL injection | `security-auditor` | - |
| Revisar XXE en XML | `security-auditor` | `dte-specialist` |
| Diseñar modelo nuevo | `odoo-architect` | - |
| Refactorizar a libs/ | `odoo-architect` | - |
| Optimizar rendimiento | `odoo-architect` | - |

---

## 🎓 Tips y Mejores Prácticas

### 1. Usa el agente correcto para la tarea
No uses `dte-specialist` para preguntas de testing. Cada agente está optimizado para su dominio.

### 2. Sé específico en tus preguntas
```bash
# ❌ Malo
> Fix the bug

# ✅ Bueno
> Review the AFP calculation in models/hr_payslip.py line 125
  for employees with partial month. The tope imponible is not being applied correctly.
```

### 3. Referencia archivos y líneas
```bash
> Review addons/localization/l10n_cl_dte/models/account_move.py:145-160
  for compliance with SII Resolution 80/2014 Section 3.2
```

### 4. Solicita validación contra knowledge base
```bash
> Validate this implementation against sii_regulatory_context.md
  and odoo19_patterns.md
```

### 5. Pide ejemplos completos
```bash
> Show me complete example with imports, setup, execution, and assertions
```

---

## 📚 Recursos Adicionales

### Documentación Oficial
- [GitHub Copilot CLI Docs](https://docs.github.com/en/copilot)
- [Custom Agents Configuration](https://docs.github.com/en/copilot/reference/custom-agents-configuration)

### Archivos del Proyecto
- `.github/agents/*.agent.md` - Configuración de agentes
- `.github/agents/knowledge/` - Base de conocimiento
- `.github/copilot-instructions.md` - Instrucciones globales de Copilot
- `AGENTS.md` - Documentación multi-CLI (raíz del proyecto)

### Contacto
Para preguntas o mejoras a los agentes:
- Maintainer: Pedro Troncoso (@pwills85)
- Documentación: `docs/copilot-agents-guide.md` (este archivo)

---

**Happy Coding with Copilot! 🚀**
