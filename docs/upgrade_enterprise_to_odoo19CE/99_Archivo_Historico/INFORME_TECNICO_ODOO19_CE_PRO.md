
# Odoo 19 "CE-Pro": Especificación Técnica y Plan de Ejecución

| **Documento:** | Especificación Técnica para Equipo de Desarrollo |
| :--- | :--- |
| **Autor:** | Ingeniero Líder de Proyecto |
| **Fecha:** | 3 de noviembre de 2025 |
| **Versión:** | 2.1 |
| **Estado:** | **ACTIVO - Guía para Desarrollo** |

---

## 1. Introducción y Misión Técnica

Este documento es la fuente única de verdad para el desarrollo del proyecto "Odoo 19 CE-Pro". Su objetivo es alinear al equipo técnico en torno a una visión, arquitectura y plan de ejecución comunes.

**Misión Técnica:** Construir una plataforma ERP sobre Odoo 19 Community Edition que sea técnicamente superior, más mantenible y más potente que la oferta estándar de Odoo Enterprise, a través de un desarrollo modular de alta calidad.

**Proyectos Pilares:**
1. **Proyecto Quantum:** Desarrollo de una suite de módulos para informes financieros dinámicos e inteligentes.
2. **Proyecto Phoenix:** Creación de un framework de UI/UX moderno y cohesivo.

## 2. Principios de Arquitectura y Estándares de Código

Todo el desarrollo se adherirá a los siguientes principios no negociables:

1. **Extender, no Reemplazar:** Heredaremos y ampliaremos la funcionalidad del núcleo de Odoo 19 CE siempre que sea posible. Se prohíbe la reimplementación de funcionalidades nativas (filtros, ORM, componentes UI básicos).
2. **Modularidad Extrema:** Cada pieza de funcionalidad debe encapsularse en el módulo más pequeño y lógico posible. Esto es clave para la mantenibilidad, el testing y la reutilización.
3. **Calidad de Código:**
    * **Testing Obligatorio:** Toda nueva lógica de negocio en el backend debe estar cubierta por tests unitarios, con un objetivo de cobertura de código (>70%).
    * **Documentación Rigurosa:** Todos los métodos públicos y clases deben tener docstrings claros. Cada módulo debe incluir un `README.md` que explique su propósito y arquitectura.
    * **Revisión por Pares (Pull Requests):** Ningún código se fusionará a la rama `develop` sin la aprobación de al menos otro miembro del equipo.
4. **API-First:** Las funcionalidades clave deben ser accesibles a través de una capa de API interna para facilitar la integración entre módulos y con sistemas futuros.

## 3. Arquitectura Detallada: Proyecto Quantum (Finanzas)

### 3.1. Motor de Reportes: `financial_reports_dynamic`

Este es el módulo central. Su arquitectura se basará en un modelo de **"Reglas Explícitas"** para máxima flexibilidad y mantenibilidad.

**Modelos Clave:**

```python
# financial_reports_dynamic/models/financial_report.py
class FinancialReport(models.Model):
    _name = 'financial.report'
    _inherit = ['mail.thread']
    
    name = fields.Char(required=True)
    line_ids = fields.One2many('financial.report.line', 'report_id')
    # ... otros campos de configuración ...

# financial_reports_dynamic/models/financial_report_line.py
class FinancialReportLine(models.Model):
    _name = 'financial.report.line'
    _parent_store = True # Optimización de jerarquía

    name = fields.Char(required=True)
    report_id = fields.Many2one('financial.report', ondelete='cascade')
    parent_id = fields.Many2one('financial.report.line', ondelete='cascade')
    children_ids = fields.One2many('financial.report.line', 'parent_id')
    parent_path = fields.Char(index=True)
    sequence = fields.Integer(default=10)
    rule_ids = fields.One2many('financial.report.rule', 'line_id')

    # Método principal de cálculo
    def _compute_balance(self, options):
        # ... lógica que itera sobre rule_ids ...

# financial_reports_dynamic/models/financial_report_rule.py
class FinancialReportRule(models.Model):
    _name = 'financial.report.rule'
    _description = "Financial Report Calculation Rule"
    _order = 'sequence'

    line_id = fields.Many2one('financial.report.line', required=True, ondelete='cascade')
    sequence = fields.Integer(default=10)
    
    rule_type = fields.Selection([
        ('account', 'Sum Accounts'),
        ('line', 'Sum Other Lines'),
        ('domain', 'Advanced Domain'),
    ], required=True, default='account')

    # Campos para 'account'
    account_ids = fields.Many2many('account.account', string="Specific Accounts")
    account_type_ids = fields.Many2many('account.account.type', string="Account Types")
    
    # Campos para 'line'
    sum_line_ids = fields.Many2many('financial.report.line', relation='financial_report_sum_line_rel', column1='rule_id', column2='line_id', string="Lines to Sum")
    subtract_line_ids = fields.Many2many('financial.report.line', relation='financial_report_sub_line_rel', column1='rule_id', column2='line_id', string="Lines to Subtract")

    # Campo para 'domain'
    domain = fields.Char(string="Domain", default="[]")
```

### 3.2. Navegación Profunda: `financial_drilldown`

Este módulo extenderá `financial.report.line` para permitir la navegación contextual.

```python
# financial_drilldown/models/financial_report_line.py
class FinancialReportLine(models.Model):
    _inherit = 'financial.report.line'

    def action_open_drilldown(self, options):
        """
        Genera una acción de ventana para mostrar los movimientos
        que componen el balance de esta línea.
        """
        domain = self._get_drilldown_domain(options)
        
        return {
            'type': 'ir.actions.act_window',
            'name': f'Drilldown: {self.name}',
            'res_model': 'account.move.line',
            'view_mode': 'tree,pivot,graph,form',
            'domain': domain,
        }

    def _get_drilldown_domain(self, options):
        """
        Construye de forma recursiva el dominio a partir de las reglas
        de la línea y sus hijas.
        """
        # ... lógica para consolidar dominios de todas las reglas ...
```

### 3.3. Inteligencia Artificial: `financial_reports_ai_insights`

Se integrará con el servicio de IA nativo de Odoo 19.

```python
# financial_reports_ai_insights/models/financial_report_ai.py
class FinancialReportAI(models.AbstractModel):
    _name = 'financial.report.ai'

    def detect_anomalies(self, report_data, threshold_pct=20.0):
        # ... implementación con self.env['ai.service'] ...

    def suggest_accounts_for_line(self, line_name):
        # ... implementación con self.env['ai.service'] ...
```

## 4. Arquitectura Detallada: Proyecto Phoenix (UI/UX)

### 4.1. Arquitectura de Micro-Módulos

La interfaz se construirá ensamblando pequeños módulos, orquestados por un meta-módulo `theme_enterprise_ce`.

* `theme_base_variables`: Contendrá únicamente los archivos SCSS con las variables de colores, tipografía y espaciado.
* `ui_home_menu_enterprise`: Reemplazará el menú de aplicaciones estándar por el nuevo componente OWL basado en un grid.
* `ui_form_view`: Aplicará los estilos a los formularios (sombras, espaciado, statusbar).
* `ui_list_view`: Aplicará los estilos a las vistas de lista (hover effects, headers).
* `theme_enterprise_ce`: Módulo principal que depende de todos los demás y asegura el orden de carga correcto de los assets.

### 4.2. Stack Tecnológico Frontend

* **Framework:** OWL 2.
* **Estilos:** SCSS, siguiendo la estructura de archivos de Odoo (`_variables.scss`, `_mixins.scss`, etc.).
* **Componentes:** Se reutilizarán al máximo los componentes nativos de `@web/core`. Ej: `Dropdown`, `Pager`, `SelectMenu`.

## 5. Roadmap de Desarrollo Técnico (Sprints)

### **Fase 1: El Núcleo Financiero Inteligente (Mes 1-2)**

* **Sprint 1:**
    * **Backend:** Implementar los modelos `FinancialReport`, `FinancialReportLine`, y `FinancialReportRule`.
    * **Backend:** Crear la lógica para la regla `rule_type = 'account'`.
    * **Frontend:** Crear el componente OWL básico que renderice una jerarquía de líneas (solo nombres).
    * **Testing:** Tests unitarios para el cálculo de balance con reglas de cuentas.
* **Sprint 2:**
    * **Backend:** Implementar la lógica para las reglas `line` y `domain`.
    * **Backend:** Implementar el método `action_open_drilldown`.
    * **Frontend:** Implementar el lazy-loading de líneas hijas y la acción de drilldown.
    * **AI:** Implementar `suggest_accounts_for_line` en el formulario de `FinancialReportLine`.

### **Fase 2: La Experiencia de Usuario "Phoenix" (Mes 3-4)**
* **Sprint 3:**
    * Crear módulos `theme_base_variables` y `ui_home_menu_enterprise`.
    * Configurar el asset bundle en `theme_enterprise_ce`.
* **Sprint 4:**
    * Crear módulos `ui_form_view` y `ui_list_view`.
    * Refinar estilos para asegurar consistencia visual.

### **Fase 3 y 4 (Inteligencia y Optimización):**
*   Las tareas se detallarán más adelante, pero incluirán la implementación de `detect_anomalies`, el dashboard de KPIs y la optimización de performance con virtual scrolling.

## 6. Gobernanza del Código y Flujo de Trabajo

* **Repositorio:** Un único monorepo en Git.
* **Ramas:**
    * `main`: Refleja el estado en producción. Protegida.
    * `develop`: Rama de integración. Todo el código nuevo se fusiona aquí.
    * `feature/TICKET-XXX-descripcion-corta`: Ramas de trabajo para cada tarea.
* **Flujo de Pull Request (PR):**
    1. Crear PR desde la rama `feature/*` hacia `develop`.
    2. El PR debe incluir un enlace al ticket/tarea correspondiente.
    3. El pipeline de CI/CD debe ejecutar los tests automáticamente.
    4. Se requiere la aprobación de **un** revisor como mínimo.
    5. Fusionar usando "Squash and merge" para mantener el historial de `develop` limpio.

## 7. Próximos Pasos Inmediatos

1. **Setup del Entorno:** Cada desarrollador debe tener una instancia local de Odoo 19.
2. **Creación del Repositorio:** Inicializar el repositorio en GitHub/GitLab con las ramas `main` y `develop`.
3. **Estructura de Módulos:** Crear las carpetas vacías para los módulos de la Fase 1 (`financial_reports_dynamic`, `financial_drilldown`).
4. **Reunión de Kick-off del Sprint 1:** Asignar las primeras tareas y empezar el desarrollo.
