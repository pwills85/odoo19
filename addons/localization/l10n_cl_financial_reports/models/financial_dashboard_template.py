# -*- coding: utf-8 -*-
"""
Financial Dashboard Template Model
Sistema de templates reutilizables para dashboards
Siguiendo PROMPT_AGENT_IA.md
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import json
import logging

_logger = logging.getLogger(__name__)


class FinancialDashboardTemplate(models.Model):
    """
    Templates predefinidos de dashboards financieros.
    Permite crear, compartir y reutilizar configuraciones de dashboard.
    """
    _name = 'financial.dashboard.template'
    _description = 'Financial Dashboard Template'
    _order = 'category_id, sequence, name'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    
    # Información básica
    name = fields.Char(
        string='Template Name',
        required=True,
        tracking=True
    )
    description = fields.Text(
        string='Description',
        help='Describe the purpose and content of this template'
    )
    active = fields.Boolean(
        default=True,
        tracking=True
    )
    sequence = fields.Integer(
        default=10,
        help='Used to order templates'
    )
    
    # Categorización
    category_id = fields.Many2one(
        'financial.dashboard.template.category',
        string='Category',
        required=True,
        ondelete='restrict'
    )
    tags_ids = fields.Many2many(
        'financial.dashboard.template.tag',
        'fin_dash_templ_tag_rel',  # Shortened relation table name
        'template_id',
        'tag_id',
        string='Tags',
        help='Tags for easy filtering'
    )
    
    # Configuración del template
    template_type = fields.Selection([
        ('standard', 'Standard Template'),
        ('industry', 'Industry Specific'),
        ('role', 'Role Based'),
        ('custom', 'Custom')
    ], default='standard', required=True)
    
    industry_id = fields.Many2one(
        'res.partner.industry',
        string='Industry',
        help='Specific industry for this template'
    )
    
    role_ids = fields.Many2many(
        'res.groups',
        string='Target Roles',
        help='User groups this template is designed for'
    )
    
    # Widgets del template
    widget_configs = fields.Json(
        string='Widget Configuration',
        help='JSON configuration of widgets and their positions'
    )
    
    # Vista previa
    preview_image = fields.Binary(
        string='Preview Image',
        attachment=True
    )
    preview_image_filename = fields.Char()
    
    # Metadata
    author_id = fields.Many2one(
        'res.users',
        string='Author',
        default=lambda self: self.env.user,
        readonly=True
    )
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        help='Leave empty for public templates'
    )
    is_public = fields.Boolean(
        string='Public Template',
        default=False,
        help='Public templates are available to all users'
    )
    
    # Estadísticas de uso
    usage_count = fields.Integer(
        string='Times Used',
        readonly=True,
        default=0
    )
    rating = fields.Float(
        string='Average Rating',
        readonly=True,
        compute='_compute_rating',
        store=True
    )
    rating_ids = fields.One2many(
        'financial.dashboard.template.rating',
        'template_id',
        string='Ratings'
    )
    
    # Configuración técnica
    min_odoo_version = fields.Char(
        string='Minimum Odoo Version',
        default='18.0'
    )
    required_modules = fields.Json(
        string='Required Modules',
        help='List of module names required for this template'
    )
    
    @api.depends('rating_ids.rating')
    def _compute_rating(self):
        """Calcula el rating promedio del template"""
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop

        # TODO: Refactorizar para usar browse en batch fuera del loop
        for template in self:
            ratings = template.rating_ids.mapped('rating')
            template.rating = sum(ratings) / len(ratings) if ratings else 0.0
    
    @api.constrains('widget_configs')
    def _check_widget_configs(self):
        """Valida la configuración de widgets"""
        for template in self:
            if template.widget_configs:
                try:
                    configs = json.loads(template.widget_configs) if isinstance(template.widget_configs, str) else template.widget_configs
                    
                    # Validar estructura
                    if not isinstance(configs, list):
                        raise ValidationError(_('Widget configuration must be a list'))
                    
                    # Validar cada widget
                    for config in configs:
                        if not isinstance(config, dict):
                            raise ValidationError(_('Each widget configuration must be a dictionary'))
                        
                        # Campos requeridos
                        required_fields = ['widget_code', 'grid_data']
                        for field in required_fields:
                            if field not in config:
                                raise ValidationError(_('Widget configuration missing required field: %s') % field)
                        
                        # Validar grid_data
                        grid = config['grid_data']
                        if not all(key in grid for key in ['x', 'y', 'w', 'h']):
                            raise ValidationError(_('Grid data must contain x, y, w, h'))
                            
                except json.JSONDecodeError:
                    raise ValidationError(_('Invalid JSON in widget configuration'))
                except Exception as e:
                    raise ValidationError(_('Error validating widget configuration: %s') % str(e))
    
    def apply_template(self, user_id=None):
        """
        Aplica este template para crear un nuevo dashboard layout.
        
        Args:
            user_id: Usuario para el cual crear el layout (default: current user)
            
        Returns:
            financial.dashboard.layout: El layout creado
        """
        self.ensure_one()
        
        # Verificar permisos
        if not self.is_public and self.company_id and self.company_id != self.env.company:
            raise UserError(_('This template is not available for your company'))
        
        # Verificar módulos requeridos
        if self.required_modules:
            missing_modules = []
            for module_name in self.required_modules:
                if not self.env['ir.module.module'].search([
                    ('name', '=', module_name),
                    ('state', '=', 'installed')
                ]):
                    missing_modules.append(module_name)
            
            if missing_modules:
                raise UserError(_('Missing required modules: %s') % ', '.join(missing_modules))
        
        # Crear layout
        user = self.env['res.users'].browse(user_id) if user_id else self.env.user
        
        layout_vals = {
            'user_id': user.id,
            'name': _('%s - %s') % (self.name, user.name),
            'is_default': False,
            'grid_config': {
                'column': 12,
                'maxRow': 20,
                'float': False,
                'animate': True,
                'cellHeight': '8rem'
            }
        }
        
        layout = self.env['financial.dashboard.layout'].create(layout_vals)
        
        # Aplicar widgets
        widget_configs = json.loads(self.widget_configs) if isinstance(self.widget_configs, str) else self.widget_configs
        
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop

        # TODO: Refactorizar para usar browse en batch fuera del loop
        for config in widget_configs:
            widget_code = config['widget_code']
            
            # Buscar widget por código
            widget = self.env['financial.dashboard.widget'].search([
                ('code', '=', widget_code),
                ('active', '=', True)
            ], limit=1)
            
            if not widget:
                _logger.warning(f"Widget with code {widget_code} not found for template {self.name}")
                continue
            
            # Crear widget de usuario
            widget_user_vals = {
                'layout_id': layout.id,
                'widget_id': widget.id,
                'grid_data': config['grid_data'],
                'custom_config': config.get('custom_config', {}),
                'custom_filters': config.get('custom_filters', {})
            }
            
            self.env['financial.dashboard.widget.user'].create(widget_user_vals)
        
        # Incrementar contador de uso
        self.sudo().usage_count += 1
        
        # Log en chatter
        self.message_post(
            body=_('Template applied by %s') % user.name,
            message_type='notification'
        )
        
        return layout
    
    def duplicate_as_custom(self):
        """
        Duplica el template como uno personalizado.
        """
        self.ensure_one()
        
        new_template = self.copy({
            'name': _('%s (Copy)') % self.name,
            'template_type': 'custom',
            'is_public': False,
            'company_id': self.env.company.id,
            'author_id': self.env.user.id,
            'usage_count': 0
        })
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'financial.dashboard.template',
            'res_id': new_template.id,
            'view_mode': 'form',
            'target': 'current'
        }
    
    @api.model
    def create_from_layout(self, layout_id, name, description='', category_id=None, is_public=False):
        """
        Crea un template desde un layout existente.
        
        Args:
            layout_id: ID del layout a convertir en template
            name: Nombre del template
            description: Descripción
            category_id: Categoría del template
            is_public: Si el template será público
            
        Returns:
            financial.dashboard.template: Template creado
        """
        layout = self.env['financial.dashboard.layout'].browse(layout_id)
        if not layout.exists():
            raise UserError(_('Layout not found'))
        
        # Preparar configuración de widgets
        widget_configs = []
        for widget_user in layout.widget_ids:
            config = {
                'widget_code': widget_user.widget_id.code,
                'grid_data': widget_user.grid_data,
                'custom_config': widget_user.custom_config or {},
                'custom_filters': widget_user.custom_filters or {}
            }
            widget_configs.append(config)
        
        # Crear template
        template_vals = {
            'name': name,
            'description': description,
            'category_id': category_id or self._get_default_category(),
            'template_type': 'custom',
            'widget_configs': widget_configs,
            'is_public': is_public,
            'company_id': False if is_public else self.env.company.id,
            'author_id': self.env.user.id
        }
        
        return self.create(template_vals)
    
    @api.model
    def _get_default_category(self):
        """Obtiene la categoría por defecto"""
        return self.env['financial.dashboard.template.category'].search([
            ('name', '=', 'Custom')
        ], limit=1).id
    
    def rate_template(self, rating, comment=''):
        """
        Permite a un usuario calificar el template.
        
        Args:
            rating: Calificación (1-5)
            comment: Comentario opcional
        """
        self.ensure_one()
        
        if not 1 <= rating <= 5:
            raise ValidationError(_('Rating must be between 1 and 5'))
        
        # Buscar rating existente del usuario
        existing_rating = self.env['financial.dashboard.template.rating'].search([
            ('template_id', '=', self.id),
            ('user_id', '=', self.env.user.id)
        ], limit=1)
        
        if existing_rating:
            existing_rating.write({
                'rating': rating,
                'comment': comment
            })
        else:
            self.env['financial.dashboard.template.rating'].create({
                'template_id': self.id,
                'user_id': self.env.user.id,
                'rating': rating,
                'comment': comment
            })
    
    @api.model
    def get_recommended_templates(self, limit=5):
        """
        Obtiene templates recomendados para el usuario actual.
        
        Args:
            limit: Número máximo de templates a retornar
            
        Returns:
            recordset: Templates recomendados
        """
        # Criterios de recomendación
        domain = [
            ('active', '=', True),
            '|',
            ('is_public', '=', True),
            ('company_id', 'in', [False, self.env.company.id])
        ]
        
        # Filtrar por rol si está configurado
        user_groups = self.env.user.groups_id
        role_domain = [
            '|',
            ('role_ids', '=', False),
            ('role_ids', 'in', user_groups.ids)
        ]
        domain.extend(role_domain)
        
        # Ordenar por rating y uso
        templates = self.search(domain, order='rating desc, usage_count desc', limit=limit)
        
        return templates


class FinancialDashboardTemplateCategory(models.Model):
    """
    Categorías para organizar templates de dashboard.
    """
    _name = 'financial.dashboard.template.category'
    _description = 'Dashboard Template Category'
    _order = 'sequence, name'
    
    name = fields.Char(
        string='Category Name',
        required=True,
        translate=True
    )
    description = fields.Text(
        string='Description',
        translate=True
    )
    sequence = fields.Integer(
        default=10
    )
    active = fields.Boolean(
        default=True
    )
    parent_id = fields.Many2one(
        'financial.dashboard.template.category',
        string='Parent Category',
        ondelete='cascade'
    )
    child_ids = fields.One2many(
        'financial.dashboard.template.category',
        'parent_id',
        string='Child Categories'
    )
    template_count = fields.Integer(
        string='Number of Templates',
        compute='_compute_template_count'
    )
    icon = fields.Char(
        string='Icon',
        default='fa-folder',
        help='FontAwesome icon class'
    )
    color = fields.Integer(
        string='Color Index',
        default=0
    )
    
    @api.depends('name')
    def _compute_template_count(self):
        """Cuenta los templates en cada categoría"""
        for category in self:
            category.template_count = self.env['financial.dashboard.template'].search_count([
                ('category_id', '=', category.id),
                ('active', '=', True)
            ])
    
    @api.constrains('parent_id')
    def _check_parent_id(self):
        """Previene loops en la jerarquía"""
        if not self._check_recursion():
            raise ValidationError(_('You cannot create recursive categories.'))


class FinancialDashboardTemplateTag(models.Model):
    """
    Tags para clasificar templates de dashboard.
    """
    _name = 'financial.dashboard.template.tag'
    _description = 'Dashboard Template Tag'
    _order = 'name'
    
    name = fields.Char(
        string='Tag Name',
        required=True,
        translate=True
    )
    color = fields.Integer(
        string='Color Index',
        default=0
    )
    active = fields.Boolean(
        default=True
    )
    
    _sql_constraints = [
        ('name_uniq', 'unique (name)', 'Tag name must be unique!')
    ]


class FinancialDashboardTemplateRating(models.Model):
    """
    Ratings y reviews de templates.
    """
    _name = 'financial.dashboard.template.rating'
    _description = 'Dashboard Template Rating'
    _order = 'create_date desc'
    
    template_id = fields.Many2one(
        'financial.dashboard.template',
        string='Template',
        required=True,
        ondelete='cascade'
    )
    user_id = fields.Many2one(
        'res.users',
        string='User',
        required=True,
        default=lambda self: self.env.user
    )
    rating = fields.Integer(
        string='Rating',
        required=True,
        help='Rating from 1 to 5'
    )
    comment = fields.Text(
        string='Comment'
    )
    create_date = fields.Datetime(
        string='Date',
        readonly=True
    )
    
    _sql_constraints = [
        ('user_template_unique', 'unique (user_id, template_id)',
         'A user can only rate a template once!')
    ]
    
    @api.constrains('rating')
    def _check_rating(self):
        """Valida que el rating esté en el rango correcto"""
        for record in self:
            if not 1 <= record.rating <= 5:
                raise ValidationError(_('Rating must be between 1 and 5'))