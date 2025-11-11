# -*- coding: utf-8 -*-
"""
Dashboard Export Controller
Maneja las peticiones HTTP para exportación de dashboards
Siguiendo PROMPT_AGENT_IA.md
"""

from odoo import http
from odoo.http import request, content_disposition
import base64
import logging

_logger = logging.getLogger(__name__)


class DashboardExportController(http.Controller):
    """
    Controlador para exportación de dashboards financieros.
    """
    
    @http.route('/financial/dashboard/export', type='jsonrpc', auth='user', methods=['POST'])
    def export_dashboard(self, layout_id, format='pdf', filters=None, options=None):
        """
        Exporta un dashboard completo.
        
        Args:
            layout_id: ID del layout del dashboard
            format: Formato de exportación (pdf, xlsx, png)
            filters: Filtros aplicados
            options: Opciones adicionales
            
        Returns:
            dict: Información del archivo exportado
        """
        try:
            # Validar acceso
            layout = request.env['financial.dashboard.layout'].browse(layout_id)
            if not layout.exists() or layout.user_id != request.env.user:
                if not request.env.user.has_group('account.group_account_manager'):
                    return {'error': 'Access denied to this dashboard'}
            
            # Llamar al servicio de exportación
            export_service = request.env['dashboard.export.service']
            result = export_service.export_dashboard(
                layout_id=layout_id,
                format=format,
                filters=filters or {},
                options=options or {}
            )
            
            return {
                'success': True,
                'data': result['data'],
                'filename': result['filename'],
                'mimetype': result['mimetype']
            }
            
        except Exception as e:
            _logger.error(f"Error exporting dashboard: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @http.route('/financial/widget/export', type='jsonrpc', auth='user', methods=['POST'])
    def export_widget(self, widget_id, format='xlsx', filters=None):
        """
        Exporta un widget individual.
        
        Args:
            widget_id: ID del widget
            format: Formato de exportación
            filters: Filtros aplicados
            
        Returns:
            dict: Información del archivo exportado
        """
        try:
            # Validar widget
            widget = request.env['financial.dashboard.widget'].browse(widget_id)
            if not widget.exists():
                return {'error': 'Widget not found'}
            
            # Verificar permisos
            if widget.group_ids and not any(g in request.env.user.groups_id for g in widget.group_ids):
                return {'error': 'Access denied to this widget'}
            
            # Llamar al servicio
            export_service = request.env['dashboard.export.service']
            result = export_service.export_widget(
                widget_id=widget_id,
                format=format,
                filters=filters or {}
            )
            
            return {
                'success': True,
                'data': result['data'],
                'filename': result['filename'],
                'mimetype': result['mimetype']
            }
            
        except Exception as e:
            _logger.error(f"Error exporting widget: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @http.route('/financial/dashboard/download/<string:filename>', type='http', auth='user')
    def download_export(self, filename, data=None, **kwargs):
        """
        Descarga un archivo exportado.
        
        Args:
            filename: Nombre del archivo
            data: Datos codificados en base64
            
        Returns:
            HTTP response con el archivo
        """
        if not data:
            return request.not_found()
        
        try:
            # Decodificar datos
            file_data = base64.b64decode(data)
            
            # Determinar mimetype por extensión
            if filename.endswith('.pdf'):
                mimetype = 'application/pdf'
            elif filename.endswith('.xlsx'):
                mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            elif filename.endswith('.csv'):
                mimetype = 'text/csv'
            elif filename.endswith('.json'):
                mimetype = 'application/json'
            else:
                mimetype = 'application/octet-stream'
            
            # Retornar archivo
            return request.make_response(
                file_data,
                headers=[
                    ('Content-Type', mimetype),
                    ('Content-Disposition', content_disposition(filename))
                ]
            )
            
        except Exception as e:
            _logger.error(f"Error downloading export: {str(e)}")
            return request.not_found()
    
    @http.route('/financial/template/preview/<int:template_id>', type='http', auth='user')
    def preview_template(self, template_id):
        """
        Muestra vista previa de un template.
        
        Args:
            template_id: ID del template
            
        Returns:
            Imagen de vista previa o placeholder
        """
        try:
            template = request.env['financial.dashboard.template'].browse(template_id)
            if not template.exists():
                return request.not_found()
            
            # Verificar acceso
            if not template.is_public and template.company_id != request.env.company:
                return request.not_found()
            
            if template.preview_image:
                image_data = base64.b64decode(template.preview_image)
                return request.make_response(
                    image_data,
                    headers=[
                        ('Content-Type', 'image/png'),
                        ('Cache-Control', 'public, max-age=3600')
                    ]
                )
            else:
                # Retornar placeholder
                return request.redirect('/l10n_cl_financial_reports/static/img/dashboard_placeholder.png')
                
        except Exception as e:
            _logger.error(f"Error showing template preview: {str(e)}")
            return request.not_found()
    
    @http.route('/financial/template/apply', type='jsonrpc', auth='user', methods=['POST'])
    def apply_template(self, template_id, user_id=None):
        """
        Aplica un template de dashboard.
        
        Args:
            template_id: ID del template
            user_id: ID del usuario (opcional)
            
        Returns:
            dict: Información del layout creado
        """
        try:
            template = request.env['financial.dashboard.template'].browse(template_id)
            if not template.exists():
                return {'error': 'Template not found'}
            
            # Aplicar template
            layout = template.apply_template(user_id=user_id)
            
            return {
                'success': True,
                'layout_id': layout.id,
                'message': f'Template "{template.name}" applied successfully'
            }
            
        except Exception as e:
            _logger.error(f"Error applying template: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @http.route('/financial/template/create_from_layout', type='jsonrpc', auth='user', methods=['POST'])
    def create_template_from_layout(self, layout_id, name, description='', category_id=None, is_public=False):
        """
        Crea un template desde un layout existente.
        
        Args:
            layout_id: ID del layout
            name: Nombre del template
            description: Descripción
            category_id: ID de la categoría
            is_public: Si será público
            
        Returns:
            dict: Información del template creado
        """
        try:
            # Verificar permisos
            layout = request.env['financial.dashboard.layout'].browse(layout_id)
            if not layout.exists() or layout.user_id != request.env.user:
                if not request.env.user.has_group('account.group_account_manager'):
                    return {'error': 'Access denied to this layout'}
            
            # Crear template
            template_model = request.env['financial.dashboard.template']
            template = template_model.create_from_layout(
                layout_id=layout_id,
                name=name,
                description=description,
                category_id=category_id,
                is_public=is_public and request.env.user.has_group('account.group_account_manager')
            )
            
            return {
                'success': True,
                'template_id': template.id,
                'message': f'Template "{name}" created successfully'
            }
            
        except Exception as e:
            _logger.error(f"Error creating template: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @http.route('/financial/template/rate', type='jsonrpc', auth='user', methods=['POST'])
    def rate_template(self, template_id, rating, comment=''):
        """
        Califica un template.
        
        Args:
            template_id: ID del template
            rating: Calificación (1-5)
            comment: Comentario opcional
            
        Returns:
            dict: Resultado
        """
        try:
            template = request.env['financial.dashboard.template'].browse(template_id)
            if not template.exists():
                return {'error': 'Template not found'}
            
            template.rate_template(rating=rating, comment=comment)
            
            return {
                'success': True,
                'message': 'Rating saved successfully',
                'new_rating': template.rating
            }
            
        except Exception as e:
            _logger.error(f"Error rating template: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @http.route('/financial/template/recommendations', type='jsonrpc', auth='user')
    def get_template_recommendations(self, limit=5):
        """
        Obtiene templates recomendados para el usuario.
        
        Args:
            limit: Número máximo de templates
            
        Returns:
            dict: Templates recomendados
        """
        # Optimización: usar with_context para prefetch
        template = template.with_context(prefetch_fields=False)

        try:
            template_model = request.env['financial.dashboard.template']
            templates = template_model.get_recommended_templates(limit=limit)
            
            result = []
            for template in templates:
                result.append({
                    'id': template.id,
                    'name': template.name,
                    'description': template.description,
                    'category': template.category_id.name,
                    'rating': template.rating,
                    'usage_count': template.usage_count,
                    'author': template.author_id.name,
                    'tags': [tag.name for tag in template.tags_ids]
                })
            
            return {
                'success': True,
                'templates': result
            }
            
        except Exception as e:
            _logger.error(f"Error getting recommendations: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'templates': []
            }
    
    @http.route('/financial/widget/data/lazy', type='jsonrpc', auth='user', methods=['POST'])
    def get_widget_data_lazy(self, widget_id, filters=None):
        """
        Obtiene datos de un widget individual para lazy loading.
        
        Args:
            widget_id: ID del widget
            filters: Filtros aplicados
            
        Returns:
            dict: Datos del widget
        """
        try:
            # Usar servicio optimizado
            service = request.env['financial.dashboard.service.optimized']
            result = service.get_widget_data_lazy(
                widget_id=widget_id,
                filters=filters or {}
            )
            
            return result
            
        except Exception as e:
            _logger.error(f"Error loading widget data: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @http.route('/financial/dashboard/performance', type='jsonrpc', auth='user')
    def get_performance_metrics(self):
        """
        Obtiene métricas de performance del dashboard.
        
        Returns:
            dict: Métricas y recomendaciones
        """
        try:
            # Solo administradores pueden ver métricas
            if not request.env.user.has_group('account.group_account_manager'):
                return {'error': 'Access denied'}
            
            service = request.env['financial.dashboard.service.optimized']
            metrics = service.get_performance_metrics()
            
            return {
                'success': True,
                'metrics': metrics
            }
            
        except Exception as e:
            _logger.error(f"Error getting performance metrics: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }