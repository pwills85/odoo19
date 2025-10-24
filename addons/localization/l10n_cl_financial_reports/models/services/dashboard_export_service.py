# -*- coding: utf-8 -*-
"""
Dashboard Export Service
Servicio de exportación multi-formato para dashboards financieros
Siguiendo PROMPT_AGENT_IA.md y arquitectura de servicios
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import base64
import io
import json
import logging
from datetime import datetime

# Importaciones para exportación
try:
    import xlsxwriter
except ImportError:
    xlsxwriter = None

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
except ImportError:
    reportlab = None

_logger = logging.getLogger(__name__)


class DashboardExportService(models.AbstractModel):
    """
    Servicio de exportación multi-formato para dashboards.
    Hereda de AbstractModel siguiendo el patrón de servicios de l10n_cl_base.
    """
    _name = 'dashboard.export.service'
    _description = 'Dashboard Export Service'
    
    @api.model
    def export_dashboard(self, layout_id, format='pdf', filters=None, options=None):
        """
        Exporta un dashboard completo en el formato especificado.
        
        Args:
            layout_id: ID del layout del dashboard
            format: Formato de exportación ('pdf', 'xlsx', 'png')
            filters: Filtros aplicados al dashboard
            options: Opciones adicionales de exportación
            
        Returns:
            dict: {
                'data': base64_encoded_file,
                'filename': str,
                'mimetype': str
            }
        """
        # Validar formato
        valid_formats = ['pdf', 'xlsx', 'png']
        if format not in valid_formats:
            raise UserError(_('Invalid export format. Valid formats are: %s') % ', '.join(valid_formats))
        
        # Obtener layout y widgets
        layout = self.env['financial.dashboard.layout'].browse(layout_id)
        if not layout.exists():
            raise UserError(_('Dashboard layout not found'))
        
        # Obtener datos de todos los widgets
        widgets_data = self._get_widgets_data(layout, filters)
        
        # Generar exportación según formato
        if format == 'pdf':
            return self._export_to_pdf(layout, widgets_data, filters, options)
        elif format == 'xlsx':
            return self._export_to_excel(layout, widgets_data, filters, options)
        elif format == 'png':
            return self._export_to_image(layout, widgets_data, filters, options)
    
    @api.model
    def _get_widgets_data(self, layout, filters):
        """
        Obtiene los datos de todos los widgets del layout.
        """
        widgets_data = []
        
        for widget_user in layout.widget_ids:
            widget = widget_user.widget_id
            
            # Combinar filtros
            widget_filters = filters or {}
            if widget_user.custom_filters:
                widget_filters.update(widget_user.custom_filters)
            
            # Obtener datos del widget
            try:
                data = widget.get_widget_data(widget_filters)
                widgets_data.append({
                    'widget': widget,
                    'widget_user': widget_user,
                    'data': data,
                    'filters': widget_filters
                })
            except Exception as e:
                _logger.error(f"Error getting data for widget {widget.name}: {str(e)}")
                widgets_data.append({
                    'widget': widget,
                    'widget_user': widget_user,
                    'data': {'error': str(e)},
                    'filters': widget_filters
                })
        
        return widgets_data
    
    @api.model
    def _export_to_pdf(self, layout, widgets_data, filters, options):
        """
        Exporta el dashboard a PDF con diseño profesional.
        """
        if not reportlab:
            raise UserError(_('ReportLab library is required for PDF export. Please install it with: pip install reportlab'))
        
        # Configurar documento
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=landscape(A4),
            rightMargin=30,
            leftMargin=30,
            topMargin=30,
            bottomMargin=30
        )
        
        # Estilos
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        # Elementos del documento
        elements = []
        
        # Página de título
        elements.append(Spacer(1, 2*inch))
        elements.append(Paragraph(layout.name, title_style))
        
        # Información del reporte
        info_style = styles['Normal']
        info_text = f"""
        <para align="center">
        <b>Generated on:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}<br/>
        <b>Company:</b> {self.env.company.name}<br/>
        <b>Period:</b> {filters.get('date_from', 'N/A')} to {filters.get('date_to', 'N/A')}
        </para>
        """
        elements.append(Paragraph(info_text, info_style))
        elements.append(PageBreak())
        
        # Contenido de widgets
        
        # TODO: Refactorizar para usar browse en batch fuera del loop
        for widget_data in widgets_data:
            widget = widget_data['widget']
            data = widget_data['data']
            
            # Título del widget
            widget_title = Paragraph(f"<b>{widget.name}</b>", styles['Heading2'])
            elements.append(widget_title)
            elements.append(Spacer(1, 0.2*inch))
            
            # Renderizar según tipo de widget
            if widget.widget_type == 'kpi':
                elements.extend(self._render_kpi_to_pdf(data, styles))
            elif widget.widget_type == 'table':
                elements.extend(self._render_table_to_pdf(data, styles))
            elif widget.widget_type.startswith('chart_'):
                elements.extend(self._render_chart_to_pdf(widget, data, styles))
            elif widget.widget_type == 'gauge':
                elements.extend(self._render_gauge_to_pdf(data, styles))
            
            elements.append(Spacer(1, 0.5*inch))
        
        # Construir PDF
        doc.build(elements)
        
        # Preparar respuesta
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return {
            'data': base64.b64encode(pdf_data).decode('utf-8'),
            'filename': f"{layout.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            'mimetype': 'application/pdf'
        }
    
    @api.model
    def _export_to_excel(self, layout, widgets_data, filters, options):
        """
        Exporta el dashboard a Excel con múltiples hojas.
        """
        if not xlsxwriter:
            raise UserError(_('XlsxWriter library is required for Excel export. Please install it with: pip install xlsxwriter'))
        
        # Crear workbook
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        
        # Formatos
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#2c3e50',
            'font_color': 'white',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1
        })
        
        title_format = workbook.add_format({
            'bold': True,
            'font_size': 16,
            'font_color': '#2c3e50'
        })
        
        currency_format = workbook.add_format({
            'num_format': '#,##0.00',
            'align': 'right'
        })
        
        # Hoja de resumen
        summary_sheet = workbook.add_worksheet('Dashboard Summary')
        summary_sheet.write(0, 0, layout.name, title_format)
        summary_sheet.write(2, 0, 'Generated on:')
        summary_sheet.write(2, 1, datetime.now().strftime('%Y-%m-%d %H:%M'))
        summary_sheet.write(3, 0, 'Company:')
        summary_sheet.write(3, 1, self.env.company.name)
        summary_sheet.write(4, 0, 'Period:')
        summary_sheet.write(4, 1, f"{filters.get('date_from', 'N/A')} to {filters.get('date_to', 'N/A')}")
        
        # Crear hoja para cada widget
        for widget_data in widgets_data:
            widget = widget_data['widget']
            data = widget_data['data']
            
            # Nombre de hoja válido (max 31 caracteres)
            sheet_name = widget.name[:31]
            worksheet = workbook.add_worksheet(sheet_name)
            
            # Escribir título
            worksheet.write(0, 0, widget.name, title_format)
            
            # Renderizar según tipo
            if widget.widget_type == 'table':
                self._render_table_to_excel(worksheet, data, 2, header_format, currency_format)
            elif widget.widget_type == 'kpi':
                self._render_kpi_to_excel(worksheet, data, 2)
            else:
                # Para otros tipos, exportar datos crudos
                self._render_raw_data_to_excel(worksheet, data, 2, header_format)
        
        # Cerrar workbook
        workbook.close()
        output.seek(0)
        
        return {
            'data': base64.b64encode(output.read()).decode('utf-8'),
            'filename': f"{layout.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
            'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        }
    
    # Métodos auxiliares para renderizado PDF
    
    @api.model
    def _render_kpi_to_pdf(self, data, styles):
        """Renderiza un KPI para PDF"""
        elements = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                if key != 'error':
                    text = f"<b>{key}:</b> {value}"
                    elements.append(Paragraph(text, styles['Normal']))
        
        return elements
    
    @api.model
    def _render_table_to_pdf(self, data, styles):
        """Renderiza una tabla para PDF"""
        elements = []
        
        if 'columns' in data and 'rows' in data:
            # Preparar datos de tabla
            table_data = []
            
            # Headers
            headers = [col.get('header', col.get('field', '')) for col in data['columns']]
            table_data.append(headers)
            
            # Rows
            for row in data['rows'][:20]:  # Limitar a 20 filas para PDF
                row_data = []
                for col in data['columns']:
                    field = col.get('field')
                    value = row.get(field, '')
                    
                    # Formatear valores monetarios
                    if col.get('type') == 'currency' and isinstance(value, (int, float)):
                        value = f"${value:,.2f}"
                    
                    row_data.append(str(value))
                table_data.append(row_data)
            
            # Crear tabla
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(table)
            
            if len(data['rows']) > 20:
                elements.append(Paragraph(
                    f"<i>Showing 20 of {len(data['rows'])} rows</i>",
                    styles['Normal']
                ))
        
        return elements
    
    @api.model
    def _render_chart_to_pdf(self, widget, data, styles):
        """Renderiza información de gráfico para PDF"""
        elements = []
        
        # Por ahora, mostrar datos tabulares del gráfico
        if 'datasets' in data:
            for dataset in data['datasets']:
                elements.append(Paragraph(f"<b>{dataset.get('label', 'Dataset')}:</b>", styles['Normal']))
                
                if 'data' in dataset and isinstance(dataset['data'], list):
                    values = ', '.join([str(v) for v in dataset['data'][:10]])
                    if len(dataset['data']) > 10:
                        values += '...'
                    elements.append(Paragraph(values, styles['Normal']))
                
                elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    @api.model
    def _render_gauge_to_pdf(self, data, styles):
        """Renderiza un gauge para PDF"""
        elements = []
        
        if isinstance(data, dict):
            value = data.get('value', 0)
            min_val = data.get('min', 0)
            max_val = data.get('max', 100)
            status = data.get('status', 'normal')
            
            text = f"""
            <b>Current Value:</b> {value}<br/>
            <b>Range:</b> {min_val} - {max_val}<br/>
            <b>Status:</b> {status.upper()}
            """
            elements.append(Paragraph(text, styles['Normal']))
        
        return elements
    
    # Métodos auxiliares para renderizado Excel
    
    @api.model
    def _render_table_to_excel(self, worksheet, data, start_row, header_format, currency_format):
        """Renderiza una tabla en Excel"""
        if 'columns' not in data or 'rows' not in data:
            return
        
        row = start_row
        
        # Headers
        for col_idx, column in enumerate(data['columns']):
            header = column.get('header', column.get('field', ''))
            worksheet.write(row, col_idx, header, header_format)
        
        row += 1
        
        # Data rows
        for row_data in data['rows']:
            for col_idx, column in enumerate(data['columns']):
                field = column.get('field')
                value = row_data.get(field, '')
                
                # Aplicar formato según tipo
                if column.get('type') == 'currency' and isinstance(value, (int, float)):
                    worksheet.write(row, col_idx, value, currency_format)
                else:
                    worksheet.write(row, col_idx, value)
            
            row += 1
        
        # Ajustar ancho de columnas
        for col_idx in range(len(data['columns'])):
            worksheet.set_column(col_idx, col_idx, 15)
    
    @api.model
    def _render_kpi_to_excel(self, worksheet, data, start_row):
        """Renderiza KPIs en Excel"""
        row = start_row
        
        if isinstance(data, dict):
            for key, value in data.items():
                if key != 'error':
                    worksheet.write(row, 0, key)
                    worksheet.write(row, 1, value)
                    row += 1
    
    @api.model
    def _render_raw_data_to_excel(self, worksheet, data, start_row, header_format):
        """Renderiza datos crudos en Excel"""
        row = start_row
        
        # Convertir a JSON para visualización
        json_str = json.dumps(data, indent=2, default=str)
        lines = json_str.split('\n')
        
        for line in lines:
            worksheet.write(row, 0, line)
            row += 1
    
    @api.model
    def _export_to_image(self, layout, widgets_data, filters, options):
        """
        Exporta el dashboard como imagen PNG.
        Nota: Esta es una implementación placeholder.
        En producción, se usaría una herramienta como Puppeteer o wkhtmltoimage.
        """
        raise UserError(_('Image export is not yet implemented. Please use PDF or Excel format.'))
    
    @api.model
    def export_widget(self, widget_id, format='xlsx', filters=None):
        """
        Exporta un widget individual.
        
        Args:
            widget_id: ID del widget
            format: Formato de exportación
            filters: Filtros aplicados
            
        Returns:
            dict: Datos de exportación
        """
        widget = self.env['financial.dashboard.widget'].browse(widget_id)
        if not widget.exists():
            raise UserError(_('Widget not found'))
        
        # Verificar permisos
        if not widget.exportable:
            raise UserError(_('This widget is not exportable'))
        
        # Obtener datos
        data = widget.get_widget_data(filters)
        
        # Exportar según formato
        if format == 'xlsx':
            return self._export_widget_to_excel(widget, data, filters)
        elif format == 'csv':
            return self._export_widget_to_csv(widget, data, filters)
        elif format == 'json':
            return self._export_widget_to_json(widget, data, filters)
        else:
            raise UserError(_('Invalid export format for widget'))
    
    @api.model
    def _export_widget_to_excel(self, widget, data, filters):
        """Exporta un widget a Excel"""
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        worksheet = workbook.add_worksheet(widget.name[:31])
        
        # Formatos
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#2c3e50',
            'font_color': 'white',
            'align': 'center',
            'border': 1
        })
        
        # Título
        worksheet.write(0, 0, widget.name)
        
        # Renderizar según tipo
        if widget.widget_type == 'table':
            self._render_table_to_excel(worksheet, data, 2, header_format, None)
        else:
            self._render_raw_data_to_excel(worksheet, data, 2, header_format)
        
        workbook.close()
        output.seek(0)
        
        return {
            'data': base64.b64encode(output.read()).decode('utf-8'),
            'filename': f"{widget.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
            'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        }
    
    @api.model
    def _export_widget_to_csv(self, widget, data, filters):
        """Exporta un widget a CSV"""
        import csv
        
        output = io.StringIO()
        
        if widget.widget_type == 'table' and 'columns' in data and 'rows' in data:
            writer = csv.writer(output)
            
            # Headers
            headers = [col.get('header', col.get('field', '')) for col in data['columns']]
            writer.writerow(headers)
            
            # Rows
            for row in data['rows']:
                row_data = []
                for col in data['columns']:
                    field = col.get('field')
                    value = row.get(field, '')
                    row_data.append(value)
                writer.writerow(row_data)
        else:
            # Exportar como pares clave-valor
            writer = csv.writer(output)
            writer.writerow(['Key', 'Value'])
            
            if isinstance(data, dict):
                for key, value in data.items():
                    writer.writerow([key, value])
        
        return {
            'data': base64.b64encode(output.getvalue().encode('utf-8')).decode('utf-8'),
            'filename': f"{widget.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            'mimetype': 'text/csv'
        }
    
    @api.model
    def _export_widget_to_json(self, widget, data, filters):
        """Exporta un widget a JSON"""
        json_data = {
            'widget': {
                'id': widget.id,
                'name': widget.name,
                'type': widget.widget_type
            },
            'filters': filters,
            'data': data,
            'exported_at': datetime.now().isoformat()
        }
        
        json_str = json.dumps(json_data, indent=2, default=str)
        
        return {
            'data': base64.b64encode(json_str.encode('utf-8')).decode('utf-8'),
            'filename': f"{widget.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            'mimetype': 'application/json'
        }