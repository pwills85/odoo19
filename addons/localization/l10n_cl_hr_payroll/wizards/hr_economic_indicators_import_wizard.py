# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import base64
import csv
import io
from datetime import date


class HrEconomicIndicatorsImportWizard(models.TransientModel):
    """
    Wizard Importación Manual de Indicadores Económicos - P0-4
    
    Permite cargar indicadores desde archivo CSV cuando falla el cron automático.
    
    Formato CSV esperado:
    period,uf,utm,uta,minimum_wage,afp_limit
    2025-01-01,39000.0,68000.0,816000.0,500000.0,87.8
    """
    _name = 'hr.economic.indicators.import.wizard'
    _description = 'Import Economic Indicators from CSV'
    
    csv_file = fields.Binary(
        string='CSV File',
        required=True,
        help='Archivo CSV con indicadores económicos'
    )
    
    filename = fields.Char(
        string='Filename'
    )
    
    period = fields.Date(
        string='Period (Manual)',
        help='Si se proporciona, sobrescribe el período del CSV'
    )
    
    preview_data = fields.Text(
        string='Preview',
        readonly=True,
        help='Vista previa de los datos a importar'
    )
    
    @api.onchange('csv_file')
    def _onchange_csv_file_preview(self):
        """Generar preview de los datos"""
        if self.csv_file:
            try:
                csv_data = base64.b64decode(self.csv_file)
                csv_text = csv_data.decode('utf-8')
                
                # Mostrar primeras 5 líneas
                lines = csv_text.split('\n')[:5]
                self.preview_data = '\n'.join(lines)
            except Exception as e:
                self.preview_data = f"Error leyendo archivo: {str(e)}"
    
    def action_import_indicators(self):
        """
        Importar indicadores desde CSV
        
        Formato esperado:
        period,uf,utm,uta,minimum_wage,afp_limit,family_allowance_t1,family_allowance_t2,family_allowance_t3
        """
        self.ensure_one()
        
        if not self.csv_file:
            raise UserError(_("Debe seleccionar un archivo CSV"))
        
        try:
            # Decodificar archivo
            csv_data = base64.b64decode(self.csv_file)
            csv_text = csv_data.decode('utf-8-sig')  # UTF-8 con BOM
            
            # Parse CSV
            csv_reader = csv.DictReader(io.StringIO(csv_text))
            
            # Validar headers
            required_fields = ['period', 'uf', 'utm', 'uta', 'minimum_wage']
            if not all(field in csv_reader.fieldnames for field in required_fields):
                raise ValidationError(_(
                    "El CSV debe contener las columnas: %s\n"
                    "Columnas encontradas: %s"
                ) % (', '.join(required_fields), ', '.join(csv_reader.fieldnames)))
            
            indicators_created = []
            indicators_skipped = []
            
            for row in csv_reader:
                # Obtener período
                if self.period:
                    period_date = self.period
                else:
                    period_str = row.get('period', '').strip()
                    if not period_str:
                        continue
                    period_date = fields.Date.from_string(period_str)
                
                # Verificar si ya existe
                existing = self.env['hr.economic.indicators'].search([
                    ('period', '=', period_date)
                ], limit=1)
                
                if existing:
                    indicators_skipped.append(period_date.strftime('%Y-%m'))
                    continue
                
                # Crear indicador
                indicator_data = {
                    'period': period_date,
                    'uf': float(row.get('uf', 0) or 0),
                    'utm': float(row.get('utm', 0) or 0),
                    'uta': float(row.get('uta', 0) or 0),
                    'minimum_wage': float(row.get('minimum_wage', 0) or 0),
                    'afp_limit': float(row.get('afp_limit', 87.8) or 87.8),
                    'family_allowance_t1': float(row.get('family_allowance_t1', 0) or 0),
                    'family_allowance_t2': float(row.get('family_allowance_t2', 0) or 0),
                    'family_allowance_t3': float(row.get('family_allowance_t3', 0) or 0),
                }
                
                indicator = self.env['hr.economic.indicators'].create(indicator_data)
                indicators_created.append(indicator.period.strftime('%Y-%m'))
            
            # Mensaje de resultado
            message = []
            if indicators_created:
                message.append(f"✅ {len(indicators_created)} indicadores creados: {', '.join(indicators_created)}")
            if indicators_skipped:
                message.append(f"ℹ️  {len(indicators_skipped)} indicadores omitidos (ya existen): {', '.join(indicators_skipped)}")
            
            if not indicators_created and not indicators_skipped:
                message.append("⚠️  No se procesaron indicadores del archivo")
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Importación Completada'),
                    'message': '\n'.join(message),
                    'type': 'success' if indicators_created else 'warning',
                    'sticky': False,
                }
            }
            
        except csv.Error as e:
            raise UserError(_(
                "Error leyendo archivo CSV:\n%s\n\n"
                "Verifique que el archivo esté en formato CSV válido."
            ) % str(e))
        
        except ValueError as e:
            raise UserError(_(
                "Error en los datos:\n%s\n\n"
                "Verifique que los valores numéricos sean válidos."
            ) % str(e))
        
        except Exception as e:
            raise UserError(_(
                "Error inesperado durante la importación:\n%s"
            ) % str(e))
