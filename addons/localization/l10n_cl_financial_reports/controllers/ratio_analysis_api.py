# -*- coding: utf-8 -*-
"""
REST API Controller for Financial Ratio Analysis
Provides external API access to ratio analysis functionality
"""

from odoo import http, _
from odoo.http import request
import json
import logging
from datetime import datetime, date
from functools import wraps
import jwt
from werkzeug.exceptions import Unauthorized, BadRequest

from .security_middleware import (
    secure_api_endpoint, SecurityUtils, validate_jwt_token,
    rate_limit, sanitize_input, audit_log
)

_logger = logging.getLogger(__name__)

# Legacy decorator - deprecated, use secure_api_endpoint instead
def validate_api_key(func):
    """Decorator to validate API key - DEPRECATED"""
    _logger.warning("validate_api_key decorator is deprecated, use secure_api_endpoint instead")
    return validate_jwt_token(func)


class RatioAnalysisAPI(http.Controller):
    """REST API endpoints for financial ratio analysis"""
    
    @http.route('/api/v1/ratio-analysis/health', type='json', auth='public', methods=['GET'], cors='*')
    def health_check(self):
        """API health check endpoint"""
        return {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }
    
    @http.route('/api/v1/ratio-analysis/compute', type='json', auth='public', methods=['POST'], cors='*', csrf=True)
    @secure_api_endpoint(
        rate_limit_per_hour=50,
        rate_limit_per_minute=5,
        require_hmac=True,
        require_jwt=True
    )
    def compute_ratios(self, **kwargs):
        """
        Compute financial ratios for a given period
        
        Expected payload:
        {
            "company_id": 1,
            "date_from": "2024-01-01",
            "date_to": "2024-12-31",
            "analysis_type": "comprehensive",
            "ratios": ["current_ratio", "debt_to_equity", "roe"]  // optional
        }
        """
        try:
            # Validate input
            data = request.jsonrequest
            company_id = data.get('company_id') or request.api_company
            date_from = data.get('date_from')
            date_to = data.get('date_to')
            analysis_type = data.get('analysis_type', 'comprehensive')
            specific_ratios = data.get('ratios', [])
            
            if not all([company_id, date_from, date_to]):
                raise BadRequest('Missing required parameters')
            
            # Validate dates
            try:
                date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
                date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
            except ValueError:
                raise BadRequest('Invalid date format. Use YYYY-MM-DD')
            
            if date_from > date_to:
                raise BadRequest('date_from must be before date_to')
            
            # Create and compute analysis
            analysis = request.env['account.ratio.analysis.service'].with_user(self.env.user).create({
                'name': f'API Analysis - {datetime.now().isoformat()}',
                'company_id': company_id,
                'date_from': date_from,
                'date_to': date_to,
                'analysis_type': analysis_type,
            })
            
            analysis.compute_analysis()
            
            # Prepare response
            ratio_data = json.loads(analysis.ratio_data)
            
            # Filter specific ratios if requested
            if specific_ratios:
                filtered_data = {}
                for category, ratios in ratio_data.items():
                    if isinstance(ratios, dict):
                        filtered_ratios = {k: v for k, v in ratios.items() if k in specific_ratios}
                        if filtered_ratios:
                            filtered_data[category] = filtered_ratios
                ratio_data = filtered_data
            
            response = {
                'status': 'success',
                'analysis_id': analysis.id,
                'company_id': company_id,
                'period': {
                    'from': date_from.isoformat(),
                    'to': date_to.isoformat()
                },
                'ratios': ratio_data,
                'financial_health_score': analysis.financial_health_score,
                'computation_date': analysis.create_date.isoformat()
            }
            
            # Add recommendations if computed
            if analysis.recommendations:
                response['recommendations'] = json.loads(analysis.recommendations)
            
            return response
            
        except BadRequest:
            raise
        except Exception as e:
            _logger.error(f"Error in compute_ratios API: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @http.route('/api/v1/ratio-analysis/<int:analysis_id>', type='json', auth='public', methods=['GET'], cors='*')
    @validate_api_key
    def get_analysis(self, analysis_id, **kwargs):
        """Get a specific ratio analysis by ID"""
        # Get analysis first
        analysis = request.env['account.ratio.analysis.service'].sudo().browse(analysis_id)
        
        # Optimización: usar with_context para prefetch
        analysis = analysis.with_context(prefetch_fields=False)

        try:
            analysis = request.env['account.ratio.analysis.service'].sudo().browse(analysis_id)
            
            if not analysis.exists():
                raise BadRequest('Analysis not found')
            
            # Check company access
            if analysis.company_id.id != request.api_company:
                raise Unauthorized('Access denied to this analysis')
            
            return {
                'status': 'success',
                'analysis': {
                    'id': analysis.id,
                    'name': analysis.name,
                    'company_id': analysis.company_id.id,
                    'period': {
                        'from': analysis.date_from.isoformat(),
                        'to': analysis.date_to.isoformat()
                    },
                    'analysis_type': analysis.analysis_type,
                    'state': analysis.state,
                    'ratios': json.loads(analysis.ratio_data) if analysis.ratio_data else {},
                    'financial_health_score': analysis.financial_health_score,
                    'recommendations': json.loads(analysis.recommendations) if analysis.recommendations else [],
                    'summary': json.loads(analysis.analysis_summary) if analysis.analysis_summary else {},
                    'computation_date': analysis.create_date.isoformat()
                }
            }
            
        except BadRequest:
            raise
        except Exception as e:
            _logger.error(f"Error in get_analysis API: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @http.route('/api/v1/ratio-analysis/historical', type='json', auth='public', methods=['POST'], cors='*', csrf=True)
    @secure_api_endpoint(rate_limit_per_hour=100, require_jwt=True)
    def get_historical_ratios(self, **kwargs):
        """
        Get historical ratio trends
        
        Expected payload:
        {
            "company_id": 1,
            "ratio_name": "current_ratio",
            "periods": 12,
            "frequency": "monthly"  // monthly, quarterly, yearly
        }
        """
        try:
            data = request.jsonrequest
            company_id = data.get('company_id') or request.api_company
            ratio_name = data.get('ratio_name')
            periods = data.get('periods', 12)
            frequency = data.get('frequency', 'monthly')
            
            if not ratio_name:
                raise BadRequest('ratio_name is required')
            
            # Validate ratio name
            valid_ratios = [
                'current_ratio', 'quick_ratio', 'cash_ratio',
                'debt_to_equity', 'debt_ratio', 'equity_ratio',
                'return_on_assets', 'return_on_equity',
                'gross_profit_margin', 'net_profit_margin',
                'asset_turnover', 'inventory_turnover',
                'altman_z_score', 'cash_conversion_cycle'
            ]
            
            if ratio_name not in valid_ratios:
                raise BadRequest(f'Invalid ratio_name. Valid options: {", ".join(valid_ratios)}')
            
            # Get historical data
            service = request.env['account.ratio.analysis.service'].sudo()
            historical_data = service.get_historical_ratios(company_id, ratio_name, periods)
            
            return {
                'status': 'success',
                'company_id': company_id,
                'ratio_name': ratio_name,
                'periods': periods,
                'frequency': frequency,
                'data': historical_data,
                'statistics': {
                    'mean': sum(d['value'] for d in historical_data) / len(historical_data) if historical_data else 0,
                    'min': min(d['value'] for d in historical_data) if historical_data else 0,
                    'max': max(d['value'] for d in historical_data) if historical_data else 0,
                }
            }
            
        except BadRequest:
            raise
        except Exception as e:
            _logger.error(f"Error in get_historical_ratios API: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @http.route('/api/v1/ratio-analysis/benchmark', type='json', auth='public', methods=['POST'], cors='*', csrf=True)
    @secure_api_endpoint(
        rate_limit_per_hour=50,
        rate_limit_per_minute=10,
        require_hmac=True,
        require_jwt=True,
    )
    def get_benchmarks(self, **kwargs):
        """
        Get industry benchmarks for ratios
        
        Expected payload:
        {
            "industry": "manufacturing",
            "company_size": "medium",
            "ratios": ["current_ratio", "debt_to_equity"]
        }
        """
        try:
            data = request.jsonrequest
            industry = data.get('industry', 'general')
            company_size = data.get('company_size', 'medium')
            ratios = data.get('ratios', [])
            
            # Define benchmark data (in production, this would come from a database)
            benchmarks = {
                'manufacturing': {
                    'current_ratio': {'min': 1.5, 'optimal': 2.0, 'max': 3.0},
                    'debt_to_equity': {'min': 0.5, 'optimal': 1.0, 'max': 1.5},
                    'return_on_assets': {'min': 5, 'optimal': 10, 'max': 15},
                    'inventory_turnover': {'min': 4, 'optimal': 8, 'max': 12},
                },
                'retail': {
                    'current_ratio': {'min': 1.2, 'optimal': 1.8, 'max': 2.5},
                    'debt_to_equity': {'min': 0.8, 'optimal': 1.5, 'max': 2.0},
                    'return_on_assets': {'min': 7, 'optimal': 12, 'max': 18},
                    'inventory_turnover': {'min': 6, 'optimal': 12, 'max': 20},
                },
                'services': {
                    'current_ratio': {'min': 1.0, 'optimal': 1.5, 'max': 2.0},
                    'debt_to_equity': {'min': 0.3, 'optimal': 0.8, 'max': 1.2},
                    'return_on_assets': {'min': 8, 'optimal': 15, 'max': 25},
                },
                'general': {
                    'current_ratio': {'min': 1.2, 'optimal': 1.8, 'max': 2.5},
                    'debt_to_equity': {'min': 0.5, 'optimal': 1.0, 'max': 2.0},
                    'return_on_assets': {'min': 5, 'optimal': 10, 'max': 15},
                    'return_on_equity': {'min': 10, 'optimal': 15, 'max': 25},
                }
            }
            
            industry_benchmarks = benchmarks.get(industry, benchmarks['general'])
            
            # Filter requested ratios
            if ratios:
                industry_benchmarks = {k: v for k, v in industry_benchmarks.items() if k in ratios}
            
            return {
                'status': 'success',
                'industry': industry,
                'company_size': company_size,
                'benchmarks': industry_benchmarks,
                'description': f'Industry benchmarks for {industry} - {company_size} companies'
            }
            
        except Exception as e:
            _logger.error(f"Error in get_benchmarks API: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @http.route('/api/v1/ratio-analysis/predict', type='json', auth='public', methods=['POST'], cors='*', csrf=True)
    @secure_api_endpoint(
        rate_limit_per_hour=30,
        rate_limit_per_minute=5,
        require_hmac=True,
        require_jwt=True,
    )
    def predict_ratios(self, **kwargs):
        """
        Predict future ratio values using ML
        
        Expected payload:
        {
            "company_id": 1,
            "target_ratio": "current_ratio",
            "prediction_horizon": 6,
            "model_type": "random_forest"
        }
        """
        try:
            data = request.jsonrequest
            company_id = data.get('company_id') or request.api_company
            target_ratio = data.get('target_ratio')
            prediction_horizon = data.get('prediction_horizon', 6)
            model_type = data.get('model_type', 'random_forest')
            
            if not target_ratio:
                raise BadRequest('target_ratio is required')
            
            # Check if trained model exists
            ml_model = request.env['ratio.prediction.ml'].sudo().search([
                ('company_id', '=', company_id),
                ('target_ratio', '=', target_ratio),
                ('state', '=', 'trained')
            ], limit=1)
            
            if not ml_model:
                # Create and train new model
                ml_model = request.env['ratio.prediction.ml'].with_user(self.env.user).create({
                    'name': f'API Prediction - {target_ratio}',
                    'company_id': company_id,
                    'prediction_type': 'single_ratio',
                    'target_ratio': target_ratio,
                    'model_type': model_type,
                    'prediction_horizon': prediction_horizon,
                })
                ml_model.action_train_model()
            
            # Generate predictions
            ml_model.prediction_horizon = prediction_horizon
            ml_model.action_predict()
            
            predictions = json.loads(ml_model.predictions) if ml_model.predictions else []
            confidence_intervals = json.loads(ml_model.confidence_intervals) if ml_model.confidence_intervals else []
            
            return {
                'status': 'success',
                'model_id': ml_model.id,
                'company_id': company_id,
                'target_ratio': target_ratio,
                'model_accuracy': ml_model.model_accuracy,
                'predictions': predictions,
                'confidence_intervals': confidence_intervals,
                'feature_importance': json.loads(ml_model.feature_importance) if ml_model.feature_importance else {},
                'last_training_date': ml_model.last_training_date.isoformat() if ml_model.last_training_date else None
            }
            
        except BadRequest:
            raise
        except Exception as e:
            _logger.error(f"Error in predict_ratios API: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @http.route('/api/v1/ratio-analysis/alerts', type='json', auth='public', methods=['GET'], cors='*')
    @validate_api_key
    def get_alerts(self, **kwargs):
        """Get active ratio alerts for a company"""
        try:
            company_id = request.api_company
            
            # Get recent analyses with alerts
            analyses = request.env['account.ratio.analysis.service'].sudo().search([
                ('company_id', '=', company_id),
                ('state', '=', 'computed'),
                ('create_date', '>=', datetime.now().replace(day=1).date())  # Current month
            ])
            
            alerts = []
            
            # TODO: Refactorizar para usar browse en batch fuera del loop
            for analysis in analyses:
                # Check for critical ratios
                if analysis.current_ratio < 1.0:
                    alerts.append({
                        'type': 'critical',
                        'ratio': 'current_ratio',
                        'value': analysis.current_ratio,
                        'threshold': 1.0,
                        'message': 'Current ratio below critical threshold',
                        'date': analysis.date_to.isoformat()
                    })
                
                if analysis.debt_to_equity > 3.0:
                    alerts.append({
                        'type': 'warning',
                        'ratio': 'debt_to_equity',
                        'value': analysis.debt_to_equity,
                        'threshold': 3.0,
                        'message': 'High leverage detected',
                        'date': analysis.date_to.isoformat()
                    })
                
                if analysis.altman_z_score and analysis.altman_z_score < 1.81:
                    alerts.append({
                        'type': 'critical',
                        'ratio': 'altman_z_score',
                        'value': analysis.altman_z_score,
                        'threshold': 1.81,
                        'message': 'High bankruptcy risk',
                        'date': analysis.date_to.isoformat()
                    })
            
            return {
                'status': 'success',
                'company_id': company_id,
                'alerts': alerts,
                'total_alerts': len(alerts),
                'critical_count': len([a for a in alerts if a['type'] == 'critical']),
                'warning_count': len([a for a in alerts if a['type'] == 'warning'])
            }
            
        except Exception as e:
            _logger.error(f"Error in get_alerts API: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }
    
    @http.route('/api/v1/ratio-analysis/export/<int:analysis_id>', type='http', auth='public', methods=['GET'], cors='*')
    @validate_api_key
    def export_analysis(self, analysis_id, format='pdf', **kwargs):
        """Export analysis report in various formats"""
        try:
            analysis = request.env['account.ratio.analysis.service'].sudo().browse(analysis_id)
            
            if not analysis.exists():
                return request.make_response(
                    json.dumps({'status': 'error', 'message': 'Analysis not found'}),
                    headers=[('Content-Type', 'application/json')],
                    status=404
                )
            
            if format == 'pdf':
                # Generate PDF report
                pdf = analysis.generate_pdf_report()
                pdfhttpheaders = [
                    ('Content-Type', 'application/pdf'),
                    ('Content-Disposition', f'attachment; filename=ratio_analysis_{analysis_id}.pdf')
                ]
                return request.make_response(pdf, headers=pdfhttpheaders)
            
            elif format == 'excel':
                # Generate Excel report
                excel_data = analysis.generate_excel_report()
                xlsxhttpheaders = [
                    ('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
                    ('Content-Disposition', f'attachment; filename=ratio_analysis_{analysis_id}.xlsx')
                ]
                return request.make_response(excel_data, headers=xlsxhttpheaders)
            
            elif format == 'json':
                # Return JSON data
                data = {
                    'analysis_id': analysis.id,
                    'name': analysis.name,
                    'company': analysis.company_id.name,
                    'period': {
                        'from': analysis.date_from.isoformat(),
                        'to': analysis.date_to.isoformat()
                    },
                    'ratios': json.loads(analysis.ratio_data) if analysis.ratio_data else {},
                    'recommendations': json.loads(analysis.recommendations) if analysis.recommendations else [],
                    'summary': json.loads(analysis.analysis_summary) if analysis.analysis_summary else {}
                }
                return request.make_response(
                    json.dumps(data, indent=2),
                    headers=[('Content-Type', 'application/json')]
                )
            
            else:
                return request.make_response(
                    json.dumps({'status': 'error', 'message': f'Unsupported format: {format}'}),
                    headers=[('Content-Type', 'application/json')],
                    status=400
                )
                
        except Exception as e:
            _logger.error(f"Error in export_analysis API: {str(e)}")
            return request.make_response(
                json.dumps({'status': 'error', 'message': str(e)}),
                headers=[('Content-Type', 'application/json')],
                status=500
            )
    
    @http.route('/api/v1/ratio-analysis/webhook/configure', type='json', auth='public', methods=['POST'], cors='*', csrf=True)
    @secure_api_endpoint(
        rate_limit_per_hour=10,
        rate_limit_per_minute=2,
        require_hmac=True,
        require_jwt=True
    )
    def configure_webhook(self, **kwargs):
        """
        Configure webhook for ratio alerts
        
        Expected payload:
        {
            "company_id": 1,
            "webhook_url": "https://example.com/webhook",
            "events": ["critical_alert", "prediction_complete"],
            "active": true
        }
        """
        try:
            data = request.jsonrequest
            company_id = data.get('company_id') or request.api_company
            webhook_url = data.get('webhook_url')
            events = data.get('events', ['critical_alert'])
            active = data.get('active', True)
            
            if not webhook_url:
                raise BadRequest('webhook_url is required')
            
            # Store webhook configuration (simplified)
            config_param = request.env['ir.config_parameter'].sudo()
            webhook_config = {
                'url': webhook_url,
                'events': events,
                'active': active,
                'created_at': datetime.now().isoformat()
            }
            
            config_param.set_param(
                f'ratio_analysis.webhook.{company_id}',
                json.dumps(webhook_config)
            )
            
            return {
                'status': 'success',
                'message': 'Webhook configured successfully',
                'configuration': webhook_config
            }
            
        except BadRequest:
            raise
        except Exception as e:
            _logger.error(f"Error in configure_webhook API: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }