# -*- coding: utf-8 -*-
"""
Machine Learning Module for Financial Ratio Prediction
Implements predictive analytics for financial ratios
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import json
import logging
import numpy as np
from datetime import datetime
from dateutil.relativedelta import relativedelta
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score
import joblib
import os

_logger = logging.getLogger(__name__)


class RatioPredictionML(models.Model):
    """Machine Learning model for financial ratio prediction"""
    
    _name = 'ratio.prediction.ml'
    _description = 'Financial Ratio Prediction with Machine Learning'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    
    name = fields.Char(
        string='Prediction Name',
        required=True,
        default=lambda self: _('New Prediction')
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        required=True,
        default=lambda self: self.env.company
    )
    
    prediction_type = fields.Selection([
        ('single_ratio', 'Single Ratio Prediction'),
        ('multi_ratio', 'Multiple Ratios Prediction'),
        ('bankruptcy', 'Bankruptcy Risk Prediction'),
        ('growth', 'Growth Prediction'),
        ('anomaly', 'Anomaly Detection')
    ], string='Prediction Type', required=True, default='single_ratio')
    
    target_ratio = fields.Selection([
        ('current_ratio', 'Current Ratio'),
        ('quick_ratio', 'Quick Ratio'),
        ('debt_to_equity', 'Debt to Equity'),
        ('return_on_assets', 'Return on Assets'),
        ('return_on_equity', 'Return on Equity'),
        ('net_profit_margin', 'Net Profit Margin'),
        ('asset_turnover', 'Asset Turnover'),
        ('altman_z_score', 'Altman Z-Score')
    ], string='Target Ratio')
    
    model_type = fields.Selection([
        ('linear_regression', 'Linear Regression'),
        ('random_forest', 'Random Forest'),
        ('gradient_boosting', 'Gradient Boosting'),
        ('neural_network', 'Neural Network'),
        ('arima', 'ARIMA Time Series')
    ], string='Model Type', required=True, default='random_forest')
    
    training_periods = fields.Integer(
        string='Training Periods (months)',
        default=24,
        help='Number of historical months to use for training'
    )
    
    prediction_horizon = fields.Integer(
        string='Prediction Horizon (months)',
        default=6,
        help='Number of months to predict into the future'
    )
    
    state = fields.Selection([
        ('draft', 'Draft'),
        ('training', 'Training'),
        ('trained', 'Trained'),
        ('predicting', 'Predicting'),
        ('completed', 'Completed'),
        ('error', 'Error')
    ], string='State', default='draft', tracking=True)
    
    # Model performance metrics
    model_accuracy = fields.Float(
        string='Model Accuracy (R²)',
        digits=(16, 4),
        readonly=True
    )
    
    mean_squared_error_value = fields.Float(
        string='Mean Squared Error',
        digits=(16, 4),
        readonly=True
    )
    
    feature_importance = fields.Text(
        string='Feature Importance',
        readonly=True
    )
    
    # Prediction results
    predictions = fields.Text(
        string='Predictions (JSON)',
        readonly=True
    )
    
    confidence_intervals = fields.Text(
        string='Confidence Intervals',
        readonly=True
    )
    
    # Model storage
    model_path = fields.Char(
        string='Model File Path',
        readonly=True
    )
    
    last_training_date = fields.Datetime(
        string='Last Training Date',
        readonly=True
    )
    
    error_message = fields.Text(
        string='Error Message',
        readonly=True
    )
    
    # Visualization data
    visualization_data = fields.Text(
        string='Visualization Data',
        readonly=True
    )
    
    @api.model_create_multi
    def create(self, vals_list):
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for vals in vals_list:
            if vals.get('name', _('New')) == _('New'):
                vals['name'] = self._generate_prediction_name(vals)
        return super().create(vals_list)
    
    def _generate_prediction_name(self, vals):
        """Generate meaningful prediction name"""
        prediction_type = vals.get('prediction_type', 'single_ratio')
        target_ratio = vals.get('target_ratio', 'general')
        return f"{prediction_type.replace('_', ' ').title()} - {target_ratio.replace('_', ' ').title()} - {fields.Date.today()}"
    
    def action_train_model(self):
        """Train the ML model with historical data"""
        for record in self:
            try:
                record.state = 'training'
                record.error_message = False
                
                # Collect historical data
                historical_data = record._collect_historical_data()
                
                if not historical_data or len(historical_data) < 12:
                    raise UserError(_("Insufficient historical data for training. Need at least 12 months of data."))
                
                # Prepare features and target
                X, y, feature_names = record._prepare_training_data(historical_data)
                
                # Split data
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42
                )
                
                # Scale features
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)
                
                # Train model
                model = record._get_model_instance()
                model.fit(X_train_scaled, y_train)
                
                # Evaluate model
                y_pred = model.predict(X_test_scaled)
                mse = mean_squared_error(y_test, y_pred)
                r2 = r2_score(y_test, y_pred)
                
                # Save model
                model_filename = record._save_model(model, scaler)
                
                # Calculate feature importance
                feature_importance = record._calculate_feature_importance(model, feature_names)
                
                # Update record
                record.write({
                    'state': 'trained',
                    'model_accuracy': r2,
                    'mean_squared_error_value': mse,
                    'feature_importance': json.dumps(feature_importance, indent=2),
                    'model_path': model_filename,
                    'last_training_date': fields.Datetime.now(),
                })
                
                # Log success
                _logger.info(f"Successfully trained model: {record.name} with R² = {r2:.4f}")
                
            except Exception as e:
                _logger.error(f"Error training model: {str(e)}")
                record.write({
                    'state': 'error',
                    'error_message': str(e)
                })
                raise
    
    def action_predict(self):
        """Generate predictions using the trained model"""
        for record in self:
            try:
                if record.state != 'trained':
                    raise UserError(_("Model must be trained before making predictions"))
                
                record.state = 'predicting'
                
                # Load model
                model, scaler = record._load_model()
                
                # Get latest data for prediction
                latest_data = record._get_latest_financial_data()
                
                # Generate predictions
                predictions = []
                confidence_intervals = []
                
                for i in range(record.prediction_horizon):
                    # Prepare features for prediction
                    X_pred = record._prepare_prediction_features(latest_data, i)
                    X_pred_scaled = scaler.transform([X_pred])
                    
                    # Make prediction
                    y_pred = model.predict(X_pred_scaled)[0]
                    
                    # Calculate confidence interval (simplified)
                    std_dev = np.sqrt(record.mean_squared_error_value)
                    lower_bound = y_pred - 1.96 * std_dev
                    upper_bound = y_pred + 1.96 * std_dev
                    
                    prediction_date = fields.Date.today() + relativedelta(months=i+1)
                    
                    predictions.append({
                        'date': prediction_date.isoformat(),
                        'value': float(y_pred),
                        'month': i + 1
                    })
                    
                    confidence_intervals.append({
                        'date': prediction_date.isoformat(),
                        'lower': float(lower_bound),
                        'upper': float(upper_bound)
                    })
                
                # Generate visualization data
                viz_data = record._generate_visualization_data(predictions)
                
                # Update record
                record.write({
                    'state': 'completed',
                    'predictions': json.dumps(predictions, indent=2),
                    'confidence_intervals': json.dumps(confidence_intervals, indent=2),
                    'visualization_data': json.dumps(viz_data, indent=2),
                })
                
                # Check for alerts
                record._check_prediction_alerts(predictions)
                
                _logger.info(f"Successfully generated predictions for: {record.name}")
                
            except Exception as e:
                _logger.error(f"Error generating predictions: {str(e)}")
                record.write({
                    'state': 'error',
                    'error_message': str(e)
                })
                raise
    
    def _collect_historical_data(self):
        """Collect historical financial data for training"""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        self.ensure_one()
        
        historical_data = []
        end_date = fields.Date.today()
        
        for i in range(self.training_periods):
            start_date = end_date - relativedelta(months=1)
            
            # Create analysis for historical period
            analysis = self.env['account.ratio.analysis.service'].create({
                'name': f'ML Training Data - Period {i+1}',
                'company_id': self.company_id.id,
                'date_from': start_date,
                'date_to': end_date,
                'analysis_type': 'comprehensive',
            })
            
            try:
                analysis.compute_analysis()
                
                # Extract all ratio values
                ratio_data = {
                    'period': i,
                    'date': end_date,
                    'current_ratio': analysis.current_ratio,
                    'quick_ratio': analysis.quick_ratio,
                    'cash_ratio': analysis.cash_ratio,
                    'debt_to_equity': analysis.debt_to_equity,
                    'return_on_assets': analysis.return_on_assets,
                    'return_on_equity': analysis.return_on_equity,
                    'gross_profit_margin': analysis.gross_profit_margin,
                    'net_profit_margin': analysis.net_profit_margin,
                    'asset_turnover': analysis.asset_turnover,
                    'inventory_turnover': analysis.inventory_turnover,
                    'receivables_turnover': analysis.receivables_turnover,
                    'altman_z_score': analysis.altman_z_score,
                }
                
                # Add economic indicators (simplified)
                ratio_data.update(self._get_economic_indicators(end_date))
                
                historical_data.append(ratio_data)
                
            finally:
                # Clean up temporary analysis
                analysis.unlink()
            
            end_date = start_date - relativedelta(days=1)
        
        return historical_data
    
    def _prepare_training_data(self, historical_data):
        """Prepare features and target for training"""
        feature_names = []
        features = []
        target = []
        
        # Define features based on prediction type
        if self.prediction_type == 'single_ratio':
            # Use other ratios as features to predict target ratio
            all_ratios = [
                'current_ratio', 'quick_ratio', 'debt_to_equity',
                'return_on_assets', 'return_on_equity', 'net_profit_margin',
                'asset_turnover', 'inventory_turnover'
            ]
            
            feature_ratios = [r for r in all_ratios if r != self.target_ratio]
            feature_names = feature_ratios + ['period', 'month', 'quarter']
            
            for i in range(len(historical_data) - 1):
                data = historical_data[i]
                next_data = historical_data[i + 1]
                
                feature_row = []
                for ratio in feature_ratios:
                    feature_row.append(data.get(ratio, 0))
                
                # Add time features
                feature_row.extend([
                    data['period'],
                    data['date'].month,
                    (data['date'].month - 1) // 3 + 1  # Quarter
                ])
                
                features.append(feature_row)
                target.append(next_data.get(self.target_ratio, 0))
        
        elif self.prediction_type == 'bankruptcy':
            # Use all ratios to predict Altman Z-Score
            feature_names = [
                'current_ratio', 'quick_ratio', 'debt_to_equity',
                'return_on_assets', 'return_on_equity', 'net_profit_margin',
                'asset_turnover', 'cash_ratio'
            ]
            
            for i in range(len(historical_data) - 1):
                data = historical_data[i]
                next_data = historical_data[i + 1]
                
                feature_row = [data.get(ratio, 0) for ratio in feature_names]
                features.append(feature_row)
                target.append(next_data.get('altman_z_score', 0))
        
        return np.array(features), np.array(target), feature_names
    
    def _get_model_instance(self):
        """Get the appropriate ML model instance"""
        if self.model_type == 'linear_regression':
            return LinearRegression()
        elif self.model_type == 'random_forest':
            return RandomForestRegressor(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
        elif self.model_type == 'gradient_boosting':
            from sklearn.ensemble import GradientBoostingRegressor
            return GradientBoostingRegressor(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
        elif self.model_type == 'neural_network':
            from sklearn.neural_network import MLPRegressor
            return MLPRegressor(
                hidden_layer_sizes=(100, 50),
                activation='relu',
                solver='adam',
                max_iter=1000,
                random_state=42
            )
        else:
            raise UserError(_("Model type %s not implemented") % self.model_type)
    
    def _save_model(self, model, scaler):
        """Save trained model and scaler to disk"""
        # Create directory for models
        model_dir = os.path.join(
            self.env['ir.config_parameter'].sudo().get_param('web.base.url'),
            'ml_models'
        )
        os.makedirs(model_dir, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"ratio_model_{self.id}_{timestamp}.pkl"
        filepath = os.path.join(model_dir, filename)
        
        # Save model and scaler
        joblib.dump({'model': model, 'scaler': scaler}, filepath)
        
        return filepath
    
    def _load_model(self):
        """Load trained model and scaler from disk"""
        if not self.model_path:
            raise UserError(_("No trained model found"))
        
        model_data = joblib.load(self.model_path)
        return model_data['model'], model_data['scaler']
    
    def _calculate_feature_importance(self, model, feature_names):
        """Calculate and return feature importance"""
        importance_dict = {}
        
        if hasattr(model, 'feature_importances_'):
            # For tree-based models
            importances = model.feature_importances_
            for name, importance in zip(feature_names, importances):
                importance_dict[name] = float(importance)
        elif hasattr(model, 'coef_'):
            # For linear models
            coefficients = model.coef_
            for name, coef in zip(feature_names, coefficients):
                importance_dict[name] = float(abs(coef))
        else:
            # For other models, use permutation importance
            importance_dict = {name: 0.0 for name in feature_names}
        
        # Sort by importance
        sorted_importance = dict(sorted(
            importance_dict.items(),
            key=lambda x: x[1],
            reverse=True
        ))
        
        return sorted_importance
    
    def _get_latest_financial_data(self):
        """Get the latest financial data for predictions"""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        # Get the most recent ratio analysis
        latest_analysis = self.env['account.ratio.analysis.service'].search([
            ('company_id', '=', self.company_id.id),
            ('state', '=', 'computed')
        ], order='date_to desc', limit=1)
        
        if not latest_analysis:
            # Create new analysis for current period
            end_date = fields.Date.today()
            start_date = end_date - relativedelta(months=1)
            
            latest_analysis = self.env['account.ratio.analysis.service'].create({
                'name': 'ML Prediction Base Data',
                'company_id': self.company_id.id,
                'date_from': start_date,
                'date_to': end_date,
                'analysis_type': 'comprehensive',
            })
            latest_analysis.compute_analysis()
        
        return {
            'current_ratio': latest_analysis.current_ratio,
            'quick_ratio': latest_analysis.quick_ratio,
            'debt_to_equity': latest_analysis.debt_to_equity,
            'return_on_assets': latest_analysis.return_on_assets,
            'return_on_equity': latest_analysis.return_on_equity,
            'net_profit_margin': latest_analysis.net_profit_margin,
            'asset_turnover': latest_analysis.asset_turnover,
            'inventory_turnover': latest_analysis.inventory_turnover,
        }
    
    def _prepare_prediction_features(self, latest_data, month_offset):
        """Prepare features for prediction"""
        features = []
        
        if self.prediction_type == 'single_ratio':
            # Use latest ratios as features
            all_ratios = [
                'current_ratio', 'quick_ratio', 'debt_to_equity',
                'return_on_assets', 'return_on_equity', 'net_profit_margin',
                'asset_turnover', 'inventory_turnover'
            ]
            
            feature_ratios = [r for r in all_ratios if r != self.target_ratio]
            
            for ratio in feature_ratios:
                features.append(latest_data.get(ratio, 0))
            
            # Add time features
            future_date = fields.Date.today() + relativedelta(months=month_offset+1)
            features.extend([
                month_offset,
                future_date.month,
                (future_date.month - 1) // 3 + 1  # Quarter
            ])
        
        return features
    
    def _generate_visualization_data(self, predictions):
        """Generate data for visualization"""
        # Get historical data for comparison
        historical = []
        
        for i in range(12):  # Last 12 months
            date = fields.Date.today() - relativedelta(months=i)
            analysis = self.env['account.ratio.analysis.service'].search([
                ('company_id', '=', self.company_id.id),
                ('date_to', '>=', date - relativedelta(days=5)),
                ('date_to', '<=', date + relativedelta(days=5)),
                ('state', '=', 'computed')
            ], limit=1)
            
            if analysis:
                value = getattr(analysis, self.target_ratio, 0)
                historical.append({
                    'date': date.isoformat(),
                    'value': value,
                    'type': 'historical'
                })
        
        # Combine with predictions
        
        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for pred in predictions:
            pred['type'] = 'predicted'
        
        return {
            'historical': list(reversed(historical)),
            'predictions': predictions,
            'target_ratio': self.target_ratio,
            'company': self.company_id.name
        }
    
    def _get_economic_indicators(self, date):
        """Get economic indicators for the given date (simplified)"""
        # In a real implementation, this would fetch actual economic data
        return {
            'gdp_growth': np.random.uniform(1.5, 3.5),
            'inflation_rate': np.random.uniform(1.0, 3.0),
            'interest_rate': np.random.uniform(2.0, 5.0),
        }
    
    def _check_prediction_alerts(self, predictions):
        """Check predictions and create alerts if necessary"""
        # Define thresholds for alerts
        alert_thresholds = {
            'current_ratio': {'min': 1.0, 'critical': 0.8},
            'quick_ratio': {'min': 0.8, 'critical': 0.6},
            'debt_to_equity': {'max': 2.0, 'critical': 3.0},
            'altman_z_score': {'min': 1.81, 'critical': 1.23},
        }
        
        if self.target_ratio in alert_thresholds:
            thresholds = alert_thresholds[self.target_ratio]
            
            for pred in predictions:
                value = pred['value']
                
                # Check for critical alerts
                if 'critical' in thresholds:
                    if 'min' in thresholds and value < thresholds['critical']:
                        self.env.create_critical_alert(pred)
                    elif 'max' in thresholds and value > thresholds['critical']:
                        self.env.create_critical_alert(pred)
                
                # Check for warning alerts
                elif 'min' in thresholds and value < thresholds['min']:
                    self.env.create_warning_alert(pred)
                elif 'max' in thresholds and value > thresholds['max']:
                    self.env.create_warning_alert(pred)
    
    def _create_critical_alert(self, prediction):
        """Create critical alert activity"""
        self.activity_schedule(
            'mail.mail_activity_data_todo',
            summary=f"Critical: {self.target_ratio} prediction",
            note=f"Predicted {self.target_ratio} of {prediction['value']:.2f} for {prediction['date']} is in critical range",
            date_deadline=fields.Date.today() + relativedelta(days=7)
        )
    
    def _create_warning_alert(self, prediction):
        """Create warning alert activity"""
        self.activity_schedule(
            'mail.mail_activity_data_warning',
            summary=f"Warning: {self.target_ratio} prediction",
            note=f"Predicted {self.target_ratio} of {prediction['value']:.2f} for {prediction['date']} requires attention"
        )
    
    @api.model
    def run_scheduled_predictions(self):
        """Cron job to run predictions for all trained models"""
        models = self.search([('state', '=', 'trained')])
        for model in models:
            try:
                model.action_predict()
            except Exception as e:
                _logger.error(f"Error in scheduled prediction for {model.name}: {str(e)}")
    
    def action_retrain(self):
        """Retrain the model with updated data"""
        self.ensure_one()
        self.state = 'draft'
        self.action_train_model()
    
    def action_export_predictions(self):
        """Export predictions to Excel"""
        # Implementation would export to Excel using xlsxwriter
        pass