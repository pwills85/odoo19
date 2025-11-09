# -*- coding: utf-8 -*-
"""
Tests para validar cálculos REALES F22 
Verifica accuracy vs datos contables y rendimiento

Caraterísticas:
- Datos contables sintéticos realistas
- Validación accuracy 100% vs cálculos manuales  
- Tests de performance con datasets grandes
- Escenarios edge cases tributarios chilenos
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import UserError
import time
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'f22_real_calculations')
class TestL10nClF22RealCalculations(TransactionCase):
    """Tests para F22 con cálculos reales desde contabilidad"""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Configurar compañía de prueba
        cls.company = cls.env.user.company_id
        cls.company.write({
            'name': 'Test Company Chile',
            'vat': '96789123-4',
            'country_id': cls.env.ref('base.cl').id,
        })
        
        # Configurar cuentas contables chilenas
        cls._setup_chilean_accounts()
        
        # Configurar servicio SII
        cls.sii_service = cls.env['account.financial.report.sii.integration.service']
        
        # Año de prueba
        cls.test_year = 2024
        cls.fiscal_year = 2025  # Año tributario
    
    @classmethod
    def _setup_chilean_accounts(cls):
        """Crea plan de cuentas chileno simplificado para tests"""
        AccountAccount = cls.env['account.account']
        
        # Crear cuentas de ingresos
        cls.account_income = AccountAccount.create({
            'name': 'Ventas',
            'code': '4101',
            'user_type_id': cls.env.ref('account.data_account_type_revenue').id,
        })
        
        cls.account_income_financial = AccountAccount.create({
            'name': 'Ingresos Financieros', 
            'code': '4201',
            'user_type_id': cls.env.ref('account.data_account_type_revenue').id,
        })
        
        # Crear cuentas de costos/gastos
        cls.account_cogs = AccountAccount.create({
            'name': 'Costo de Ventas',
            'code': '5101', 
            'user_type_id': cls.env.ref('account.data_account_type_expenses').id,
        })
        
        cls.account_opex = AccountAccount.create({
            'name': 'Gastos Operacionales',
            'code': '6101',
            'user_type_id': cls.env.ref('account.data_account_type_expenses').id,
        })
        
        cls.account_finex = AccountAccount.create({
            'name': 'Gastos Financieros',
            'code': '6201',
            'user_type_id': cls.env.ref('account.data_account_type_expenses').id,
        })
        
        cls.account_depreciation = AccountAccount.create({
            'name': 'Depreciación',
            'code': '6301',
            'user_type_id': cls.env.ref('account.data_account_type_expenses').id,
        })
        
        # Cuenta para gastos rechazados
        cls.account_rejected = AccountAccount.create({
            'name': 'Gastos Rechazados',
            'code': '6801',
            'user_type_id': cls.env.ref('account.data_account_type_expenses').id,
        })
    
    def _create_account_moves(self, year, income_data, expense_data):
        """
        Crea movimientos contables de prueba
        
        Args:
            year: Año contable
            income_data: dict con montos de ingresos
            expense_data: dict con montos de gastos
        """
        AccountMove = self.env['account.move']
        journal = self.env['account.journal'].search([
            ('type', '=', 'general'),
            ('company_id', '=', self.company.id)
        ], limit=1)
        
        moves_data = []
        
        # Crear movimiento de ingresos
        if income_data:
            move_lines = []
            
            # Ingresos operacionales
            if income_data.get('operacional', 0):
                move_lines.extend([
                    (0, 0, {
                        'name': 'Ventas del año',
                        'account_id': self.account_income.id,
                        'credit': income_data['operacional'],
                        'debit': 0.0,
                    }),
                    (0, 0, {
                        'name': 'Clientes',
                        'account_id': self.env['account.account'].search([
                            ('user_type_id', '=', self.env.ref('account.data_account_type_receivable').id)
                        ], limit=1).id,
                        'debit': income_data['operacional'],
                        'credit': 0.0,
                    })
                ])
            
            # Ingresos no operacionales
            if income_data.get('no_operacional', 0):
                move_lines.extend([
                    (0, 0, {
                        'name': 'Ingresos Financieros',
                        'account_id': self.account_income_financial.id,
                        'credit': income_data['no_operacional'],
                        'debit': 0.0,
                    }),
                    (0, 0, {
                        'name': 'Banco',
                        'account_id': self.env['account.account'].search([
                            ('user_type_id', '=', self.env.ref('account.data_account_type_liquidity').id)
                        ], limit=1).id,
                        'debit': income_data['no_operacional'],
                        'credit': 0.0,
                    })
                ])
            
            if move_lines:
                move = AccountMove.create({
                    'journal_id': journal.id,
                    'date': f'{year}-12-31',
                    'ref': f'Ingresos {year}',
                    'line_ids': move_lines,
                })
                move.action_post()
                moves_data.append(move)
        
        # Crear movimiento de gastos
        if expense_data:
            move_lines = []
            
            # Mapeo cuenta -> monto
            expense_mapping = {
                'costo_ventas': self.account_cogs.id,
                'gastos_operacionales': self.account_opex.id, 
                'gastos_financieros': self.account_finex.id,
                'depreciacion': self.account_depreciation.id,
                'gastos_rechazados': self.account_rejected.id,
            }
            
            for expense_type, amount in expense_data.items():
                if amount > 0 and expense_type in expense_mapping:
                    move_lines.extend([
                        (0, 0, {
                            'name': expense_type.replace('_', ' ').title(),
                            'account_id': expense_mapping[expense_type],
                            'debit': amount,
                            'credit': 0.0,
                        }),
                        (0, 0, {
                            'name': 'Proveedores',
                            'account_id': self.env['account.account'].search([
                                ('user_type_id', '=', self.env.ref('account.data_account_type_payable').id)
                            ], limit=1).id,
                            'credit': amount,
                            'debit': 0.0,
                        })
                    ])
            
            if move_lines:
                move = AccountMove.create({
                    'journal_id': journal.id,
                    'date': f'{year}-12-31',
                    'ref': f'Gastos {year}',
                    'line_ids': move_lines,
                })
                move.action_post()
                moves_data.append(move)
        
        return moves_data
    
    def test_f22_basic_calculation_accuracy(self):
        """Test accuracy de cálculo F22 básico"""
        
        # Datos de prueba conocidos
        income_data = {
            'operacional': 1000000,      # $1.000.000
            'no_operacional': 50000,     # $50.000
        }
        
        expense_data = {
            'costo_ventas': 600000,      # $600.000
            'gastos_operacionales': 200000,  # $200.000
            'gastos_financieros': 30000,     # $30.000
            'depreciacion': 20000,           # $20.000
        }
        
        # Crear movimientos contables
        self._create_account_moves(self.test_year, income_data, expense_data)
        
        # Crear F22
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.fiscal_year,
        })
        
        # Ejecutar cálculo real
        start_time = time.time()
        f22.action_calculate()
        calculation_time = time.time() - start_time
        
        # Verificar accuracy de cálculos
        expected_totals = {
            'ingresos_totales': 1050000,    # 1.000.000 + 50.000
            'gastos_totales': 850000,       # 600.000 + 200.000 + 30.000 + 20.000
            'resultado_antes_impuesto': 200000,  # 1.050.000 - 850.000
            'renta_liquida_imponible': 200000,   # sin ajustes en este caso
            'impuesto_primera_categoria': 54000, # 200.000 * 0.27
        }
        
        for field, expected_value in expected_totals.items():
            actual_value = getattr(f22, field)
            self.assertEqual(
                actual_value, 
                expected_value,
                f"Campo {field}: esperado {expected_value}, obtenido {actual_value}"
            )
        
        # Verificar performance (debe ser < 3 segundos)
        self.assertLess(calculation_time, 3.0, 
                       f"Cálculo F22 tardó {calculation_time:.2f}s, debe ser < 3s")
        
        _logger.info(f"Test F22 básico: Cálculo en {calculation_time:.3f}s - ACCURACY OK")
    
    def test_f22_with_tax_adjustments(self):
        """Test F22 con ajustes tributarios (agregados/deducciones)"""
        
        # Datos con ajustes tributarios
        income_data = {
            'operacional': 2000000,
            'no_operacional': 100000,
        }
        
        expense_data = {
            'costo_ventas': 1000000,
            'gastos_operacionales': 500000,
            'gastos_financieros': 50000,
            'depreciacion': 100000,
            'gastos_rechazados': 80000,  # Gastos rechazados tributariamente
        }
        
        # Crear movimientos
        self._create_account_moves(self.test_year, income_data, expense_data)
        
        # Crear F22
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.fiscal_year,
        })
        
        # Calcular
        f22.action_calculate()
        
        # Verificar cálculos con ajustes
        # Resultado antes impuesto = 2.100.000 - 1.650.000 = 450.000
        # + Gastos rechazados = 450.000 + 80.000 = 530.000
        # Impuesto = 530.000 * 0.27 = 143.100
        
        self.assertEqual(f22.resultado_antes_impuesto, 450000)
        self.assertEqual(f22.agregados_gastos_rechazados, 80000)
        self.assertEqual(f22.renta_liquida_imponible, 530000)
        self.assertEqual(f22.impuesto_primera_categoria, 143100)
        
        _logger.info("Test F22 con ajustes tributarios: ACCURACY OK")
    
    def test_f22_performance_large_dataset(self):
        """Test performance F22 con dataset grande"""
        
        # Crear muchos movimientos pequeños (simula empresa real)
        large_income = {'operacional': 10000000}  # $10M
        large_expenses = {
            'costo_ventas': 6000000,
            'gastos_operacionales': 2000000,
            'gastos_financieros': 500000,
            'depreciacion': 300000,
        }
        
        # Crear movimientos distribuidos en el año
        for month in range(1, 13):
            monthly_income = {k: v // 12 for k, v in large_income.items()}
            monthly_expenses = {k: v // 12 for k, v in large_expenses.items()}
            
            self._create_account_moves(
                self.test_year, 
                monthly_income, 
                monthly_expenses
            )
        
        # Crear F22
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.fiscal_year,
        })
        
        # Medir performance
        start_time = time.time()
        f22.action_calculate()
        calculation_time = time.time() - start_time
        
        # Verificar que performance sea aceptable (< 30s como requerido)
        self.assertLess(calculation_time, 30.0,
                       f"Cálculo F22 con dataset grande tardó {calculation_time:.2f}s")
        
        # Verificar accuracy con datos grandes
        expected_rli = 1200000  # (10M - 8.8M)
        expected_tax = 324000   # 1.200.000 * 0.27
        
        self.assertEqual(f22.renta_liquida_imponible, expected_rli)
        self.assertEqual(f22.impuesto_primera_categoria, expected_tax)
        
        _logger.info(f"Test F22 performance dataset grande: {calculation_time:.3f}s - OK")
    
    def test_f22_edge_cases(self):
        """Test casos extremos F22"""
        
        # Caso 1: Pérdida tributaria (RLI = 0)
        loss_data_income = {'operacional': 100000}
        loss_data_expenses = {'costo_ventas': 150000}
        
        self._create_account_moves(self.test_year, loss_data_income, loss_data_expenses)
        
        f22_loss = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.fiscal_year,
        })
        
        f22_loss.action_calculate()
        
        # Con pérdida, RLI debe ser 0
        self.assertEqual(f22_loss.renta_liquida_imponible, 0)
        self.assertEqual(f22_loss.impuesto_primera_categoria, 0)
        
        # Caso 2: Solo ingresos financieros
        financial_only_income = {'no_operacional': 500000}
        
        # Limpiar movimientos previos y crear nuevos
        self.env['account.move'].search([
            ('company_id', '=', self.company.id),
            ('date', '>=', f'{self.test_year}-01-01'),
            ('date', '<=', f'{self.test_year}-12-31'),
        ]).button_cancel()
        
        self._create_account_moves(self.test_year, financial_only_income, {})
        
        f22_financial = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.fiscal_year + 1,  # Evitar duplicado
        })
        
        f22_financial.action_calculate()
        
        # Solo ingresos financieros
        self.assertEqual(f22_financial.ingresos_no_operacionales, 500000)
        self.assertEqual(f22_financial.ingresos_operacionales, 0)
        self.assertEqual(f22_financial.renta_liquida_imponible, 500000)
        
        _logger.info("Test F22 casos extremos: OK")
    
    def test_f22_cache_functionality(self):
        """Test funcionalidad de cache del servicio F22"""
        
        # Configurar datos
        income_data = {'operacional': 500000}
        expense_data = {'costo_ventas': 300000}
        
        self._create_account_moves(self.test_year, income_data, expense_data)
        
        # Primera llamada (sin cache)
        start_time = time.time()
        f22_data_1 = self.sii_service.generate_f22_data(self.company, self.fiscal_year)
        first_call_time = time.time() - start_time
        
        # Segunda llamada (con cache)
        start_time = time.time()
        f22_data_2 = self.sii_service.generate_f22_data(self.company, self.fiscal_year)
        second_call_time = time.time() - start_time
        
        # Verificar que los datos son idénticos
        self.assertEqual(f22_data_1, f22_data_2)
        
        # Verificar que cache mejora performance (segunda llamada debe ser más rápida)
        self.assertLess(second_call_time, first_call_time)
        
        # Limpiar cache y verificar
        self.sii_service.clear_cache('f22_*')
        
        # Tercera llamada (cache limpiado)
        start_time = time.time()
        f22_data_3 = self.sii_service.generate_f22_data(self.company, self.fiscal_year)
        third_call_time = time.time() - start_time
        
        # Debe ser similar al primer llamado (sin cache)
        self.assertGreater(third_call_time, second_call_time)
        self.assertEqual(f22_data_1, f22_data_3)
        
        _logger.info(f"Test cache F22: 1era={first_call_time:.3f}s, "
                    f"2da={second_call_time:.3f}s, 3era={third_call_time:.3f}s - OK")
    
    def test_f22_validation_errors(self):
        """Test validaciones y manejo de errores F22"""
        
        # Caso 1: Sin movimientos contables
        f22_empty = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.fiscal_year + 5,  # Año sin datos
        })
        
        # Debe calcular sin errores (valores en 0)
        f22_empty.action_calculate()
        self.assertEqual(f22_empty.ingresos_totales, 0)
        self.assertEqual(f22_empty.renta_liquida_imponible, 0)
        
        # Caso 2: F22 ya validado (debe dar error al recalcular)
        income_data = {'operacional': 100000}
        self._create_account_moves(self.test_year, income_data, {})
        
        f22_validated = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.fiscal_year + 6,
            'state': 'validated',
        })
        
        with self.assertRaises(UserError):
            f22_validated.action_calculate()
        
        _logger.info("Test validaciones F22: OK")