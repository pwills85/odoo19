# -*- coding: utf-8 -*-
from odoo.tests import TransactionCase, tagged
from datetime import date, timedelta


@tagged('post_install', '-at_install', 'balance_eight_columns')
class TestBalanceEightColumns(TransactionCase):
    """Test cases para el Balance de 8 Columnas"""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Compañía de prueba
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company Chile',
            'currency_id': cls.env.ref('base.CLP').id,
        })
        
        # Plan de cuentas de prueba
        cls.account_type_asset = cls.env.ref('account.data_account_type_current_assets')
        cls.account_type_liability = cls.env.ref('account.data_account_type_current_liabilities')
        cls.account_type_income = cls.env.ref('account.data_account_type_revenue')
        cls.account_type_expense = cls.env.ref('account.data_account_type_expenses')
        
        # Crear cuentas de prueba
        cls.account_cash = cls._create_account(cls, '1110', 'Caja', cls.account_type_asset)
        cls.account_bank = cls._create_account(cls, '1111', 'Banco', cls.account_type_asset)
        cls.account_receivable = cls._create_account(cls, '1120', 'Clientes', cls.account_type_asset)
        cls.account_payable = cls._create_account(cls, '2110', 'Proveedores', cls.account_type_liability)
        cls.account_capital = cls._create_account(cls, '3110', 'Capital Social', cls.account_type_liability)
        cls.account_sales = cls._create_account(cls, '4110', 'Ventas', cls.account_type_income)
        cls.account_expenses = cls._create_account(cls, '6110', 'Gastos Generales', cls.account_type_expense)
        
        # Diario de prueba
        cls.journal = cls.env['account.journal'].create({
            'name': 'Test Journal',
            'type': 'general',
            'code': 'TEST',
            'company_id': cls.company.id,
        })
        
        # Fecha de prueba
        cls.date_from = date.today().replace(day=1)
        cls.date_to = date.today()
        
    def _create_account(self, code, name, account_type):
        """Helper para crear cuentas"""
        return self.env['account.account'].create({
            'code': code,
            'name': name,
            'account_type': account_type.id,
            'company_id': self.company.id,
        })
    
    def _create_move(self, date_move, lines):
        """Helper para crear asientos contables"""
        move_vals = {
            'date': date_move,
            'journal_id': self.journal.id,
            'company_id': self.company.id,
            'line_ids': [(0, 0, line) for line in lines],
        }
        move = self.env['account.move'].create(move_vals)
        move.action_post()
        return move
    
    def test_01_balance_creation(self):
        """Test creación básica del balance"""
        balance = self.env['account.balance.eight.columns'].create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
        })
        
        self.assertEqual(balance.state, 'draft')
        self.assertEqual(balance.company_id, self.company)
        self.assertTrue(balance.name)
        
    def test_02_balance_computation_empty(self):
        """Test cálculo de balance sin movimientos"""
        balance = self.env['account.balance.eight.columns'].create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
            'show_zero_balance': True,
        })
        
        # Calcular balance
        balance.action_compute_balance()
        
        self.assertEqual(balance.state, 'computed')
        self.assertTrue(balance.is_balanced)
        self.assertEqual(balance.total_debit, 0.0)
        self.assertEqual(balance.total_credit, 0.0)
        
    def test_03_balance_with_movements(self):
        """Test balance con movimientos contables"""
        # Crear movimientos de prueba
        # Asiento 1: Aporte de capital
        self.env.create_move(self.date_from, [
            {
                'account_id': self.account_cash.id,
                'debit': 1000000.0,
                'credit': 0.0,
            },
            {
                'account_id': self.account_capital.id,
                'debit': 0.0,
                'credit': 1000000.0,
            },
        ])
        
        # Asiento 2: Venta al contado
        self.env.create_move(self.date_from + timedelta(days=5), [
            {
                'account_id': self.account_cash.id,
                'debit': 500000.0,
                'credit': 0.0,
            },
            {
                'account_id': self.account_sales.id,
                'debit': 0.0,
                'credit': 500000.0,
            },
        ])
        
        # Asiento 3: Pago de gastos
        self.env.create_move(self.date_from + timedelta(days=10), [
            {
                'account_id': self.account_expenses.id,
                'debit': 200000.0,
                'credit': 0.0,
            },
            {
                'account_id': self.account_cash.id,
                'debit': 0.0,
                'credit': 200000.0,
            },
        ])
        
        # Crear y calcular balance
        balance = self.env['account.balance.eight.columns'].with_company(self.company).create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
        })
        
        balance.action_compute_balance()
        
        # Verificar estado
        self.assertEqual(balance.state, 'computed')
        self.assertTrue(balance.is_balanced)
        
        # Verificar totales
        self.assertEqual(balance.total_debit, 1700000.0)  # 1000000 + 500000 + 200000
        self.assertEqual(balance.total_credit, 1700000.0)  # 1000000 + 500000 + 200000
        
        # Verificar columnas de saldos
        self.assertEqual(balance.total_debit_balance, balance.total_credit_balance)
        
        # Verificar activos (caja debe tener saldo deudor de 1300000)
        cash_line = balance.line_ids.filtered(lambda l: l.account_id == self.account_cash)
        self.assertTrue(cash_line)
        self.assertEqual(cash_line.debit_balance, 1300000.0)
        self.assertEqual(cash_line.assets, 1300000.0)
        
        # Verificar resultado (ganancia de 300000 = 500000 ventas - 200000 gastos)
        self.assertEqual(balance.total_profit - balance.total_loss, 300000.0)
        
    def test_04_balance_multi_period(self):
        """Test balance con múltiples períodos"""
        # Crear movimientos en diferentes meses
        for month in range(1, 4):
            date_move = date(2024, month, 15)
            self.env.create_move(date_move, [
                {
                    'account_id': self.account_receivable.id,
                    'debit': 100000.0 * month,
                    'credit': 0.0,
                },
                {
                    'account_id': self.account_sales.id,
                    'debit': 0.0,
                    'credit': 100000.0 * month,
                },
            ])
        
        # Balance del primer trimestre
        balance = self.env['account.balance.eight.columns'].with_company(self.company).create({
            'company_id': self.company.id,
            'date_from': date(2024, 1, 1),
            'date_to': date(2024, 3, 31),
        })
        
        balance.action_compute_balance()
        
        # Verificar totales acumulados
        self.assertEqual(balance.total_debit, 600000.0)  # 100000 + 200000 + 300000
        self.assertEqual(balance.total_credit, 600000.0)
        
    def test_05_balance_cuadratura_validation(self):
        """Test validación de cuadratura del balance"""
        # Crear un movimiento descuadrado (esto no debería ser posible en Odoo)
        # pero simulamos para probar la validación
        
        balance = self.env['account.balance.eight.columns'].create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
        })
        
        # Crear líneas manualmente para simular descuadre
        self.env['account.balance.eight.columns.line'].create({
            'balance_id': balance.id,
            'account_id': self.account_cash.id,
            'account_code': self.account_cash.code,
            'account_name': self.account_cash.name,
            'debit': 1000.0,
            'credit': 0.0,
            'debit_balance': 1000.0,
            'credit_balance': 0.0,
            'assets': 1000.0,
            'liabilities': 0.0,
            'loss': 0.0,
            'profit': 0.0,
        })
        
        # Forzar cálculo de validaciones
        balance._compute_validations()
        
        # Debe detectar el descuadre
        self.assertFalse(balance.is_balanced)
        self.assertTrue(balance.validation_errors)
        
    def test_06_balance_export_excel(self):
        """Test exportación a Excel"""
        balance = self.env['account.balance.eight.columns'].create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
        })
        
        balance.action_compute_balance()
        
        # Intentar exportar
        result = balance.action_export_excel()
        
        self.assertTrue(result)
        self.assertEqual(result['type'], 'ir.actions.act_url')
        self.assertIn('/web/content/', result['url'])
        
    def test_07_balance_filters(self):
        """Test filtros del balance"""
        # Crear cuenta con saldo cero
        account_zero = self.env.create_account('1999', 'Cuenta Sin Movimiento', self.account_type_asset)
        
        # Crear movimiento
        self.env.create_move(self.date_from, [
            {
                'account_id': self.account_cash.id,
                'debit': 1000.0,
                'credit': 0.0,
            },
            {
                'account_id': self.account_capital.id,
                'debit': 0.0,
                'credit': 1000.0,
            },
        ])
        
        # Balance sin mostrar cuentas con saldo cero
        balance1 = self.env['account.balance.eight.columns'].with_company(self.company).create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
            'show_zero_balance': False,
        })
        balance1.action_compute_balance()
        
        # Balance mostrando cuentas con saldo cero
        balance2 = self.env['account.balance.eight.columns'].with_company(self.company).create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
            'show_zero_balance': True,
        })
        balance2.action_compute_balance()
        
        # Verificar diferencia
        self.assertLess(len(balance1.line_ids), len(balance2.line_ids))
        self.assertFalse(balance1.line_ids.filtered(lambda l: l.account_id == account_zero))
        self.assertTrue(balance2.line_ids.filtered(lambda l: l.account_id == account_zero))
        
    def test_08_balance_performance(self):
        """Test rendimiento con muchas cuentas"""
        import time
        
        # Crear 100 cuentas
        accounts = []
        for i in range(100):
            account = self.env.create_account(f'1{i:03d}', f'Cuenta Test {i}', self.account_type_asset)
            accounts.append(account)
        
        # Crear 50 movimientos
        for i in range(50):
            lines = [
                {
                    'account_id': accounts[i].id,
                    'debit': 1000.0 * (i + 1),
                    'credit': 0.0,
                },
                {
                    'account_id': accounts[50 + i].id,
                    'debit': 0.0,
                    'credit': 1000.0 * (i + 1),
                },
            ]
            self.env.create_move(self.date_from + timedelta(days=i % 30), lines)
        
        # Medir tiempo de cálculo
        balance = self.env['account.balance.eight.columns'].with_company(self.company).create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
        })
        
        start_time = time.time()
        balance.action_compute_balance()
        end_time = time.time()
        
        processing_time = end_time - start_time
        
        # Verificar que se procesa en menos de 3 segundos
        self.assertLess(processing_time, 3.0, f"Procesamiento tomó {processing_time:.2f}s (máx 3s)")
        self.assertEqual(balance.state, 'computed')
        self.assertTrue(balance.is_balanced)
        
    def test_09_balance_security(self):
        """Test permisos de seguridad"""
        # Crear usuario sin permisos contables
        user_no_access = self.env['res.users'].create({
            'name': 'Usuario Sin Acceso',
            'login': 'user_no_access',
            'company_id': self.company.id,
            'company_ids': [(4, self.company.id)],
        })
        
        # Intentar crear balance sin permisos
        with self.assertRaises(Exception):
            self.env['account.balance.eight.columns'].with_user(user_no_access).create({
                'company_id': self.company.id,
                'date_from': self.date_from,
                'date_to': self.date_to,
            })
            
        # Crear usuario con permisos contables
        user_accountant = self.env['res.users'].create({
            'name': 'Contador',
            'login': 'accountant',
            'company_id': self.company.id,
            'company_ids': [(4, self.company.id)],
            'groups_id': [(4, self.env.ref('account.group_account_user').id)],
        })
        
        # Debe poder crear balance
        balance = self.env['account.balance.eight.columns'].with_user(user_accountant).create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
        })
        
        self.assertTrue(balance)
        
    def test_10_balance_multi_company(self):
        """Test balance multi-compañía"""
        # Crear segunda compañía
        company2 = self.env['res.company'].create({
            'name': 'Test Company 2',
            'currency_id': self.env.ref('base.CLP').id,
        })
        
        # Crear cuentas en company2
        account_cash_c2 = self.env.create_account('1110', 'Caja C2', self.account_type_asset)
        account_cash_c2.company_id = company2
        
        # Balance debe filtrar por compañía
        balance = self.env['account.balance.eight.columns'].create({
            'company_id': self.company.id,
            'date_from': self.date_from,
            'date_to': self.date_to,
            'show_zero_balance': True,
        })
        
        balance.action_compute_balance()
        
        # No debe incluir cuentas de company2
        self.assertFalse(balance.line_ids.filtered(lambda l: l.account_id.company_id == company2))