/** @odoo-module **/

import { Component, useState, onWillStart, useRef } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { _t } from "@web/core/l10n/translation";
import { formatMonetary } from "@web/views/fields/formatters";
import { download } from "@web/core/network/download";
import { registry } from "@web/core/registry";

export class BalanceEightColumns extends Component {
    static template = "account_financial_report.BalanceEightColumns";
    static props = {
        action: Object,
        context: { type: Object, optional: true },
    };

    setup() {
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.dialog = useService("dialog");
        this.user = useService("user");
        this.actionService = useService("action");
        
        // Referencias para virtual scrolling
        this.tableRef = useRef("balanceTable");
        this.scrollTimeout = null;
        
        // Estado reactivo
        this.state = useState({
            // Datos
            loading: true,
            data: [],
            filteredData: [],
            displayedData: [],
            
            // Filtros
            filters: {
                dateFrom: moment().startOf('month').format('YYYY-MM-DD'),
                dateTo: moment().endOf('month').format('YYYY-MM-DD'),
                showZeroBalance: false,
                accountLevel: 'all',
                searchTerm: '',
                chartOfAccounts: 'sii_pyme'
            },
            
            // Totales
            totals: {
                debit: 0,
                credit: 0,
                debitBalance: 0,
                creditBalance: 0,
                assets: 0,
                liabilities: 0,
                loss: 0,
                profit: 0
            },
            
            // Validaciones
            isBalanced: true,
            validationErrors: [],
            
            // UI
            expandedAccounts: new Set(),
            selectedAccounts: new Set(),
            sortColumn: 'code',
            sortDirection: 'asc',
            
            // Virtual scrolling
            visibleStartIndex: 0,
            visibleEndIndex: 50,
            rowHeight: 48,
            containerHeight: 600,
            
            // Configuración
            companyId: null,
            companyName: '',
            currency: { symbol: '$', position: 'before' },
            
            // Vista actual
            viewMode: 'table', // 'table' o 'chart'
        });
        
        onWillStart(async () => {
            await this.loadInitialData();
        });
    }
    
    async loadInitialData() {
        try {
            // Si viene un balance_id en el contexto, cargar ese balance
            if (this.props.context && this.props.context.active_id) {
                await this.loadExistingBalance(this.props.context.active_id);
            } else {
                // Obtener configuración de la compañía
                const session = await this.rpc("/web/session/get_session_info");
                this.state.companyId = session.user_companies.current_company;
                this.state.companyName = session.user_companies.allowed_companies[this.state.companyId];
                
                // Cargar datos del balance
                await this.loadBalanceData();
            }
        } catch (error) {
            this.notification.add(_t("Error al cargar datos iniciales"), {
                type: "danger",
            });
            console.error("Error loading initial data:", error);
        }
    }
    
    async loadExistingBalance(balanceId) {
        this.state.loading = true;
        
        try {
            const result = await this.rpc("/web/dataset/call_kw/account.balance.eight.columns/read", {
                model: "account.balance.eight.columns",
                method: "read",
                args: [[balanceId]],
                kwargs: {
                    fields: ['name', 'company_id', 'date_from', 'date_to', 'line_ids', 
                             'total_debit', 'total_credit', 'total_debit_balance', 
                             'total_credit_balance', 'total_assets', 'total_liabilities',
                             'total_loss', 'total_profit', 'is_balanced', 'validation_errors']
                }
            });
            
            if (result && result.length > 0) {
                const balance = result[0];
                
                // Configurar estado
                this.state.companyId = balance.company_id[0];
                this.state.companyName = balance.company_id[1];
                this.state.filters.dateFrom = balance.date_from;
                this.state.filters.dateTo = balance.date_to;
                
                // Cargar totales
                this.state.totals = {
                    debit: balance.total_debit,
                    credit: balance.total_credit,
                    debitBalance: balance.total_debit_balance,
                    creditBalance: balance.total_credit_balance,
                    assets: balance.total_assets,
                    liabilities: balance.total_liabilities,
                    loss: balance.total_loss,
                    profit: balance.total_profit
                };
                
                this.state.isBalanced = balance.is_balanced;
                this.state.validationErrors = balance.validation_errors ? balance.validation_errors.split('\n') : [];
                
                // Cargar líneas
                await this.loadBalanceLines(balance.line_ids);
            }
        } catch (error) {
            this.notification.add(_t("Error al cargar el balance"), {
                type: "danger",
            });
            console.error("Error loading balance:", error);
        } finally {
            this.state.loading = false;
        }
    }
    
    async loadBalanceLines(lineIds) {
        if (!lineIds || lineIds.length === 0) return;
        
        const lines = await this.rpc("/web/dataset/call_kw/account.balance.eight.columns.line/read", {
            model: "account.balance.eight.columns.line",
            method: "read",
            args: [lineIds],
            kwargs: {
                fields: ['account_id', 'account_code', 'account_name', 'hierarchy_level',
                         'is_parent_account', 'debit', 'credit', 'debit_balance', 
                         'credit_balance', 'assets', 'liabilities', 'loss', 'profit']
            }
        });
        
        this.state.data = lines.map(line => ({
            account_id: line.account_id[0],
            code: line.account_code,
            name: line.account_name,
            level: line.hierarchy_level || 0,
            is_parent: line.is_parent_account,
            debit: line.debit,
            credit: line.credit,
            debitBalance: line.debit_balance,
            creditBalance: line.credit_balance,
            assets: line.assets,
            liabilities: line.liabilities,
            loss: line.loss,
            profit: line.profit
        }));
        
        this.applyFiltersAndSort();
    }
    
    async loadBalanceData() {
        this.state.loading = true;
        
        try {
            // Crear nuevo balance y computarlo
            const balanceId = await this.rpc("/web/dataset/call_kw/account.balance.eight.columns/create", {
                model: "account.balance.eight.columns",
                method: "create",
                args: [{
                    company_id: this.state.companyId,
                    date_from: this.state.filters.dateFrom,
                    date_to: this.state.filters.dateTo,
                    show_zero_balance: this.state.filters.showZeroBalance,
                    account_level: this.state.filters.accountLevel,
                    chart_of_accounts: this.state.filters.chartOfAccounts
                }],
                kwargs: {}
            });
            
            // Computar el balance
            await this.rpc("/web/dataset/call_kw/account.balance.eight.columns/action_compute_balance", {
                model: "account.balance.eight.columns",
                method: "action_compute_balance",
                args: [[balanceId]],
                kwargs: {}
            });
            
            // Cargar el balance computado
            await this.loadExistingBalance(balanceId);
            
        } catch (error) {
            this.notification.add(_t("Error al calcular el balance"), {
                type: "danger",
            });
            console.error("Error loading balance data:", error);
            this.state.loading = false;
        }
    }
    
    applyFiltersAndSort() {
        let filtered = [...this.state.data];
        
        // Aplicar búsqueda
        if (this.state.filters.searchTerm) {
            const searchLower = this.state.filters.searchTerm.toLowerCase();
            filtered = filtered.filter(line => 
                line.code.toLowerCase().includes(searchLower) ||
                line.name.toLowerCase().includes(searchLower)
            );
        }
        
        // Aplicar ordenamiento
        filtered.sort((a, b) => {
            let aVal = a[this.state.sortColumn];
            let bVal = b[this.state.sortColumn];
            
            // Manejar valores numéricos
            if (typeof aVal === 'number' && typeof bVal === 'number') {
                return this.state.sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
            }
            
            // Manejar strings
            aVal = String(aVal).toLowerCase();
            bVal = String(bVal).toLowerCase();
            
            if (this.state.sortDirection === 'asc') {
                return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
            } else {
                return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
            }
        });
        
        this.state.filteredData = filtered;
        this.updateDisplayedData();
    }
    
    updateDisplayedData() {
        // Virtual scrolling: mostrar solo las filas visibles
        const start = this.state.visibleStartIndex;
        const end = Math.min(
            this.state.visibleEndIndex,
            this.state.filteredData.length
        );
        
        this.state.displayedData = this.state.filteredData.slice(start, end);
    }
    
    // Manejadores de eventos
    onDateChange(field, value) {
        this.state.filters[field] = value;
        this.loadBalanceData();
    }
    
    onFilterChange(field, value) {
        this.state.filters[field] = value;
        
        if (field === 'searchTerm') {
            // Debounce para búsqueda
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => {
                this.applyFiltersAndSort();
            }, 300);
        } else {
            this.loadBalanceData();
        }
    }
    
    onSort(column) {
        if (this.state.sortColumn === column) {
            this.state.sortDirection = this.state.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.state.sortColumn = column;
            this.state.sortDirection = 'asc';
        }
        
        this.applyFiltersAndSort();
    }
    
    onScroll(event) {
        // Virtual scrolling
        clearTimeout(this.scrollTimeout);
        this.scrollTimeout = setTimeout(() => {
            const scrollTop = event.target.scrollTop;
            const newStartIndex = Math.floor(scrollTop / this.state.rowHeight);
            const newEndIndex = newStartIndex + Math.ceil(this.state.containerHeight / this.state.rowHeight) + 5;
            
            if (newStartIndex !== this.state.visibleStartIndex) {
                this.state.visibleStartIndex = newStartIndex;
                this.state.visibleEndIndex = newEndIndex;
                this.updateDisplayedData();
            }
        }, 50);
    }
    
    toggleAccountExpansion(accountId) {
        if (this.state.expandedAccounts.has(accountId)) {
            this.state.expandedAccounts.delete(accountId);
        } else {
            this.state.expandedAccounts.add(accountId);
        }
        this.applyFiltersAndSort();
    }
    
    toggleAccountSelection(accountId) {
        if (this.state.selectedAccounts.has(accountId)) {
            this.state.selectedAccounts.delete(accountId);
        } else {
            this.state.selectedAccounts.add(accountId);
        }
    }
    
    selectAllAccounts() {
        if (this.state.selectedAccounts.size === this.state.filteredData.length) {
            this.state.selectedAccounts.clear();
        } else {
            this.state.filteredData.forEach(line => {
                this.state.selectedAccounts.add(line.account_id);
            });
        }
    }
    
    // Cambiar vista
    switchView(mode) {
        this.state.viewMode = mode;
    }
    
    // Acciones
    async onRefresh() {
        await this.loadBalanceData();
    }
    
    onOpenFormView() {
        this.actionService.doAction({
            type: 'ir.actions.act_window',
            res_model: 'account.balance.eight.columns',
            views: [[false, 'form']],
            target: 'current',
        });
    }
    
    // Drill-down a cuenta
    onAccountClick(accountId) {
        this.actionService.doAction({
            type: 'ir.actions.act_window',
            res_model: 'account.move.line',
            name: _t('Movimientos de Cuenta'),
            views: [[false, 'list'], [false, 'form']],
            domain: [
                ['account_id', '=', accountId],
                ['date', '>=', this.state.filters.dateFrom],
                ['date', '<=', this.state.filters.dateTo],
                ['company_id', '=', this.state.companyId]
            ],
            context: {
                search_default_posted: 1,
            },
            target: 'current',
        });
    }
    
    // Acciones de exportación
    async exportToExcel() {
        if (this.props.context && this.props.context.active_id) {
            this.actionService.doAction({
                type: 'ir.actions.act_url',
                url: `/web/dataset/call_kw/account.balance.eight.columns/action_export_excel?id=${this.props.context.active_id}`,
                target: 'self',
            });
        }
    }
    
    async exportToPDF() {
        if (this.props.context && this.props.context.active_id) {
            this.actionService.doAction({
                type: 'ir.actions.act_url',
                url: `/web/dataset/call_kw/account.balance.eight.columns/action_export_pdf?id=${this.props.context.active_id}`,
                target: 'self',
            });
        }
    }
    
    // Helpers de formato
    formatMoney(value) {
        if (!value) return '0.00';
        return new Intl.NumberFormat('es-CL', {
            style: 'currency',
            currency: 'CLP',
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }).format(value);
    }
    
    getRowClass(line) {
        const classes = ['balance-row'];
        
        if (line.is_parent) {
            classes.push('fw-bold', 'bg-light');
        }
        
        if (line.level > 0) {
            classes.push(`ps-${line.level * 3}`);
        }
        
        if (this.state.selectedAccounts.has(line.account_id)) {
            classes.push('table-active');
        }
        
        return classes.join(' ');
    }
    
    getSortIcon(column) {
        if (this.state.sortColumn !== column) {
            return 'fa-sort text-muted';
        }
        return this.state.sortDirection === 'asc' ? 'fa-sort-up text-primary' : 'fa-sort-down text-primary';
    }
}

// Registrar el componente
registry.category("actions").add("balance_eight_columns_report", BalanceEightColumns);