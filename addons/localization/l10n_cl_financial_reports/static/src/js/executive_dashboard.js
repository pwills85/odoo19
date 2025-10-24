/** @odoo-module **/

import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { Component, useState, onWillStart, onMounted } from "@odoo/owl";
import { formatCurrency } from "@web/core/currency";

/**
 * Executive Dashboard Component for Chilean Business Intelligence
 * Migrated from l10n_cl_enterprise following technical manifest
 */
export class ExecutiveDashboard extends Component {
    static template = "executivedashboard_template";

    setup() {
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.action = useService("action");
        
        this.state = useState({
            loading: true,
            period: 'month',
            data: {},
            charts: {
                dteStatus: null,
                revenueTrend: null,
                expenseDistribution: null,
            }
        });
        
        onWillStart(async () => {
            await this.loadDashboardData();
        });
        
        onMounted(() => {
            this.initializeCharts();
            this.setupEventHandlers();
        });
    }
    
    /**
     * Load dashboard data from the service
     */
    async loadDashboardData() {
        this.state.loading = true;
        try {
            const result = await this.rpc("/web/dataset/call_kw", {
                model: "account_financial_report.executive_dashboard_service",
                method: "get_executive_summary",
                args: [],
                kwargs: {
                    company_id: this.env.company.id,
                    date_from: this._getDateFrom(),
                    date_to: new Date().toISOString().split('T')[0],
                },
            });
            
            this.state.data = result;
            this.updateDashboard();
            
        } catch (error) {
            this.notification.add("Error loading dashboard data", {
                type: "danger",
            });
            console.error("Dashboard error:", error);
        } finally {
            this.state.loading = false;
        }
    }
    
    /**
     * Update dashboard UI with loaded data
     */
    updateDashboard() {
        const data = this.state.data;
        
        // Update financial metrics
        if (data.financial) {
            this._updateElement('revenue_total', this._formatCurrency(data.financial.revenue.total));
            this._updateElement('revenue_growth', this._formatGrowth(data.financial.revenue.growth));
            this._updateElement('expense_total', this._formatCurrency(data.financial.expenses.total));
            this._updateElement('expense_growth', this._formatGrowth(data.financial.expenses.growth));
            this._updateElement('profit_total', this._formatCurrency(data.financial.profitability.gross_profit));
            this._updateElement('profit_margin', data.financial.profitability.margin.toFixed(1) + '%');
            this._updateElement('cashflow_net', this._formatCurrency(data.financial.cash_flow.net));
            this._updateElement('cash_inflow', this._formatCurrency(data.financial.cash_flow.inflow));
            this._updateElement('cash_outflow', this._formatCurrency(data.financial.cash_flow.outflow));
        }
        
        // Update operational metrics
        if (data.operational) {
            this._updateDTEMetrics(data.operational.dte);
            this._updateCAFStatus(data.operational.caf_status);
        }
        
        // Update HR metrics if available
        if (data.hr && data.hr.available) {
            this._updateHRMetrics(data.hr);
        }
        
        // Update compliance deadlines
        if (data.compliance) {
            this._updateComplianceDeadlines(data.compliance.next_deadlines);
        }
        
        // Update alerts
        if (data.alerts && data.alerts.length > 0) {
            this._updateAlerts(data.alerts);
        }
        
        // Update charts
        this.updateCharts();
    }
    
    /**
     * Initialize Chart.js charts
     */
    initializeCharts() {
        // DTE Status Chart
        const dteCtx = document.getElementById('dte_status_chart');
        if (dteCtx) {
            this.state.charts.dteStatus = new Chart(dteCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Aceptados', 'Rechazados', 'Pendientes'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: ['#28a745', '#dc3545', '#ffc107'],
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        }
                    }
                }
            });
        }
        
        // Revenue vs Expense Trend
        const trendCtx = document.getElementById('revenue_expense_trend');
        if (trendCtx) {
            this.state.charts.revenueTrend = new Chart(trendCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Ingresos',
                        data: [],
                        borderColor: '#28a745',
                        backgroundColor: 'rgba(40, 167, 69, 0.1)',
                        tension: 0.1
                    }, {
                        label: 'Gastos',
                        data: [],
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                callback: function(value) {
                                    return '$' + value.toLocaleString();
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    
    /**
     * Update charts with new data
     */
    updateCharts() {
        const data = this.state.data;
        
        // Update DTE Status Chart
        if (this.state.charts.dteStatus && data.operational?.dte) {
            const dte = data.operational.dte;
            this.state.charts.dteStatus.data.datasets[0].data = [
                dte.accepted || 0,
                dte.rejected || 0,
                dte.pending || 0
            ];
            this.state.charts.dteStatus.update();
        }
        
        // Update trend chart (would need historical data from service)
        // This is a simplified version - real implementation would fetch trend data
        if (this.state.charts.revenueTrend && data.financial) {
            // Placeholder for trend data
            const months = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun'];
            const revenueData = [100000, 120000, 115000, 130000, 125000, data.financial.revenue.total];
            const expenseData = [80000, 90000, 85000, 95000, 92000, data.financial.expenses.total];
            
            this.state.charts.revenueTrend.data.labels = months;
            this.state.charts.revenueTrend.data.datasets[0].data = revenueData;
            this.state.charts.revenueTrend.data.datasets[1].data = expenseData;
            this.state.charts.revenueTrend.update();
        }
    }
    
    /**
     * Setup event handlers
     */
    setupEventHandlers() {
        // Period buttons
        document.querySelectorAll('[data-period]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('[data-period]').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.state.period = e.target.dataset.period;
                this.loadDashboardData();
            });
        });
        
        // Refresh button
        const refreshBtn = document.getElementById('refresh_dashboard');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadDashboardData());
        }
        
        // Export button
        const exportBtn = document.getElementById('export_dashboard');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportDashboard());
        }
    }
    
    /**
     * Export dashboard to Excel
     */
    async exportDashboard() {
        try {
            await this.action.doAction({
                type: 'ir.actions.report',
                report_type: 'xlsx',
                report_name: 'account_financial_report.executive_dashboard_xlsx',
                report_file: 'executive_dashboard',
                data: {
                    period: this.state.period,
                    company_id: this.env.company.id,
                },
                context: this.env.context,
            });
        } catch (error) {
            this.notification.add("Error exporting dashboard", {
                type: "danger",
            });
        }
    }
    
    // Helper methods
    
    _getDateFrom() {
        const today = new Date();
        switch (this.state.period) {
            case 'month':
                return new Date(today.getFullYear(), today.getMonth(), 1).toISOString().split('T')[0];
            case 'quarter':
                const quarter = Math.floor(today.getMonth() / 3);
                return new Date(today.getFullYear(), quarter * 3, 1).toISOString().split('T')[0];
            case 'year':
                return new Date(today.getFullYear(), 0, 1).toISOString().split('T')[0];
            default:
                return new Date(today.getFullYear(), today.getMonth(), 1).toISOString().split('T')[0];
        }
    }
    
    _updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }
    
    _formatCurrency(value) {
        return new Intl.NumberFormat('es-CL', {
            style: 'currency',
            currency: 'CLP',
            minimumFractionDigits: 0,
            maximumFractionDigits: 0,
        }).format(value);
    }
    
    _formatGrowth(value) {
        const formatted = value.toFixed(1) + '%';
        const element = document.createElement('span');
        element.textContent = formatted;
        element.className = value >= 0 ? 'badge bg-success' : 'badge bg-danger';
        return element.outerHTML;
    }
    
    _updateDTEMetrics(dte) {
        if (!dte) return;
        
        this._updateElement('dte_acceptance_rate', (dte.acceptance_rate || 0).toFixed(1) + '%');
        
        const progressBar = document.getElementById('dte_acceptance_bar');
        if (progressBar) {
            progressBar.style.width = dte.acceptance_rate + '%';
        }
    }
    
    _updateCAFStatus(cafStatus) {
        const container = document.getElementById('caf_availability');
        if (!container || !cafStatus) return;
        
        let html = '';
        cafStatus.forEach(caf => {
            const badgeClass = caf.severity === 'critical' ? 'danger' : 'warning';
            html += `
                <div class="alert alert-${badgeClass} p-2 mb-2">
                    <strong>${caf.type}:</strong> ${caf.available} folios disponibles
                    ${caf.expiry ? `<br><small>Vence: ${new Date(caf.expiry).toLocaleDateString('es-CL')}</small>` : ''}
                </div>
            `;
        });
        
        if (!html) {
            html = '<p class="text-success">✓ Todos los CAF con disponibilidad adecuada</p>';
        }
        
        container.innerHTML = html;
    }
    
    _updateHRMetrics(hr) {
        document.getElementById('hr_section').style.display = 'block';
        this._updateElement('hr_headcount', hr.headcount);
        this._updateElement('hr_contracts', hr.active_contracts);
        this._updateElement('hr_payroll_total', this._formatCurrency(hr.payroll.total));
        this._updateElement('hr_avg_salary', this._formatCurrency(hr.payroll.average));
    }
    
    _updateComplianceDeadlines(deadlines) {
        const container = document.getElementById('compliance_deadlines');
        if (!container || !deadlines) return;
        
        let html = '<ul class="list-unstyled mb-0">';
        deadlines.forEach(deadline => {
            const badgeClass = deadline.days_remaining < 7 ? 'danger' : 
                              deadline.days_remaining < 15 ? 'warning' : 'info';
            html += `
                <li class="mb-2">
                    <strong>${deadline.type}:</strong> 
                    ${new Date(deadline.date).toLocaleDateString('es-CL')}
                    <span class="badge bg-${badgeClass} ms-2">${deadline.days_remaining} días</span>
                </li>
            `;
        });
        html += '</ul>';
        
        container.innerHTML = html;
    }
    
    _updateAlerts(alerts) {
        const container = document.getElementById('alerts_section');
        if (!container || !alerts) return;
        
        let html = '';
        alerts.forEach(alert => {
            const alertClass = alert.severity === 'critical' ? 'danger' : 'warning';
            html += `
                <div class="col-12">
                    <div class="alert alert-${alertClass} alert-dismissible fade show" role="alert">
                        <strong>${alert.type}:</strong> ${alert.message}
                        ${alert.action ? `<a href="#" class="alert-link ms-2" data-action="${alert.action}">Tomar acción</a>` : ''}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                </div>
            `;
        });
        
        container.innerHTML = html;
    }
}

ExecutiveDashboard.template = "account_financial_report.ExecutiveDashboard";

registry.category("actions").add("account_financial_report.executive_dashboard", ExecutiveDashboard);