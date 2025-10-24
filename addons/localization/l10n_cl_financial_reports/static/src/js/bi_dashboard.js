/** @odoo-module **/

import { registry } from "@web/core/registry";
import { Component, useState, onWillStart, onMounted } from "@odoo/owl";
import { useService } from "@web/core/utils/hooks";
import { loadJS } from "@web/core/assets";

export class BiDashboard extends Component {
    static template = "account_financial_report.BiDashboard";
    static props = ["*"];
    
    setup() {
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.action = useService("action");
        
        this.state = useState({
            loading: true,
            dateFrom: this.getDefaultDateFrom(),
            dateTo: this.getDefaultDateTo(),
            dashboardData: null,
            charts: {},
            selectedCompanies: [this.env.user.company_id],
        });
        
        onWillStart(async () => {
            // Load Chart.js if not already loaded
            await loadJS("/web/static/lib/Chart/Chart.js");
        });
        
        onMounted(() => {
            this.loadDashboard();
            // Set up auto-refresh every 5 minutes
            this.refreshInterval = setInterval(() => {
                this.loadDashboard(false);
            }, 300000);
        });
    }
    
    /**
     * Get default date from (first day of current month)
     */
    getDefaultDateFrom() {
        const now = new Date();
        return new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];
    }
    
    /**
     * Get default date to (today)
     */
    getDefaultDateTo() {
        return new Date().toISOString().split('T')[0];
    }
    
    /**
     * Load dashboard data from backend
     */
    async loadDashboard(showLoading = true) {
        if (showLoading) {
            this.state.loading = true;
        }
        
        try {
            const data = await this.rpc("/web/dataset/call_kw/account.financial.bi.service/get_executive_dashboard", {
                model: "account.financial.bi.service",
                method: "get_executive_dashboard",
                args: [this.state.dateFrom, this.state.dateTo],
                kwargs: {
                    company_ids: this.state.selectedCompanies,
                },
            });
            
            this.state.dashboardData = data;
            this.updateKPIs(data.kpis);
            this.updateCharts(data);
            this.updateAlerts(data.alerts);
            this.updateTables(data);
            
        } catch (error) {
            this.notification.add("Error loading dashboard: " + error.message, {
                type: "danger",
            });
        } finally {
            this.state.loading = false;
        }
    }
    
    /**
     * Update KPI cards
     */
    updateKPIs(kpis) {
        if (!kpis) return;
        
        // Update revenue KPI
        if (kpis.revenue) {
            const revenueEl = document.getElementById('kpi_revenue');
            const growthEl = document.getElementById('kpi_revenue_growth');
            if (revenueEl) {
                revenueEl.textContent = kpis.revenue.formatted;
                if (growthEl) {
                    growthEl.textContent = `${kpis.revenue.growth > 0 ? '+' : ''}${kpis.revenue.growth}%`;
                    growthEl.className = `badge badge-${kpis.revenue.trend === 'up' ? 'success' : kpis.revenue.trend === 'down' ? 'danger' : 'secondary'}`;
                }
            }
        }
        
        // Update expenses KPI
        if (kpis.expenses) {
            const expensesEl = document.getElementById('kpi_expenses');
            const ratioEl = document.getElementById('kpi_expense_ratio');
            if (expensesEl) {
                expensesEl.textContent = kpis.expenses.formatted;
                if (ratioEl) {
                    ratioEl.textContent = `${kpis.expenses.percentage_of_revenue}%`;
                }
            }
        }
        
        // Update profit KPI
        if (kpis.profit) {
            const profitEl = document.getElementById('kpi_profit');
            const marginEl = document.getElementById('kpi_margin');
            if (profitEl) {
                profitEl.textContent = kpis.profit.formatted;
                profitEl.className = `text-${kpis.profit.status === 'profit' ? 'success' : kpis.profit.status === 'loss' ? 'danger' : 'warning'}`;
                if (marginEl) {
                    marginEl.textContent = `${kpis.profit.margin}% margin`;
                }
            }
        }
        
        // Update cash KPI
        if (kpis.cash_balance) {
            const cashEl = document.getElementById('kpi_cash');
            const daysEl = document.getElementById('kpi_cash_days');
            if (cashEl) {
                cashEl.textContent = kpis.cash_balance.formatted;
                if (daysEl) {
                    daysEl.textContent = `${kpis.cash_balance.days_of_expenses} days of expenses`;
                }
            }
        }
    }
    
    /**
     * Update charts
     */
    updateCharts(data) {
        // Revenue Trend Chart
        if (data.revenue_metrics && data.revenue_metrics.monthly_breakdown) {
            this.createRevenueChart(data.revenue_metrics.monthly_breakdown);
        }
        
        // Expense Analysis Chart
        if (data.expense_analysis && data.expense_analysis.by_category) {
            this.createExpenseChart(data.expense_analysis.by_category);
        }
        
        // Cashflow Projection Chart
        if (data.cashflow_projection && data.cashflow_projection.projections) {
            this.createCashflowChart(data.cashflow_projection);
        }
    }
    
    /**
     * Create revenue trend chart
     */
    createRevenueChart(monthlyData) {
        const canvas = document.getElementById('revenue_trend_chart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        
        // Destroy existing chart if any
        if (this.state.charts.revenue) {
            this.state.charts.revenue.destroy();
        }
        
        const labels = monthlyData.map(d => new Date(d.period).toLocaleDateString('es-CL', { month: 'short', year: 'numeric' }));
        const revenues = monthlyData.map(d => d.revenue);
        
        this.state.charts.revenue = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Revenue',
                    data: revenues,
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return 'Revenue: $' + context.parsed.y.toLocaleString('es-CL');
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return '$' + value.toLocaleString('es-CL');
                            }
                        }
                    }
                }
            }
        });
    }
    
    /**
     * Create expense analysis chart
     */
    createExpenseChart(byCategory) {
        const canvas = document.getElementById('expense_analysis_chart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        
        // Destroy existing chart if any
        if (this.state.charts.expense) {
            this.state.charts.expense.destroy();
        }
        
        const categories = Object.keys(byCategory);
        const amounts = categories.map(cat => byCategory[cat].total);
        const percentages = categories.map(cat => byCategory[cat].percentage);
        
        this.state.charts.expense = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: categories.map((cat, i) => `${cat} (${percentages[i]}%)`),
                datasets: [{
                    data: amounts,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 205, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)'
                    ],
                    borderColor: [
                        'rgb(255, 99, 132)',
                        'rgb(54, 162, 235)',
                        'rgb(255, 205, 86)',
                        'rgb(75, 192, 192)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.label + ': $' + context.parsed.toLocaleString('es-CL');
                            }
                        }
                    }
                }
            }
        });
    }
    
    /**
     * Create cashflow projection chart
     */
    createCashflowChart(cashflowData) {
        const canvas = document.getElementById('cashflow_projection_chart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        
        // Destroy existing chart if any
        if (this.state.charts.cashflow) {
            this.state.charts.cashflow.destroy();
        }
        
        const projections = cashflowData.projections;
        const labels = projections.map(p => p.period);
        
        this.state.charts.cashflow = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Income',
                        data: projections.map(p => p.projected_income + p.pending_collections),
                        backgroundColor: 'rgba(75, 192, 192, 0.8)',
                        stack: 'stack0',
                    },
                    {
                        label: 'Expenses',
                        data: projections.map(p => -(p.projected_expenses + p.pending_payments)),
                        backgroundColor: 'rgba(255, 99, 132, 0.8)',
                        stack: 'stack0',
                    },
                    {
                        label: 'Net Cashflow',
                        data: projections.map(p => p.net_cashflow),
                        type: 'line',
                        borderColor: 'rgb(54, 162, 235)',
                        backgroundColor: 'rgba(54, 162, 235, 0.2)',
                        borderWidth: 2,
                        fill: false,
                        tension: 0.1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': $' + Math.abs(context.parsed.y).toLocaleString('es-CL');
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        stacked: true,
                    },
                    y: {
                        stacked: true,
                        ticks: {
                            callback: function(value) {
                                return '$' + value.toLocaleString('es-CL');
                            }
                        }
                    }
                }
            }
        });
    }
    
    /**
     * Update alerts section
     */
    updateAlerts(alerts) {
        const container = document.getElementById('alerts_container');
        if (!container || !alerts) return;
        
        container.innerHTML = '';
        
        if (alerts.length === 0) {
            container.innerHTML = '<p class="text-muted">No alerts at this time</p>';
            return;
        }
        
        alerts.forEach(alert => {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${this.getAlertClass(alert.severity)} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                <strong>${alert.type}:</strong> ${alert.message}
                <br><small>${alert.recommendation}</small>
                <button type="button" class="close" data-dismiss="alert">
                    <span>&times;</span>
                </button>
            `;
            container.appendChild(alertDiv);
        });
    }
    
    /**
     * Update data tables
     */
    updateTables(data) {
        // Update top customers table
        if (data.revenue_metrics && data.revenue_metrics.top_customers) {
            this.updateTopCustomersTable(data.revenue_metrics.top_customers);
        }
        
        // Update tax compliance status
        if (data.tax_compliance) {
            this.updateTaxComplianceStatus(data.tax_compliance);
        }
    }
    
    /**
     * Update top customers table
     */
    updateTopCustomersTable(customers) {
        const tbody = document.querySelector('#top_customers_table tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        const totalRevenue = customers.reduce((sum, c) => sum + c.total_revenue, 0);
        
        customers.forEach(customer => {
            const percentage = ((customer.total_revenue / totalRevenue) * 100).toFixed(1);
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${customer.customer_name}</td>
                <td>$${customer.total_revenue.toLocaleString('es-CL')}</td>
                <td>${percentage}%</td>
            `;
            tbody.appendChild(row);
        });
    }
    
    /**
     * Update tax compliance status
     */
    updateTaxComplianceStatus(compliance) {
        const container = document.getElementById('tax_compliance_status');
        if (!container) return;
        
        let html = '<div class="list-group">';
        
        // F29 Status
        html += `
            <div class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">F29 - Monthly VAT</h6>
                    <small class="${compliance.f29_status.compliant ? 'text-success' : 'text-danger'}">
                        ${compliance.f29_status.compliant ? 'Compliant' : 'Pending'}
                    </small>
                </div>
                <p class="mb-1">${compliance.f29_status.message || 'All declarations up to date'}</p>
            </div>
        `;
        
        // F22 Status
        html += `
            <div class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">F22 - Annual Income Tax</h6>
                    <small class="${compliance.f22_status.compliant ? 'text-success' : 'text-warning'}">
                        ${compliance.f22_status.compliant ? 'Compliant' : 'Upcoming'}
                    </small>
                </div>
                <p class="mb-1">${compliance.f22_status.message || 'Declaration period not started'}</p>
            </div>
        `;
        
        // Compliance Score
        html += `
            <div class="list-group-item">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">Overall Compliance Score</h6>
                    <h4 class="${compliance.compliance_score >= 90 ? 'text-success' : compliance.compliance_score >= 70 ? 'text-warning' : 'text-danger'}">
                        ${compliance.compliance_score}%
                    </h4>
                </div>
            </div>
        `;
        
        html += '</div>';
        container.innerHTML = html;
    }
    
    /**
     * Get alert class based on severity
     */
    getAlertClass(severity) {
        switch(severity) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'secondary';
        }
    }
    
    /**
     * Handle date change
     */
    onDateChange(field, value) {
        this.state[field] = value;
        this.loadDashboard();
    }
    
    /**
     * Handle refresh button click
     */
    onRefreshClick() {
        this.loadDashboard();
    }
    
    /**
     * Handle export button click
     */
    async onExportClick() {
        try {
            const result = await this.rpc("/web/dataset/call_kw/account.financial.bi.service/export_dashboard_data", {
                model: "account.financial.bi.service",
                method: "export_dashboard_data",
                args: [this.state.dateFrom, this.state.dateTo],
                kwargs: {
                    format: 'xlsx',
                },
            });
            
            this.notification.add("Dashboard exported successfully", {
                type: "success",
            });
            
            // Trigger download
            window.location.href = `/web/content/?model=account.financial.bi.service&id=${result.id}&field=file&download=true&filename=bi_dashboard.xlsx`;
            
        } catch (error) {
            this.notification.add("Error exporting dashboard: " + error.message, {
                type: "danger",
            });
        }
    }
    
    /**
     * Clean up on destroy
     */
    willUnmount() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        
        // Destroy all charts
        Object.values(this.state.charts).forEach(chart => {
            if (chart) chart.destroy();
        });
    }
}

// Register the component
registry.category("actions").add("bi_dashboard", BiDashboard);