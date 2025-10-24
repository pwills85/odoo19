/** @odoo-module **/

import { Component, useState, onWillStart, useRef } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@odoo/owl";
import { _t } from "@web/core/l10n/translation";
import { loadJS } from "@web/core/assets";

export class AnalyticReportDashboard extends Component {
    static template = "account_financial_report.AnalyticReportDashboard";
    static props = {};

    setup() {
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.action = useService("action");
        
        this.state = useState({
            loading: true,
            selectedProjects: [],
            dateFrom: this._getDefaultDateFrom(),
            dateTo: this._getDefaultDateTo(),
            includeTimesheet: true,
            groupByAccount: true,
            includeChildAccounts: true,
            reportData: null,
            dashboardData: null,
            activeTab: 'detail', // detail, dashboard, comparison
            comparisonPeriod: 'month',
            chartInstances: {}
        });

        this.chartRefs = {
            monthlyEvolution: useRef("monthlyEvolutionChart"),
            costBreakdown: useRef("costBreakdownChart"),
            projectProfitability: useRef("projectProfitabilityChart"),
            hoursDistribution: useRef("hoursDistributionChart")
        };

        onWillStart(async () => {
            await loadJS("/web/static/lib/Chart/Chart.js");
            await this.loadInitialData();
        });
    }

    _getDefaultDateFrom() {
        const date = new Date();
        date.setMonth(date.getMonth() - 6);
        return date.toISOString().split('T')[0];
    }

    _getDefaultDateTo() {
        return new Date().toISOString().split('T')[0];
    }

    async loadInitialData() {
        try {
            // Cargar proyectos disponibles
            const projects = await this.rpc("/web/dataset/search_read", {
                model: "account.analytic.account",
                fields: ["id", "name", "code", "partner_id"],
                domain: [["active", "=", true]],
                sort: "code"
            });

            this.availableProjects = projects;
            
            // Seleccionar primeros 5 proyectos por defecto
            this.state.selectedProjects = projects.slice(0, 5).map(p => p.id);
            
            // Cargar datos iniciales
            await this.loadReportData();
            
        } catch (error) {
            this.notification.add(_t("Error loading initial data"), {
                type: "danger"
            });
            console.error("Error:", error);
        } finally {
            this.state.loading = false;
        }
    }

    async loadReportData() {
        if (this.state.selectedProjects.length === 0) {
            this.notification.add(_t("Please select at least one project"), {
                type: "warning"
            });
            return;
        }

        this.state.loading = true;

        try {
            // Cargar datos del reporte detallado
            const reportResponse = await this.rpc("/web/dataset/call_kw", {
                model: "analytic.report.service",
                method: "get_analytic_report_data",
                args: [
                    this.state.selectedProjects,
                    this.state.dateFrom,
                    this.state.dateTo,
                    this.state.includeTimesheet,
                    this.state.groupByAccount,
                    this.state.includeChildAccounts
                ],
                kwargs: {}
            });

            if (reportResponse.success) {
                this.state.reportData = reportResponse.data;
                
                // Cargar datos del dashboard
                const dashboardResponse = await this.rpc("/web/dataset/call_kw", {
                    model: "analytic.report.service",
                    method: "get_project_dashboard_data",
                    args: [this.state.selectedProjects, 6],
                    kwargs: {}
                });

                if (dashboardResponse.success) {
                    this.state.dashboardData = dashboardResponse.data;
                    
                    // Actualizar gráficos después de que el DOM se actualice
                    setTimeout(() => this.updateCharts(), 100);
                }
            } else {
                throw new Error(reportResponse.error);
            }

        } catch (error) {
            this.notification.add(_t("Error loading report data"), {
                type: "danger"
            });
            console.error("Error:", error);
        } finally {
            this.state.loading = false;
        }
    }

    updateCharts() {
        if (this.state.activeTab === 'dashboard' && this.state.dashboardData) {
            this.renderMonthlyEvolutionChart();
            this.renderCostBreakdownChart();
            this.renderProjectProfitabilityChart();
            this.renderHoursDistributionChart();
        }
    }

    renderMonthlyEvolutionChart() {
        const canvas = this.chartRefs.monthlyEvolution.el;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const data = this.state.dashboardData.monthly_evolution;

        // Destruir gráfico anterior si existe
        if (this.state.chartInstances.monthlyEvolution) {
            this.state.chartInstances.monthlyEvolution.destroy();
        }

        this.state.chartInstances.monthlyEvolution = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map(d => d.month),
                datasets: [{
                    label: _t('Revenue'),
                    data: data.map(d => d.revenue),
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                }, {
                    label: _t('Costs'),
                    data: data.map(d => d.costs),
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.1
                }, {
                    label: _t('Margin'),
                    data: data.map(d => d.margin),
                    borderColor: 'rgb(54, 162, 235)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: _t('Monthly Evolution')
                    },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const value = context.parsed.y;
                                return `${context.dataset.label}: ${this.formatCurrency(value)}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: (value) => this.formatCurrency(value, true)
                        }
                    }
                }
            }
        });
    }

    renderCostBreakdownChart() {
        const canvas = this.chartRefs.costBreakdown.el;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const data = this.state.dashboardData.cost_breakdown;

        if (this.state.chartInstances.costBreakdown) {
            this.state.chartInstances.costBreakdown.destroy();
        }

        this.state.chartInstances.costBreakdown = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.map(d => d.category),
                datasets: [{
                    data: data.map(d => d.amount),
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                        '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF',
                        '#4BC0C0', '#36A2EB', '#FFCE56'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: _t('Cost Breakdown by Category')
                    },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${label}: ${this.formatCurrency(value)} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    renderProjectProfitabilityChart() {
        const canvas = this.chartRefs.projectProfitability.el;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const data = this.state.dashboardData.top_projects;

        if (this.state.chartInstances.projectProfitability) {
            this.state.chartInstances.projectProfitability.destroy();
        }

        this.state.chartInstances.projectProfitability = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(d => d.code || d.name),
                datasets: [{
                    label: _t('Revenue'),
                    data: data.map(d => d.revenue),
                    backgroundColor: 'rgba(75, 192, 192, 0.6)'
                }, {
                    label: _t('Costs'),
                    data: data.map(d => d.costs),
                    backgroundColor: 'rgba(255, 99, 132, 0.6)'
                }, {
                    label: _t('Margin'),
                    data: data.map(d => d.margin),
                    backgroundColor: 'rgba(54, 162, 235, 0.6)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: _t('Top Projects by Profitability')
                    },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const value = context.parsed.y;
                                return `${context.dataset.label}: ${this.formatCurrency(value)}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: (value) => this.formatCurrency(value, true)
                        }
                    }
                }
            }
        });
    }

    renderHoursDistributionChart() {
        const canvas = this.chartRefs.hoursDistribution.el;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        
        // Preparar datos de distribución de horas
        const projectHours = [];
        for (const [projectId, data] of Object.entries(this.state.reportData || {})) {
            if (data.timesheet.total_hours > 0) {
                projectHours.push({
                    name: data.analytic_account_code || data.analytic_account_name,
                    hours: data.timesheet.total_hours,
                    cost: data.timesheet.total_cost
                });
            }
        }

        if (this.state.chartInstances.hoursDistribution) {
            this.state.chartInstances.hoursDistribution.destroy();
        }

        this.state.chartInstances.hoursDistribution = new Chart(ctx, {
            type: 'bubble',
            data: {
                datasets: [{
                    label: _t('Projects'),
                    data: projectHours.map((p, index) => ({
                        x: index,
                        y: p.hours,
                        r: Math.sqrt(p.cost) / 10 // Radio proporcional al costo
                    })),
                    backgroundColor: 'rgba(255, 159, 64, 0.6)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: _t('Hours Distribution by Project')
                    },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const project = projectHours[context.parsed.x];
                                return [
                                    `${project.name}`,
                                    `${_t('Hours')}: ${project.hours.toFixed(2)}`,
                                    `${_t('Cost')}: ${this.formatCurrency(project.cost)}`
                                ];
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        display: false
                    },
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: _t('Hours')
                        }
                    }
                }
            }
        });
    }

    formatCurrency(value, compact = false) {
        if (compact && Math.abs(value) >= 1000000) {
            return `$${(value / 1000000).toFixed(1)}M`;
        } else if (compact && Math.abs(value) >= 1000) {
            return `$${(value / 1000).toFixed(1)}K`;
        }
        return new Intl.NumberFormat('es-CL', {
            style: 'currency',
            currency: 'CLP',
            minimumFractionDigits: 0,
            maximumFractionDigits: 0
        }).toFormat(value);
    }

    formatNumber(value, decimals = 2) {
        return new Intl.NumberFormat('es-CL', {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals
        }).toFormat(value);
    }

    onProjectSelectionChange(ev) {
        const select = ev.target;
        const selectedOptions = Array.from(select.selectedOptions);
        this.state.selectedProjects = selectedOptions.map(opt => parseInt(opt.value));
    }

    async onDateChange() {
        await this.loadReportData();
    }

    async onFilterChange() {
        await this.loadReportData();
    }

    onTabChange(tab) {
        this.state.activeTab = tab;
        if (tab === 'dashboard') {
            setTimeout(() => this.updateCharts(), 100);
        }
    }

    async exportToExcel() {
        try {
            const response = await this.rpc("/account_financial_report/analytic/export", {
                project_ids: this.state.selectedProjects,
                date_from: this.state.dateFrom,
                date_to: this.state.dateTo,
                include_timesheet: this.state.includeTimesheet,
                group_by_account: this.state.groupByAccount
            });

            if (response.success) {
                // Descargar archivo
                const link = document.createElement('a');
                link.href = `data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,${response.file}`;
                link.download = response.filename;
                link.click();
                
                this.notification.add(_t("Report exported successfully"), {
                    type: "success"
                });
            }
        } catch (error) {
            this.notification.add(_t("Error exporting report"), {
                type: "danger"
            });
        }
    }

    toggleAccountDetails(projectId) {
        const detailsEl = document.querySelector(`#account-details-${projectId}`);
        if (detailsEl) {
            detailsEl.classList.toggle('show');
        }
    }

    async openAccountMoveLines(accountId, analyticAccountId) {
        const action = {
            type: 'ir.actions.act_window',
            name: _t('Journal Items'),
            res_model: 'account.move.line',
            view_mode: 'tree,form',
            views: [[false, 'tree'], [false, 'form']],
            domain: [
                ['analytic_account_id', '=', analyticAccountId],
                ['account_id', '=', accountId]
            ],
            context: {
                search_default_posted: 1,
                search_default_date: 1
            }
        };
        
        await this.action.doAction(action);
    }

    getProjectClass(margin) {
        if (margin > 0) return 'text-success';
        if (margin < 0) return 'text-danger';
        return 'text-warning';
    }

    getEfficiencyClass(value, threshold) {
        return value >= threshold ? 'text-success' : 'text-warning';
    }
}

AnalyticReportDashboard.components = {};

registry.category("actions").add("account_financial_report.analytic_dashboard", AnalyticReportDashboard);
