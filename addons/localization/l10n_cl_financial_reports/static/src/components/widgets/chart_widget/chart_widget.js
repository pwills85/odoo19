/** @odoo-module **/
/**
 * Chart Widget Component
 * Implementado según claude/01_documentacion_mejorada/03_frontend_reactivo/01_componente_owl.md
 */

import { Component, useState, onWillStart, useRef, onMounted, onWillUnmount, onPatched } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { _t } from "@web/core/l10n/translation";
import { loadJS } from "@web/core/assets";

export class ChartWidget extends Component {
    static template = "account_financial_report.ChartWidget";
    static props = {
        widgetData: Object,
        config: Object,
        filters: { type: Object, optional: true },
        size: { type: Object, optional: true },
        websocketService: { type: Object, optional: true }
    };

    setup() {
        // Servicios
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.websocketService = this.props.websocketService || useService("dashboard.websocket", { optional: true });
        
        // Referencias
        this.chartRef = useRef("chartCanvas");
        this.chart = null;
        this.websocketSubscription = null;
        
        // Estado reactivo
        this.state = useState({
            isLoading: true,
            hasError: false,
            errorMessage: "",
            data: null
        });
        
        // Hooks del ciclo de vida
        onWillStart(async () => {
            await this.loadChartLibrary();
            await this.loadData();
        });
        
        onMounted(() => {
            if (this.state.data && !this.state.hasError) {
                this.initializeChart();
            }
            // Suscribir a actualizaciones en tiempo real si hay WebSocket
            this.subscribeToRealTimeUpdates();
        });
        
        onPatched(() => {
            if (this.chart && this.state.data) {
                this.updateChart();
            } else if (!this.chart && this.state.data) {
                this.initializeChart();
            }
        });
        
        onWillUnmount(() => {
            this.destroyChart();
            this.unsubscribeFromRealTimeUpdates();
        });
    }
    
    /**
     * Carga la librería Chart.js si no está disponible
     */
    async loadChartLibrary() {
        if (!window.Chart) {
            try {
                await loadJS("/web/static/lib/Chart/Chart.js");
            } catch (error) {
                console.error("Error loading Chart.js:", error);
                this.state.hasError = true;
                this.state.errorMessage = _t("Failed to load chart library");
            }
        }
    }
    
    /**
     * Carga los datos del widget desde el servicio
     */
    async loadData() {
        this.state.isLoading = true;
        this.state.hasError = false;
        
        try {
            // Construir parámetros para el servicio
            const params = {
                model: this.props.widgetData.data_service_model,
                method: this.props.widgetData.data_service_method,
                args: [],
                kwargs: this.props.filters || {}
            };
            
            // Llamar al servicio
            const data = await this.rpc("/web/dataset/call_kw", params);
            
            // Validar respuesta
            if (data.error) {
                throw new Error(data.error);
            }
            
            this.state.data = data;
            
        } catch (error) {
            console.error("Error loading chart data:", error);
            this.state.hasError = true;
            this.state.errorMessage = error.message || _t("Failed to load chart data");
            this.notification.add(
                _t("Error loading chart data"),
                { type: "danger" }
            );
        } finally {
            this.state.isLoading = false;
        }
    }
    
    /**
     * Inicializa el gráfico con Chart.js
     */
    initializeChart() {
        if (!this.chartRef.el || !window.Chart) {
            return;
        }
        
        const ctx = this.chartRef.el.getContext('2d');
        
        // Configuración base del gráfico
        const chartConfig = {
            type: this._getChartType(),
            data: this.state.data,
            options: this._getChartOptions()
        };
        
        try {
            this.chart = new window.Chart(ctx, chartConfig);
        } catch (error) {
            console.error("Error initializing chart:", error);
            this.state.hasError = true;
            this.state.errorMessage = _t("Failed to render chart");
        }
    }
    
    /**
     * Actualiza el gráfico con nuevos datos
     */
    updateChart() {
        if (!this.chart) {
            return;
        }
        
        // Actualizar datos
        this.chart.data = this.state.data;
        
        // Actualizar opciones si cambiaron
        const newOptions = this._getChartOptions();
        Object.assign(this.chart.options, newOptions);
        
        // Re-renderizar
        this.chart.update('active');
    }
    
    /**
     * Destruye el gráfico para liberar memoria
     */
    destroyChart() {
        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }
    }
    
    /**
     * Obtiene el tipo de gráfico desde la configuración
     */
    _getChartType() {
        const widgetType = this.props.widgetData.widget_type;
        
        // Mapear tipos de widget a tipos de Chart.js
        const typeMap = {
            'chart_line': 'line',
            'chart_bar': 'bar',
            'chart_pie': 'pie',
            'chart_radar': 'radar',
            'chart_scatter': 'scatter',
            'chart_doughnut': 'doughnut',
            'chart_polarArea': 'polarArea'
        };
        
        return typeMap[widgetType] || 'line';
    }
    
    /**
     * Construye las opciones del gráfico
     */
    _getChartOptions() {
        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom',
                    labels: {
                        padding: 10,
                        usePointStyle: true,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: (context) => {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            
                            // Formatear valores monetarios
                            if (this._isMonetaryChart()) {
                                const value = context.parsed.y || context.parsed;
                                label += new Intl.NumberFormat('es-CL', {
                                    style: 'currency',
                                    currency: 'CLP'
                                }).format(value);
                            } else {
                                label += context.parsed.y || context.parsed;
                            }
                            
                            return label;
                        }
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        };
        
        // Agregar opciones específicas según el tipo
        const chartType = this._getChartType();
        
        if (chartType === 'line' || chartType === 'bar') {
            defaultOptions.scales = {
                x: {
                    display: true,
                    grid: {
                        display: false
                    }
                },
                y: {
                    display: true,
                    beginAtZero: true,
                    grid: {
                        borderDash: [2, 2]
                    },
                    ticks: {
                        callback: (value) => {
                            if (this._isMonetaryChart()) {
                                return new Intl.NumberFormat('es-CL', {
                                    notation: 'compact',
                                    compactDisplay: 'short'
                                }).format(value);
                            }
                            return value;
                        }
                    }
                }
            };
        }
        
        // Mezclar con configuración personalizada del widget
        const customConfig = this.props.widgetData.chart_config || {};
        return this._deepMerge(defaultOptions, customConfig);
    }
    
    /**
     * Determina si el gráfico muestra valores monetarios
     */
    _isMonetaryChart() {
        const method = this.props.widgetData.data_service_method;
        const monetaryMethods = [
            'get_revenue_trend',
            'get_expense_distribution',
            'get_cash_flow_data',
            'get_comparative_analysis'
        ];
        return monetaryMethods.includes(method);
    }
    
    /**
     * Utilidad para mezclar objetos profundamente
     */
    _deepMerge(target, source) {
        const output = Object.assign({}, target);
        if (this._isObject(target) && this._isObject(source)) {
            Object.keys(source).forEach(key => {
                if (this._isObject(source[key])) {
                    if (!(key in target))
                        Object.assign(output, { [key]: source[key] });
                    else
                        output[key] = this._deepMerge(target[key], source[key]);
                } else {
                    Object.assign(output, { [key]: source[key] });
                }
            });
        }
        return output;
    }
    
    _isObject(item) {
        return item && typeof item === 'object' && !Array.isArray(item);
    }
    
    /**
     * Suscribe a actualizaciones en tiempo real
     */
    subscribeToRealTimeUpdates() {
        if (!this.websocketService || !this.props.widgetData.id) {
            return;
        }
        
        // Suscribir al widget
        this.websocketService.subscribeToWidget(
            this.props.widgetData.id,
            this.props.widgetData.widget_type,
            this.props.filters
        );
        
        // Escuchar actualizaciones usando el event bus
        const eventBus = this.websocketService.getEventBus();
        if (eventBus) {
            this.websocketSubscription = eventBus.addEventListener(
                `widget-update-${this.props.widgetData.id}`,
                this.handleRealTimeUpdate.bind(this)
            );
        }
    }
    
    /**
     * Desuscribe de actualizaciones en tiempo real
     */
    unsubscribeFromRealTimeUpdates() {
        if (!this.websocketService || !this.props.widgetData.id) {
            return;
        }
        
        // Desuscribir del widget
        this.websocketService.unsubscribeFromWidget(this.props.widgetData.id);
        
        // Remover listener del event bus
        if (this.websocketSubscription) {
            const eventBus = this.websocketService.getEventBus();
            if (eventBus) {
                eventBus.removeEventListener(
                    `widget-update-${this.props.widgetData.id}`,
                    this.websocketSubscription
                );
            }
        }
    }
    
    /**
     * Maneja actualizaciones en tiempo real
     */
    handleRealTimeUpdate(event) {
        const { data, timestamp } = event.detail || event;
        
        // Actualizar datos del estado
        this.state.data = data;
        
        // Si el gráfico está inicializado, actualizarlo
        if (this.chart) {
            this.updateChart();
        }
        
        // Mostrar indicador de actualización
        this.showUpdateIndicator(timestamp);
    }
    
    /**
     * Muestra indicador visual de actualización
     */
    showUpdateIndicator(timestamp) {
        // Agregar clase de animación temporal
        const container = this.chartRef.el?.parentElement;
        if (container) {
            container.classList.add('o_chart_updating');
            setTimeout(() => {
                container.classList.remove('o_chart_updating');
            }, 1000);
        }
    }
    
    /**
     * Maneja el clic en el botón de actualización
     */
    async onRefreshClick() {
        // Si hay WebSocket, solo actualizar filtros
        if (this.websocketService && this.props.widgetData.id) {
            this.websocketService.updateWidgetFilters(
                this.props.widgetData.id,
                this.props.filters
            );
        } else {
            // Fallback: cargar datos manualmente
            await this.loadData();
        }
    }
    
    /**
     * Maneja el clic en el botón de exportación
     */
    async onExportClick() {
        if (!this.chart) {
            return;
        }
        
        // Obtener imagen del gráfico
        const imageData = this.chart.toBase64Image();
        
        // Crear enlace de descarga
        const link = document.createElement('a');
        link.download = `${this.props.widgetData.name}_${new Date().toISOString().split('T')[0]}.png`;
        link.href = imageData;
        link.click();
    }
    
    /**
     * Getters para la plantilla
     */
    get widgetTitle() {
        return this.props.widgetData.name || _t("Chart");
    }
    
    get widgetIcon() {
        return this.props.widgetData.icon || 'fa-chart-line';
    }
    
    get showExportButton() {
        return this.props.widgetData.exportable !== false;
    }
    
    get containerClass() {
        const classes = ['o_chart_widget'];
        
        if (this.state.isLoading) {
            classes.push('o_chart_loading');
        }
        
        if (this.state.hasError) {
            classes.push('o_chart_error');
        }
        
        return classes.join(' ');
    }
}