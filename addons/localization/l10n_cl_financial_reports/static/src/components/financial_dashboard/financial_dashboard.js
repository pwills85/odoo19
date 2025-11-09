
// Lazy loading implementation
const LazyLoader = {
    loadWidget: async function(widgetId) {
        // Load widget data on demand
        const response = await this.rpc({
            model: 'financial.dashboard.widget',
            method: 'get_widget_data',
            args: [widgetId],
        });
        return response;
    },

    observeWidgets: function() {
        // Use Intersection Observer for lazy loading
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const widgetId = entry.target.dataset.widgetId;
                    if (!entry.target.dataset.loaded) {
                        this.loadWidget(widgetId).then(data => {
                            this.renderWidget(entry.target, data);
                            entry.target.dataset.loaded = 'true';
                        });
                    }
                }
            });
        });

        // Observe all widgets
        document.querySelectorAll('.dashboard-widget[data-lazy="true"]').forEach(widget => {
            observer.observe(widget);
        });
    }
};

// Virtual scrolling for large tables
const VirtualScroller = {
    init: function(container, items, itemHeight) {
        this.container = container;
        this.items = items;
        this.itemHeight = itemHeight;
        this.visibleItems = Math.ceil(container.clientHeight / itemHeight);
        this.render();
    },

    render: function() {
        const scrollTop = this.container.scrollTop;
        const startIndex = Math.floor(scrollTop / this.itemHeight);
        const endIndex = startIndex + this.visibleItems;

        // Render only visible items
        const visibleItems = this.items.slice(startIndex, endIndex);
        this.container.innerHTML = this.renderItems(visibleItems, startIndex);
    }
};

/** @odoo-module **/
/**
 * Financial Dashboard Component - Enhanced Version
 * Integra los nuevos widgets (Chart, Table, Gauge) siguiendo PROMPT_AGENT_IA.md
 */

import { registry } from "@web/core/registry";
import { Component, onWillStart, onMounted, useState, useRef, onWillUnmount } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { luxon } from "@web/core/l10n/dates";
import { _t } from "@web/core/l10n/translation";

// Importar nuevos componentes de widgets
import { ChartWidget } from "../widgets/chart_widget/chart_widget";
import { TableWidget } from "../widgets/table_widget/table_widget";
import { GaugeWidget } from "../widgets/gauge_widget/gauge_widget";
import { KpiCard } from "../kpi_card/kpi_card"; // Widget KPI existente
import { FilterPanel } from "../filter_panel/filter_panel";

class FinancialDashboard extends Component {
    static template = "account_financial_report.FinancialDashboard";
    static components = { 
        KpiCard,
        ChartWidget,
        TableWidget,
        GaugeWidget,
        FilterPanel
    };
    
    setup() {
        // Servicios
        this.orm = useService("orm");
        this.action = useService("action");
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.websocketService = useService("dashboard.websocket");
        
        // Referencias
        this.root = useRef("dashboard_root");
        this.gridContainer = useRef("grid_container");
        this.grid = null;
        
        // Estado reactivo
        this.state = useState({
            isLoading: true,
            layout: null,
            widgets: [],
            filters: {
                date_from: luxon.DateTime.now().startOf('year').toISODate(),
                date_to: luxon.DateTime.now().endOf('year').toISODate(),
                company_id: null,
                department_id: null
            },
            refreshInterval: null
        });
        
        // WebSocket para actualizaciones en tiempo real
        this.websocketConnected = false;
        this.widgetSubscriptions = new Map();
        
        // Hooks del ciclo de vida
        onWillStart(async () => {
            await this.loadDashboardData();
        });
        
        onMounted(() => {
            this.initializeGridStack();
            this.setupWebSocket();
            this.updateDateInputs();
        });
        
        onWillUnmount(() => {
            this.cleanup();
        });
    }
    
    /**
     * Carga los datos iniciales del dashboard
     */
    async loadDashboardData() {
        this.state.isLoading = true;
        
        try {
            // Cargar layout del usuario
            const layoutData = await this.orm.call(
                'financial.dashboard.layout',
                'get_user_layout',
                []
            );
            
            this.state.layout = layoutData;
            
            // Cargar widgets del layout
            if (layoutData.id) {
                await this.loadWidgets(layoutData.id);
            }
            
        } catch (error) {
            console.error("Error loading dashboard:", error);
            this.notification.add(
                _t("Error loading dashboard configuration"),
                { type: "danger" }
            );
        } finally {
            this.state.isLoading = false;
        }
    }
    
    /**
     * Carga los widgets del layout
     */
    async loadWidgets(layoutId) {
        const widgetData = await this.orm.searchRead(
            'financial.dashboard.widget.user',
            [['layout_id', '=', layoutId]],
            ['widget_id', 'grid_data', 'custom_config', 'custom_filters']
        );
        
        // Cargar información completa de cada widget
        const widgetIds = widgetData.map(w => w.widget_id[0]);
        const widgets = await this.orm.read(
            'financial.dashboard.widget',
            widgetIds,
            []
        );
        
        // Combinar datos
        this.state.widgets = widgetData.map(userWidget => {
            const widget = widgets.find(w => w.id === userWidget.widget_id[0]);
            return {
                ...widget,
                user_widget_id: userWidget.id,
                grid_data: userWidget.grid_data,
                custom_config: userWidget.custom_config,
                custom_filters: userWidget.custom_filters
            };
        });
    }
    
    /**
     * Inicializa GridStack para drag & drop
     */
    initializeGridStack() {
        if (!this.gridContainer.el) return;
        
        const options = {
            float: false,
            cellHeight: '8rem',
            minRow: 1,
            column: 12,
            handle: '.widget-header',
            alwaysShowResizeHandle: true,
            resizable: {
                handles: 'se, sw'
            },
            animate: true,
            disableOneColumnMode: true
        };
        
        this.grid = GridStack.init(options, this.gridContainer.el);
        
        // Escuchar cambios en el layout
        this.grid.on('change', (event, items) => {
            this.onGridChange(items);
        });
        
        // Cargar widgets en el grid
        this.loadWidgetsIntoGrid();
    }
    
    /**
     * Carga los widgets en el grid
     */
    loadWidgetsIntoGrid() {
        if (!this.grid || !this.state.widgets.length) return;
        
        // Limpiar grid existente
        this.grid.removeAll();
        
        // Desuscribir widgets anteriores
        this.widgetSubscriptions.forEach((subscribed, widgetId) => {
            if (subscribed) {
                this.websocketService.unsubscribeFromWidget(widgetId);
            }
        });
        this.widgetSubscriptions.clear();
        
        // Añadir cada widget
        this.state.widgets.forEach(widget => {
            const gridItem = this.createGridItem(widget);
            this.grid.addWidget(gridItem, widget.grid_data);
        });
        
        // Si WebSocket está conectado, suscribir widgets
        if (this.websocketConnected) {
            this.subscribeAllWidgets();
        }
    }
    
    /**
     * Crea un elemento del grid para un widget
     */
    createGridItem(widget) {
        const div = document.createElement('div');
        div.className = 'grid-stack-item';
        div.dataset.gsId = widget.user_widget_id;
        
        const content = document.createElement('div');
        content.className = 'grid-stack-item-content';
        
        // El contenido real será renderizado por OWL
        div.appendChild(content);
        
        return div;
    }
    
    /**
     * Maneja cambios en el grid (drag & drop)
     */
    async onGridChange(items) {
        const updates = items.map(item => ({
            id: parseInt(item.el.dataset.gsId),
            grid_data: {
                x: item.x,
                y: item.y,
                w: item.w,
                h: item.h
            }
        }));
        
        try {
            await this.orm.call(
                'financial.dashboard.layout',
                'save_grid_layout',
                [this.state.layout.id, updates]
            );
        } catch (error) {
            console.error("Error saving layout:", error);
            this.notification.add(
                _t("Error saving dashboard layout"),
                { type: "danger" }
            );
        }
    }
    
    /**
     * Configura conexión WebSocket para actualizaciones en tiempo real
     */
    setupWebSocket() {
        // Conectar al WebSocket
        this.websocketService.connect();
        
        // Escuchar eventos de conexión
        this.websocketService.addEventListener('connected', () => {
            this.websocketConnected = true;
            this.subscribeAllWidgets();
        });
        
        // Escuchar actualizaciones de widgets
        this.websocketService.addEventListener('widget-update', (event) => {
            this.handleWidgetUpdate(event.detail);
        });
        
        // Escuchar alertas del dashboard
        this.websocketService.addEventListener('dashboard-alert', (event) => {
            this.handleDashboardAlert(event.detail);
        });
        
        // Escuchar desconexión
        this.websocketService.addEventListener('disconnected', () => {
            this.websocketConnected = false;
            // Mostrar indicador de desconexión
            this.notification.add(
                _t("Real-time updates disconnected. Attempting to reconnect..."),
                { type: "warning" }
            );
        });
        
        // Fallback: refresh cada 5 minutos si no hay WebSocket
        this.state.refreshInterval = setInterval(() => {
            if (!this.websocketConnected) {
                this.refreshWidgets();
            }
        }, 300000); // 5 minutos
    }
    
    /**
     * Suscribe todos los widgets a actualizaciones en tiempo real
     */
    subscribeAllWidgets() {
        this.state.widgets.forEach(widget => {
            this.websocketService.subscribeToWidget(
                widget.id,
                widget.widget_type,
                this.state.filters
            );
            this.widgetSubscriptions.set(widget.id, true);
        });
    }
    
    /**
     * Maneja actualizaciones de widgets desde WebSocket
     */
    handleWidgetUpdate(detail) {
        const { widgetId, widgetType, data, timestamp } = detail;
        
        // Encontrar el widget y actualizar sus datos
        const widgetIndex = this.state.widgets.findIndex(w => w.id === parseInt(widgetId));
        if (widgetIndex !== -1) {
            // Actualizar datos del widget
            this.state.widgets[widgetIndex] = {
                ...this.state.widgets[widgetIndex],
                last_update: timestamp,
                real_time_data: data
            };
            
            // Forzar re-render
            this.state.widgets = [...this.state.widgets];
        }
    }
    
    /**
     * Maneja alertas del dashboard
     */
    handleDashboardAlert(detail) {
        const { title, message, severity } = detail;
        
        // Mapear severidad a tipo de notificación
        const typeMap = {
            'info': 'info',
            'warning': 'warning',
            'error': 'danger',
            'critical': 'danger'
        };
        
        this.notification.add(
            `${title}: ${message}`,
            { 
                type: typeMap[severity] || 'info',
                sticky: severity === 'critical'
            }
        );
    }
    
    /**
     * Refresca todos los widgets
     */
    async refreshWidgets() {
        if (this.websocketConnected) {
            // Si hay WebSocket, actualizar filtros provocará refresh
            this.state.widgets.forEach(widget => {
                this.websocketService.updateWidgetFilters(widget.id, this.state.filters);
            });
        } else {
            // Fallback: cargar datos manualmente
            await this.loadDashboardData();
        }
    }
    
    /**
     * Actualiza los inputs de fecha con los valores del estado
     */
    updateDateInputs() {
        const { date_from, date_to } = this.state.filters;
        const dateFromEl = this.root.el?.querySelector('#filter_date_from');
        const dateToEl = this.root.el?.querySelector('#filter_date_to');
        
        if (dateFromEl) dateFromEl.value = date_from;
        if (dateToEl) dateToEl.value = date_to;
    }
    
    /**
     * Obtiene el componente correcto para el tipo de widget
     */
    getWidgetComponent(widgetType) {
        const componentMap = {
            'kpi': KpiCard,
            'chart_line': ChartWidget,
            'chart_bar': ChartWidget,
            'chart_pie': ChartWidget,
            'chart_radar': ChartWidget,
            'chart_scatter': ChartWidget,
            'table': TableWidget,
            'gauge': GaugeWidget
        };
        
        return componentMap[widgetType] || KpiCard;
    }
    
    /**
     * Limpieza al destruir el componente
     */
    cleanup() {
        if (this.state.refreshInterval) {
            clearInterval(this.state.refreshInterval);
        }
        
        // Desuscribir todos los widgets
        this.widgetSubscriptions.forEach((subscribed, widgetId) => {
            if (subscribed) {
                this.websocketService.unsubscribeFromWidget(widgetId);
            }
        });
        
        // Desconectar WebSocket
        this.websocketService.disconnect();
        
        if (this.grid) {
            this.grid.destroy();
        }
    }
    
    // ========================================
    // Manejadores de eventos
    // ========================================
    
    /**
     * Abre el wizard para añadir widgets
     */
    onAddWidget() {
        this.action.doAction({
            type: 'ir.actions.act_window',
            res_model: 'financial.dashboard.add.widget.wizard',
            name: _t('Add Widget'),
            view_mode: 'form',
            view_type: 'form',
            views: [[false, 'form']],
            target: 'new',
            context: {
                default_layout_id: this.state.layout.id
            },
        }, {
            onClose: () => this.loadDashboardData()
        });
    }
    
    /**
     * Maneja cambios en los filtros desde el FilterPanel
     */
    onFiltersChanged(newFilters) {
        this.state.filters = newFilters;
        
        // Si hay WebSocket, actualizar filtros en tiempo real
        if (this.websocketConnected) {
            this.state.widgets.forEach(widget => {
                this.websocketService.updateWidgetFilters(widget.id, newFilters);
            });
        } else {
            // Fallback: refresh manual
            this.refreshWidgets();
        }
    }
    
    /**
     * Maneja cambios en los filtros (retrocompatibilidad)
     */
    onFilterChange(ev) {
        const filterId = ev.target.id.replace('filter_', '');
        this.state.filters[filterId] = ev.target.value;
        
        // Actualizar todos los widgets con nuevos filtros
        this.refreshWidgets();
    }
    
    /**
     * Exporta el dashboard completo
     */
    async onExportDashboard() {
        // Mostrar diálogo de opciones de exportación
        const formats = [
            { value: 'pdf', label: _t('PDF Document'), icon: 'fa-file-pdf-o' },
            { value: 'xlsx', label: _t('Excel Workbook'), icon: 'fa-file-excel-o' }
        ];
        
        // Por ahora usar PDF por defecto, en el futuro mostrar un diálogo
        await this._exportDashboard('pdf');
    }
    
    /**
     * Realiza la exportación del dashboard
     */
    async _exportDashboard(format) {
        try {
            // Mostrar loading
            this.notification.add(
                _t("Generating export..."),
                { type: "info", sticky: false }
            );
            
            const result = await this.rpc("/financial/dashboard/export", {
                layout_id: this.state.layout.id,
                format: format,
                filters: this.state.filters,
                options: {
                    include_filters: true,
                    include_metadata: true
                }
            });
            
            if (result.success) {
                // Descargar el archivo
                const link = document.createElement('a');
                link.href = `data:${result.mimetype};base64,${result.data}`;
                link.download = result.filename;
                link.click();
                
                this.notification.add(
                    _t("Dashboard exported successfully"),
                    { type: "success" }
                );
            } else {
                throw new Error(result.error || 'Export failed');
            }
            
        } catch (error) {
            this.notification.add(
                _t("Error exporting dashboard: %s", error.message),
                { type: "danger" }
            );
        }
    }
    
    /**
     * Abre el selector de plantillas
     */
    onSelectTemplate() {
        this.action.doAction({
            type: 'ir.actions.act_window',
            res_model: 'financial.dashboard.template',
            name: _t('Dashboard Templates'),
            view_mode: 'kanban,form',
            view_type: 'kanban',
            views: [[false, 'kanban'], [false, 'form']],
            target: 'new',
            context: {}
        }, {
            onClose: () => this.loadDashboardData()
        });
    }
    
    /**
     * Guarda el dashboard actual como plantilla
     */
    async onSaveAsTemplate() {
        // Abrir wizard para guardar como template
        this.action.doAction({
            type: 'ir.actions.act_window',
            res_model: 'financial.dashboard.save.template.wizard',
            name: _t('Save Dashboard as Template'),
            view_mode: 'form',
            view_type: 'form',
            views: [[false, 'form']],
            target: 'new',
            context: {
                default_layout_id: this.state.layout.id
            }
        }, {
            onClose: (result) => {
                if (result && result.template_created) {
                    this.notification.add(
                        _t("Template saved successfully"),
                        { type: "success" }
                    );
                }
            }
        });
    }
    
    /**
     * Toggle modo pantalla completa
     */
    onToggleFullscreen() {
        const dashboardEl = this.root.el;
        
        if (!document.fullscreenElement) {
            dashboardEl.requestFullscreen().catch(err => {
                console.error(`Error attempting to enable fullscreen: ${err.message}`);
            });
        } else {
            document.exitFullscreen();
        }
    }
    
    // ========================================
    // Getters para la plantilla
    // ========================================
    
    get hasWidgets() {
        return this.state.widgets.length > 0;
    }
    
    get dashboardTitle() {
        return this.state.layout?.name || _t("Financial Dashboard");
    }
    
    get showAdvancedFilters() {
        // Por ahora solo fecha, en Fase 2 se añadirán más
        return true;
    }
}

// Registrar el componente
registry.category("actions").add("financial_dashboard", FinancialDashboard);