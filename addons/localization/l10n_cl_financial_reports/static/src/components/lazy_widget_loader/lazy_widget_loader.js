/** @odoo-module **/
/**
 * Lazy Widget Loader Component
 * Carga widgets bajo demanda con indicador de loading
 * Siguiendo PROMPT_AGENT_IA.md
 */

import { Component, useState, onWillStart, onMounted, useRef } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { ChartWidget } from "../widgets/chart_widget/chart_widget";
import { TableWidget } from "../widgets/table_widget/table_widget";
import { GaugeWidget } from "../widgets/gauge_widget/gauge_widget";
import { KpiCard } from "../kpi_card/kpi_card";

export class LazyWidgetLoader extends Component {
    static template = "account_financial_report.LazyWidgetLoader";
    static props = {
        widgetData: Object,
        filters: Object,
        websocketService: { type: Object, optional: true }
    };
    
    setup() {
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        
        // Referencias
        this.containerRef = useRef("container");
        
        // Estado
        this.state = useState({
            isLoading: true,
            isVisible: false,
            hasError: false,
            errorMessage: "",
            loadedData: null
        });
        
        // Observer para lazy loading
        this.intersectionObserver = null;
        
        onMounted(() => {
            this.setupIntersectionObserver();
        });
        
        onWillUnmount(() => {
            this.cleanupObserver();
        });
    }
    
    /**
     * Configura el Intersection Observer para lazy loading
     */
    setupIntersectionObserver() {
        const options = {
            root: null, // viewport
            rootMargin: '50px', // Cargar 50px antes de ser visible
            threshold: 0.01 // 1% visible
        };
        
        this.intersectionObserver = new IntersectionObserver(
            this.handleIntersection.bind(this),
            options
        );
        
        if (this.containerRef.el) {
            this.intersectionObserver.observe(this.containerRef.el);
        }
    }
    
    /**
     * Maneja cuando el widget entra en el viewport
     */
    handleIntersection(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting && !this.state.isVisible) {
                this.state.isVisible = true;
                this.loadWidgetData();
                
                // Dejar de observar una vez cargado
                this.intersectionObserver.unobserve(entry.target);
            }
        });
    }
    
    /**
     * Carga los datos del widget
     */
    async loadWidgetData() {
        if (this.props.widgetData.data) {
            // Datos ya incluidos (no lazy)
            this.state.loadedData = this.props.widgetData.data;
            this.state.isLoading = false;
            return;
        }
        
        try {
            // Simular delay mínimo para evitar flicker
            const minDelay = new Promise(resolve => setTimeout(resolve, 300));
            
            const dataPromise = this.rpc("/financial/widget/data/lazy", {
                widget_id: this.props.widgetData.id,
                filters: this.props.filters
            });
            
            const [result] = await Promise.all([dataPromise, minDelay]);
            
            if (result.success) {
                this.state.loadedData = result.data;
                this.state.hasError = false;
            } else {
                throw new Error(result.error || 'Failed to load widget data');
            }
            
        } catch (error) {
            console.error("Error loading widget data:", error);
            this.state.hasError = true;
            this.state.errorMessage = error.message;
            
            this.notification.add(
                `Error loading ${this.props.widgetData.name}`,
                { type: "danger", sticky: false }
            );
        } finally {
            this.state.isLoading = false;
        }
    }
    
    /**
     * Limpia el observer
     */
    cleanupObserver() {
        if (this.intersectionObserver) {
            this.intersectionObserver.disconnect();
        }
    }
    
    /**
     * Obtiene el componente correcto para el tipo de widget
     */
    get WidgetComponent() {
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
        
        return componentMap[this.props.widgetData.widget_type] || KpiCard;
    }
    
    /**
     * Props para el widget hijo
     */
    get widgetProps() {
        return {
            widgetData: {
                ...this.props.widgetData,
                data: this.state.loadedData
            },
            config: this.props.widgetData.custom_config || {},
            filters: this.props.filters,
            size: {
                width: this.props.widgetData.grid_data?.w || 4,
                height: this.props.widgetData.grid_data?.h || 4
            },
            websocketService: this.props.websocketService
        };
    }
    
    /**
     * Altura mínima basada en el grid
     */
    get minHeight() {
        const gridHeight = this.props.widgetData.grid_data?.h || 4;
        return `${gridHeight * 8}rem`; // 8rem por unidad de grid
    }
}