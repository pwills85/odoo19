/** @odoo-module **/
/**
 * Gauge Widget Component
 * Medidor visual animado siguiendo patrones OWL y performance optimization
 */

import { Component, useState, onWillStart, useRef, onMounted, onPatched, onWillUnmount } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { _t } from "@web/core/l10n/translation";

export class GaugeWidget extends Component {
    static template = "account_financial_report.GaugeWidget";
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
        this.gaugeRef = useRef("gaugeCanvas");
        this.gauge = null;
        this.websocketSubscription = null;
        this.animationFrame = null;
        
        // Estado reactivo
        this.state = useState({
            isLoading: true,
            hasError: false,
            errorMessage: "",
            data: {
                value: 0,
                min: 0,
                max: 100,
                status: 'normal',
                color: '#28a745',
                details: {}
            }
        });
        
        // Configuración del gauge
        this.gaugeConfig = this._mergeGaugeConfig();
        
        // Hooks
        onWillStart(async () => {
            await this.loadData();
        });
        
        onMounted(() => {
            if (!this.state.hasError) {
                this.initializeGauge();
            }
            this.subscribeToRealTimeUpdates();
        });
        
        onPatched(() => {
            if (this.gauge && !this.state.hasError) {
                this.updateGauge();
            }
        });
        
        onWillUnmount(() => {
            this.cleanup();
        });
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
        
        // Normalizar y actualizar datos
        const normalizedData = this._normalizeData(data);
        
        // Animar transición suave del valor
        this.animateValueChange(this.state.data.value, normalizedData.value);
        
        // Actualizar estado
        this.state.data = normalizedData;
        
        // Mostrar indicador de actualización
        this.showUpdateIndicator(timestamp);
    }
    
    /**
     * Anima el cambio de valor del gauge
     */
    animateValueChange(oldValue, newValue) {
        if (!this.gauge) return;
        
        const duration = 1000; // 1 segundo
        const startTime = Date.now();
        const deltaValue = newValue - oldValue;
        
        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function para animación suave
            const easeProgress = 1 - Math.pow(1 - progress, 3);
            const currentValue = oldValue + (deltaValue * easeProgress);
            
            // Actualizar gauge
            this.state.data.value = currentValue;
            this.updateGauge();
            
            if (progress < 1) {
                this.animationFrame = requestAnimationFrame(animate);
            }
        };
        
        // Cancelar animación anterior si existe
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
        }
        
        animate();
    }
    
    /**
     * Muestra indicador visual de actualización
     */
    showUpdateIndicator(timestamp) {
        // Agregar clase de animación temporal
        const container = this.gaugeRef.el?.parentElement;
        if (container) {
            container.classList.add('o_gauge_updating');
            setTimeout(() => {
                container.classList.remove('o_gauge_updating');
            }, 1000);
        }
    }
    
    /**
     * Limpieza de recursos
     */
    cleanup() {
        // Cancelar animación
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
        }
        
        // Desuscribir de actualizaciones
        this.unsubscribeFromRealTimeUpdates();
        
        // Limpiar gauge
        if (this.gauge) {
            // Limpieza específica del gauge si es necesario
            this.gauge = null;
        }
    }
    
    /**
     * Carga los datos del widget
     */
    async loadData() {
        this.state.isLoading = true;
        this.state.hasError = false;
        
        try {
            const params = {
                model: this.props.widgetData.data_service_model,
                method: this.props.widgetData.data_service_method,
                args: [],
                kwargs: this.props.filters || {}
            };
            
            const data = await this.rpc("/web/dataset/call_kw", params);
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Validar y normalizar datos
            this.state.data = this._normalizeData(data);
            
        } catch (error) {
            console.error("Error loading gauge data:", error);
            this.state.hasError = true;
            this.state.errorMessage = error.message || _t("Failed to load gauge data");
            this.notification.add(
                _t("Error loading gauge data"),
                { type: "danger" }
            );
        } finally {
            this.state.isLoading = false;
        }
    }
    
    /**
     * Normaliza los datos recibidos
     */
    _normalizeData(data) {
        return {
            value: parseFloat(data.value) || 0,
            min: parseFloat(data.min) || 0,
            max: parseFloat(data.max) || 100,
            status: data.status || 'normal',
            color: data.color || this._getColorByValue(data.value, data.min, data.max),
            units: data.units || '',
            details: data.details || {}
        };
    }
    
    /**
     * Combina la configuración del gauge
     */
    _mergeGaugeConfig() {
        const defaultConfig = {
            min: 0,
            max: 100,
            thresholds: {
                danger: [0, 33],
                warning: [33, 66],
                success: [66, 100]
            },
            units: '%',
            decimals: 1,
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            },
            style: {
                strokeWidth: 15,
                trailWidth: 15,
                trailColor: '#e0e0e0',
                textSize: '2rem'
            }
        };
        
        return Object.assign({}, defaultConfig, this.props.widgetData.gauge_config || {});
    }
    
    /**
     * Inicializa el gauge
     */
    initializeGauge() {
        if (!this.gaugeRef.el) return;
        
        const canvas = this.gaugeRef.el;
        const ctx = canvas.getContext('2d');
        
        // Configurar dimensiones
        const size = Math.min(canvas.parentElement.offsetWidth, canvas.parentElement.offsetHeight);
        canvas.width = size;
        canvas.height = size;
        
        // Crear gauge personalizado
        this.gauge = {
            canvas: canvas,
            ctx: ctx,
            size: size,
            center: size / 2,
            radius: (size / 2) - 20,
            currentValue: this.state.data.min,
            targetValue: this.state.data.value,
            animationId: null
        };
        
        // Iniciar animación
        this.animateGauge();
    }
    
    /**
     * Actualiza el gauge con nuevos valores
     */
    updateGauge() {
        if (!this.gauge) return;
        
        // Cancelar animación anterior
        if (this.gauge.animationId) {
            cancelAnimationFrame(this.gauge.animationId);
        }
        
        // Actualizar valores objetivo
        this.gauge.targetValue = this.state.data.value;
        
        // Reiniciar animación
        this.animateGauge();
    }
    
    /**
     * Anima el gauge
     */
    animateGauge() {
        const startTime = Date.now();
        const duration = this.gaugeConfig.animation.duration;
        const startValue = this.gauge.currentValue;
        const endValue = this.gauge.targetValue;
        
        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Aplicar easing
            const easedProgress = this._easeOutQuart(progress);
            
            // Calcular valor actual
            this.gauge.currentValue = startValue + (endValue - startValue) * easedProgress;
            
            // Dibujar gauge
            this.drawGauge();
            
            // Continuar animación si no ha terminado
            if (progress < 1) {
                this.gauge.animationId = requestAnimationFrame(animate);
            }
        };
        
        animate();
    }
    
    /**
     * Dibuja el gauge en el canvas
     */
    drawGauge() {
        const { ctx, size, center, radius } = this.gauge;
        const { min, max } = this.state.data;
        const value = this.gauge.currentValue;
        
        // Limpiar canvas
        ctx.clearRect(0, 0, size, size);
        
        // Configurar estilos
        ctx.lineCap = 'round';
        
        // Calcular ángulos (3/4 de círculo)
        const startAngle = Math.PI * 0.75;
        const endAngle = Math.PI * 2.25;
        const valueAngle = startAngle + ((value - min) / (max - min)) * (endAngle - startAngle);
        
        // Dibujar pista de fondo
        ctx.beginPath();
        ctx.arc(center, center, radius, startAngle, endAngle);
        ctx.strokeStyle = this.gaugeConfig.style.trailColor;
        ctx.lineWidth = this.gaugeConfig.style.trailWidth;
        ctx.stroke();
        
        // Dibujar valor
        ctx.beginPath();
        ctx.arc(center, center, radius, startAngle, valueAngle);
        ctx.strokeStyle = this._getGradient(ctx, center, radius, this.state.data.color);
        ctx.lineWidth = this.gaugeConfig.style.strokeWidth;
        ctx.stroke();
        
        // Dibujar texto central
        ctx.fillStyle = this.state.data.color;
        ctx.font = `bold ${this.gaugeConfig.style.textSize} -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        
        const displayValue = value.toFixed(this.gaugeConfig.decimals);
        const displayText = `${displayValue}${this.state.data.units || ''}`;
        ctx.fillText(displayText, center, center);
        
        // Dibujar etiqueta de estado
        if (this.state.data.status) {
            ctx.font = '0.875rem -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto';
            ctx.fillStyle = '#666';
            ctx.fillText(this._getStatusLabel(), center, center + 30);
        }
    }
    
    /**
     * Crea un gradiente para el arco
     */
    _getGradient(ctx, center, radius, color) {
        const gradient = ctx.createRadialGradient(center, center, 0, center, center, radius);
        
        // Convertir color hex a RGB para el gradiente
        const rgb = this._hexToRgb(color);
        if (rgb) {
            gradient.addColorStop(0, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.8)`);
            gradient.addColorStop(1, `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 1)`);
        } else {
            gradient.addColorStop(0, color);
            gradient.addColorStop(1, color);
        }
        
        return gradient;
    }
    
    /**
     * Convierte hex a RGB
     */
    _hexToRgb(hex) {
        const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        return result ? {
            r: parseInt(result[1], 16),
            g: parseInt(result[2], 16),
            b: parseInt(result[3], 16)
        } : null;
    }
    
    /**
     * Función de easing
     */
    _easeOutQuart(t) {
        return 1 - Math.pow(1 - t, 4);
    }
    
    /**
     * Obtiene el color según el valor y umbrales
     */
    _getColorByValue(value, min, max) {
        const percentage = ((value - min) / (max - min)) * 100;
        const thresholds = this.gaugeConfig.thresholds;
        
        if (percentage >= thresholds.success[0] && percentage <= thresholds.success[1]) {
            return '#28a745'; // Verde
        } else if (percentage >= thresholds.warning[0] && percentage <= thresholds.warning[1]) {
            return '#ffc107'; // Amarillo
        } else if (percentage >= thresholds.danger[0] && percentage <= thresholds.danger[1]) {
            return '#dc3545'; // Rojo
        }
        
        return '#6c757d'; // Gris por defecto
    }
    
    /**
     * Obtiene la etiqueta de estado
     */
    _getStatusLabel() {
        const statusLabels = {
            'excellent': _t('Excellent'),
            'good': _t('Good'),
            'fair': _t('Fair'),
            'poor': _t('Poor'),
            'critical': _t('Critical')
        };
        
        return statusLabels[this.state.data.status] || this.state.data.status;
    }
    
    /**
     * Maneja el clic en refresh
     */
    async onRefreshClick() {
        await this.loadData();
    }
    
    /**
     * Maneja el clic en detalles
     */
    onDetailsClick() {
        // Mostrar modal con detalles
        this.env.services.dialog.add(GaugeDetailsDialog, {
            title: this.widgetTitle,
            data: this.state.data,
            config: this.gaugeConfig
        });
    }
    
    /**
     * Getters para la plantilla
     */
    get widgetTitle() {
        return this.props.widgetData.name || _t("Gauge");
    }
    
    get widgetIcon() {
        return this.props.widgetData.icon || 'fa-tachometer-alt';
    }
    
    get showDetails() {
        return Object.keys(this.state.data.details).length > 0;
    }
    
    get detailItems() {
        return Object.entries(this.state.data.details).map(([key, value]) => ({
            label: this._formatDetailLabel(key),
            value: this._formatDetailValue(value)
        }));
    }
    
    _formatDetailLabel(key) {
        // Convertir snake_case a Title Case
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
    
    _formatDetailValue(value) {
        if (typeof value === 'number') {
            return value.toFixed(1);
        }
        return String(value);
    }
}

/**
 * Dialog para mostrar detalles del gauge
 */
export class GaugeDetailsDialog extends Component {
    static template = "account_financial_report.GaugeDetailsDialog";
    static props = {
        close: Function,
        title: String,
        data: Object,
        config: Object
    };
}