/** @odoo-module **/
/**
 * Dashboard WebSocket Service
 * Servicio para actualizaciones en tiempo real del dashboard
 * Siguiendo patrones de documentación técnica
 */

import { registry } from "@web/core/registry";
import { EventBus } from "@odoo/owl";

export class DashboardWebSocketService extends EventTarget {
    constructor(env, services) {
        super();
        this.env = env;
        this.services = services;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.subscriptions = new Map();
        this.isConnected = false;
        this.eventBus = new EventBus();
        
        // Auto-conectar si estamos en modo dashboard
        if (this._shouldConnect()) {
            this.connect();
        }
    }
    
    /**
     * Determina si debe conectarse automáticamente
     */
    _shouldConnect() {
        // Solo conectar si estamos en el dashboard financiero
        const currentAction = this.env.services.action.currentController?.action;
        return currentAction?.xml_id === 'account_financial_report.action_financial_dashboard';
    }
    
    /**
     * Establece conexión WebSocket
     */
    connect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return; // Ya conectado
        }
        
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/websocket/dashboard`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            this._setupEventHandlers();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this._scheduleReconnect();
        }
    }
    
    /**
     * Configura manejadores de eventos del WebSocket
     */
    _setupEventHandlers() {
        this.ws.onopen = () => {
            // console.log('WebSocket connected');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            
            // Re-suscribir a todos los widgets
            this._resubscribeAll();
            
            // Emitir evento de conexión
            this.dispatchEvent(new CustomEvent('connected'));
        };
        
        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this._handleMessage(data);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.isConnected = false;
        };
        
        this.ws.onclose = () => {
            // console.log('WebSocket disconnected');
            this.isConnected = false;
            this.dispatchEvent(new CustomEvent('disconnected'));
            
            // Intentar reconectar
            this._scheduleReconnect();
        };
    }
    
    /**
     * Maneja mensajes recibidos
     */
    _handleMessage(data) {
        switch (data.type) {
            case 'widget_update':
                this._handleWidgetUpdate(data);
                break;
                
            case 'notification':
                this._handleNotification(data);
                break;
                
            case 'alert':
                this._handleAlert(data);
                break;
                
            case 'heartbeat':
                // Keep-alive, no acción necesaria
                break;
                
            default:
                console.warn('Unknown WebSocket message type:', data.type);
        }
    }
    
    /**
     * Maneja actualizaciones de widgets
     */
    _handleWidgetUpdate(data) {
        const { widget_id, widget_type, update_data, timestamp } = data;
        
        // Verificar si tenemos suscripción activa
        if (!this.subscriptions.has(widget_id)) {
            return;
        }
        
        // Emitir evento específico del widget
        this.dispatchEvent(new CustomEvent('widget-update', {
            detail: {
                widgetId: widget_id,
                widgetType: widget_type,
                data: update_data,
                timestamp: timestamp
            }
        }));
        
        // También emitir en el event bus para componentes OWL
        this.eventBus.trigger(`widget-update-${widget_id}`, {
            data: update_data,
            timestamp: timestamp
        });
    }
    
    /**
     * Maneja notificaciones
     */
    _handleNotification(data) {
        const { message, type, sticky } = data;
        
        this.services.notification.add(message, {
            type: type || 'info',
            sticky: sticky || false
        });
    }
    
    /**
     * Maneja alertas críticas
     */
    _handleAlert(data) {
        const { title, message, severity } = data;
        
        // Emitir evento de alerta
        this.dispatchEvent(new CustomEvent('dashboard-alert', {
            detail: { title, message, severity }
        }));
        
        // Mostrar notificación si es crítica
        if (severity === 'critical') {
            this.services.notification.add(
                `${title}: ${message}`,
                { type: 'danger', sticky: true }
            );
        }
    }
    
    /**
     * Suscribe a actualizaciones de un widget
     */
    subscribeToWidget(widgetId, widgetType, filters = {}) {
        if (!this.isConnected) {
            console.warn('WebSocket not connected, queuing subscription');
            // Guardar para re-suscribir cuando se conecte
            this.subscriptions.set(widgetId, { widgetType, filters });
            return;
        }
        
        const subscription = {
            action: 'subscribe',
            widget_id: widgetId,
            widget_type: widgetType,
            filters: filters
        };
        
        this._send(subscription);
        this.subscriptions.set(widgetId, { widgetType, filters });
    }
    
    /**
     * Cancela suscripción a un widget
     */
    unsubscribeFromWidget(widgetId) {
        if (!this.subscriptions.has(widgetId)) {
            return;
        }
        
        if (this.isConnected) {
            this._send({
                action: 'unsubscribe',
                widget_id: widgetId
            });
        }
        
        this.subscriptions.delete(widgetId);
    }
    
    /**
     * Actualiza filtros de una suscripción
     */
    updateWidgetFilters(widgetId, filters) {
        const subscription = this.subscriptions.get(widgetId);
        if (!subscription) {
            return;
        }
        
        subscription.filters = filters;
        
        if (this.isConnected) {
            this._send({
                action: 'update_filters',
                widget_id: widgetId,
                filters: filters
            });
        }
    }
    
    /**
     * Re-suscribe todos los widgets después de reconexión
     */
    _resubscribeAll() {
        for (const [widgetId, subscription] of this.subscriptions) {
            this._send({
                action: 'subscribe',
                widget_id: widgetId,
                widget_type: subscription.widgetType,
                filters: subscription.filters
            });
        }
    }
    
    /**
     * Envía mensaje al servidor
     */
    _send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        } else {
            console.warn('WebSocket not ready, message not sent:', data);
        }
    }
    
    /**
     * Programa reconexión
     */
    _scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            this.dispatchEvent(new CustomEvent('connection-failed'));
            return;
        }
        
        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        
        // console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
        
        setTimeout(() => {
            this.connect();
        }, delay);
    }
    
    /**
     * Cierra la conexión
     */
    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        
        this.subscriptions.clear();
        this.isConnected = false;
    }
    
    /**
     * Obtiene el event bus para componentes OWL
     */
    getEventBus() {
        return this.eventBus;
    }
}

// Registrar el servicio
export const dashboardWebSocketService = {
    dependencies: ["notification", "action"],
    start(env, services) {
        return new DashboardWebSocketService(env, services);
    },
};

registry.category("services").add("dashboard.websocket", dashboardWebSocketService);