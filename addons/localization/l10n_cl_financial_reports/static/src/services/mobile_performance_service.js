/** @odoo-module **/

/**
 * Mobile Performance Service
 * Optimizations for mobile dashboard performance
 */
export class MobilePerformanceService {
    constructor() {
        this.observers = new Map();
        this.rafCallbacks = new Set();
        this.idleCallbacks = new Set();
        this.networkInfo = null;
        this.batteryInfo = null;
        this.performanceMetrics = {
            fps: 60,
            memoryUsage: 0,
            loadTime: 0,
        };
        
        this._initialize();
    }
    
    _initialize() {
        // Initialize network information API
        if ('connection' in navigator) {
            this.networkInfo = navigator.connection;
            this.networkInfo.addEventListener('change', () => this._onNetworkChange());
        }
        
        // Initialize battery API
        if ('getBattery' in navigator) {
            navigator.getBattery().then(battery => {
                this.batteryInfo = battery;
                battery.addEventListener('levelchange', () => this._onBatteryChange());
            });
        }
        
        // Start performance monitoring
        this._startPerformanceMonitoring();
    }
    
    /**
     * Create Intersection Observer for lazy loading
     */
    createLazyLoadObserver(callback, options = {}) {
        const defaultOptions = {
            root: null,
            rootMargin: '50px',
            threshold: 0.01,
            ...options
        };
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    callback(entry.target);
                }
            });
        }, defaultOptions);
        
        this.observers.set(callback, observer);
        return observer;
    }
    
    /**
     * Destroy observer
     */
    destroyObserver(callback) {
        const observer = this.observers.get(callback);
        if (observer) {
            observer.disconnect();
            this.observers.delete(callback);
        }
    }
    
    /**
     * Request animation frame with fallback
     */
    requestAnimationFrame(callback) {
        const raf = window.requestAnimationFrame || 
                   window.webkitRequestAnimationFrame ||
                   ((cb) => setTimeout(cb, 16));
        
        const handle = raf(callback);
        this.rafCallbacks.add(handle);
        return handle;
    }
    
    /**
     * Cancel animation frame
     */
    cancelAnimationFrame(handle) {
        const caf = window.cancelAnimationFrame || 
                   window.webkitCancelAnimationFrame ||
                   clearTimeout;
        
        caf(handle);
        this.rafCallbacks.delete(handle);
    }
    
    /**
     * Request idle callback for non-critical tasks
     */
    requestIdleCallback(callback, options = {}) {
        if ('requestIdleCallback' in window) {
            const handle = window.requestIdleCallback(callback, options);
            this.idleCallbacks.add(handle);
            return handle;
        } else {
            // Fallback for browsers without idle callback
            return setTimeout(() => {
                callback({
                    didTimeout: false,
                    timeRemaining: () => 50
                });
            }, 1);
        }
    }
    
    /**
     * Cancel idle callback
     */
    cancelIdleCallback(handle) {
        if ('cancelIdleCallback' in window) {
            window.cancelIdleCallback(handle);
        } else {
            clearTimeout(handle);
        }
        this.idleCallbacks.delete(handle);
    }
    
    /**
     * Debounce function for performance
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    /**
     * Throttle function for performance
     */
    throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
    
    /**
     * Check if device is low-end
     */
    isLowEndDevice() {
        // Check various indicators of low-end device
        const indicators = {
            lowMemory: this._checkLowMemory(),
            slowNetwork: this._checkSlowNetwork(),
            lowBattery: this._checkLowBattery(),
            reducedMotion: this._checkReducedMotion(),
        };
        
        // Device is considered low-end if any 2+ indicators are true
        const trueCount = Object.values(indicators).filter(v => v).length;
        return trueCount >= 2;
    }
    
    _checkLowMemory() {
        if ('memory' in navigator) {
            // Device memory less than 2GB
            return navigator.deviceMemory < 2;
        }
        return false;
    }
    
    _checkSlowNetwork() {
        if (this.networkInfo) {
            const slowConnections = ['slow-2g', '2g', '3g'];
            return slowConnections.includes(this.networkInfo.effectiveType);
        }
        return false;
    }
    
    _checkLowBattery() {
        if (this.batteryInfo) {
            return this.batteryInfo.level < 0.2; // Less than 20%
        }
        return false;
    }
    
    _checkReducedMotion() {
        return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    
    /**
     * Get performance recommendations
     */
    getPerformanceRecommendations() {
        const recommendations = [];
        
        if (this.isLowEndDevice()) {
            recommendations.push({
                type: 'disable-animations',
                priority: 'high',
                message: 'Disable animations for better performance'
            });
            
            recommendations.push({
                type: 'reduce-widget-count',
                priority: 'high',
                message: 'Show fewer widgets simultaneously'
            });
        }
        
        if (this._checkSlowNetwork()) {
            recommendations.push({
                type: 'enable-offline-mode',
                priority: 'medium',
                message: 'Enable offline mode for cached data'
            });
            
            recommendations.push({
                type: 'reduce-update-frequency',
                priority: 'medium',
                message: 'Reduce real-time update frequency'
            });
        }
        
        if (this._checkLowBattery()) {
            recommendations.push({
                type: 'disable-auto-refresh',
                priority: 'low',
                message: 'Disable auto-refresh to save battery'
            });
        }
        
        return recommendations;
    }
    
    /**
     * Apply performance optimizations
     */
    applyOptimizations(options = {}) {
        const defaults = {
            disableAnimations: false,
            reduceQuality: false,
            enableLazyLoad: true,
            limitWidgets: false,
            ...options
        };
        
        if (defaults.disableAnimations || this._checkReducedMotion()) {
            document.body.classList.add('no-animations');
        }
        
        if (defaults.reduceQuality || this.isLowEndDevice()) {
            document.body.classList.add('reduced-quality');
        }
        
        if (defaults.enableLazyLoad) {
            document.body.classList.add('lazy-load-enabled');
        }
        
        if (defaults.limitWidgets) {
            document.body.classList.add('limited-widgets');
        }
        
        return defaults;
    }
    
    /**
     * Monitor FPS
     */
    _startPerformanceMonitoring() {
        let lastTime = performance.now();
        let frames = 0;
        
        const measureFPS = () => {
            frames++;
            const currentTime = performance.now();
            
            if (currentTime >= lastTime + 1000) {
                this.performanceMetrics.fps = Math.round((frames * 1000) / (currentTime - lastTime));
                frames = 0;
                lastTime = currentTime;
            }
            
            this.requestAnimationFrame(measureFPS);
        };
        
        this.requestAnimationFrame(measureFPS);
    }
    
    /**
     * Get current performance metrics
     */
    getMetrics() {
        const metrics = {
            ...this.performanceMetrics,
            networkType: this.networkInfo?.effectiveType || 'unknown',
            batteryLevel: this.batteryInfo?.level || 1,
            deviceMemory: navigator.deviceMemory || 'unknown',
        };
        
        // Add memory usage if available
        if (performance.memory) {
            metrics.memoryUsage = Math.round(
                (performance.memory.usedJSHeapSize / performance.memory.jsHeapSizeLimit) * 100
            );
        }
        
        return metrics;
    }
    
    /**
     * Network change handler
     */
    _onNetworkChange() {
        const event = new CustomEvent('network-change', {
            detail: {
                effectiveType: this.networkInfo.effectiveType,
                downlink: this.networkInfo.downlink,
            }
        });
        window.dispatchEvent(event);
    }
    
    /**
     * Battery change handler
     */
    _onBatteryChange() {
        const event = new CustomEvent('battery-change', {
            detail: {
                level: this.batteryInfo.level,
                charging: this.batteryInfo.charging,
            }
        });
        window.dispatchEvent(event);
    }
    
    /**
     * Cleanup
     */
    destroy() {
        // Clean up observers
        this.observers.forEach(observer => observer.disconnect());
        this.observers.clear();
        
        // Cancel pending callbacks
        this.rafCallbacks.forEach(handle => this.cancelAnimationFrame(handle));
        this.rafCallbacks.clear();
        
        this.idleCallbacks.forEach(handle => this.cancelIdleCallback(handle));
        this.idleCallbacks.clear();
    }
}

// Export singleton instance
export const mobilePerformanceService = new MobilePerformanceService();