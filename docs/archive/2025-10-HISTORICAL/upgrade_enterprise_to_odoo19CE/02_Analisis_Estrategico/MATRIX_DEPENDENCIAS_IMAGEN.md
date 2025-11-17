# Matriz de Dependencias Técnicas de la Imagen Odoo 19 CE-Pro

Fecha: 2025-11-08  
Autor: Ingeniería Senior  
Estado: Borrador inicial

## 1) Propósito

Documentar todas las dependencias del entorno (sistema, Python, Node, herramientas de build, librerías externas) necesarias para soportar los micro-módulos Phoenix (UI) y Quantum (reportería) con calidad enterprise. Servirá para validar la imagen Docker y definir políticas de versionado y actualización.

## 2) Alcance

Incluye dependencias de:

- Sistema base (OS, locales, fuentes)
- Python (paquetes Odoo + libs auxiliares)
- Node / build frontend
- Generación de reportes (PDF/XLSX)
- Performance / cache / queue
- Observabilidad / monitoreo
- Seguridad / validación

## 3) Tabla Resumen (Completar)

| Categoría            | Paquete / Herramienta     | Versión Objetivo | Versión Actual | Criticidad | Uso Principal                                | Política Actualización | Observaciones |
|----------------------|---------------------------|------------------|----------------|------------|----------------------------------------------|------------------------|--------------|
| Sistema              | Ubuntu/Debian Base        | 22.04 LTS        |                | Alta       | Compatibilidad general                       | LTS anual              |              |
| Sistema              | tzdata / locales es_CL    | latest           |                | Alta       | Formatos fecha/num Chile                     | Semestral              |              |
| Sistema              | Fuentes (DejaVu/Inter)    | latest           |                | Media      | PDF/XLSX tipografía                          | Cuando haya cambios    |              |
| Python               | odoo==19.x                | pinned           |                | Alta       | Core ERP                                     | Parche crítico / minor |              |
| Python               | psycopg2 / pg8000         | latest stable    |                | Alta       | Conexión Postgres                            | Minor stable           |              |
| Python               | xlsxwriter                | >=3.x            |                | Alta       | Export XLSX                                  | Minor stable           |              |
| Python               | weasyprint (opcional)     | >=60             |                | Media      | Export PDF alternativa                       | Evaluar trimestral     |              |
| Python               | pillow                     | latest           |                | Baja       | Logos / imágenes en reportes                 | Minor stable           |              |
| Python               | babel                      | latest           |                | Alta       | Localización / formatos                      | Minor stable           |              |
| Python               | passlib                    | latest           |                | Media      | Seguridad / hashing                          | Minor stable           |              |
| Python               | redis (lib)                | latest           |                | Alta       | Cache externa                                | Minor stable           |              |
| Node                 | nodejs                     | 18.x LTS         |                | Alta       | Build OWL / assets                           | LTS + security patches |              |
| Node                 | npm / pnpm                 | latest LTS       |                | Media      | Gestión dependencias frontend                | LTS                    |              |
| Node                 | sass (dart-sass)           | latest           |                | Alta       | Compilación SCSS                             | Minor stable           |              |
| Node                 | rtlcss                     | latest           |                | Baja       | Estilos RTL (opcional)                       | On demand              |              |
| Reportes             | wkhtmltopdf                | 0.12.5 patched   |                | Alta       | PDF QWeb                                     | Fijado, cambios control|              |
| Cache / Cola         | redis-server               | 6.x stable       |                | Alta       | Cache reportes + sesiones                    | Minor stable           |              |
| Cache / Cola         | rabbitmq (opcional)        | 3.13.x           |                | Media      | Jobs diferidos / colas                       | Minor stable           |              |
| Observabilidad       | prometheus client python   | latest           |                | Media      | Métricas                                     | Minor stable           |              |
| Observabilidad       | grafana                    | latest LTS       |                | Media      | Dashboards métricas                           | LTS                    |              |
| Observabilidad       | newrelic/elastic (opcional)| latest           |                | Baja       | APM / tracing                                | On demand              |              |
| Seguridad            | openssl                    | latest           |                | Alta       | TLS / cifrado                                | Security patches       |              |
| Seguridad            | vault (opcional)           | latest           |                | Media      | Gestión secretos                              | Minor stable           |              |

## 4) Políticas de Versionado

- Core Odoo: fijado a versión mayor 19.x; sólo subir tras validación regresiva (tests + reportería).
- wkhtmltopdf: Fijar build estable; cualquier cambio exige validación visual PDF (snapshot diff) en 5 reportes.
- node / sass: actualizar sólo para parches seguridad o features imprescindibles (macros SCSS, performance build).
- redis / rabbitmq: mantener versiones estables, sin upgrades mayores en medio de sprints críticos.

## 5) Checklist de Validación en Imagen Actual

- [ ] Odoo 19.x instalado y accesible.
- [ ] Postgres versión soportada (≥14) y parámetros tuning (work_mem, shared_buffers) revisados.
- [ ] wkhtmltopdf render correcto (sin cortes, fuentes incrustadas).
- [ ] xlsxwriter genera archivo con estilos básicos.
- [ ] Redis accesible y TTLs configurados para cache reportes.
- [ ] Node 18.x presente (node -v).
- [ ] sass compila theme_ce_core sin warnings.
- [ ] Fuentes personalizadas disponibles en contenedor (ls /usr/share/fonts/...).
- [ ] Prometheus endpoint expone métricas básicas (latencias dummy).

## 6) Gaps / Acciones Pendientes

| Gap | Impacto | Acción | Responsable | Fecha objetivo |
|-----|---------|-------|-------------|----------------|
| Falta validación wkhtmltopdf en contenedor alpine | Media | Probar rendering PDF 5 reportes | Dev Backend | YYYY-MM-DD |
| No definido TTL cache reportes | Alta | Proponer TTL 15m + invalidación movimientos | Arquitecto | YYYY-MM-DD |
| Falta dataset sintético finanzas | Alta | Crear script generación (10k apuntes) | Dev Backend | YYYY-MM-DD |
| Falta monitoreo base métricas | Media | Añadir prometheus_client a motor reportes | Dev Backend | YYYY-MM-DD |

## 7) Riesgos y Mitigaciones

| Riesgo | Prob | Impacto | Mitigación | Estado |
|--------|------|---------|-----------|--------|
| wkhtmltopdf inconsistencias | Media | Alto | Fijar versión y pruebas snapshot | Abierto |
| Latencias altas en drill-down | Media | Alto | Cache + índices + paginación | Abierto |
| Falta de aislamiento clean-room en build assets | Baja | Medio | Revisar origen de estilos y escaneo tokens | Abierto |
| Cambios no controlados en dependencias Node | Baja | Medio | Lockfile audit y CI pipeline | Abierto |

## 8) Aprobación

- Responsable Técnico: __________ Fecha: __________
- Revisión Seguridad: __________ Fecha: __________

---
