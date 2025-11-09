# Base Normativa Nómina Chile

Este directorio centraliza conocimiento regulatorio para cálculos laborales en Chile.

## Contenido previsto
- Topes imponibles (AFP, Salud, Seguro Cesantía) con vigencias.
- UF / UTM: definición, fuente oficial y actualización.
- Tabla de Impuesto Único / Segunda Categoría (tramos, tasas, factor rebaja).
- Cotización adicional SIS.
- Retenciones Boletas Honorarios y transición porcentual.
- Indicadores previsionales mensuales (Fuente: Previred / Superintendencia).
- Fórmulas de cálculo y referencias legales.

## Estructura sugerida
```
nomina/
  tope_imponible_afp.md
  tope_imponible_salud.md
  impuesto_unico_tramos.md
  uf_utm_definicion.md
  seguro_cesantia.md
  sis_cotizacion.md
  retencion_honorarios.md
  indicadores_previred_2025.md
```

## Fuente de Datos
- Previred (publicaciones mensuales).
- SII (tablas de impuesto y UTM).
- Superintendencia de Pensiones (topes y tasas).

## Actualización
1. Descargar fuentes oficiales.
2. Validar vigencias (`valid_from`, `valid_until`).
3. Actualizar modelos paramétricos en Odoo.
4. Registrar cambio en CHANGELOG Nómina.

## Próximos pasos
- Crear archivos base por cada tópico.
- Integrar scraper/loader (`previred_scraper.py`) para ingestión automatizada.
- Añadir tests que verifiquen existencia de indicadores vigentes para la fecha actual.
