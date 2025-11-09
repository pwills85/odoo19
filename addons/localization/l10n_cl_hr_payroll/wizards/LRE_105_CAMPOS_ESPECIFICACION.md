# LRE Previred - Especificación 105 Campos
## Dirección del Trabajo Chile - Formato Oficial

**Fecha:** 2025-11-07
**Referencia:** DT Circular 1 - Formato LRE Previred
**Fuente Oficial:** https://www.previred.com/documents/80476/80730/FormatoLargoVariablePorSeparador.pdf
**Brecha P0-2:** Implementar 76 campos faltantes (29 → 105 campos)

---

## Estructura Actual (29 campos implementados)

### ✅ Sección A: Datos Empresa (10 campos)
1. RUT_EMPLEADOR
2. PERIODO (YYYYMM)
3. NOMBRE_EMPRESA
4. DIRECCION_EMPRESA
5. COMUNA_EMPRESA
6. CIUDAD_EMPRESA
7. TELEFONO_EMPRESA
8. EMAIL_EMPRESA
9. ACTIVIDAD_ECONOMICA
10. REGIMEN_PREVISIONAL

### ✅ Sección B: Datos Trabajador (19 campos)
11. RUT_TRABAJADOR
12. DV_TRABAJADOR
13. APELLIDO_PATERNO
14. APELLIDO_MATERNO
15. NOMBRES
16. FECHA_NACIMIENTO
17. SEXO
18. NACIONALIDAD
19. DIRECCION_TRABAJADOR
20. COMUNA_TRABAJADOR
21. CIUDAD_TRABAJADOR
22. FECHA_INGRESO
23. FECHA_TERMINO (si aplica)
24. TIPO_CONTRATO
25. JORNADA_TRABAJO
26. CARGO
27. CODIGO_AFP
28. CODIGO_SALUD
29. CARGAS_FAMILIARES

---

## Estructura Faltante (76 campos a implementar)

### ❌ Sección C: Remuneraciones Imponibles Detalladas (15 campos)
**Criticidad:** ALTA - Base para cálculos previsionales

30. SUELDO_BASE
31. HORAS_EXTRAS
32. COMISIONES
33. SEMANA_CORRIDA
34. PARTICIPACION
35. GRATIFICACION_MENSUAL
36. AGUINALDO
37. BONO_PRODUCCION
38. REEMPLAZO_FERIADO
39. REEMPLAZO_PERMISO
40. TURNOS
41. REMUNERACION_VARIABLE_1
42. REMUNERACION_VARIABLE_2
43. OTROS_IMPONIBLES
44. **TOTAL_HABERES_IMPONIBLES** (suma validada)

### ❌ Sección D: Descuentos Legales (12 campos)
**Criticidad:** ALTA - Obligatorios por ley

45. COTIZACION_AFP
46. COMISION_AFP
47. COTIZACION_SALUD (FONASA 7% o ISAPRE pactado)
48. ADICIONAL_ISAPRE_UF
49. SEGURO_CESANTIA_TRABAJADOR (0.6%)
50. IMPUESTO_UNICO
51. OTROS_DESCUENTOS_LEGALES_1
52. OTROS_DESCUENTOS_LEGALES_2
53. OTROS_DESCUENTOS_LEGALES_3
54. PRESTAMO_EMPRESA
55. ANTICIPO_SUELDO
56. **TOTAL_DESCUENTOS_LEGALES** (suma validada)

### ❌ Sección E: Descuentos Voluntarios (8 campos)
**Criticidad:** MEDIA - Frecuentes en empresas

57. APV_REGIMEN_A
58. APV_REGIMEN_B
59. APVC (Ahorro Previsional Colectivo)
60. DEPOSITO_CONVENIDO
61. SEGURO_VIDA_VOLUNTARIO
62. CUOTA_SINDICAL
63. CAJA_COMPENSACION
64. **TOTAL_DESCUENTOS_VOLUNTARIOS**

### ❌ Sección F: Haberes No Imponibles (10 campos)
**Criticidad:** ALTA - Afectan cálculo líquido pero no cotizaciones

65. ASIGNACION_FAMILIAR
66. ASIGNACION_MOVILIZACION
67. ASIGNACION_COLACION
68. ASIGNACION_DESGASTE_HERRAMIENTAS
69. ASIGNACION_PERDIDA_CAJA
70. VIATICOS
71. ASIGNACION_ZONA_EXTREMA
72. BONOS_NO_IMPONIBLES
73. OTROS_NO_IMPONIBLES
74. **TOTAL_HABERES_NO_IMPONIBLES**

### ❌ Sección G: Otros Movimientos (18 campos)
**Criticidad:** MEDIA-ALTA - Eventos especiales

75. LICENCIA_MEDICA_DIAS
76. LICENCIA_MEDICA_MONTO
77. SUBSIDIO_INCAPACIDAD_LABORAL
78. SUBSIDIO_MATERNAL
79. VACACIONES_PROGRESIVAS_DIAS
80. VACACIONES_PROPORCIONALES_DIAS
81. INDEMNIZACION_AÑOS_SERVICIO
82. INDEMNIZACION_AVISO_PREVIO
83. INDEMNIZACION_VOLUNTARIA
84. GRATIFICACION_LEGAL_ANUAL
85. AGUINALDO_FIESTAS_PATRIAS
86. AGUINALDO_NAVIDAD
87. BONO_TERMINO_CONFLICTO
88. FINIQUITO_OTROS_CONCEPTOS
89. ATRASOS_DESCUENTO
90. INASISTENCIAS_DESCUENTO
91. PERMISOS_SIN_GOCE
92. **TOTAL_OTROS_MOVIMIENTOS**

### ❌ Sección H: Aportes Empleador (13 campos)
**Criticidad:** ALTA - Reforma 2025 SOPA

93. SEGURO_CESANTIA_EMPLEADOR (2.4%)
94. SEGURO_ACCIDENTES_TRABAJO (0.93% base)
95. ADICIONAL_RIESGO_EMPRESA
96. APORTE_SOLIDARIO_AFP (según tramos Reforma 2025)
97. COTIZACION_ESPERANZA_VIDA (según tramos Reforma 2025)
98. APORTE_SOPA_BASE
99. APORTE_SOPA_PROGRESIVO
100. INDEMNIZACION_EMPLEADOR_AÑO
101. MUTUAL_SEGURIDAD
102. CAJA_COMPENSACION_EMPLEADOR
103. OTROS_APORTES_EMPLEADOR
104. **TOTAL_APORTES_EMPLEADOR**
105. **ALCANCE_LIQUIDO_FINAL** (validación total)

---

## Validaciones Críticas DT

### Validación 1: Suma Total Imponible
```
TOTAL_HABERES_IMPONIBLES =
  SUELDO_BASE + HORAS_EXTRAS + COMISIONES + ... + OTROS_IMPONIBLES
```

### Validación 2: Tope Imponible AFP
```
BASE_COTIZACION_AFP = min(TOTAL_HABERES_IMPONIBLES, 83.1_UF * UF_VALOR_MES)
```

### Validación 3: Cálculo Impuesto Único
```
BASE_IMPONIBLE_IMPUESTO = TOTAL_HABERES_IMPONIBLES - COTIZACION_AFP - APV_REGIMEN_A
```

### Validación 4: Alcance Líquido
```
ALCANCE_LIQUIDO_FINAL =
  TOTAL_HABERES_IMPONIBLES
  + TOTAL_HABERES_NO_IMPONIBLES
  - TOTAL_DESCUENTOS_LEGALES
  - TOTAL_DESCUENTOS_VOLUNTARIOS
```

### Validación 5: Formato Campos
- **RUT**: 8-9 dígitos sin puntos, separado DV
- **Montos**: Enteros, sin decimales
- **Fechas**: YYYYMMDD
- **Códigos AFP**: 03-35 (según tabla oficial)
- **Códigos ISAPRE**: 01-99 (según tabla oficial)

---

## Referencias Legales

| Campo | Normativa |
|-------|-----------|
| AFP | Ley 20.255 Art. 17 |
| Salud | DFL N°1 (2005) Art. 70 |
| Seguro Cesantía | Ley 19.728 Art. 5-8 |
| Impuesto Único | DL 824 Art. 42-52 |
| SOPA 2025 | Ley Reforma Previsional 2025 |
| Gratificación | Código del Trabajo Art. 47 |
| Indemnizaciones | Código del Trabajo Art. 163 |
| Asignación Familiar | Ley 18.020 |

---

## Plan de Implementación

### Fase 1: Secciones C y D (Prioritarias - 4 horas)
- ✅ 27 campos críticos
- Validación topes imponibles
- Tests unitarios

### Fase 2: Secciones E y F (2 horas)
- ✅ 18 campos frecuentes
- Haberes no imponibles
- Tests edge cases

### Fase 3: Secciones G y H (2 horas)
- ✅ 31 campos especiales
- Aportes empleador SOPA 2025
- Validación integral

**Total estimado:** 8 horas desarrollo + 2 horas tests = **10 horas**

---

## Archivo Resultado

**Formato:** CSV (delimitador: `;`)
**Encoding:** UTF-8
**Nombre:** `LRE_[RUT_EMPLEADOR]_[YYYYMM].csv`
**Tamaño estimado:** ~5KB por empleado x mes

**Ejemplo línea completa (105 campos):**
```
111111111;202501;12345678;9;PEREZ;GONZALEZ;JUAN;...;500000;50000;0;...;1200000;60000;84000;40000;...;980000
```

---

**Última actualización:** 2025-11-07
**Responsable:** Dev Team
**Estado:** P0-2 en implementación
