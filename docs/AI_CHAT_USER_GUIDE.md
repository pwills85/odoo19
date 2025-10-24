# Guía de Usuario - Asistente IA para DTE

**Versión**: 1.0
**Fecha**: 2025-10-22
**Audiencia**: Usuarios finales, Contadores, Administradores

---

## 📋 Tabla de Contenidos

1. [Introducción](#introducción)
2. [Acceso al Asistente](#acceso-al-asistente)
3. [Interfaz de Usuario](#interfaz-de-usuario)
4. [Casos de Uso Comunes](#casos-de-uso-comunes)
5. [Mejores Prácticas](#mejores-prácticas)
6. [Limitaciones](#limitaciones)
7. [Troubleshooting](#troubleshooting)

---

## Introducción

### ¿Qué es el Asistente IA DTE?

El **Asistente IA DTE** es un chatbot conversacional especializado en **Facturación Electrónica Chilena** integrado directamente en Odoo 19. Está diseñado para ayudar a los usuarios con:

- ✅ Generación de DTEs (tipos 33, 34, 52, 56, 61)
- ✅ Gestión de certificados digitales y CAF
- ✅ Operación en modo contingencia
- ✅ Resolución de errores comunes del SII
- ✅ Consultas sobre compliance y normativa chilena

### Tecnología

El asistente utiliza:
- **LLM Principal**: Anthropic Claude 3.5 Sonnet
- **LLM Fallback**: OpenAI GPT-4 Turbo
- **Base de Conocimiento**: 7 documentos especializados en DTE
- **Contexto**: Conversaciones con memoria (hasta 10 mensajes)

---

## Acceso al Asistente

### Opción 1: Desde el Menú Principal

1. Vaya a **Contabilidad** → **Facturación Electrónica** → **🤖 Asistente IA**
2. Se abrirá una ventana modal con el chat

![Menú Principal](./screenshots/ai-chat-menu.png)

### Opción 2: Desde una Factura (Contexto)

1. Abra cualquier **Factura**, **Nota de Crédito** o **Nota de Débito**
2. Click en el botón **🤖 Ayuda IA** en la parte superior
3. El asistente se abrirá con **contexto automático** de la factura actual

![Botón en Factura](./screenshots/ai-chat-invoice-button.png)

**Ventaja**: El asistente conoce automáticamente:
- Tipo de documento (factura/NC/ND)
- Cliente/Proveedor
- Monto total
- Estado DTE (si aplica)

### Opción 3: Desde Otras Operaciones DTE

El botón **🤖 Ayuda IA** también está disponible en:
- **Liquidación de Honorarios** (DTE 34)
- **Guías de Despacho** (DTE 52)

---

## Interfaz de Usuario

### Pantalla Principal

La interfaz del chat tiene 3 secciones principales:

#### 1. Header - Información de Sesión

```
🤖 Asistente IA - Soporte DTE
Asistente especializado en Facturación Electrónica Chilena

┌─────────────────────────────────────────┐
│ Información de Sesión                   │
├─────────────────────────────────────────┤
│ Session ID: abc123...                   │
│ Mensajes: 5                             │
│ LLM: anthropic                          │
└─────────────────────────────────────────┘
```

#### 2. Pestaña "Conversación"

**Historial de Conversación**:
- Muestra todos los mensajes intercambiados
- Código de colores:
  - 🔵 Azul: Tus mensajes
  - 🟢 Verde: Respuestas del asistente
- Scroll automático a mensaje más reciente

**Campo de Entrada**:
```
┌─────────────────────────────────────────┐
│ Escribe tu pregunta aquí...             │
│ (ej: ¿Cómo genero un DTE 33?)           │
└─────────────────────────────────────────┘
```

**Botones de Acción**:
- **📤 Enviar Mensaje**: Enviar y obtener respuesta
- **🔄 Nueva Conversación**: Limpiar historial y empezar de nuevo
- **Cerrar**: Cerrar el chat

#### 3. Pestaña "Información"

**Mensaje de Bienvenida**: Saludo personalizado del asistente

**Fuentes Consultadas**: Lista de documentación utilizada para responder

**💡 Ejemplos de Preguntas**: Categorías de consultas con ejemplos

**ℹ️ Acerca del Asistente**: Capacidades y limitaciones

---

## Casos de Uso Comunes

### 1. Generación de Factura Electrónica (DTE 33)

**Pregunta**:
```
¿Cómo genero una factura electrónica DTE 33?
```

**Respuesta esperada**:
```
Para generar una Factura Electrónica (DTE 33) en Odoo, sigue estos pasos:

1. **Crear Factura**
   - Ve a Contabilidad → Clientes → Facturas
   - Click en "Crear"
   - Selecciona Cliente (con RUT válido)

2. **Configurar Tipo de Documento**
   - En el campo "Tipo de Documento", selecciona "33 - Factura Electrónica"
   - Verifica que el Diario tenga folios CAF disponibles

3. **Completar Datos**
   - Agrega líneas de factura (productos/servicios)
   - Verifica impuestos (IVA 19% en Chile)
   - Confirma totales

4. **Generar DTE**
   - Click en botón "Generar DTE"
   - El sistema creará el XML, lo firmará y enviará al SII
   - Espera confirmación (aprox. 30 segundos)

5. **Verificar Estado**
   - Estado DTE debe cambiar a "Aceptado"
   - Descarga PDF timbrado para entregar al cliente

📚 Fuentes: DTE Generation Wizard, DTE Types
```

### 2. Operación en Modo Contingencia

**Pregunta**:
```
¿Qué hago si el SII está caído y necesito facturar?
```

**Respuesta esperada**:
```
Si el SII no responde, puedes operar en **Modo Contingencia**:

⚠️ **Importante**: Solo usar cuando SII realmente esté inaccesible.

**Pasos**:

1. **Activar Contingencia**
   - Ve a Configuración → Facturación Electrónica
   - Activa "Modo Contingencia"
   - Registra razón (ej: "SII sin respuesta")

2. **Generar DTEs Normalmente**
   - Los DTEs se generan y almacenan localmente
   - Estado: "Contingencia - Pendiente de Envío"
   - Puedes imprimir PDF (marca de agua "CONTINGENCIA")

3. **Cuando SII se Recupere**
   - Ve a Facturación Electrónica → DTEs en Contingencia
   - Selecciona DTEs a enviar
   - Click en "Enviar al SII"
   - Sistema enviará en lote

4. **Límites**
   - Máximo 7 días en contingencia
   - Debes enviar dentro de ese plazo
   - Notifica a clientes del estado

📚 Fuentes: Contingency Mode
```

### 3. Gestión de Folios (CAF)

**Pregunta**:
```
¿Cómo solicito folios al SII?
```

**Respuesta esperada**:
```
Para solicitar un **CAF (Código Autorización Folios)** al SII:

**Requisitos Previos**:
- ✅ Certificado digital instalado en Odoo
- ✅ Actividad económica registrada en SII
- ✅ Autorización de facturación electrónica activa

**Proceso en Portal SII**:

1. **Ingresa a Portal Mipyme**
   - https://mipyme.sii.cl
   - Login con RUT y clave

2. **Solicitar Folios**
   - Menú: "Folios" → "Solicitar Timbraje"
   - Selecciona tipo DTE (ej: 33 - Factura)
   - Indica rango (ej: desde 1, cantidad 100)
   - Click "Solicitar"

3. **Descargar CAF**
   - El SII generará archivo .xml
   - Descarga a tu computador
   - Archivo tiene formato: Folio33_1_100.xml

**Cargar en Odoo**:

1. Ve a Contabilidad → Configuración → Folios CAF
2. Click "Crear"
3. Campos:
   - **Tipo DTE**: 33
   - **Rango Desde**: 1
   - **Rango Hasta**: 100
   - **Archivo CAF**: Sube el XML descargado
4. Guardar

✅ **Verificación**:
- Estado debe ser "Vigente"
- Folios disponibles: 100
- Ahora puedes generar DTEs en ese rango

📚 Fuentes: CAF Management
```

### 4. Resolución de Errores

**Pregunta**:
```
Recibí error "Firma inválida" al enviar DTE
```

**Respuesta esperada**:
```
El error **"Firma inválida"** generalmente indica problema con el certificado digital.

**Causas Comunes**:

1. **Certificado Vencido**
   - Verifica fecha de vencimiento
   - Ve a: Configuración → Certificados Digitales
   - Si vencido: Solicita nuevo al SII

2. **Certificado Incorrecto**
   - Debe ser del mismo RUT de la empresa
   - Clase 2 o Clase 3 del SII
   - Formato PKCS#12 (.p12 o .pfx)

3. **Password Incorrecto**
   - Al cargar certificado, ingresaste contraseña correcta?
   - Intenta recargar con password correcto

4. **Algoritmo Obsoleto**
   - SII requiere RSA-SHA1
   - Certificados muy antiguos pueden no ser compatibles

**Solución Paso a Paso**:

1. **Verificar Certificado Actual**
   ```
   Ve a Configuración → Certificados Digitales
   Verifica:
   - Fecha válida ✓
   - RUT coincide con empresa ✓
   - Estado "Activo" ✓
   ```

2. **Re-cargar Certificado**
   - Elimina certificado actual
   - Vuelve a cargar desde archivo .p12
   - Ingresa contraseña cuidadosamente
   - Prueba con DTE de prueba

3. **Si Persiste**
   - Solicita nuevo certificado al SII
   - O contacta soporte técnico con:
     - Mensaje error completo
     - Fecha de certificado
     - Tipo de DTE que intentas generar

📚 Fuentes: Error Resolution, Certificate Management
```

### 5. Consulta de Estado DTE

**Pregunta**:
```
¿Cómo consulto si el SII aceptó mi factura?
```

**Respuesta esperada**:
```
Para consultar el estado de un DTE en el SII:

**Opción 1: Desde Odoo (Recomendado)**

1. Ve a la factura/DTE
2. Verifica campo **"Estado DTE"**:
   - 🟢 **Aceptado**: SII aprobó, DTE válido
   - 🔴 **Rechazado**: SII rechazó, ver motivo
   - 🟡 **Reparo**: Aceptado con observaciones
   - ⚪ **Pendiente**: Aún procesando

3. Si estado "Pendiente" > 24 horas:
   - Click botón "Consultar Estado SII"
   - Sistema consultará automáticamente

**Opción 2: Portal SII**

1. Ingresa a https://www4.sii.cl
2. Login con RUT y clave
3. Menú: "Consultas y Certificados" → "Documentos Emitidos"
4. Busca por:
   - Tipo DTE: 33
   - Folio: 123
   - Fecha emisión
5. Verás estado oficial

**Estados Posibles**:

- **ACD (Aceptado)**: ✅ Todo OK
- **RCH (Rechazado)**: ❌ DTE inválido, no tributariamente válido
- **RPR (Reparado)**: ⚠️ Aceptado pero con observaciones menores
- **RSC (Rechazado - Sin Conexión)**: 🔄 Reintenta envío

**Notas**:
- Respuesta SII puede tardar hasta 24 horas
- DTEs rechazados NO generan obligación tributaria
- Debes generar nuevo DTE (no se puede editar)

📚 Fuentes: Query Status, DTE Types
```

---

## Mejores Prácticas

### 1. Formular Preguntas Claras

✅ **Bueno**:
```
¿Cómo configuro mi certificado digital clase 3 en Odoo?
```

❌ **Malo**:
```
certificado
```

**Por qué**: Preguntas completas permiten al asistente entender contexto y dar respuestas precisas.

### 2. Usar Terminología Chilena

✅ **Bueno**:
```
¿Cómo genero una factura afecta (DTE 33)?
```

❌ **Malo**:
```
How do I create an invoice?
```

**Por qué**: El asistente está optimizado para terminología chilena (factura, folio, RUT, SII).

### 3. Aprovechar el Contexto

✅ **Bueno**:
- Abrir chat desde una factura específica
- El asistente conoce automáticamente el contexto

❌ **Malo**:
- Abrir chat desde menú general
- Tener que explicar todos los detalles manualmente

### 4. Hacer Seguimiento en la Misma Sesión

✅ **Bueno**:
```
Usuario: ¿Cómo genero un DTE 33?
Asistente: [Explica pasos]
Usuario: ¿Y si el cliente no tiene RUT?
Asistente: [Responde en contexto de DTE 33]
```

❌ **Malo**:
```
Usuario: ¿Cómo genero un DTE 33?
[Cierra chat, abre nuevo]
Usuario: ¿Y si el cliente no tiene RUT?
Asistente: [No tiene contexto, pregunta qué tipo de DTE]
```

**Por qué**: El asistente recuerda los últimos 10 mensajes de la conversación.

### 5. Consultar Fuentes Citadas

Después de cada respuesta, revisa la sección **"Fuentes Consultadas"**:

```
📚 Fuentes: DTE Generation Wizard, Certificate Management
```

Esto indica qué documentación utilizó el asistente. Si quieres profundizar, menciona la fuente en tu siguiente pregunta:

```
¿Puedes darme más detalles sobre "Certificate Management"?
```

---

## Limitaciones

### ⚠️ El Asistente NO Puede:

1. **Ejecutar Acciones en Odoo**
   - ❌ No puede crear facturas por ti
   - ❌ No puede enviar DTEs al SII
   - ❌ No puede modificar configuraciones
   - ✅ Solo **explica cómo hacerlo**

2. **Acceder a Datos Privados**
   - ❌ No puede ver tus facturas específicas
   - ❌ No puede acceder a RUTs de clientes
   - ✅ Solo conoce datos que tú le proporciones explícitamente

3. **Temas Fuera de DTE**
   - ❌ No responde sobre contabilidad general
   - ❌ No responde sobre inventario/compras (salvo DTE 34, 52)
   - ❌ No responde sobre nómina (salvo retenciones IUE)
   - ✅ Solo **Facturación Electrónica Chilena**

4. **Garantías Legales**
   - ⚠️ Las respuestas son orientativas
   - ⚠️ No sustituyen asesoría contable/legal profesional
   - ⚠️ Siempre verifica con tu contador o SII en caso de duda

### 🕐 Expiración de Sesión

- Las sesiones expiran después de **1 hora de inactividad**
- Cuando expira, se pierde el historial
- Puedes crear una nueva sesión con el botón **🔄 Nueva Conversación**

---

## Troubleshooting

### Problema: "El Asistente IA no está disponible"

**Síntomas**:
```
Error: El Asistente IA no está disponible en este momento.
Estado: unavailable
```

**Soluciones**:

1. **Verificar Servicio**
   - Contacta al administrador del sistema
   - El servicio `ai-service` debe estar corriendo
   - Verifica: `docker-compose ps ai-service`

2. **Verificar Configuración**
   - Ve a Configuración → Facturación Electrónica
   - Sección "AI Service"
   - Click "Probar Conexión"
   - Debe responder: "AI Service está disponible"

### Problema: Respuestas Lentas

**Síntomas**: El asistente tarda > 10 segundos en responder

**Soluciones**:

1. **LLM Fallback Activado**
   - Si Anthropic está lento/caído, usa OpenAI GPT-4
   - Es normal tardar un poco más
   - Verifica campo "LLM Usado" en la interfaz

2. **Red Lenta**
   - El asistente hace llamadas a APIs externas
   - Depende de conexión a internet del servidor
   - Espera pacientemente

### Problema: Respuestas Incorrectas

**Síntomas**: El asistente da información errónea o desactualizada

**Soluciones**:

1. **Reportar al Administrador**
   - La base de conocimiento puede necesitar actualización
   - Contacta a soporte técnico con:
     - Pregunta realizada
     - Respuesta recibida
     - Respuesta esperada

2. **Reformular Pregunta**
   - Intenta ser más específico
   - Usa terminología chilena (DTE, CAF, SII, folio)
   - Menciona número de DTE (33, 34, 52, 56, 61)

### Problema: Sesión se Pierde

**Síntomas**: El historial de conversación desaparece

**Causas**:
- Sesión expiró (> 1 hora inactividad)
- Se cerró la ventana del chat
- Se reinició el navegador

**Solución**:
- Click **🔄 Nueva Conversación** para empezar de nuevo
- El asistente recordará el contexto si abres desde una factura

---

## Soporte Adicional

### Documentación Técnica

Si eres administrador o desarrollador, consulta:

- **AI Service Technical Guide**: `/docs/AI_SERVICE_TRANSFORMATION_PLAN.md`
- **Deployment Guide**: `/docs/AI_CHAT_DEPLOYMENT_GUIDE.md`
- **API Reference**: `http://ai-service:8002/docs` (Swagger)

### Contacto

Para soporte técnico:
- 📧 Email: soporte@eergygroup.com
- 📞 Teléfono: +56 2 XXXX XXXX
- 🌐 Web: https://www.eergygroup.com

---

**Última actualización**: 2025-10-22
**Versión**: 1.0
**Autor**: Eergygroup
**Licencia**: LGPL-3
