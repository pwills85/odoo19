# 🔨 CERRAR BRECHA (Iterativo con Retroalimentación)

**Versión:** 1.0.0  
**Nivel:** P2  
**Propósito:** Ejecutar fix para una brecha específica, validar, y reintentar si falla

---

## 📋 CONTEXTO

Has recibido una brecha específica a cerrar. Tu tarea es:

1. **Analizar** la brecha y contexto del código
2. **Consultar memoria** para fixes similares exitosos
3. **Aplicar fix** según método definido
4. **Validar** que el fix cierra la brecha
5. **Reintentar** con estrategia ajustada si falla

**Modo iterativo:** Tienes un número máximo de intentos según prioridad:
- P0: {MAX_ITER_P0} intentos
- P1: {MAX_ITER_P1} intentos
- P2: {MAX_ITER_P2} intentos

---

## 🎯 INPUT

```json
{
  "brecha": {
    "id": "P0-001",
    "prioridad": "P0",
    "tipo": "deprecacion_t_esc",
    "descripcion": "12 ocurrencias de t-esc en views (deprecated)",
    "archivo": "views/account_move_views.xml",
    "linea": 125,
    "metodo_fix": "regex_replace",
    "patron_fix": "s/t-esc=\"/t-out=\"/g",
    "validacion": "grep -r 't-esc' views/ | wc -l == 0"
  },
  "intento_actual": 1,
  "max_intentos": 5,
  "fix_similar_previo": "{MEMORIA_DIR}/fixes_exitosos/20251110_fix_t_esc.json",
  "modificacion_codigo_permitida": "con_restricciones"
}
```

---

## 🎯 INSTRUCCIONES

### 1. ANALIZAR CONTEXTO CÓDIGO

Antes de aplicar fix, examina:

```bash
# Leer archivo afectado
cat {ARCHIVO} | grep -A 5 -B 5 {LINEA}

# Entender contexto (modelo, vista, función)
head -50 {ARCHIVO}

# Verificar imports/dependencias
grep -E "^import|^from" {ARCHIVO}
```

**Preguntas clave:**
- ¿Es fix simple (regex) o requiere refactor?
- ¿Hay dependencias en otros archivos?
- ¿Existen tests para validar?

---

### 2. CONSULTAR MEMORIA INTELIGENTE

Lee fix similar previo (si existe):

```bash
cat {FIX_SIMILAR_PREVIO} | jq .
```

Extrae:
- **Estrategia exitosa** usada
- **Archivos modificados**
- **Comandos ejecutados**
- **Validación aplicada**

**Si estrategia previa existe:** Reutilízala tal cual.  
**Si no existe:** Procede con método definido en brecha.

---

### 3. APLICAR FIX SEGÚN MÉTODO

#### Método A: Regex Replace (complejidad baja)

```bash
# Backup
cp {ARCHIVO} {ARCHIVO}.bak

# Aplicar regex
sed -i '' '{PATRON_FIX}' {ARCHIVO}

# Verificar cambios
diff {ARCHIVO}.bak {ARCHIVO}
```

#### Método B: Refactor Manual (complejidad media)

```python
# Ejemplo: Reemplazar self._cr por self.env.cr

# 1. Leer archivo
with open('{ARCHIVO}', 'r') as f:
    content = f.read()

# 2. Aplicar transformación
content_fixed = content.replace('self._cr', 'self.env.cr')

# 3. Validar sintaxis
compile(content_fixed, '{ARCHIVO}', 'exec')

# 4. Escribir
with open('{ARCHIVO}', 'w') as f:
    f.write(content_fixed)
```

#### Método C: Rediseño Arquitectónico (complejidad alta)

**STOP:** Si la brecha requiere rediseño arquitectónico:

1. **Solicitar aprobación manual** (si `NIVEL_AUTONOMIA != full_autonomous`)
2. **Generar plan detallado** antes de modificar
3. **Aplicar cambios incrementales** (archivo por archivo)
4. **Validar tras cada cambio**

---

### 4. VALIDAR FIX APLICADO

Ejecuta validación definida en brecha:

```bash
# Ejemplo: Validar que t-esc ya no existe
OCURRENCIAS=$(grep -r 't-esc' {ARCHIVO} | wc -l)

if [ $OCURRENCIAS -eq 0 ]; then
  echo "✅ Fix validado: t-esc eliminado"
  exit 0
else
  echo "❌ Fix falló: quedan $OCURRENCIAS ocurrencias"
  exit 1
fi
```

**Validaciones adicionales:**

1. **Sintaxis válida:**
   ```bash
   python -m py_compile {ARCHIVO}  # Para Python
   xmllint --noout {ARCHIVO}       # Para XML
   ```

2. **Tests pasan:**
   ```bash
   pytest tests/test_relacionado.py -v
   ```

3. **No se rompió nada:**
   ```bash
   # Smoke test básico
   odoo-bin -c config/odoo.conf --test-enable --stop-after-init
   ```

---

### 5. MANEJO ERRORES Y REINTENTOS

#### Si validación falla:

```json
{
  "resultado": "FALLO",
  "intento": 1,
  "error": "Quedan 3 ocurrencias de t-esc en archivo",
  "causa_raiz": "Regex no cubrió casos con comillas simples",
  "estrategia_ajustada": "Ampliar regex para cubrir t-esc='' y t-esc=\"\"",
  "siguiente_intento": {
    "metodo": "regex_replace_mejorado",
    "patron": "s/t-esc=['\"][^'\"]*['\"]/t-out=\\1/g"
  }
}
```

**Estrategia reintento:**

1. **Intento 1:** Aplicar método original
2. **Intento 2:** Ampliar patrón regex
3. **Intento 3:** Refactor manual línea por línea
4. **Intento 4:** Consultar memoria para estrategias alternativas
5. **Intento 5:** Solicitar intervención manual

**Importante:** Guardar cada intento fallido en memoria (estrategias_fallidas).

---

### 6. GUARDAR EN MEMORIA (Si éxito)

Al cerrar brecha exitosamente:

```bash
# Guardar fix exitoso
cat > {MEMORIA_DIR}/fixes_exitosos/{TIMESTAMP}_{BRECHA_ID}.json << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "brecha_id": "{BRECHA_ID}",
  "tipo": "{TIPO_BRECHA}",
  "descripcion": "{DESCRIPCION}",
  "fix": {
    "estrategia": "{ESTRATEGIA_USADA}",
    "metodo": "{METODO}",
    "patron": "{PATRON}",
    "archivos_modificados": ["{ARCHIVO}"],
    "lineas_cambiadas": 12,
    "intentos_necesarios": 1
  },
  "validacion": {
    "comando": "{COMANDO_VALIDACION}",
    "resultado": "PASS",
    "tests_pasados": 42
  },
  "metricas": {
    "tiempo_resolucion": "15min",
    "complejidad": "baja"
  }
}
EOF

# Actualizar índice
{LIB_DIR}/memoria_inteligente.sh guardar_fix_exitoso_brecha
```

---

## 📊 OUTPUT REQUERIDO

**Archivo JSON:** `fix_{BRECHA_ID}_intento{N}.json`

```json
{
  "resultado": "EXITO" | "FALLO",
  "brecha_id": "P0-001",
  "intento": 1,
  "estrategia_usada": "regex_replace",
  "archivos_modificados": ["views/account_move_views.xml"],
  "cambios_aplicados": {
    "lineas_cambiadas": 12,
    "insertadas": 0,
    "eliminadas": 0,
    "reemplazadas": 12
  },
  "validacion": {
    "sintaxis_valida": true,
    "tests_pasados": true,
    "smoke_test_ok": true,
    "criterio_brecha_cumplido": true
  },
  "errores": [],
  "tiempo_ejecucion": "15min",
  "memoria_guardada": "{MEMORIA_DIR}/fixes_exitosos/20251112_P0_001.json"
}
```

**Si fallo:**

```json
{
  "resultado": "FALLO",
  "brecha_id": "P0-001",
  "intento": 1,
  "estrategia_usada": "regex_replace",
  "error": "Quedan 3 ocurrencias de t-esc",
  "causa_raiz": "Regex no cubrió casos con comillas simples",
  "archivos_modificados": [],
  "rollback": "EJECUTADO",
  "estrategia_siguiente": "regex_replace_mejorado",
  "patron_siguiente": "s/t-esc=['\\\"][^'\\\"]*['\\\"][\\s]*//t-out=\\1/g",
  "memoria_guardada": "{MEMORIA_DIR}/estrategias_fallidas/20251112_P0_001_intento1.json"
}
```

---

## ✅ CRITERIOS ÉXITO

1. ✅ Fix aplicado correctamente
2. ✅ Validación sintaxis PASS
3. ✅ Tests relacionados PASS
4. ✅ Criterio brecha cumplido (0 ocurrencias)
5. ✅ Guardado en memoria inteligente
6. ✅ Rollback ejecutado si fallo

---

## 🚫 RESTRICCIONES

Según `MODIFICACION_CODIGO_PERMITIDA`:

### `con_restricciones`:
- ✅ Modificar archivos existentes
- ✅ Agregar imports/docstrings
- ❌ Crear nuevos módulos
- ❌ Eliminar módulos/archivos
- ❌ Modificar `__manifest__.py` sin aprobación

### `solo_fixes_simples`:
- ✅ Regex replace
- ✅ Formateo (black, isort)
- ❌ Refactor multi-archivo
- ❌ Cambios arquitectónicos

### `solo_generar`:
- ❌ NO aplicar cambios
- ✅ Generar diff/patch
- ✅ Reportar cambios sugeridos

---

## 🔄 RETROALIMENTACIÓN

**Tras cada intento:**

1. **Log detallado** en `{OUTPUTS_DIR}/{SESSION_ID}_fix_{BRECHA_ID}.log`
2. **Actualizar estado** brecha en plan de cierre
3. **Si fallo:** Ajustar estrategia y reintentar
4. **Si éxito:** Marcar brecha como CERRADA y continuar

**Si agotas intentos:**

- Reportar brecha como **NO CERRADA**
- Guardar en memoria (estrategia_fallida)
- Solicitar intervención manual (si no `full_autonomous`)

---

**🔨 Procede con máxima precisión. Valida cada cambio. Aprende de errores.**

