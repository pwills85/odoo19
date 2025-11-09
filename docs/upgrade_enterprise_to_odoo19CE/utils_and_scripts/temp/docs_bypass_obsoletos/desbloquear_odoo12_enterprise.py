#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║          🔓 SCRIPT DE DESBLOQUEO ODOO 12 ENTERPRISE                         ║
║                                                                              ║
║  Propósito: Desbloquear instancia de Odoo 12 Enterprise con BBDD vencida   ║
║  Método: Extensión de fecha de expiración via PostgreSQL                    ║
║  Autor: Análisis Técnico Odoo 12                                           ║
║  Fecha: 4 de octubre de 2025                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

INSTRUCCIONES DE USO:
---------------------
1. Editar la sección CONFIGURACIÓN con tus datos de PostgreSQL
2. Ejecutar: python3 desbloquear_odoo12_enterprise.py
3. Cerrar navegador completamente
4. Volver a ingresar a Odoo

REQUISITOS:
-----------
- Python 3.6+
- psycopg2: pip3 install psycopg2-binary
- Acceso a PostgreSQL con permisos de escritura

ADVERTENCIA:
------------
- Este script modifica la base de datos de Odoo
- Hacer backup antes de ejecutar
- Solo para recuperación de emergencia de datos
- Uso prolongado sin licencia puede violar términos de Odoo SA
"""

import psycopg2
from datetime import datetime, timedelta
import sys
import os

# ==================== CONFIGURACIÓN ====================
# ⚠️ MODIFICAR ESTOS VALORES CON TUS DATOS REALES
# =======================================================

DB_CONFIG = {
    'host': 'localhost',           # IP del servidor PostgreSQL
    'port': 5432,                  # Puerto de PostgreSQL (default: 5432)
    'database': 'nombre_db_aqui',  # ⚠️ CAMBIAR: Nombre de tu base de datos Odoo
    'user': 'odoo',                # Usuario PostgreSQL (default: odoo)
    'password': 'tu_password'      # ⚠️ CAMBIAR: Password de PostgreSQL
}

# Configuración de extensión de fecha
EXTENSION_YEARS = 10  # Años a extender (default: 10 años = hasta 2035)
CLEAN_SESSIONS = True  # Limpiar sesiones activas (fuerza re-login)
NEW_REASON = 'demo'    # Nueva razón: 'demo', 'trial', 'valid'

# =======================================================


def print_banner():
    """Muestra banner del script"""
    print("\n" + "="*80)
    print("║" + " "*28 + "🔓 ODOO 12 ENTERPRISE" + " "*29 + "║")
    print("║" + " "*26 + "SCRIPT DE DESBLOQUEO" + " "*32 + "║")
    print("="*80 + "\n")


def verificar_configuracion():
    """Verifica que la configuración sea válida"""
    print("🔍 Verificando configuración...")
    
    errores = []
    
    if DB_CONFIG['database'] == 'nombre_db_aqui':
        errores.append("❌ Debes configurar el nombre de la base de datos")
    
    if DB_CONFIG['password'] == 'tu_password':
        errores.append("❌ Debes configurar el password de PostgreSQL")
    
    if errores:
        print("\n⚠️  ERRORES DE CONFIGURACIÓN:\n")
        for error in errores:
            print(f"   {error}")
        print("\n💡 Edita el archivo y modifica la sección CONFIGURACIÓN")
        return False
    
    print("✅ Configuración válida\n")
    return True


def conectar_postgresql():
    """Conecta a PostgreSQL con la configuración especificada"""
    try:
        print(f"🔌 Conectando a PostgreSQL...")
        print(f"   Host: {DB_CONFIG['host']}:{DB_CONFIG['port']}")
        print(f"   Base de datos: {DB_CONFIG['database']}")
        print(f"   Usuario: {DB_CONFIG['user']}")
        
        conn = psycopg2.connect(**DB_CONFIG)
        print("✅ Conexión exitosa\n")
        return conn
        
    except psycopg2.OperationalError as e:
        print(f"\n❌ Error de conexión a PostgreSQL:")
        print(f"   {str(e)}")
        print("\n💡 Verifica que:")
        print("   - PostgreSQL esté corriendo")
        print("   - Host y puerto sean correctos")
        print("   - Usuario y password sean correctos")
        print("   - La base de datos exista")
        return None
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        return None


def obtener_estado_actual(cursor):
    """Obtiene el estado actual de expiración de la base de datos"""
    print("📊 Estado actual de la base de datos:")
    print("-" * 60)
    
    try:
        cursor.execute("""
            SELECT key, value 
            FROM ir_config_parameter 
            WHERE key IN ('database.expiration_date', 
                          'database.expiration_reason',
                          'database.enterprise_code')
            ORDER BY key
        """)
        
        parametros = {}
        for row in cursor.fetchall():
            parametros[row[0]] = row[1]
            print(f"   {row[0]:<30} = {row[1] or 'NULL'}")
        
        # Calcular días hasta expiración
        if 'database.expiration_date' in parametros and parametros['database.expiration_date']:
            try:
                fecha_exp = datetime.strptime(parametros['database.expiration_date'], '%Y-%m-%d')
                dias_diff = (fecha_exp - datetime.now()).days
                
                if dias_diff < 0:
                    print(f"\n   ⚠️  Base de datos VENCIDA hace {abs(dias_diff)} días")
                    print(f"   🔴 Estado: BLOQUEADA")
                else:
                    print(f"\n   ✅ Base de datos válida por {dias_diff} días más")
                
                return dias_diff, parametros
            except:
                pass
        
        print("-" * 60 + "\n")
        return None, parametros
        
    except Exception as e:
        print(f"❌ Error al obtener estado: {e}")
        return None, {}


def aplicar_desbloqueo(cursor, conn):
    """Aplica el desbloqueo extendiendo la fecha de expiración"""
    
    try:
        # Calcular nueva fecha
        nueva_fecha = (datetime.now() + timedelta(days=365*EXTENSION_YEARS)).strftime('%Y-%m-%d')
        
        print(f"🔓 Aplicando desbloqueo...")
        print(f"   Nueva fecha de expiración: {nueva_fecha}")
        print(f"   Nueva razón: {NEW_REASON}")
        print()
        
        # 1. Actualizar fecha de expiración
        cursor.execute("""
            UPDATE ir_config_parameter 
            SET value = %s, write_date = NOW()
            WHERE key = 'database.expiration_date'
        """, (nueva_fecha,))
        
        filas_actualizadas = cursor.rowcount
        
        # Si no existe, crear el parámetro
        if filas_actualizadas == 0:
            print("   ℹ️  Creando parámetro database.expiration_date...")
            cursor.execute("""
                INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date)
                VALUES ('database.expiration_date', %s, 1, NOW(), 1, NOW())
            """, (nueva_fecha,))
        
        # 2. Actualizar razón de expiración
        cursor.execute("""
            UPDATE ir_config_parameter 
            SET value = %s, write_date = NOW()
            WHERE key = 'database.expiration_reason'
        """, (NEW_REASON,))
        
        if cursor.rowcount == 0:
            print("   ℹ️  Creando parámetro database.expiration_reason...")
            cursor.execute("""
                INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date)
                VALUES ('database.expiration_reason', %s, 1, NOW(), 1, NOW())
            """, (NEW_REASON,))
        
        # 3. Limpiar sesiones si está configurado
        if CLEAN_SESSIONS:
            print("   🧹 Limpiando sesiones activas...")
            cursor.execute("DELETE FROM ir_sessions")
            sesiones_eliminadas = cursor.rowcount
            print(f"   ✅ {sesiones_eliminadas} sesiones eliminadas")
        
        # Commit de cambios
        conn.commit()
        
        print("\n✅ ¡Desbloqueo aplicado exitosamente!")
        print(f"   La base de datos ahora es válida hasta: {nueva_fecha}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error al aplicar desbloqueo: {e}")
        conn.rollback()
        return False


def verificar_desbloqueo(cursor):
    """Verifica que el desbloqueo se haya aplicado correctamente"""
    print("\n🔍 Verificando cambios...")
    print("-" * 60)
    
    try:
        cursor.execute("""
            SELECT key, value 
            FROM ir_config_parameter 
            WHERE key IN ('database.expiration_date', 'database.expiration_reason')
            ORDER BY key
        """)
        
        for row in cursor.fetchall():
            print(f"   {row[0]:<30} = {row[1]}")
        
        # Verificar fecha
        cursor.execute("""
            SELECT value FROM ir_config_parameter 
            WHERE key = 'database.expiration_date'
        """)
        
        result = cursor.fetchone()
        if result:
            fecha_exp = datetime.strptime(result[0], '%Y-%m-%d')
            dias_restantes = (fecha_exp - datetime.now()).days
            print(f"\n   ✅ Días restantes de validez: {dias_restantes}")
        
        print("-" * 60)
        return True
        
    except Exception as e:
        print(f"❌ Error en verificación: {e}")
        return False


def mostrar_instrucciones_post():
    """Muestra instrucciones después del desbloqueo"""
    print("\n" + "="*80)
    print("║" + " "*25 + "⚠️  INSTRUCCIONES IMPORTANTES" + " "*24 + "║")
    print("="*80)
    print("""
Para que los cambios tomen efecto:

1. 🌐 CERRAR EL NAVEGADOR COMPLETAMENTE
   - No solo la pestaña, sino todo el navegador
   - Esto limpiará la caché de sesión

2. 🔄 VOLVER A ABRIR EL NAVEGADOR
   - Abrir nueva ventana del navegador

3. 🔐 INGRESAR A ODOO
   - Ir a la URL de tu instancia Odoo
   - Hacer login normalmente
   - La interfaz ya NO estará bloqueada

4. ✅ VERIFICAR FUNCIONAMIENTO
   - Navegar por diferentes menús
   - Verificar que no aparezca mensaje de expiración

NOTAS ADICIONALES:
-----------------
• Los datos de tu base de datos están intactos
• Solo se modificaron parámetros de configuración
• Este desbloqueo es válido por {years} años
• Considera regularizar tu licencia de Odoo Enterprise

SOLUCIÓN PERMANENTE:
-------------------
→ Comprar subscripción Enterprise: https://www.odoo.com/pricing
→ Migrar a Community Edition (gratis, sin Enterprise features)
→ Migrar a Odoo 18 (tu proyecto actual en este workspace)

""".format(years=EXTENSION_YEARS))
    print("="*80 + "\n")


def main():
    """Función principal del script"""
    
    print_banner()
    
    # Verificar configuración
    if not verificar_configuracion():
        return False
    
    # Solicitar confirmación
    print("⚠️  ADVERTENCIA:")
    print("   Este script modificará la base de datos de Odoo")
    print("   Se recomienda hacer un backup antes de continuar\n")
    
    respuesta = input("¿Desea continuar con el desbloqueo? (S/n): ").strip().lower()
    
    if respuesta not in ['s', 'si', 'yes', 'y', '']:
        print("\n❌ Operación cancelada por el usuario")
        return False
    
    print()
    
    # Conectar a PostgreSQL
    conn = conectar_postgresql()
    if not conn:
        return False
    
    cursor = conn.cursor()
    
    try:
        # Obtener estado actual
        dias_restantes, parametros = obtener_estado_actual(cursor)
        
        # Aplicar desbloqueo
        if not aplicar_desbloqueo(cursor, conn):
            return False
        
        # Verificar cambios
        if not verificar_desbloqueo(cursor):
            print("\n⚠️  Advertencia: No se pudieron verificar los cambios")
        
        # Mostrar instrucciones
        mostrar_instrucciones_post()
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        return False
        
    finally:
        cursor.close()
        conn.close()
        print("🔌 Conexión a PostgreSQL cerrada\n")


if __name__ == "__main__":
    try:
        exito = main()
        sys.exit(0 if exito else 1)
    except KeyboardInterrupt:
        print("\n\n❌ Operación cancelada por el usuario (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        sys.exit(1)
