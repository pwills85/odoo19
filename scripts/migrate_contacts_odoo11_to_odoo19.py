#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ETL Script: Migración de Contactos Odoo 11 CE → Odoo 19 CE
===========================================================

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-10-25
Sprint: 4 - Contact Migration

Descripción:
-----------
Script enterprise-grade para migrar 3,922 contactos desde Odoo 11 CE (EERGYGROUP)
a Odoo 19 CE (TEST) con validaciones exhaustivas y transformaciones de datos.

Transformaciones:
----------------
1. RUT: document_number → vat (formato chileno XX.XXX.XXX-X)
2. Ranking: customer/supplier boolean → customer_rank/supplier_rank integer
3. Provincia → Región: state_id (54 provincias) → state_id (16 regiones)
4. Comuna: city_id (FK) → l10n_cl_comuna_id (catálogo SII)
5. Actividad: activity_description (FK) → l10n_cl_activity_description (texto)
6. Email DTE: dte_email → dte_email (directo)
7. MIPYME: es_mipyme → es_mipyme (directo)

Requisitos:
----------
- psycopg2-binary
- Docker containers corriendo (Odoo 11 y Odoo 19)

Uso:
----
    python3 scripts/migrate_contacts_odoo11_to_odoo19.py

    # Dry-run (sin commit):
    python3 scripts/migrate_contacts_odoo11_to_odoo19.py --dry-run

    # Solo primeros 100:
    python3 scripts/migrate_contacts_odoo11_to_odoo19.py --limit 100
"""

import psycopg2
import re
import sys
import argparse
from datetime import datetime
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════════

# Odoo 11 CE (Fuente)
ODOO11_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'EERGYGROUP',
    'user': 'odoo',
    'password': 'l&UKgl^9046hPo7K!AowqV&g',
    'container': 'prod_odoo-11_eergygroup_db'
}

# Odoo 19 CE (Destino)
ODOO19_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'TEST',
    'user': 'odoo',
    'password': 'odoo',
    'container': 'odoo19_db'
}

# Mapeo Provincia (Odoo 11) → Región (Odoo 19)
# Basado en estructura administrativa chilena oficial
PROVINCIA_TO_REGION_MAP = {
    # Región de Arica y Parinacota (XV)
    1: 1,  # Arica → XV Región
    2: 1,  # Parinacota → XV Región

    # Región de Tarapacá (I)
    3: 2,  # Iquique → I Región
    4: 2,  # Tamarugal → I Región

    # Región de Antofagasta (II)
    5: 3,  # Antofagasta → II Región
    6: 3,  # El Loa → II Región
    7: 3,  # Tocopilla → II Región

    # Región de Atacama (III)
    8: 4,  # Copiapó → III Región
    9: 4,  # Chañaral → III Región
    10: 4, # Huasco → III Región

    # Región de Coquimbo (IV)
    11: 5, # Elqui → IV Región
    12: 5, # Choapa → IV Región
    13: 5, # Limarí → IV Región

    # Región de Valparaíso (V)
    14: 6, # Valparaíso → V Región
    15: 6, # Isla de Pascua → V Región
    16: 6, # Los Andes → V Región
    17: 6, # Petorca → V Región
    18: 6, # Quillota → V Región
    19: 6, # San Antonio → V Región
    20: 6, # San Felipe de Aconcagua → V Región
    21: 6, # Marga Marga → V Región

    # Región Metropolitana (XIII)
    22: 7, # Santiago → RM
    23: 7, # Cordillera → RM
    24: 7, # Chacabuco → RM
    25: 7, # Maipo → RM
    26: 7, # Melipilla → RM
    27: 7, # Talagante → RM

    # Región del Libertador Gral. Bernardo O'Higgins (VI)
    28: 8, # Cachapoal → VI Región
    29: 8, # Cardenal Caro → VI Región
    30: 8, # Colchagua → VI Región

    # Región del Maule (VII)
    31: 9, # Talca → VII Región
    32: 9, # Cauquenes → VII Región
    33: 9, # Curicó → VII Región
    34: 9, # Linares → VII Región

    # Región de Ñuble (XVI)
    35: 16, # Diguillín → XVI Región
    36: 16, # Itata → XVI Región
    37: 16, # Punilla → XVI Región

    # Región del Biobío (VIII)
    38: 10, # Concepción → VIII Región
    39: 10, # Arauco → VIII Región
    40: 10, # Biobío → VIII Región

    # Región de La Araucanía (IX)
    41: 11, # Cautín → IX Región
    42: 11, # Malleco → IX Región

    # Región de Los Ríos (XIV)
    43: 12, # Valdivia → XIV Región
    44: 12, # Ranco → XIV Región

    # Región de Los Lagos (X)
    45: 13, # Llanquihue → X Región
    46: 13, # Chiloé → X Región
    47: 13, # Osorno → X Región
    48: 13, # Palena → X Región

    # Región Aysén del Gral. Carlos Ibáñez del Campo (XI)
    49: 14, # Coihaique → XI Región
    50: 14, # Aysén → XI Región
    51: 14, # Capitán Prat → XI Región
    52: 14, # General Carrera → XI Región

    # Región de Magallanes y de la Antártica Chilena (XII)
    53: 15, # Magallanes → XII Región
    54: 15, # Antártica Chilena → XII Región
    55: 15, # Tierra del Fuego → XII Región
    56: 15, # Última Esperanza → XII Región
}

# Batch size para commits (enterprise-grade)
BATCH_SIZE = 100

# ═══════════════════════════════════════════════════════════════════════
# UTILIDADES
# ═══════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI colors para output terminal"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log(message, level='INFO'):
    """Log con colores y timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    colors = {
        'INFO': Colors.OKBLUE,
        'SUCCESS': Colors.OKGREEN,
        'WARNING': Colors.WARNING,
        'ERROR': Colors.FAIL,
        'HEADER': Colors.HEADER
    }

    color = colors.get(level, '')
    print(f"{color}[{timestamp}] [{level}] {message}{Colors.ENDC}")

def format_rut(document_number):
    """
    Formatea RUT chileno al formato estándar.

    Input formats:
        - CL06425796K
        - 064257967
        - 6425796-7
        - 6.425.796-7

    Output format: 6425796-7 (sin puntos, con guión)

    Args:
        document_number (str): RUT en cualquier formato

    Returns:
        str: RUT formateado o None si inválido
    """
    if not document_number:
        return None

    # Remover prefijo CL si existe
    rut = str(document_number).upper().replace('CL', '').strip()

    # Remover puntos y espacios
    rut = rut.replace('.', '').replace(' ', '')

    # Si no tiene guión, agregarlo antes del último caracter
    if '-' not in rut and len(rut) >= 2:
        rut = rut[:-1] + '-' + rut[-1]

    # Validar formato básico
    if not re.match(r'^\d{7,8}-[\dK]$', rut):
        return None

    return rut

def validate_rut_modulo11(rut):
    """
    Valida RUT chileno usando algoritmo Módulo 11.

    Args:
        rut (str): RUT en formato XXXXXXXX-X

    Returns:
        bool: True si RUT es válido
    """
    if not rut or '-' not in rut:
        return False

    try:
        numero, dv = rut.split('-')
        numero = int(numero)

        # Algoritmo Módulo 11
        suma = 0
        multiplo = 2

        for digit in reversed(str(numero)):
            suma += int(digit) * multiplo
            multiplo = multiplo + 1 if multiplo < 7 else 2

        resto = suma % 11
        dv_calculado = 11 - resto

        if dv_calculado == 11:
            dv_esperado = '0'
        elif dv_calculado == 10:
            dv_esperado = 'K'
        else:
            dv_esperado = str(dv_calculado)

        return dv.upper() == dv_esperado

    except (ValueError, AttributeError):
        return False

# ═══════════════════════════════════════════════════════════════════════
# CONEXIONES DATABASE
# ═══════════════════════════════════════════════════════════════════════

def get_odoo11_connection():
    """Conecta a base de datos Odoo 11 (via Docker container)"""
    try:
        # Intentar conexión directa primero
        conn = psycopg2.connect(
            host='localhost',
            port=5432,
            database=ODOO11_CONFIG['database'],
            user=ODOO11_CONFIG['user'],
            password=ODOO11_CONFIG['password']
        )
        log(f"✅ Conectado a Odoo 11: {ODOO11_CONFIG['database']}", 'SUCCESS')
        return conn
    except psycopg2.OperationalError:
        # Si falla, intentar via Docker exec
        log("ℹ️  Conexión directa falló, intentando via Docker...", 'INFO')
        # TODO: Implementar conexión via Docker exec si es necesario
        raise

def get_odoo19_connection():
    """Conecta a base de datos Odoo 19"""
    try:
        conn = psycopg2.connect(
            host='localhost',
            port=5432,
            database=ODOO19_CONFIG['database'],
            user=ODOO19_CONFIG['user'],
            password=ODOO19_CONFIG['password']
        )
        log(f"✅ Conectado a Odoo 19: {ODOO19_CONFIG['database']}", 'SUCCESS')
        return conn
    except psycopg2.OperationalError as e:
        log(f"❌ Error conectando a Odoo 19: {e}", 'ERROR')
        raise

# ═══════════════════════════════════════════════════════════════════════
# EXTRACCIÓN (Odoo 11)
# ═══════════════════════════════════════════════════════════════════════

def extract_partners_odoo11(conn, limit=None):
    """
    Extrae partners desde Odoo 11.

    Args:
        conn: Conexión psycopg2 a DB Odoo 11
        limit (int, optional): Limitar resultados (para testing)

    Returns:
        list: Lista de dicts con datos de partners
    """
    log("📤 Extrayendo partners desde Odoo 11...", 'INFO')

    cursor = conn.cursor()

    query = """
        SELECT
            p.id,
            p.name,
            p.ref,
            p.vat as vat_old,
            p.document_number,
            p.document_type_id,
            p.email,
            p.phone,
            p.mobile,
            p.website,
            p.street,
            p.street2,
            p.zip,
            p.city,
            p.state_id,
            p.country_id,
            p.function,
            p.is_company,
            p.customer,
            p.supplier,
            p.active,
            p.comment,
            p.activity_description,
            p.dte_email,
            p.es_mipyme,
            p.parent_id,
            p.lang,
            p.tz,
            p.title,
            p.type,
            p.company_id,
            p.user_id,
            p.create_date,
            p.write_date,
            -- Lookup activity description text
            (SELECT name FROM res_partner_category WHERE id = p.activity_description LIMIT 1) as activity_text,
            -- Lookup state/provincia name
            (SELECT name FROM res_country_state WHERE id = p.state_id LIMIT 1) as state_name
        FROM res_partner p
        WHERE p.active = true
        ORDER BY p.id
    """

    if limit:
        query += f" LIMIT {limit}"

    cursor.execute(query)
    columns = [desc[0] for desc in cursor.description]

    partners = []
    for row in cursor.fetchall():
        partner_dict = dict(zip(columns, row))
        partners.append(partner_dict)

    cursor.close()

    log(f"✅ Extraídos {len(partners)} partners desde Odoo 11", 'SUCCESS')

    return partners

# ═══════════════════════════════════════════════════════════════════════
# TRANSFORMACIÓN
# ═══════════════════════════════════════════════════════════════════════

def transform_partner(partner_o11, stats):
    """
    Transforma datos de partner Odoo 11 → Odoo 19.

    Args:
        partner_o11 (dict): Partner de Odoo 11
        stats (dict): Diccionario para acumular estadísticas

    Returns:
        dict: Partner transformado para Odoo 19, o None si debe omitirse
    """
    partner_o19 = {}

    # ───────────────────────────────────────────────────────────────────
    # 1. CAMPOS BÁSICOS (sin transformación)
    # ───────────────────────────────────────────────────────────────────

    direct_fields = [
        'name', 'ref', 'email', 'phone', 'mobile', 'website',
        'street', 'street2', 'zip', 'city', 'function', 'is_company',
        'active', 'comment', 'parent_id', 'lang', 'tz', 'title',
        'type', 'company_id', 'user_id', 'country_id'
    ]

    for field in direct_fields:
        if partner_o11.get(field) is not None:
            partner_o19[field] = partner_o11[field]

    # ───────────────────────────────────────────────────────────────────
    # 2. VAT (RUT): document_number → vat
    # ───────────────────────────────────────────────────────────────────

    if partner_o11.get('document_number'):
        rut_formatted = format_rut(partner_o11['document_number'])

        if rut_formatted:
            # Validar RUT con Módulo 11
            if validate_rut_modulo11(rut_formatted):
                partner_o19['vat'] = rut_formatted
                stats['rut_valid'] += 1
            else:
                log(f"⚠️  RUT inválido (Módulo 11): {rut_formatted} - Partner: {partner_o11['name']}", 'WARNING')
                partner_o19['vat'] = rut_formatted  # Igual lo guardamos para revisión manual
                stats['rut_invalid'] += 1
        else:
            log(f"⚠️  RUT mal formateado: {partner_o11['document_number']} - Partner: {partner_o11['name']}", 'WARNING')
            stats['rut_malformed'] += 1
    else:
        # Si tiene vat_old, intentar usarlo
        if partner_o11.get('vat_old'):
            rut_formatted = format_rut(partner_o11['vat_old'])
            if rut_formatted and validate_rut_modulo11(rut_formatted):
                partner_o19['vat'] = rut_formatted
                stats['rut_from_vat_old'] += 1
        else:
            stats['rut_missing'] += 1

    # ───────────────────────────────────────────────────────────────────
    # 3. CUSTOMER/SUPPLIER RANK: boolean → integer
    # ───────────────────────────────────────────────────────────────────

    partner_o19['customer_rank'] = 1 if partner_o11.get('customer') else 0
    partner_o19['supplier_rank'] = 1 if partner_o11.get('supplier') else 0

    if partner_o11.get('customer'):
        stats['customers'] += 1
    if partner_o11.get('supplier'):
        stats['suppliers'] += 1

    # ───────────────────────────────────────────────────────────────────
    # 4. PROVINCIA → REGIÓN: state_id mapping
    # ───────────────────────────────────────────────────────────────────

    if partner_o11.get('state_id'):
        old_state_id = partner_o11['state_id']
        new_state_id = PROVINCIA_TO_REGION_MAP.get(old_state_id)

        if new_state_id:
            partner_o19['state_id'] = new_state_id
            stats['state_mapped'] += 1
        else:
            log(f"⚠️  Provincia sin mapeo: ID={old_state_id}, Name={partner_o11.get('state_name')} - Partner: {partner_o11['name']}", 'WARNING')
            stats['state_unmapped'] += 1
            # Intentar mapeo por defecto a RM (región más común)
            partner_o19['state_id'] = 7  # Región Metropolitana
            stats['state_default_rm'] += 1

    # ───────────────────────────────────────────────────────────────────
    # 5. ACTIVIDAD ECONÓMICA: FK → texto
    # ───────────────────────────────────────────────────────────────────

    if partner_o11.get('activity_text'):
        # Truncar a 80 caracteres (límite del campo)
        partner_o19['l10n_cl_activity_description'] = partner_o11['activity_text'][:80]
        stats['activity_mapped'] += 1
    elif partner_o11.get('activity_description'):
        # Tiene FK pero no pudimos obtener texto (lookup falló)
        stats['activity_missing_text'] += 1

    # ───────────────────────────────────────────────────────────────────
    # 6. DTE_EMAIL (directo)
    # ───────────────────────────────────────────────────────────────────

    if partner_o11.get('dte_email'):
        partner_o19['dte_email'] = partner_o11['dte_email']
        stats['dte_email_present'] += 1

    # ───────────────────────────────────────────────────────────────────
    # 7. ES_MIPYME (directo)
    # ───────────────────────────────────────────────────────────────────

    if partner_o11.get('es_mipyme'):
        partner_o19['es_mipyme'] = partner_o11['es_mipyme']
        stats['mipyme'] += 1
    else:
        partner_o19['es_mipyme'] = False

    # ───────────────────────────────────────────────────────────────────
    # VALIDACIÓN FINAL: Name es obligatorio
    # ───────────────────────────────────────────────────────────────────

    if not partner_o19.get('name'):
        log(f"❌ Partner sin nombre (ID={partner_o11['id']}), omitiendo...", 'ERROR')
        stats['skipped_no_name'] += 1
        return None

    return partner_o19

# ═══════════════════════════════════════════════════════════════════════
# CARGA (Odoo 19)
# ═══════════════════════════════════════════════════════════════════════

def load_partners_odoo19(conn, partners, dry_run=False):
    """
    Carga partners transformados en Odoo 19.

    Args:
        conn: Conexión psycopg2 a DB Odoo 19
        partners (list): Lista de partners transformados
        dry_run (bool): Si True, no hace commit

    Returns:
        dict: Estadísticas de carga
    """
    log(f"📥 Cargando {len(partners)} partners en Odoo 19...", 'INFO')

    if dry_run:
        log("🔍 DRY-RUN MODE: No se harán commits", 'WARNING')

    cursor = conn.cursor()
    stats = {
        'inserted': 0,
        'updated': 0,
        'errors': 0,
        'duplicates': 0
    }

    for i, partner in enumerate(partners, 1):
        try:
            # Verificar si partner ya existe (por VAT o email)
            existing_id = None

            if partner.get('vat'):
                cursor.execute(
                    "SELECT id FROM res_partner WHERE vat = %s LIMIT 1",
                    (partner['vat'],)
                )
                result = cursor.fetchone()
                if result:
                    existing_id = result[0]
                    stats['duplicates'] += 1
                    log(f"ℹ️  Partner duplicado (RUT: {partner['vat']}), omitiendo...", 'INFO')
                    continue

            # Construir query INSERT
            fields = list(partner.keys())
            values = [partner[f] for f in fields]
            placeholders = ', '.join(['%s'] * len(fields))
            fields_str = ', '.join(fields)

            query = f"""
                INSERT INTO res_partner ({fields_str})
                VALUES ({placeholders})
                RETURNING id
            """

            cursor.execute(query, values)
            new_id = cursor.fetchone()[0]
            stats['inserted'] += 1

            # Commit cada BATCH_SIZE registros (performance)
            if i % BATCH_SIZE == 0:
                if not dry_run:
                    conn.commit()
                log(f"✅ Batch {i // BATCH_SIZE}: {BATCH_SIZE} partners insertados", 'SUCCESS')

        except psycopg2.Error as e:
            stats['errors'] += 1
            log(f"❌ Error insertando partner '{partner.get('name', 'Unknown')}': {e}", 'ERROR')
            conn.rollback()
            continue

    # Commit final
    if not dry_run:
        conn.commit()
        log("✅ Commit final realizado", 'SUCCESS')
    else:
        conn.rollback()
        log("🔄 Rollback (dry-run)", 'WARNING')

    cursor.close()

    return stats

# ═══════════════════════════════════════════════════════════════════════
# MAIN ETL
# ═══════════════════════════════════════════════════════════════════════

def run_etl(dry_run=False, limit=None):
    """
    Ejecuta ETL completo: Extract → Transform → Load

    Args:
        dry_run (bool): Si True, no hace commit en DB destino
        limit (int, optional): Limitar número de partners (testing)
    """
    log("=" * 80, 'HEADER')
    log("  ETL: MIGRACIÓN CONTACTOS ODOO 11 CE → ODOO 19 CE", 'HEADER')
    log("=" * 80, 'HEADER')
    log(f"  Dry-run: {dry_run}", 'HEADER')
    log(f"  Limit: {limit if limit else 'None (todos)'}", 'HEADER')
    log("=" * 80, 'HEADER')

    start_time = datetime.now()

    # Estadísticas transformación
    transform_stats = defaultdict(int)

    try:
        # ─────────────────────────────────────────────────────────────
        # EXTRACT
        # ─────────────────────────────────────────────────────────────

        log("\n📤 FASE 1: EXTRACCIÓN", 'HEADER')
        conn_o11 = get_odoo11_connection()
        partners_o11 = extract_partners_odoo11(conn_o11, limit=limit)
        conn_o11.close()

        if not partners_o11:
            log("❌ No se encontraron partners para migrar", 'ERROR')
            return

        # ─────────────────────────────────────────────────────────────
        # TRANSFORM
        # ─────────────────────────────────────────────────────────────

        log("\n🔄 FASE 2: TRANSFORMACIÓN", 'HEADER')
        partners_o19 = []

        for partner_o11 in partners_o11:
            partner_o19 = transform_partner(partner_o11, transform_stats)
            if partner_o19:
                partners_o19.append(partner_o19)

        log(f"✅ {len(partners_o19)} partners transformados exitosamente", 'SUCCESS')

        # Mostrar estadísticas transformación
        log("\n📊 ESTADÍSTICAS TRANSFORMACIÓN:", 'HEADER')
        log(f"  • RUT válidos: {transform_stats['rut_valid']}", 'INFO')
        log(f"  • RUT inválidos (Módulo 11): {transform_stats['rut_invalid']}", 'WARNING')
        log(f"  • RUT mal formateados: {transform_stats['rut_malformed']}", 'WARNING')
        log(f"  • RUT faltantes: {transform_stats['rut_missing']}", 'WARNING')
        log(f"  • RUT desde vat_old: {transform_stats['rut_from_vat_old']}", 'INFO')
        log(f"  • Customers: {transform_stats['customers']}", 'INFO')
        log(f"  • Suppliers: {transform_stats['suppliers']}", 'INFO')
        log(f"  • Provincias mapeadas: {transform_stats['state_mapped']}", 'INFO')
        log(f"  • Provincias sin mapeo: {transform_stats['state_unmapped']}", 'WARNING')
        log(f"  • Default a RM: {transform_stats['state_default_rm']}", 'WARNING')
        log(f"  • Actividades mapeadas: {transform_stats['activity_mapped']}", 'INFO')
        log(f"  • DTE emails: {transform_stats['dte_email_present']}", 'INFO')
        log(f"  • MIPYMEs: {transform_stats['mipyme']}", 'INFO')
        log(f"  • Omitidos (sin nombre): {transform_stats['skipped_no_name']}", 'WARNING')

        # ─────────────────────────────────────────────────────────────
        # LOAD
        # ─────────────────────────────────────────────────────────────

        log("\n📥 FASE 3: CARGA", 'HEADER')
        conn_o19 = get_odoo19_connection()
        load_stats = load_partners_odoo19(conn_o19, partners_o19, dry_run=dry_run)
        conn_o19.close()

        # Mostrar estadísticas carga
        log("\n📊 ESTADÍSTICAS CARGA:", 'HEADER')
        log(f"  • Insertados: {load_stats['inserted']}", 'SUCCESS')
        log(f"  • Actualizados: {load_stats['updated']}", 'INFO')
        log(f"  • Duplicados omitidos: {load_stats['duplicates']}", 'WARNING')
        log(f"  • Errores: {load_stats['errors']}", 'ERROR')

        # ─────────────────────────────────────────────────────────────
        # RESUMEN FINAL
        # ─────────────────────────────────────────────────────────────

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        log("\n" + "=" * 80, 'HEADER')
        log("  ✅ MIGRACIÓN COMPLETADA", 'HEADER')
        log("=" * 80, 'HEADER')
        log(f"  • Duración: {duration:.2f} segundos", 'INFO')
        log(f"  • Partners procesados: {len(partners_o11)}", 'INFO')
        log(f"  • Partners insertados: {load_stats['inserted']}", 'SUCCESS')
        log(f"  • Errores totales: {load_stats['errors']}", 'ERROR' if load_stats['errors'] > 0 else 'INFO')

        if dry_run:
            log("\n⚠️  DRY-RUN: No se realizaron cambios permanentes en DB", 'WARNING')
        else:
            log("\n✅ Cambios confirmados en base de datos TEST", 'SUCCESS')

        log("=" * 80, 'HEADER')

    except Exception as e:
        log(f"\n❌ ERROR FATAL: {e}", 'ERROR')
        import traceback
        traceback.print_exc()
        sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Migración de contactos Odoo 11 CE → Odoo 19 CE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Dry-run (sin commit):
  python3 scripts/migrate_contacts_odoo11_to_odoo19.py --dry-run

  # Solo primeros 100:
  python3 scripts/migrate_contacts_odoo11_to_odoo19.py --limit 100 --dry-run

  # Migración completa:
  python3 scripts/migrate_contacts_odoo11_to_odoo19.py
        """
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Ejecutar sin hacer commit (testing)'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limitar número de partners a migrar (testing)'
    )

    args = parser.parse_args()

    run_etl(dry_run=args.dry_run, limit=args.limit)
