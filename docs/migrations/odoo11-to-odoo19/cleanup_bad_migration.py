#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Limpieza de Migración Fallida
=============================

Elimina todos los contactos importados incorrectamente de la migración
"""

print("=" * 100)
print("  🗑️  LIMPIEZA DE MIGRACIÓN FALLIDA")
print("=" * 100)

Partner = env['res.partner']

# IDs de contactos que NO debemos eliminar (pre-existentes importantes)
PROTECTED_IDS = [
    1,  # Tu Compañía
    2,  # OdooBot
    3,  # Administrator
]

print("\n📊 Estado actual:")
total_before = Partner.search_count([])
print(f"  Total partners antes: {total_before:,}")

# Buscar contactos migrados (todos después de ID 70 aproximadamente)
# Los primeros ~70 son contactos del sistema y de prueba inicial
migrated = Partner.search([
    ('id', '>', 70),
    ('id', 'not in', PROTECTED_IDS)
])

print(f"\n🎯 Contactos a eliminar:")
print(f"  Total identificados: {len(migrated):,}")

# Mostrar primeros 10
print(f"\n  Primeros 10 contactos a eliminar:")
for p in migrated[:10]:
    print(f"    • ID {p.id}: {p.name[:60]}")

# Preguntar confirmación
print(f"\n⚠️  SE ELIMINARÁN {len(migrated):,} CONTACTOS")
print(f"  Esto es IRREVERSIBLE (a menos que tengas backup)")
print(f"\n  ¿Continuar? (Este script se ejecuta sin confirmación en shell)")
print(f"  ELIMINANDO EN 3... 2... 1...")

# Eliminar en batches de 100 para evitar timeouts
batch_size = 100
deleted = 0

for i in range(0, len(migrated), batch_size):
    batch = migrated[i:i+batch_size]
    batch.unlink()
    deleted += len(batch)

    if deleted % 500 == 0:
        print(f"  ✓ Eliminados {deleted:,} / {len(migrated):,} contactos...")
        env.cr.commit()

# Commit final
env.cr.commit()

# Verificar
total_after = Partner.search_count([])

print("\n" + "=" * 100)
print("  ✅ LIMPIEZA COMPLETADA")
print("=" * 100)
print(f"  Partners antes:     {total_before:,}")
print(f"  Eliminados:         {deleted:,}")
print(f"  Partners después:   {total_after:,}")
print(f"  Restantes:          {total_after} (solo sistema + pruebas iniciales)")
print("=" * 100)
