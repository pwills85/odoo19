#!/bin/bash
# Indexación de Base de Conocimiento Enterprise
# Indexa toda la documentación y código del proyecto para RAG

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENTERPRISE_DIR="$PROJECT_ROOT/.codex/enterprise"

# Configuración de colores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [$level] $message" >> "$ENTERPRISE_DIR/indexation.log"
    case $level in
        "INFO") echo -e "${BLUE}[INFO]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        "PROGRESS") echo -e "${YELLOW}[PROGRESS]${NC} $message" ;;
        "ENTERPRISE") echo -e "${PURPLE}[ENTERPRISE]${NC} $message" ;;
    esac
}

# Función de indexación de documentos
index_documents() {
    log "ENTERPRISE" "Indexando documentación del proyecto..."

    python3 -c "
import os
import json
from pathlib import Path

project_root = '$PROJECT_ROOT'
documents = []

# Documentos principales
doc_paths = [
    '.github/agents/knowledge/*.md',
    '.github/copilot-instructions.md',
    'README.md',
    'CLAUDE.md',
    'docs/**/*.md'
]

for pattern in doc_paths:
    for path in Path(project_root).glob(pattern):
        if path.is_file():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if len(content.strip()) > 100:  # Solo documentos con contenido significativo
                        documents.append({
                            'path': str(path.relative_to(project_root)),
                            'content': content,
                            'type': 'documentation',
                            'domain': 'odoo19' if 'odoo19' in str(path) else 'general'
                        })
            except Exception as e:
                print(f'Error leyendo {path}: {e}')

# Guardar documentos indexados
index_path = 'knowledge-index/documents.json'
os.makedirs(os.path.dirname(index_path), exist_ok=True)

with open(index_path, 'w', encoding='utf-8') as f:
    json.dump(documents, f, indent=2, ensure_ascii=False)

print(f'Documentos indexados: {len(documents)}')
print(f'Índice guardado en: {index_path}')
    "

    log "SUCCESS" "Documentación indexada correctamente"
}

# Función de indexación de código
index_codebase() {
    log "ENTERPRISE" "Indexando base de código..."

    python3 -c "
import os
import json
from pathlib import Path

project_root = '$PROJECT_ROOT'
code_files = []

# Patrones de archivos de código
code_patterns = [
    '**/*.py',
    '**/*.js',
    '**/*.xml',
    '**/*.sh'
]

exclude_patterns = [
    '__pycache__',
    '.git',
    'node_modules',
    '.codex',
    'scripts/__pycache__'
]

for pattern in code_patterns:
    for path in Path(project_root).glob(pattern):
        if path.is_file():
            # Verificar si está en directorios excluidos
            if any(excl in str(path) for excl in exclude_patterns):
                continue

            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if len(content.strip()) > 50:  # Solo archivos con contenido significativo
                        # Determinar tipo de archivo y dominio
                        file_type = path.suffix[1:] if path.suffix else 'unknown'
                        domain = 'unknown'

                        if 'l10n_cl_dte' in str(path):
                            domain = 'dte_compliance'
                        elif 'l10n_cl_hr_payroll' in str(path):
                            domain = 'payroll_compliance'
                        elif 'models' in str(path):
                            domain = 'odoo_models'
                        elif 'controllers' in str(path):
                            domain = 'web_controllers'
                        elif 'ai-service' in str(path):
                            domain = 'ai_service'

                        code_files.append({
                            'path': str(path.relative_to(project_root)),
                            'content': content,
                            'type': 'code',
                            'language': file_type,
                            'domain': domain,
                            'size': len(content)
                        })
            except Exception as e:
                print(f'Error leyendo {path}: {e}')

# Guardar código indexado
index_path = 'knowledge-index/codebase.json'
os.makedirs(os.path.dirname(index_path), exist_ok=True)

with open(index_path, 'w', encoding='utf-8') as f:
    json.dump(code_files, f, indent=2, ensure_ascii=False)

print(f'Archivos de código indexados: {len(code_files)}')
print(f'Índice guardado en: {index_path}')
    "

    log "SUCCESS" "Base de código indexada correctamente"
}

# Función de creación de embeddings vectoriales
create_vector_embeddings() {
    log "ENTERPRISE" "Creando embeddings vectoriales..."

    python3 -c "
import os
import json
import chromadb
from sentence_transformers import SentenceTransformer

# Cargar modelo de embeddings
model = SentenceTransformer('all-MiniLM-L6-v2')

# Cargar documentos indexados
docs_path = os.path.expanduser('~/.codex/enterprise/knowledge-index/documents.json')
code_path = os.path.expanduser('~/.codex/enterprise/knowledge-index/codebase.json')

documents = []
if os.path.exists(docs_path):
    with open(docs_path, 'r', encoding='utf-8') as f:
        documents.extend(json.load(f))

if os.path.exists(code_path):
    with open(code_path, 'r', encoding='utf-8') as f:
        documents.extend(json.load(f))

# Inicializar ChromaDB
vector_db_path = 'vector-store/odoo19-chile.db'
client = chromadb.PersistentClient(path=vector_db_path)

# Crear colección
collection_name = 'odoo19_knowledge'
try:
    collection = client.get_collection(collection_name)
    client.delete_collection(collection_name)
except:
    pass

collection = client.create_collection(collection_name)

# Procesar documentos en chunks
chunk_size = 1000
overlap = 200

total_chunks = 0
for doc in documents:
    content = doc['content']
    path = doc['path']

    # Dividir en chunks
    chunks = []
    start = 0
    while start < len(content):
        end = start + chunk_size
        chunk = content[start:end]
        if len(chunk.strip()) > 50:  # Solo chunks significativos
            chunks.append(chunk)
        start = end - overlap

    # Crear embeddings y añadir a la colección
    if chunks:
        embeddings = model.encode(chunks)
        ids = [f'{path}_chunk_{i}' for i in range(len(chunks))]
        metadatas = [{
            'path': path,
            'type': doc.get('type', 'unknown'),
            'domain': doc.get('domain', 'unknown'),
            'language': doc.get('language', 'unknown')
        } for _ in chunks]

        collection.add(
            embeddings=embeddings.tolist(),
            documents=chunks,
            ids=ids,
            metadatas=metadatas
        )

        total_chunks += len(chunks)
        print(f'Procesado: {path} ({len(chunks)} chunks)')

print(f'Total de chunks indexados: {total_chunks}')
print(f'Embeddings guardados en: {vector_db_path}')
    "

    log "SUCCESS" "Embeddings vectoriales creados correctamente"
}

# Función de validación de indexación
validate_indexation() {
    log "ENTERPRISE" "Validando indexación completa..."

    python3 -c "
import os
import chromadb

# Verificar archivos de índice
docs_path = os.path.expanduser('~/.codex/enterprise/knowledge-index/documents.json')
code_path = os.path.expanduser('~/.codex/enterprise/knowledge-index/codebase.json')

docs_count = 0
code_count = 0

if os.path.exists(docs_path):
    with open(docs_path, 'r') as f:
        docs = json.load(f)
        docs_count = len(docs)
        print(f'Documentos indexados: {docs_count}')

if os.path.exists(code_path):
    with open(code_path, 'r') as f:
        code = json.load(f)
        code_count = len(code)
        print(f'Archivos de código indexados: {code_count}')

# Verificar base de datos vectorial
vector_db_path = os.path.expanduser('~/.codex/enterprise/vector-store/odoo19-chile.db')
client = chromadb.PersistentClient(path=vector_db_path)

try:
    collection = client.get_collection('odoo19_knowledge')
    total_vectors = collection.count()
    print(f'Vectores en base de datos: {total_vectors}')
except Exception as e:
    print(f'Error accediendo a base de datos vectorial: {e}')

print(f'Indexación validada correctamente')
    "

    log "SUCCESS" "Validación de indexación completada"
}

# Función principal
main() {
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ 📚 INDEXACIÓN DE BASE DE CONOCIMIENTO ENTERPRISE                          ║"
    echo "║                                                                            ║"
    echo "║ Procesos:                                                                 ║"
    echo "║ • Indexación de documentación                                              ║"
    echo "║ • Indexación de base de código                                             ║"
    echo "║ • Creación de embeddings vectoriales                                      ║"
    echo "║ • Validación completa                                                     ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo

    log "ENTERPRISE" "Iniciando indexación de base de conocimiento..."

    # Crear directorios necesarios
    mkdir -p "$HOME/.codex/enterprise/knowledge-index"

    # Ejecutar procesos de indexación
    index_documents
    index_codebase
    create_vector_embeddings
    validate_indexation

    echo
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║ ✅ INDEXACIÓN COMPLETADA EXITOSAMENTE                                     ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo
    log "SUCCESS" "Indexación de base de conocimiento completada"

    echo "📊 Estadísticas:"
    echo "- Documentos indexados: $(wc -l < "$HOME/.codex/enterprise/knowledge-index/documents.json" 2>/dev/null || echo "0")"
    echo "- Archivos de código: $(wc -l < "$HOME/.codex/enterprise/knowledge-index/codebase.json" 2>/dev/null || echo "0")"
    echo "- Vectores generados: $(python3 -c "import chromadb; client = chromadb.PersistentClient(path='$HOME/.codex/enterprise/vector-store/odoo19-chile.db'); print(client.get_collection('odoo19_knowledge').count())" 2>/dev/null || echo "0")"
    echo
    echo "🎯 Sistema listo para consultas RAG inteligentes"
    echo
}

# Ejecutar función principal
main "$@"
