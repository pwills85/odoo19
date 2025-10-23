# -*- coding: utf-8 -*-
"""
Knowledge Base V2 - Multi-Module Support
==========================================

Enhanced knowledge base with:
- File-based storage (Markdown files)
- Multi-module support
- Backward compatibility with hardcoded docs
- Feature flag controlled

BACKWARD COMPATIBLE: Falls back to hardcoded docs if files not available.
"""
from typing import List, Dict, Optional
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)


class KnowledgeBaseV2:
    """
    Multi-module knowledge base with file-based storage.
    
    Features:
    - Load from Markdown files (/app/knowledge/{module}/*.md)
    - Backward compatible with hardcoded docs
    - Module-based filtering
    - Tag-based search
    """
    
    def __init__(self, knowledge_path: str = "/app/knowledge", enable_file_loading: bool = False):
        """
        Initialize knowledge base.
        
        Args:
            knowledge_path: Path to knowledge base directory
            enable_file_loading: If True, load from files; if False, use hardcoded
        """
        self.knowledge_path = Path(knowledge_path)
        self.enable_file_loading = enable_file_loading
        self.documents: Dict[str, List[Dict]] = {}  # {module: [docs]}
        
        if enable_file_loading:
            self._load_from_files()
        else:
            # BACKWARD COMPATIBILITY: Use hardcoded DTE docs
            self._load_hardcoded_dte_docs()
        
        total_docs = sum(len(docs) for docs in self.documents.values())
        logger.info("knowledge_base_v2_initialized",
                   mode="files" if enable_file_loading else "hardcoded",
                   modules=list(self.documents.keys()),
                   document_count=total_docs)
    
    def _load_from_files(self):
        """Load documents from Markdown files"""
        if not self.knowledge_path.exists():
            logger.warning("knowledge_path_not_found",
                          path=str(self.knowledge_path),
                          fallback="using hardcoded docs")
            self._load_hardcoded_dte_docs()
            return
        
        loaded_count = 0
        
        for module_dir in self.knowledge_path.iterdir():
            if not module_dir.is_dir():
                continue
            
            module_name = module_dir.name
            self.documents[module_name] = []
            
            for md_file in module_dir.glob("*.md"):
                try:
                    doc = self._parse_markdown_file(md_file, module_name)
                    self.documents[module_name].append(doc)
                    loaded_count += 1
                except Exception as e:
                    logger.error("failed_to_parse_doc",
                                file=str(md_file),
                                error=str(e))
        
        logger.info("documents_loaded_from_files",
                   modules=list(self.documents.keys()),
                   count=loaded_count)
    
    def _parse_markdown_file(self, file_path: Path, module: str) -> Dict:
        """
        Parse Markdown file.
        
        Supports frontmatter format:
        ---
        id: doc_id
        title: Document Title
        tags: [tag1, tag2]
        ---
        Content here...
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Simple frontmatter parsing (no external dependency)
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                # Parse frontmatter
                frontmatter = parts[1].strip()
                body = parts[2].strip()
                
                metadata = {}
                for line in frontmatter.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Parse lists
                        if value.startswith('[') and value.endswith(']'):
                            value = [v.strip().strip('"\'') for v in value[1:-1].split(',')]
                        
                        metadata[key] = value
                
                return {
                    'id': metadata.get('id', file_path.stem),
                    'title': metadata.get('title', file_path.stem),
                    'module': module,
                    'tags': metadata.get('tags', []),
                    'content': body
                }
        
        # No frontmatter, use filename as title
        return {
            'id': file_path.stem,
            'title': file_path.stem.replace('_', ' ').title(),
            'module': module,
            'tags': [module],
            'content': content
        }
    
    def _load_hardcoded_dte_docs(self):
        """
        BACKWARD COMPATIBILITY: Load hardcoded DTE docs.
        
        Preserves original functionality from knowledge_base.py
        """
        from chat.knowledge_base import KnowledgeBase
        
        # Use original KnowledgeBase to get hardcoded docs
        original_kb = KnowledgeBase()
        self.documents['l10n_cl_dte'] = original_kb.documents
        
        logger.info("loaded_hardcoded_dte_docs",
                   count=len(self.documents['l10n_cl_dte']))
    
    def search(
        self,
        query: str,
        top_k: int = 3,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Search documents (backward compatible).
        
        Args:
            query: Search query
            top_k: Number of results to return
            filters: Optional filters (e.g., {'module': 'l10n_cl_dte'})
        
        Returns:
            List of matching documents
        """
        module_filter = filters.get('module') if filters else None
        
        # Determine which documents to search
        if module_filter and module_filter in self.documents:
            docs_to_search = self.documents[module_filter]
        else:
            # Search all modules
            docs_to_search = []
            for module_docs in self.documents.values():
                docs_to_search.extend(module_docs)
        
        # Keyword search (same algorithm as before)
        results = self._keyword_search(query, docs_to_search, top_k)
        
        return results
    
    def _keyword_search(self, query: str, documents: List[Dict], top_k: int) -> List[Dict]:
        """
        Simple keyword-based search.
        
        PRESERVED from original knowledge_base.py
        """
        query_lower = query.lower()
        query_words = set(query_lower.split())
        
        scored_docs = []
        
        for doc in documents:
            score = 0.0
            
            # Search in title (weight: 3.0)
            title_lower = doc['title'].lower()
            if query_lower in title_lower:
                score += 3.0
            for word in query_words:
                if word in title_lower:
                    score += 1.5
            
            # Search in tags (weight: 2.0)
            tags_lower = [tag.lower() for tag in doc.get('tags', [])]
            for tag in tags_lower:
                if query_lower in tag:
                    score += 2.0
                for word in query_words:
                    if word in tag:
                        score += 1.0
            
            # Search in content (weight: 1.0)
            content_lower = doc['content'].lower()
            if query_lower in content_lower:
                score += 1.0
            for word in query_words:
                if word in content_lower:
                    score += 0.5
            
            if score > 0:
                scored_docs.append((score, doc))
        
        # Sort by score and return top_k
        scored_docs.sort(key=lambda x: x[0], reverse=True)
        
        return [doc for score, doc in scored_docs[:top_k]]
    
    def get_modules(self) -> List[str]:
        """Get list of available modules"""
        return list(self.documents.keys())
    
    def get_document_count(self, module: Optional[str] = None) -> int:
        """Get document count for module or total"""
        if module:
            return len(self.documents.get(module, []))
        return sum(len(docs) for docs in self.documents.values())
