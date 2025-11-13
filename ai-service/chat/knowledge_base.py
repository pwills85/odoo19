# -*- coding: utf-8 -*-
"""
Knowledge Base - DTE Operations Documentation
==============================================

In-memory knowledge base with DTE documentation for Chilean electronic invoicing.

Features:
- Simple keyword search (no embeddings needed)
- Module-based filtering
- Tag-based categorization
- Extensible (easy to add more docs)

Future:
- Load from Markdown files (/app/knowledge/*.md)
- External docs sync (official Odoo docs)
- Vector search (if justified by usage)
"""

from typing import List, Dict, Optional
import structlog

logger = structlog.get_logger(__name__)


class KnowledgeBase:
    """
    In-memory knowledge base for DTE operations.

    Storage:
    - documents: List[Dict] with {id, title, module, tags, content}
    - Indexed by tags for fast search

    Search:
    - Keyword matching (simple, fast)
    - Tag filtering
    - Module filtering
    """

    def __init__(self):
        self.documents = self._load_documents()
        logger.info("knowledge_base_initialized",
                   document_count=len(self.documents))

    def _load_documents(self) -> List[Dict]:
        """
        Load DTE documentation from markdown files.
        
        Attempts to load from /app/knowledge/*.md files (recursively).
        Falls back to hardcoded documents if directory doesn't exist or is empty.

        Returns:
            List of document dicts with keys: id, title, module, tags, content, file_path
        """
        # Try to load from markdown files first
        md_documents = self._load_documents_from_markdown()
        
        if md_documents:
            return md_documents
        
        # Fallback to minimal hardcoded documents
        logger.warning("knowledge_base_using_fallback",
                      message="No markdown files found, using minimal defaults")
        
        return [
            {
                'id': 'getting_started',
                'title': 'AI Service Getting Started',
                'module': 'general',
                'tags': ['intro', 'help'],
                'content': 'AI Service for Odoo 19 Chilean localization. Ask questions about DTE, Payroll, or general Odoo usage.',
                'file_path': 'builtin'
            }
        ]
    
    def _load_documents_from_markdown(self) -> List[Dict]:
        """
        Load knowledge base documents from markdown files.
        
        Reads all .md files in /app/knowledge/ directory (recursively) and parses
        frontmatter metadata using simple YAML parsing.
        
        Expected frontmatter format:
        ---
        title: Document Title
        module: module_name
        tags: [tag1, tag2, tag3]
        ---
        
        Returns:
            List[Dict]: List of document dictionaries
        """
        import os
        import re
        
        documents = []
        knowledge_dir = "/app/knowledge"
        
        if not os.path.exists(knowledge_dir):
            logger.warning("knowledge_directory_not_found", path=knowledge_dir)
            return []
        
        # Walk through all subdirectories
        for root, dirs, files in os.walk(knowledge_dir):
            for filename in files:
                if not filename.endswith('.md'):
                    continue
                
                file_path = os.path.join(root, filename)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_content = f.read()
                    
                    # Parse frontmatter (simple YAML-like format)
                    frontmatter_match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)$', file_content, re.DOTALL)
                    
                    if frontmatter_match:
                        # Extract frontmatter and content
                        frontmatter_text = frontmatter_match.group(1)
                        markdown_content = frontmatter_match.group(2)
                        
                        # Parse frontmatter fields
                        metadata = {}
                        for line in frontmatter_text.split('\n'):
                            if ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                
                                # Parse tags as list
                                if key == 'tags' and value.startswith('['):
                                    # Remove brackets and split
                                    value = value.strip('[]').replace(' ', '')
                                    metadata[key] = [tag.strip() for tag in value.split(',')]
                                else:
                                    metadata[key] = value
                    else:
                        # No frontmatter, use entire content
                        metadata = {}
                        markdown_content = file_content
                    
                    # Build document dict
                    doc_id = os.path.splitext(filename)[0]
                    
                    documents.append({
                        'id': doc_id,
                        'title': metadata.get('title', doc_id.replace('_', ' ').title()),
                        'module': metadata.get('module', 'general'),
                        'tags': metadata.get('tags', []),
                        'content': markdown_content.strip(),
                        'file_path': file_path
                    })
                    
                    logger.info("knowledge_document_loaded",
                               filename=filename,
                               module=metadata.get('module', 'general'),
                               tags_count=len(metadata.get('tags', [])))
                    
                except Exception as e:
                    logger.error("knowledge_document_load_failed",
                                filename=filename,
                                error=str(e))
                    continue
        
        logger.info("knowledge_base_documents_loaded",
                   total_documents=len(documents))
        
        return documents

    def search(
        self,
        query: str,
        top_k: int = 3,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Search knowledge base for relevant documents.

        Simple keyword matching (no embeddings).

        Args:
            query: User query
            top_k: Number of results to return
            filters: Optional filters {'module': 'l10n_cl_dte'}

        Returns:
            List of relevant documents (sorted by relevance)
        """
        query_lower = query.lower()

        # Filter by module if specified
        candidates = self.documents
        if filters and 'module' in filters:
            candidates = [d for d in candidates if d['module'] == filters['module']]

        # Score documents by keyword matches
        scored = []
        for doc in candidates:
            score = 0

            # Title match (high weight)
            if any(keyword in doc['title'].lower() for keyword in query_lower.split()):
                score += 10

            # Tag match (medium weight)
            for tag in doc['tags']:
                if tag in query_lower:
                    score += 5

            # Content match (low weight)
            content_lower = doc['content'].lower()
            for keyword in query_lower.split():
                if keyword in content_lower:
                    score += 1

            if score > 0:
                scored.append((score, doc))

        # Sort by score descending
        scored.sort(reverse=True, key=lambda x: x[0])

        # Return top K
        results = [doc for score, doc in scored[:top_k]]

        logger.info("knowledge_base_search",
                   query=query[:50],
                   results_found=len(results),
                   top_scores=[s for s, _ in scored[:3]])

        return results

    def get_all_tags(self) -> List[str]:
        """Get all unique tags in knowledge base."""
        tags = set()
        for doc in self.documents:
            tags.update(doc['tags'])
        return sorted(list(tags))

    def get_document_by_id(self, doc_id: str) -> Optional[Dict]:
        """Get specific document by ID."""
        for doc in self.documents:
            if doc['id'] == doc_id:
                return doc
        return None
