"""
Tests para SII Scraper
"""

import pytest
from sii_monitor.scraper import SIIScraper, Document
from datetime import datetime


def test_scraper_initialization():
    """Test inicialización del scraper"""
    scraper = SIIScraper(timeout=30, rate_limit=1.0)
    
    assert scraper.timeout == 30
    assert scraper.rate_limit == 1.0
    assert scraper.session is not None


def test_calculate_hash():
    """Test cálculo de hash"""
    content1 = "Test content"
    content2 = "Test content"
    content3 = "Different content"
    
    hash1 = SIIScraper._calculate_hash(content1)
    hash2 = SIIScraper._calculate_hash(content2)
    hash3 = SIIScraper._calculate_hash(content3)
    
    assert hash1 == hash2
    assert hash1 != hash3
    assert len(hash1) == 64  # SHA256


def test_detect_changes():
    """Test detección de cambios"""
    scraper = SIIScraper()
    
    # Primera vez (sin hash previo)
    assert scraper.detect_changes("newhash", None) == True
    
    # Sin cambios
    assert scraper.detect_changes("samehash", "samehash") == False
    
    # Con cambios
    assert scraper.detect_changes("newhash", "oldhash") == True


def test_document_creation():
    """Test creación de Document"""
    doc = Document(
        url="https://test.com",
        html="<html></html>",
        title="Test",
        content_hash="abc123",
        scraped_at=datetime.now()
    )
    
    assert doc.url == "https://test.com"
    assert doc.title == "Test"
    
    doc_dict = doc.to_dict()
    assert 'url' in doc_dict
    assert 'title' in doc_dict


# Para ejecutar: pytest sii_monitor/tests/test_scraper.py -v
