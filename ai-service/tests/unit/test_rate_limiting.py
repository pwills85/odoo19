# -*- coding: utf-8 -*-
"""
Unit Tests for Rate Limiting Utilities
=======================================

Tests for rate limiting identifier function used by slowapi.

Author: EERGYGROUP - Gap Closure Sprint 2025-11-09
P3-2: Rate Limiting Tests
"""

import pytest
from unittest.mock import Mock
from main import get_user_identifier


class TestGetUserIdentifier:
    """Tests for get_user_identifier() - rate limiting key function."""

    def test_get_user_identifier_uses_api_key_and_ip(self):
        """MUST combine API key prefix + IP address for unique identification."""
        # Arrange
        request = Mock()
        request.headers = {"Authorization": "Bearer test_key_12345678"}
        request.client = Mock()
        request.client.host = "192.168.1.100"

        # Act
        identifier = get_user_identifier(request)

        # Assert
        assert identifier == "test_key:192.168.1.100"
        assert "test_key" in identifier  # First 8 chars of token
        assert "192.168.1.100" in identifier

    def test_get_user_identifier_handles_missing_api_key(self):
        """MUST handle requests without API key (anonymous users)."""
        # Arrange
        request = Mock()
        request.headers = {}  # No Authorization header
        request.client = Mock()
        request.client.host = "192.168.1.200"

        # Act
        identifier = get_user_identifier(request)

        # Assert
        assert identifier == "anonymous:192.168.1.200"
        assert "anonymous" in identifier

    def test_get_user_identifier_handles_invalid_bearer(self):
        """MUST handle malformed Authorization headers."""
        # Arrange
        request = Mock()
        request.headers = {"Authorization": "InvalidFormat"}
        request.client = Mock()
        request.client.host = "192.168.1.300"

        # Act
        identifier = get_user_identifier(request)

        # Assert
        assert identifier == "anonymous:192.168.1.300"

    def test_get_user_identifier_handles_empty_bearer(self):
        """MUST handle empty Bearer tokens."""
        # Arrange
        request = Mock()
        request.headers = {"Authorization": "Bearer "}
        request.client = Mock()
        request.client.host = "192.168.1.400"

        # Act
        identifier = get_user_identifier(request)

        # Assert
        assert identifier == "anonymous:192.168.1.400"

    def test_get_user_identifier_truncates_long_keys(self):
        """MUST truncate API keys to first 8 characters."""
        # Arrange
        request = Mock()
        request.headers = {"Authorization": "Bearer very_long_api_key_with_many_characters"}
        request.client = Mock()
        request.client.host = "192.168.1.500"

        # Act
        identifier = get_user_identifier(request)

        # Assert
        assert identifier == "very_lon:192.168.1.500"  # Only first 8 chars

    def test_get_user_identifier_handles_missing_client(self):
        """MUST handle requests without client info (edge case)."""
        # Arrange
        request = Mock()
        request.headers = {"Authorization": "Bearer test1234"}
        request.client = None

        # Act
        identifier = get_user_identifier(request)

        # Assert
        assert identifier == "test1234:unknown"
        assert "unknown" in identifier

    def test_get_user_identifier_different_ips_different_identifiers(self):
        """MUST generate different identifiers for same API key from different IPs."""
        # Arrange
        request1 = Mock()
        request1.headers = {"Authorization": "Bearer samekey1"}
        request1.client = Mock()
        request1.client.host = "192.168.1.1"

        request2 = Mock()
        request2.headers = {"Authorization": "Bearer samekey1"}
        request2.client = Mock()
        request2.client.host = "192.168.1.2"

        # Act
        identifier1 = get_user_identifier(request1)
        identifier2 = get_user_identifier(request2)

        # Assert
        assert identifier1 != identifier2
        assert identifier1 == "samekey1:192.168.1.1"
        assert identifier2 == "samekey1:192.168.1.2"

    def test_get_user_identifier_different_keys_same_ip_different_identifiers(self):
        """MUST generate different identifiers for different API keys from same IP."""
        # Arrange
        request1 = Mock()
        request1.headers = {"Authorization": "Bearer keyAAAAA"}
        request1.client = Mock()
        request1.client.host = "192.168.1.100"

        request2 = Mock()
        request2.headers = {"Authorization": "Bearer keyBBBBB"}
        request2.client = Mock()
        request2.client.host = "192.168.1.100"

        # Act
        identifier1 = get_user_identifier(request1)
        identifier2 = get_user_identifier(request2)

        # Assert
        assert identifier1 != identifier2
        assert identifier1 == "keyAAAAA:192.168.1.100"
        assert identifier2 == "keyBBBBB:192.168.1.100"

    def test_get_user_identifier_format_consistency(self):
        """MUST always return identifiers in api_key:ip format."""
        # Arrange
        request = Mock()
        request.headers = {"Authorization": "Bearer abc12345"}
        request.client = Mock()
        request.client.host = "10.0.0.1"

        # Act
        identifier = get_user_identifier(request)

        # Assert
        parts = identifier.split(":")
        assert len(parts) == 2
        assert parts[0]  # API key part not empty
        assert parts[1] == "10.0.0.1"  # IP part correct
