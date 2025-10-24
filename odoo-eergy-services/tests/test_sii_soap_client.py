# -*- coding: utf-8 -*-
"""
Unit Tests for SII SOAP Client
Tests communication with SII web services
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from requests.exceptions import ConnectionError, Timeout
from zeep.exceptions import Fault


class TestSIISoapClient:
    """Tests for SII SOAP client"""

    def test_client_initialization(self):
        """Test that client initializes correctly"""
        with patch('clients.sii_soap_client.Client') as mock_client_class:
            from clients.sii_soap_client import SIISoapClient

            wsdl_url = 'https://maullin.sii.cl/DTEWS/CrSeed.jws?WSDL'
            client = SIISoapClient(wsdl_url=wsdl_url, timeout=60)

            assert client.wsdl_url == wsdl_url
            assert client.timeout == 60
            mock_client_class.assert_called_once()

    def test_send_dte_success(self, mock_sii_client, sample_dte_xml):
        """Test successful DTE sending"""
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)
            client.client = mock_sii_client

            # Mock SOAP response
            mock_response = Mock()
            mock_response.TRACKID = 'TEST_TRACK_12345'
            mock_response.ESTADO = 'EPR'  # En Proceso
            mock_sii_client.service.EnvioDTE = Mock(return_value=mock_response)

            result = client.send_dte(sample_dte_xml, 'test')

            assert result['success'] == True
            assert result['track_id'] == 'TEST_TRACK_12345'
            assert 'duration_ms' in result

    def test_send_dte_with_retry_on_timeout(self, sample_dte_xml):
        """Test retry logic on timeout"""
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)

            # Mock service that fails twice then succeeds
            mock_service = Mock()
            mock_response = Mock()
            mock_response.TRACKID = 'TRACK_AFTER_RETRY'
            mock_response.ESTADO = 'EPR'

            mock_service.EnvioDTE = Mock(
                side_effect=[
                    Timeout("Timeout 1"),
                    Timeout("Timeout 2"),
                    mock_response  # Success on 3rd attempt
                ]
            )

            client.client = Mock()
            client.client.service = mock_service

            # Should succeed after retries
            result = client.send_dte(sample_dte_xml, '76123456-K')

            # Verify 3 attempts were made
            assert mock_service.EnvioDTE.call_count == 3
            assert result['success'] == True
            assert result['track_id'] == 'TRACK_AFTER_RETRY'

    def test_send_dte_fails_after_max_retries(self, sample_dte_xml):
        """Test that send fails after max retries"""
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)

            mock_service = Mock()
            mock_service.EnvioDTE = Mock(side_effect=Timeout("Always timeout"))

            client.client = Mock()
            client.client.service = mock_service

            # Should raise Timeout after 3 attempts
            with pytest.raises(Timeout):
                client.send_dte(sample_dte_xml, '76123456-K')

            # Verify exactly 3 attempts
            assert mock_service.EnvioDTE.call_count == 3

    def test_send_dte_handles_soap_fault(self, sample_dte_xml):
        """Test handling of SOAP faults from SII"""
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)

            mock_service = Mock()
            fault = Fault(message="RUT Incorrecto")
            fault.code = 'RCT'
            mock_service.EnvioDTE = Mock(side_effect=fault)

            client.client = Mock()
            client.client.service = mock_service

            result = client.send_dte(sample_dte_xml, '76123456-K')

            # Should return error dict, not raise
            assert result['success'] == False
            assert 'error_code' in result
            assert 'error_message' in result

    def test_query_status_success(self):
        """Test successful status query"""
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)

            mock_service = Mock()
            mock_response = Mock()
            mock_response.ESTADO = 'ACE'  # Aceptado
            mock_service.QueryEstDte = Mock(return_value=mock_response)

            client.client = Mock()
            client.client.service = mock_service

            result = client.query_status('TRACK123', '76123456-K')

            assert result['success'] == True
            assert result['status'] == 'ACE'
            assert result['track_id'] == 'TRACK123'

    def test_get_received_dte_success(self):
        """Test GetDTE for receiving supplier DTEs"""
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)

            # Mock response with DTEs
            mock_service = Mock()
            mock_dte = Mock()
            mock_dte.Folio = '12345'
            mock_dte.TipoDTE = '33'
            mock_dte.RUTEmisor = '12345678-9'
            mock_dte.FechaEmision = '2025-10-21'
            mock_dte.MontoTotal = 119000
            mock_dte.Estado = 'RECIBIDO'

            mock_response = Mock()
            mock_response.DTE = [mock_dte]
            mock_service.GetDTE = Mock(return_value=mock_response)

            client.client = Mock()
            client.client.service = mock_service

            result = client.get_received_dte('76123456-K', dte_type='33')

            assert result['success'] == True
            assert result['count'] == 1
            assert len(result['dtes']) == 1
            assert result['dtes'][0]['folio'] == '12345'

    def test_extract_dv_from_rut(self):
        """Test RUT DV extraction"""
        from clients.sii_soap_client import SIISoapClient

        client = SIISoapClient(wsdl_url='test', timeout=60)

        # Test with hyphen
        dv = client._extract_dv('76123456-K')
        assert dv == 'K'

        # Test without hyphen (last char)
        dv = client._extract_dv('761234569')
        assert dv == '9'


class TestSIIErrorHandling:
    """Tests for SII error code handling"""

    @pytest.mark.parametrize('error_code,expected_level', [
        ('0', 'success'),
        ('RCT', 'error'),
        ('RFR', 'error'),
        ('EPR', 'info'),
    ])
    def test_error_code_interpretation(self, error_code, expected_level):
        """Test that error codes are correctly interpreted"""
        from utils.sii_error_codes import interpret_sii_error

        result = interpret_sii_error(error_code)

        assert result['level'] == expected_level
        assert 'message' in result
        assert 'action' in result

    def test_retriable_error_detection(self):
        """Test detection of retriable errors"""
        from utils.sii_error_codes import is_retriable_error

        # Network errors should be retriable
        assert is_retriable_error('RE1') == True  # Connection error

        # Business logic errors should not be retriable
        assert is_retriable_error('RCT') == False  # RUT incorrecto

    def test_user_friendly_messages(self):
        """Test user-friendly error messages"""
        from utils.sii_error_codes import interpret_sii_error

        result = interpret_sii_error('RFR')

        # Should have user-friendly message
        assert 'user_message' in result or 'message' in result
        message = result.get('user_message', result.get('message'))
        assert len(message) > 10  # Should be descriptive


class TestSIIPerformance:
    """Performance tests for SII client"""

    @pytest.mark.slow
    def test_send_dte_performance(self, sample_dte_xml, performance_threshold):
        """Test that SOAP send completes within threshold"""
        import time
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)

            mock_service = Mock()
            mock_response = Mock()
            mock_response.TRACKID = 'TRACK'
            mock_response.ESTADO = 'EPR'
            mock_service.EnvioDTE = Mock(return_value=mock_response)

            client.client = Mock()
            client.client.service = mock_service

            start = time.time()
            client.send_dte(sample_dte_xml, '76123456-K')
            duration_ms = (time.time() - start) * 1000

            # Should be fast with mocked SOAP (< 100ms)
            assert duration_ms < 100


class TestIntegrationWithRetry:
    """Integration tests for retry logic"""

    def test_exponential_backoff_timing(self, sample_dte_xml):
        """Test that exponential backoff is applied correctly"""
        import time
        with patch('clients.sii_soap_client.Client'):
            from clients.sii_soap_client import SIISoapClient

            client = SIISoapClient(wsdl_url='test_wsdl', timeout=60)

            mock_service = Mock()
            mock_response = Mock()
            mock_response.TRACKID = 'TRACK'
            mock_response.ESTADO = 'EPR'

            # Fail twice, then succeed
            call_times = []

            def record_time(*args, **kwargs):
                call_times.append(time.time())
                if len(call_times) < 3:
                    raise Timeout("Timeout")
                return mock_response

            mock_service.EnvioDTE = Mock(side_effect=record_time)

            client.client = Mock()
            client.client.service = mock_service

            client.send_dte(sample_dte_xml, '76123456-K')

            # Verify backoff timing (should be ~4s, ~8s between retries)
            if len(call_times) >= 3:
                gap1 = call_times[1] - call_times[0]
                gap2 = call_times[2] - call_times[1]

                # First retry should wait ~4 seconds
                assert gap1 >= 3.5  # Allow some tolerance

                # Second retry should wait ~8 seconds
                assert gap2 >= 7.5
