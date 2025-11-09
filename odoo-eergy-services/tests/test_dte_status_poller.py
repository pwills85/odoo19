# -*- coding: utf-8 -*-
"""
Unit Tests for DTE Status Poller
Tests automatic polling functionality
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock


class TestDTEStatusPoller:
    """Tests for DTE status poller"""

    def test_poller_initialization(self, mock_sii_client, mock_redis_client):
        """Test poller initializes correctly"""
        from scheduler.dte_status_poller import DTEStatusPoller

        poller = DTEStatusPoller(
            sii_client=mock_sii_client,
            redis_url='redis://localhost:6379/15',
            poll_interval_minutes=15
        )

        assert poller.sii_client == mock_sii_client
        assert poller.poll_interval == 15
        assert poller.scheduler is not None

    def test_poller_start_creates_job(self, mock_sii_client, mock_redis_client):
        """Test that start() creates APScheduler job"""
        from scheduler.dte_status_poller import DTEStatusPoller

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            poller = DTEStatusPoller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=10
            )

            poller.start()

            # Verify scheduler was started
            assert poller.scheduler.running == True

            # Cleanup
            poller.stop()

    def test_get_pending_dtes_from_redis(self, mock_sii_client, mock_redis_client):
        """Test retrieval of pending DTEs from Redis"""
        from scheduler.dte_status_poller import DTEStatusPoller

        # Setup Redis with pending DTEs
        dte1 = {
            'id': '1',
            'track_id': 'TRACK_001',
            'rut_emisor': '76123456-K',
            'status': 'sent',
            'timestamp': datetime.now().isoformat()
        }

        dte2 = {
            'id': '2',
            'track_id': 'TRACK_002',
            'rut_emisor': '76123456-K',
            'status': 'sent',
            'timestamp': datetime.now().isoformat()
        }

        mock_redis_client._data = {
            'dte:pending:TRACK_001': json.dumps(dte1),
            'dte:pending:TRACK_002': json.dumps(dte2)
        }

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            poller = DTEStatusPoller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=15
            )

            pending_dtes = poller._get_pending_dtes()

            assert len(pending_dtes) == 2
            assert pending_dtes[0]['track_id'] == 'TRACK_001'
            assert pending_dtes[1]['track_id'] == 'TRACK_002'

    def test_poll_dte_status_updates_redis(self, mock_sii_client, mock_redis_client):
        """Test that polling updates DTE status in Redis"""
        from scheduler.dte_status_poller import DTEStatusPoller

        # Mock SII returning accepted status
        mock_sii_client.query_status = Mock(return_value={
            'success': True,
            'status': 'accepted',
            'response_xml': '<SII>ACCEPTED</SII>'
        })

        dte = {
            'id': '1',
            'track_id': 'TRACK_001',
            'rut_emisor': '76123456-K',
            'status': 'sent',
            'timestamp': datetime.now().isoformat()
        }

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            poller = DTEStatusPoller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=15
            )

            result = poller._poll_dte_status(dte)

            # Should indicate update occurred
            assert result['updated'] == True
            assert result['new_status'] == 'accepted'

            # Verify Redis was updated
            # Should be moved to completed
            assert 'dte:completed:TRACK_001' in mock_redis_client._data

    def test_timeout_detection_for_old_dtes(self, mock_sii_client, mock_redis_client):
        """Test that DTEs older than 7 days are marked as timeout"""
        from scheduler.dte_status_poller import DTEStatusPoller

        # Create DTE older than 7 days
        old_timestamp = (datetime.now() - timedelta(days=8)).isoformat()

        dte = {
            'id': '1',
            'track_id': 'TRACK_OLD',
            'rut_emisor': '76123456-K',
            'status': 'sent',
            'timestamp': old_timestamp
        }

        mock_redis_client._data = {
            'dte:pending:TRACK_OLD': json.dumps(dte)
        }

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            poller = DTEStatusPoller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=15
            )

            pending_dtes = poller._get_pending_dtes()

            # Should be empty (old DTE removed)
            assert len(pending_dtes) == 0

            # Should be in timeout
            assert 'dte:timeout:TRACK_OLD' in mock_redis_client._data

            # Should not be in pending anymore
            assert 'dte:pending:TRACK_OLD' not in mock_redis_client._data

    def test_webhook_notification_to_odoo(self, mock_sii_client, mock_redis_client):
        """Test webhook notification when status changes"""
        from scheduler.dte_status_poller import DTEStatusPoller

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            with patch('scheduler.dte_status_poller.requests.post') as mock_post:
                mock_post.return_value.status_code = 200

                poller = DTEStatusPoller(
                    sii_client=mock_sii_client,
                    redis_url='redis://localhost:6379/15',
                    poll_interval_minutes=15
                )

                dte = {
                    'id': '1',
                    'track_id': 'TRACK_001',
                    'status': 'sent'
                }

                sii_response = {
                    'success': True,
                    'status': 'accepted'
                }

                poller._notify_odoo(dte, 'accepted', sii_response)

                # Verify webhook was called
                assert mock_post.called
                call_args = mock_post.call_args

                # Verify payload structure
                payload = call_args[1]['json']
                assert payload['dte_id'] == '1'
                assert payload['new_status'] == 'accepted'
                assert payload['track_id'] == 'TRACK_001'

    def test_poll_pending_dtes_main_workflow(self, mock_sii_client, mock_redis_client):
        """Test the main polling workflow"""
        from scheduler.dte_status_poller import DTEStatusPoller

        # Setup test data
        dte1 = {
            'id': '1',
            'track_id': 'TRACK_001',
            'rut_emisor': '76123456-K',
            'status': 'sent',
            'timestamp': datetime.now().isoformat()
        }

        dte2 = {
            'id': '2',
            'track_id': 'TRACK_002',
            'rut_emisor': '76123456-K',
            'status': 'sent',
            'timestamp': datetime.now().isoformat()
        }

        mock_redis_client._data = {
            'dte:pending:TRACK_001': json.dumps(dte1),
            'dte:pending:TRACK_002': json.dumps(dte2)
        }

        # Mock SII responses
        def mock_query(track_id, rut):
            if track_id == 'TRACK_001':
                return {'success': True, 'status': 'accepted'}
            else:
                return {'success': True, 'status': 'sent'}  # No change

        mock_sii_client.query_status = Mock(side_effect=lambda t, r: mock_query(t, r))

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            with patch('scheduler.dte_status_poller.requests.post'):
                poller = DTEStatusPoller(
                    sii_client=mock_sii_client,
                    redis_url='redis://localhost:6379/15',
                    poll_interval_minutes=15
                )

                # Run polling job
                poller.poll_pending_dtes()

                # Verify SII was queried for both
                assert mock_sii_client.query_status.call_count == 2

                # Verify TRACK_001 was moved to completed
                assert 'dte:completed:TRACK_001' in mock_redis_client._data

                # Verify TRACK_002 still in pending
                assert 'dte:pending:TRACK_002' in mock_redis_client._data

    def test_graceful_shutdown(self, mock_sii_client, mock_redis_client):
        """Test that poller shuts down gracefully"""
        from scheduler.dte_status_poller import DTEStatusPoller

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            poller = DTEStatusPoller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=15
            )

            poller.start()
            assert poller.scheduler.running == True

            # Stop should shutdown cleanly
            poller.stop()
            assert poller.scheduler.running == False

    def test_error_handling_in_polling(self, mock_sii_client, mock_redis_client):
        """Test error handling during polling"""
        from scheduler.dte_status_poller import DTEStatusPoller

        # Setup DTE
        dte = {
            'id': '1',
            'track_id': 'TRACK_001',
            'rut_emisor': '76123456-K',
            'status': 'sent',
            'timestamp': datetime.now().isoformat()
        }

        mock_redis_client._data = {
            'dte:pending:TRACK_001': json.dumps(dte)
        }

        # Mock SII error
        mock_sii_client.query_status = Mock(side_effect=Exception("SII connection error"))

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            poller = DTEStatusPoller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=15
            )

            # Should not raise, should log error
            try:
                poller.poll_pending_dtes()
                # Should complete without raising
                assert True
            except Exception as e:
                pytest.fail(f"Polling should handle errors gracefully, but raised: {e}")


class TestPollerHelperFunctions:
    """Tests for poller helper functions"""

    def test_init_poller_creates_instance(self, mock_sii_client):
        """Test init_poller helper function"""
        from scheduler import init_poller

        with patch('scheduler.dte_status_poller.redis.from_url'):
            poller = init_poller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=20
            )

            assert poller is not None
            assert poller.poll_interval == 20

            # Cleanup
            poller.stop()

    def test_shutdown_poller_stops_instance(self, mock_sii_client):
        """Test shutdown_poller helper function"""
        from scheduler import init_poller, shutdown_poller

        with patch('scheduler.dte_status_poller.redis.from_url'):
            poller = init_poller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=15
            )

            assert poller.scheduler.running == True

            # Shutdown should stop scheduler
            shutdown_poller()

            # Global poller should be None now
            from scheduler import dte_poller
            assert dte_poller is None


class TestPollerPerformance:
    """Performance tests for poller"""

    @pytest.mark.slow
    def test_polling_performance_with_many_dtes(self, mock_sii_client, mock_redis_client):
        """Test polling performance with 100 DTEs"""
        import time
        from scheduler.dte_status_poller import DTEStatusPoller

        # Create 100 pending DTEs
        for i in range(100):
            dte = {
                'id': str(i),
                'track_id': f'TRACK_{i:04d}',
                'rut_emisor': '76123456-K',
                'status': 'sent',
                'timestamp': datetime.now().isoformat()
            }
            mock_redis_client._data[f'dte:pending:TRACK_{i:04d}'] = json.dumps(dte)

        # Mock fast SII responses
        mock_sii_client.query_status = Mock(return_value={
            'success': True,
            'status': 'sent'  # No changes
        })

        with patch('scheduler.dte_status_poller.redis.from_url', return_value=mock_redis_client):
            poller = DTEStatusPoller(
                sii_client=mock_sii_client,
                redis_url='redis://localhost:6379/15',
                poll_interval_minutes=15
            )

            start = time.time()
            poller.poll_pending_dtes()
            duration = time.time() - start

            # Should complete in < 10 seconds even with 100 DTEs (mocked)
            assert duration < 10

            # All DTEs should have been queried
            assert mock_sii_client.query_status.call_count == 100
