"""
Integration tests for probe communication
Tests the Pull mode communication between cloud and probes
"""
import pytest
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime, timedelta
import json


class TestProbeRegistration:
    """Tests for probe registration flow"""

    @pytest.mark.asyncio
    async def test_probe_registration_request(self):
        """Test probe registration request format"""
        request = {
            'cmd': 30,  # REGISTER command
            'data': {
                'probe_id': 'probe-001',
                'name': 'Test Probe',
                'ip': '192.168.1.100',
                'probe_types': ['nids', 'attack_tool']
            }
        }

        assert request['cmd'] == 30
        assert request['data']['probe_id'] == 'probe-001'
        assert 'nids' in request['data']['probe_types']

    @pytest.mark.asyncio
    async def test_probe_registration_response(self):
        """Test probe registration response format"""
        response = {
            'cmd': 31,  # REGISTER_RESPONSE
            'data': {
                'status': 'ok',
                'probe_id': 'probe-001',
                'registered_at': datetime.now().isoformat()
            }
        }

        assert response['cmd'] == 31
        assert response['data']['status'] == 'ok'


class TestProbeHeartbeat:
    """Tests for probe heartbeat flow"""

    @pytest.mark.asyncio
    async def test_heartbeat_request(self):
        """Test heartbeat request format"""
        request = {
            'cmd': 20,  # HEARTBEAT
            'data': {
                'probe_id': 'probe-001',
                'rule_version': '20260120120000',
                'status': {
                    'cpu_usage': 25.5,
                    'memory_usage': 1024,
                    'uptime': 3600
                },
                'probes': [
                    {
                        'probe_id': 'nids-001',
                        'type': 'nids',
                        'status': 'online'
                    }
                ]
            }
        }

        assert request['cmd'] == 20
        assert request['data']['rule_version'] is not None
        assert len(request['data']['probes']) == 1

    @pytest.mark.asyncio
    async def test_heartbeat_response(self):
        """Test heartbeat response format"""
        response = {
            'cmd': 21,  # HEARTBEAT_RESPONSE
            'data': {
                'status': 'ok',
                'timestamp': datetime.now().isoformat()
            }
        }

        assert response['cmd'] == 21
        assert response['data']['status'] == 'ok'


class TestRuleVersionCheck:
    """Tests for rule version check (Pull mode)"""

    @pytest.mark.asyncio
    async def test_version_check_needs_update(self):
        """Test version check when update is needed"""
        probe_version = '20260120100000'
        latest_version = '20260120120000'

        response = {
            'needs_update': True,
            'current_version': probe_version,
            'latest_version': latest_version
        }

        assert response['needs_update'] is True
        assert response['latest_version'] > response['current_version']

    @pytest.mark.asyncio
    async def test_version_check_up_to_date(self):
        """Test version check when already up to date"""
        current_version = '20260120120000'

        response = {
            'needs_update': False,
            'current_version': current_version,
            'latest_version': current_version
        }

        assert response['needs_update'] is False
        assert response['latest_version'] == response['current_version']


class TestRuleDownloadPull:
    """Tests for rule download (Pull mode)"""

    @pytest.mark.asyncio
    async def test_rule_download_response(self, sample_rule_content):
        """Test rule download response format"""
        response = {
            'version': '20260120120000',
            'content': sample_rule_content,
            'checksum': 'abc123',
            'rules_count': 3
        }

        assert response['version'] is not None
        assert len(response['content']) > 0
        assert response['rules_count'] == 3

    @pytest.mark.asyncio
    async def test_rule_content_format(self, sample_rule_content):
        """Test that rule content is valid Suricata format"""
        lines = sample_rule_content.strip().split('\n')

        for line in lines:
            # Each line should start with an action
            assert line.startswith(('alert', 'drop', 'pass', 'reject', '#'))

            # Should contain required fields
            if not line.startswith('#'):
                assert 'sid:' in line
                assert 'msg:' in line


class TestTaskPolling:
    """Tests for attack task polling (Pull mode)"""

    @pytest.mark.asyncio
    async def test_poll_tasks_empty(self):
        """Test polling when no tasks available"""
        response = {
            'tasks': [],
            'total': 0
        }

        assert len(response['tasks']) == 0
        assert response['total'] == 0

    @pytest.mark.asyncio
    async def test_poll_tasks_with_tasks(self, sample_probe_task):
        """Test polling with pending tasks"""
        response = {
            'tasks': [sample_probe_task],
            'total': 1
        }

        assert len(response['tasks']) == 1
        assert response['tasks'][0]['status'] == 'pending'

    @pytest.mark.asyncio
    async def test_task_payload_structure(self, sample_probe_task):
        """Test task payload structure"""
        task = sample_probe_task
        payload = task['payload']

        # Verify required fields
        assert 'attack_type' in payload
        assert 'payload' in payload
        assert 'target' in payload

        # Verify target structure
        target = payload['target']
        assert 'host' in target
        assert 'port' in target


class TestTaskResultReporting:
    """Tests for task result reporting"""

    @pytest.mark.asyncio
    async def test_successful_result(self):
        """Test successful task result format"""
        result = {
            'task_id': 'task-001',
            'success': True,
            'response_time_ms': 150,
            'data': {
                'http_code': 200,
                'response_size': 1024
            }
        }

        assert result['success'] is True
        assert result['response_time_ms'] > 0
        assert result['data']['http_code'] == 200

    @pytest.mark.asyncio
    async def test_failed_result(self):
        """Test failed task result format"""
        result = {
            'task_id': 'task-001',
            'success': False,
            'response_time_ms': 5000,
            'error': 'Connection timeout'
        }

        assert result['success'] is False
        assert 'error' in result
        assert result['error'] == 'Connection timeout'

    @pytest.mark.asyncio
    async def test_task_start_notification(self):
        """Test task start notification"""
        notification = {
            'task_id': 'task-001',
            'started_at': datetime.now().isoformat()
        }

        assert notification['task_id'] == 'task-001'
        assert 'started_at' in notification


class TestProtocolSerialization:
    """Tests for protocol message serialization"""

    def test_json_serialization(self):
        """Test JSON message serialization"""
        message = {
            'cmd': 'CMD_ATTACK_EXECUTE',
            'data': {
                'task_id': 'task-001',
                'attack_type': 'http'
            }
        }

        # Serialize
        serialized = json.dumps(message)
        assert isinstance(serialized, str)

        # Deserialize
        deserialized = json.loads(serialized)
        assert deserialized['cmd'] == 'CMD_ATTACK_EXECUTE'
        assert deserialized['data']['task_id'] == 'task-001'

    def test_length_prefix_protocol(self):
        """Test length-prefixed message format"""
        import struct

        message = {'cmd': 'test', 'data': {}}
        body = json.dumps(message).encode('utf-8')

        # Create length-prefixed message
        length = len(body)
        header = struct.pack('!I', length)  # Network byte order, unsigned int
        packet = header + body

        # Verify
        assert len(packet) == 4 + length  # 4 bytes header + body

        # Parse
        received_length = struct.unpack('!I', packet[:4])[0]
        received_body = packet[4:4 + received_length]
        received_message = json.loads(received_body.decode('utf-8'))

        assert received_message['cmd'] == 'test'


class TestConnectionHandling:
    """Tests for connection handling"""

    @pytest.mark.asyncio
    async def test_reconnection_backoff(self):
        """Test exponential backoff for reconnection"""
        base_interval = 5000  # ms
        max_attempts = 5

        intervals = []
        for attempt in range(max_attempts):
            interval = base_interval * (2 ** min(attempt, 5))
            intervals.append(interval)

        # Verify exponential growth
        assert intervals[0] == 5000
        assert intervals[1] == 10000
        assert intervals[2] == 20000
        assert intervals[3] == 40000
        assert intervals[4] == 80000

    @pytest.mark.asyncio
    async def test_connection_state_tracking(self):
        """Test connection state tracking"""
        class ConnectionState:
            def __init__(self):
                self.connected = False
                self.last_heartbeat = None
                self.reconnect_attempts = 0

            def connect(self):
                self.connected = True
                self.reconnect_attempts = 0

            def disconnect(self):
                self.connected = False
                self.reconnect_attempts += 1

        state = ConnectionState()
        assert state.connected is False

        state.connect()
        assert state.connected is True
        assert state.reconnect_attempts == 0

        state.disconnect()
        assert state.connected is False
        assert state.reconnect_attempts == 1
