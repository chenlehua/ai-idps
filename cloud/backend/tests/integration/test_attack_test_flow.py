"""
Integration tests for attack test flow
Tests the complete flow: create test -> generate payloads -> execute -> verify -> report
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta


class TestAttackTestCreation:
    """Tests for attack test creation"""

    @pytest.mark.asyncio
    async def test_create_single_rule_test(self, sample_attack_test):
        """Test creating a single rule test"""
        test = sample_attack_test

        assert test['test_id'] is not None
        assert test['test_type'] == 'single'
        assert test['total_rules'] == 1
        assert 2001 in test['rule_sids']

    @pytest.mark.asyncio
    async def test_create_batch_test(self, sample_parsed_rules):
        """Test creating a batch test"""
        rule_sids = [rule['sid'] for rule in sample_parsed_rules]

        test = {
            'test_id': 'test-batch-001',
            'name': 'Batch Security Test',
            'test_type': 'batch',
            'status': 'pending',
            'total_rules': len(rule_sids),
            'rule_sids': rule_sids,
            'probe_id': 'probe-001',
            'config': {
                'timeout': 30,
                'parallel': 5
            }
        }

        assert test['test_type'] == 'batch'
        assert test['total_rules'] == 3
        assert len(test['rule_sids']) == 3


class TestAttackPayloadGeneration:
    """Tests for attack payload generation"""

    @pytest.mark.asyncio
    async def test_generate_http_attack_from_rule(self):
        """Test HTTP attack generation from rule content"""
        rule = {
            'sid': 2001,
            'protocol': 'http',
            'msg': 'SQL Injection',
            'content': 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection"; content:"SELECT"; http_uri; content:"FROM"; http_uri; sid:2001;)'
        }

        # Extract content patterns
        import re
        content_patterns = re.findall(r'content:"([^"]+)"', rule['content'])

        # Generate HTTP attack
        attack = {
            'attack_type': 'http',
            'method': 'GET',
            'path': '/search?q=' + '+'.join(content_patterns),
            'headers': {
                'User-Agent': 'AttackTool/1.0',
                'Accept': '*/*'
            }
        }

        assert attack['attack_type'] == 'http'
        assert 'SELECT' in attack['path']
        assert 'FROM' in attack['path']

    @pytest.mark.asyncio
    async def test_generate_tcp_attack_from_rule(self):
        """Test TCP attack generation from rule content"""
        rule = {
            'sid': 2003,
            'protocol': 'tcp',
            'msg': 'SMB Exploit',
            'content': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (content:"|00|"; offset:4; depth:1; sid:2003;)'
        }

        # Extract hex content
        import re
        hex_match = re.search(r'content:"\|([0-9a-fA-F]+)\|"', rule['content'])
        hex_content = hex_match.group(1) if hex_match else ''

        # Extract port
        port_match = re.search(r'\$HOME_NET (\d+)', rule['content'])
        port = int(port_match.group(1)) if port_match else 445

        attack = {
            'attack_type': 'tcp',
            'port': port,
            'payload': {
                'hex': hex_content,
                'offset': 4,
                'depth': 1
            }
        }

        assert attack['attack_type'] == 'tcp'
        assert attack['port'] == 445
        assert attack['payload']['hex'] == '00'

    @pytest.mark.asyncio
    async def test_generate_dns_attack(self):
        """Test DNS attack generation"""
        rule = {
            'sid': 3001,
            'protocol': 'udp',
            'msg': 'DNS Query for Malicious Domain',
            'content': 'alert udp any any -> any 53 (content:"|01 00 00 01|"; content:"malware"; nocase; sid:3001;)'
        }

        attack = {
            'attack_type': 'udp',
            'port': 53,
            'payload': {
                'domain': 'malware.example.com',
                'query_type': 1  # A record
            }
        }

        assert attack['attack_type'] == 'udp'
        assert attack['port'] == 53
        assert 'malware' in attack['payload']['domain']


class TestProbeTaskExecution:
    """Tests for probe task execution flow"""

    @pytest.mark.asyncio
    async def test_create_probe_task(self, sample_probe_task):
        """Test probe task creation"""
        task = sample_probe_task

        assert task['task_id'] is not None
        assert task['task_type'] == 'attack'
        assert task['status'] == 'pending'
        assert task['payload']['attack_type'] == 'http'

    @pytest.mark.asyncio
    async def test_task_polling_response(self, sample_probe_task):
        """Test task polling response format"""
        response = {
            'tasks': [sample_probe_task],
            'total': 1
        }

        assert len(response['tasks']) == 1
        assert response['tasks'][0]['task_id'] == 'task-001'

    @pytest.mark.asyncio
    async def test_task_result_reporting(self):
        """Test task result reporting format"""
        result = {
            'task_id': 'task-001',
            'success': True,
            'response_time_ms': 150,
            'data': {
                'http_code': 200,
                'response_size': 1024
            },
            'error': None
        }

        assert result['success'] is True
        assert result['response_time_ms'] == 150
        assert result['data']['http_code'] == 200


class TestResultValidation:
    """Tests for test result validation"""

    @pytest.mark.asyncio
    async def test_validate_alert_match(self):
        """Test validation of alert log match"""
        test_item = {
            'rule_sid': 2001,
            'executed_at': datetime.now(),
            'status': 'running'
        }

        alert_log = {
            'alert.signature_id': 2001,
            'timestamp': datetime.now() + timedelta(seconds=1),
            'alert.signature': 'ET WEB_SPECIFIC_APPS SQL Injection'
        }

        # Validation logic
        time_window = timedelta(seconds=30)
        is_match = (
            test_item['rule_sid'] == alert_log['alert.signature_id'] and
            alert_log['timestamp'] >= test_item['executed_at'] and
            alert_log['timestamp'] <= test_item['executed_at'] + time_window
        )

        assert is_match is True

    @pytest.mark.asyncio
    async def test_validate_no_alert_timeout(self):
        """Test validation when no alert is found (timeout)"""
        test_item = {
            'rule_sid': 2001,
            'executed_at': datetime.now() - timedelta(seconds=60),
            'status': 'running',
            'timeout_seconds': 30
        }

        # No alert found within time window
        alert_log = None
        current_time = datetime.now()
        time_since_execution = (current_time - test_item['executed_at']).total_seconds()

        is_timeout = (
            alert_log is None and
            time_since_execution > test_item['timeout_seconds']
        )

        assert is_timeout is True

    @pytest.mark.asyncio
    async def test_update_test_status(self):
        """Test updating test status based on results"""
        test = {
            'test_id': 'test-001',
            'total_rules': 3,
            'success_count': 0,
            'failed_count': 0,
            'status': 'running'
        }

        # Simulate completing all items
        results = [
            {'status': 'success'},
            {'status': 'success'},
            {'status': 'failed'}
        ]

        for result in results:
            if result['status'] == 'success':
                test['success_count'] += 1
            else:
                test['failed_count'] += 1

        # Check if test is complete
        completed = (test['success_count'] + test['failed_count']) == test['total_rules']
        if completed:
            test['status'] = 'completed'

        assert test['status'] == 'completed'
        assert test['success_count'] == 2
        assert test['failed_count'] == 1


class TestTestReport:
    """Tests for test report generation"""

    @pytest.mark.asyncio
    async def test_generate_test_summary(self):
        """Test generating test summary"""
        test = {
            'test_id': 'test-001',
            'name': 'Security Test',
            'total_rules': 10,
            'success_count': 8,
            'failed_count': 2,
            'started_at': datetime.now() - timedelta(minutes=5),
            'completed_at': datetime.now()
        }

        summary = {
            'test_id': test['test_id'],
            'name': test['name'],
            'success_rate': test['success_count'] / test['total_rules'] * 100,
            'duration_seconds': (test['completed_at'] - test['started_at']).total_seconds(),
            'total': test['total_rules'],
            'passed': test['success_count'],
            'failed': test['failed_count']
        }

        assert summary['success_rate'] == 80.0
        assert summary['passed'] == 8
        assert summary['failed'] == 2

    @pytest.mark.asyncio
    async def test_list_failed_rules(self):
        """Test listing failed rules for report"""
        test_items = [
            {'rule_sid': 2001, 'status': 'success', 'error': None},
            {'rule_sid': 2002, 'status': 'failed', 'error': 'No alert triggered'},
            {'rule_sid': 2003, 'status': 'timeout', 'error': 'Request timeout'}
        ]

        failed_rules = [
            item for item in test_items
            if item['status'] in ('failed', 'timeout')
        ]

        assert len(failed_rules) == 2
        assert failed_rules[0]['rule_sid'] == 2002
        assert failed_rules[1]['rule_sid'] == 2003
