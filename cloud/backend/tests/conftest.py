"""
Pytest configuration and fixtures for integration tests
"""
import pytest
import asyncio
from typing import AsyncGenerator
from datetime import datetime
from unittest.mock import MagicMock, AsyncMock

# Test configuration
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=True)
    redis.hget = AsyncMock(return_value=None)
    redis.hset = AsyncMock(return_value=True)
    redis.expire = AsyncMock(return_value=True)
    return redis


@pytest.fixture
def mock_db_session():
    """Mock database session"""
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def sample_rule_content():
    """Sample Suricata rule for testing"""
    return '''alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS SQL Injection Attempt"; flow:established,to_server; content:"SELECT"; nocase; http_uri; content:"FROM"; nocase; http_uri; classtype:web-application-attack; sid:2001; rev:5;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Trojan Callback"; flow:established,to_server; content:"POST"; http_method; content:"/gate.php"; http_uri; classtype:trojan-activity; sid:2002; rev:3;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT SMB Buffer Overflow"; flow:established,to_server; content:"|00|"; offset:4; depth:1; classtype:attempted-admin; sid:2003; rev:2;)'''


@pytest.fixture
def sample_parsed_rules():
    """Sample parsed rules"""
    return [
        {
            "sid": 2001,
            "msg": "ET WEB_SPECIFIC_APPS SQL Injection Attempt",
            "classtype": "web-application-attack",
            "action": "alert",
            "protocol": "http",
            "content": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS SQL Injection Attempt"; flow:established,to_server; content:"SELECT"; nocase; http_uri; content:"FROM"; nocase; http_uri; classtype:web-application-attack; sid:2001; rev:5;)'
        },
        {
            "sid": 2002,
            "msg": "ET MALWARE Trojan Callback",
            "classtype": "trojan-activity",
            "action": "alert",
            "protocol": "http",
            "content": 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Trojan Callback"; flow:established,to_server; content:"POST"; http_method; content:"/gate.php"; http_uri; classtype:trojan-activity; sid:2002; rev:3;)'
        },
        {
            "sid": 2003,
            "msg": "ET EXPLOIT SMB Buffer Overflow",
            "classtype": "attempted-admin",
            "action": "alert",
            "protocol": "tcp",
            "content": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET EXPLOIT SMB Buffer Overflow"; flow:established,to_server; content:"|00|"; offset:4; depth:1; classtype:attempted-admin; sid:2003; rev:2;)'
        }
    ]


@pytest.fixture
def sample_attack_test():
    """Sample attack test data"""
    return {
        "test_id": "test-001",
        "name": "SQL Injection Test",
        "test_type": "single",
        "status": "pending",
        "total_rules": 1,
        "rule_sids": [2001],
        "probe_id": "probe-001",
        "config": {
            "timeout": 30,
            "retry_count": 3
        }
    }


@pytest.fixture
def sample_probe_task():
    """Sample probe task data"""
    return {
        "task_id": "task-001",
        "task_type": "attack",
        "probe_id": "probe-001",
        "status": "pending",
        "payload": {
            "test_id": "test-001",
            "rule_sid": 2001,
            "attack_type": "http",
            "payload": {
                "method": "GET",
                "path": "/search?q=SELECT%20*%20FROM%20users",
                "headers": {
                    "User-Agent": "AttackTool/1.0"
                }
            },
            "target": {
                "host": "127.0.0.1",
                "port": 80
            }
        }
    }
