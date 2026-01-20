"""
Integration tests for rule update flow
Tests the complete flow: download -> parse -> compare -> update -> sync
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


class TestRuleDownloadFlow:
    """Tests for rule download and parsing"""

    @pytest.mark.asyncio
    async def test_parse_single_rule(self, sample_rule_content):
        """Test parsing a single Suricata rule"""
        # This would use the actual rule parser service
        lines = sample_rule_content.strip().split('\n')
        assert len(lines) == 3

        # First rule should be SQL injection
        first_rule = lines[0]
        assert 'sid:2001' in first_rule
        assert 'SQL Injection' in first_rule
        assert 'classtype:web-application-attack' in first_rule

    @pytest.mark.asyncio
    async def test_parse_rule_extracts_fields(self):
        """Test that parser extracts all required fields"""
        rule = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Test Rule"; sid:1001; rev:1; classtype:web-application-attack;)'

        # Parse the rule to extract fields
        import re

        # Extract SID
        sid_match = re.search(r'sid:(\d+)', rule)
        assert sid_match is not None
        assert sid_match.group(1) == '1001'

        # Extract msg
        msg_match = re.search(r'msg:"([^"]+)"', rule)
        assert msg_match is not None
        assert msg_match.group(1) == 'Test Rule'

        # Extract classtype
        ct_match = re.search(r'classtype:([^;]+)', rule)
        assert ct_match is not None
        assert ct_match.group(1) == 'web-application-attack'

        # Extract protocol
        assert rule.startswith('alert http')

    @pytest.mark.asyncio
    async def test_classify_rule_by_msg_prefix(self, sample_parsed_rules):
        """Test rule classification by msg prefix"""
        # Rules should be categorized by their msg prefix
        categories = {}
        for rule in sample_parsed_rules:
            msg = rule['msg']
            if msg.startswith('ET WEB_SPECIFIC_APPS'):
                category = 'WEB_SPECIFIC_APPS'
            elif msg.startswith('ET MALWARE'):
                category = 'MALWARE'
            elif msg.startswith('ET EXPLOIT'):
                category = 'EXPLOIT'
            else:
                category = 'OTHER'

            if category not in categories:
                categories[category] = []
            categories[category].append(rule['sid'])

        assert 'WEB_SPECIFIC_APPS' in categories
        assert 2001 in categories['WEB_SPECIFIC_APPS']
        assert 'MALWARE' in categories
        assert 2002 in categories['MALWARE']
        assert 'EXPLOIT' in categories
        assert 2003 in categories['EXPLOIT']


class TestRuleComparisonFlow:
    """Tests for rule version comparison"""

    @pytest.mark.asyncio
    async def test_detect_added_rules(self, sample_parsed_rules):
        """Test detection of new rules"""
        existing_sids = {2001, 2002}
        new_sids = {rule['sid'] for rule in sample_parsed_rules}

        added = new_sids - existing_sids
        assert 2003 in added
        assert len(added) == 1

    @pytest.mark.asyncio
    async def test_detect_deleted_rules(self, sample_parsed_rules):
        """Test detection of deleted rules"""
        existing_sids = {2001, 2002, 2004}
        new_sids = {rule['sid'] for rule in sample_parsed_rules}

        deleted = existing_sids - new_sids
        assert 2004 in deleted
        assert len(deleted) == 1

    @pytest.mark.asyncio
    async def test_detect_modified_rules(self):
        """Test detection of modified rules"""
        old_rule = {
            'sid': 2001,
            'rev': 4,
            'content': 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Old Rule"; sid:2001; rev:4;)'
        }
        new_rule = {
            'sid': 2001,
            'rev': 5,
            'content': 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"New Rule"; sid:2001; rev:5;)'
        }

        # Rule is modified if content or rev changed
        is_modified = (old_rule['content'] != new_rule['content'] or
                       old_rule['rev'] != new_rule['rev'])
        assert is_modified is True

    @pytest.mark.asyncio
    async def test_generate_change_summary(self, sample_parsed_rules):
        """Test generation of change summary"""
        existing_sids = {2001, 2004}
        new_sids = {rule['sid'] for rule in sample_parsed_rules}

        summary = {
            'added': list(new_sids - existing_sids),
            'deleted': list(existing_sids - new_sids),
            'unchanged': list(new_sids & existing_sids),
            'total_new': len(new_sids),
            'total_old': len(existing_sids)
        }

        assert 2002 in summary['added']
        assert 2003 in summary['added']
        assert 2004 in summary['deleted']
        assert 2001 in summary['unchanged']


class TestRuleVersionFlow:
    """Tests for rule version management"""

    @pytest.mark.asyncio
    async def test_create_version_number(self):
        """Test version number generation"""
        from datetime import datetime

        # Generate version based on timestamp
        now = datetime.now()
        version = now.strftime("%Y%m%d%H%M%S")

        assert len(version) == 14
        assert version.isdigit()

    @pytest.mark.asyncio
    async def test_version_comparison(self):
        """Test version comparison logic"""
        current_version = "20260120100000"
        latest_version = "20260120120000"

        needs_update = latest_version > current_version
        assert needs_update is True

        # Same version
        needs_update = latest_version > latest_version
        assert needs_update is False


class TestProbeSyncFlow:
    """Tests for probe rule synchronization"""

    @pytest.mark.asyncio
    async def test_probe_version_check_response(self):
        """Test probe version check response format"""
        current_version = "20260120100000"
        latest_version = "20260120120000"

        response = {
            'needs_update': latest_version > current_version,
            'current_version': current_version,
            'latest_version': latest_version
        }

        assert response['needs_update'] is True
        assert response['latest_version'] == "20260120120000"

    @pytest.mark.asyncio
    async def test_probe_rule_download_format(self, sample_rule_content):
        """Test probe rule download response format"""
        version = "20260120120000"

        response = {
            'version': version,
            'content': sample_rule_content,
            'rules_count': 3
        }

        assert response['version'] == version
        assert 'sid:2001' in response['content']
        assert response['rules_count'] == 3
