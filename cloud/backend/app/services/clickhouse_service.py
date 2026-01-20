from typing import List, Optional
from datetime import datetime
import clickhouse_connect

from app.config import settings


class ClickHouseService:
    def __init__(self):
        self.client = None

    async def connect(self):
        self.client = clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            database=settings.clickhouse_database,
        )

    async def disconnect(self):
        if self.client:
            self.client.close()
            self.client = None

    async def insert_logs(self, logs: List[dict]) -> int:
        """批量插入告警日志"""
        if not logs or not self.client:
            return 0

        columns = [
            'node_id', 'instance_id', 'probe_type', 'timestamp',
            'src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol',
            'alert_msg', 'signature_id', 'severity', 'category', 'raw_log'
        ]

        data = []
        for log in logs:
            # 解析时间戳
            ts = log.get('timestamp')
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except:
                    ts = datetime.utcnow()
            elif ts is None:
                ts = datetime.utcnow()

            # 获取告警信息
            alert = log.get('alert', {})

            data.append([
                log.get('probe_id', log.get('node_id', '')),
                log.get('instance_id', ''),
                log.get('probe_type', 'nids'),
                ts,
                log.get('src_ip', '0.0.0.0'),
                log.get('dest_ip', '0.0.0.0'),
                log.get('src_port', 0),
                log.get('dest_port', 0),
                log.get('protocol', ''),
                alert.get('signature', alert.get('message', '')),
                alert.get('signature_id', 0),
                alert.get('severity', 3),
                alert.get('category', ''),
                log.get('raw', '')
            ])

        try:
            self.client.insert('alert_logs', data, column_names=columns)
            return len(data)
        except Exception as e:
            print(f"ClickHouse insert error: {e}")
            return 0

    async def query_logs(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        probe_id: Optional[str] = None,
        severity: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[dict]:
        """查询告警日志"""
        if not self.client:
            return []

        conditions = ["1=1"]
        params = {}

        if start_time:
            conditions.append("timestamp >= {start_time:DateTime64}")
            params['start_time'] = start_time
        if end_time:
            conditions.append("timestamp <= {end_time:DateTime64}")
            params['end_time'] = end_time
        if probe_id:
            conditions.append("node_id = {probe_id:String}")
            params['probe_id'] = probe_id
        if severity is not None:
            conditions.append("severity = {severity:UInt8}")
            params['severity'] = severity

        query = f"""
            SELECT 
                id,
                node_id,
                instance_id,
                probe_type,
                timestamp,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                protocol,
                alert_msg,
                signature_id,
                severity,
                category,
                created_at
            FROM alert_logs
            WHERE {' AND '.join(conditions)}
            ORDER BY timestamp DESC
            LIMIT {limit} OFFSET {offset}
        """

        try:
            result = self.client.query(query, parameters=params)
            columns = result.column_names
            rows = []
            for row in result.result_rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    val = row[i]
                    # 转换特殊类型
                    if hasattr(val, 'isoformat'):
                        val = val.isoformat()
                    elif hasattr(val, '__str__') and not isinstance(val, (str, int, float, bool, type(None))):
                        val = str(val)
                    row_dict[col] = val
                rows.append(row_dict)
            return rows
        except Exception as e:
            print(f"ClickHouse query error: {e}")
            return []

    async def get_stats(self, hours: int = 24) -> List[dict]:
        """获取统计数据"""
        if not self.client:
            return []

        query = f"""
            SELECT
                toStartOfHour(timestamp) as hour,
                severity,
                count() as count
            FROM alert_logs
            WHERE timestamp >= now() - INTERVAL {hours} HOUR
            GROUP BY hour, severity
            ORDER BY hour DESC
        """

        try:
            result = self.client.query(query)
            stats = []
            for row in result.result_rows:
                stats.append({
                    'hour': row[0].isoformat() if hasattr(row[0], 'isoformat') else str(row[0]),
                    'severity': row[1],
                    'count': row[2]
                })
            return stats
        except Exception as e:
            print(f"ClickHouse stats error: {e}")
            return []

    async def get_total_count(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        probe_id: Optional[str] = None,
        severity: Optional[int] = None
    ) -> int:
        """获取日志总数"""
        if not self.client:
            return 0

        conditions = ["1=1"]
        params = {}

        if start_time:
            conditions.append("timestamp >= {start_time:DateTime64}")
            params['start_time'] = start_time
        if end_time:
            conditions.append("timestamp <= {end_time:DateTime64}")
            params['end_time'] = end_time
        if probe_id:
            conditions.append("node_id = {probe_id:String}")
            params['probe_id'] = probe_id
        if severity is not None:
            conditions.append("severity = {severity:UInt8}")
            params['severity'] = severity

        query = f"""
            SELECT count() FROM alert_logs
            WHERE {' AND '.join(conditions)}
        """

        try:
            result = self.client.query(query, parameters=params)
            return result.result_rows[0][0] if result.result_rows else 0
        except Exception as e:
            print(f"ClickHouse count error: {e}")
            return 0

    async def get_alert_count_by_sid(self, sid: int, hours: int = 24) -> int:
        """获取指定规则SID的告警数量

        Args:
            sid: 规则SID
            hours: 时间范围(小时)

        Returns:
            告警数量
        """
        if not self.client:
            return 0

        query = f"""
            SELECT count() FROM alert_logs
            WHERE signature_id = {{sid:UInt32}}
              AND timestamp >= now() - INTERVAL {hours} HOUR
              AND is_test_traffic = 0
        """

        try:
            result = self.client.query(query, parameters={'sid': sid})
            return result.result_rows[0][0] if result.result_rows else 0
        except Exception as e:
            print(f"ClickHouse get_alert_count_by_sid error: {e}")
            return 0

    async def get_alerts_by_test_id(
        self,
        test_id: str,
        limit: int = 100
    ) -> List[dict]:
        """获取攻击测试相关的告警日志

        Args:
            test_id: 测试ID
            limit: 返回数量限制

        Returns:
            告警日志列表
        """
        if not self.client:
            return []

        query = f"""
            SELECT
                id, node_id, instance_id, probe_type, timestamp,
                src_ip, dest_ip, src_port, dest_port, protocol,
                alert_msg, signature_id, severity, category,
                test_id, test_item_id
            FROM alert_logs
            WHERE test_id = {{test_id:String}}
            ORDER BY timestamp DESC
            LIMIT {limit}
        """

        try:
            result = self.client.query(query, parameters={'test_id': test_id})
            columns = result.column_names
            rows = []
            for row in result.result_rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    val = row[i]
                    if hasattr(val, 'isoformat'):
                        val = val.isoformat()
                    elif hasattr(val, '__str__') and not isinstance(val, (str, int, float, bool, type(None))):
                        val = str(val)
                    row_dict[col] = val
                rows.append(row_dict)
            return rows
        except Exception as e:
            print(f"ClickHouse get_alerts_by_test_id error: {e}")
            return []


clickhouse_service = ClickHouseService()
