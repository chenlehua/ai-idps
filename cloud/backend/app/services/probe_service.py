from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import json

from app.services.redis_service import redis_service
from app.services.mysql_service import mysql_service

# 探针离线超时时间（秒）
PROBE_OFFLINE_TIMEOUT = 60


class ProbeService:
    async def register_probe(
        self,
        probe_id: str,
        name: str,
        ip: str,
        probe_types: List[str]
    ) -> Dict[str, Any]:
        """注册探针"""
        now = datetime.utcnow()

        # 检查是否已存在
        existing = await mysql_service.fetchone(
            "SELECT node_id FROM probe_nodes WHERE node_id = %s",
            (probe_id,)
        )

        if existing:
            # 更新现有探针
            await mysql_service.execute(
                """UPDATE probe_nodes 
                   SET name = %s, ip_address = %s, status = 'online', 
                       last_seen = %s, updated_at = %s
                   WHERE node_id = %s""",
                (name, ip, now, now, probe_id)
            )
        else:
            # 插入新探针
            await mysql_service.execute(
                """INSERT INTO probe_nodes 
                   (node_id, name, ip_address, status, last_seen, created_at, updated_at)
                   VALUES (%s, %s, %s, 'online', %s, %s, %s)""",
                (probe_id, name, ip, now, now, now)
            )

        # 更新探针实例
        for probe_type in probe_types:
            instance_id = f"{probe_id}-{probe_type}"
            existing_instance = await mysql_service.fetchone(
                "SELECT instance_id FROM probe_instances WHERE instance_id = %s",
                (instance_id,)
            )
            if not existing_instance:
                await mysql_service.execute(
                    """INSERT INTO probe_instances 
                       (instance_id, node_id, probe_type, status, created_at, updated_at)
                       VALUES (%s, %s, %s, 'stopped', %s, %s)""",
                    (instance_id, probe_id, probe_type, now, now)
                )

        # 更新 Redis 缓存
        await redis_service.add_online_probe(probe_id)
        await redis_service.set_probe_status(probe_id, {
            "status": "online",
            "last_seen": now.isoformat(),
            "ip": ip
        })

        return {
            "status": "ok",
            "probe_id": probe_id,
            "message": "注册成功"
        }

    async def update_probe_status(
        self,
        probe_id: str,
        status: Dict[str, Any],
        probes: List[Dict[str, Any]],
        rule_version: Optional[str] = None
    ) -> None:
        """更新探针状态"""
        now = datetime.utcnow()

        # 更新 MySQL
        await mysql_service.execute(
            """UPDATE probe_nodes 
               SET status = 'online', last_seen = %s, 
                   current_rule_version = %s, system_status = %s,
                   updated_at = %s
               WHERE node_id = %s""",
            (now, rule_version, json.dumps(status), now, probe_id)
        )

        # 更新探针实例状态
        for probe in probes:
            instance_id = probe.get('id', f"{probe_id}-{probe.get('type', 'unknown')}")
            await mysql_service.execute(
                """UPDATE probe_instances 
                   SET status = %s, interface = %s, last_seen = %s,
                       metrics = %s, updated_at = %s
                   WHERE instance_id = %s""",
                (
                    probe.get('status', 'unknown'),
                    probe.get('interface', ''),
                    now,
                    json.dumps(probe.get('metrics', {})),
                    now,
                    instance_id
                )
            )

        # 更新 Redis 缓存
        await redis_service.add_online_probe(probe_id)
        await redis_service.set_probe_status(probe_id, {
            "status": "online",
            "last_seen": now.isoformat(),
            "rule_version": rule_version or "",
            "system_status": json.dumps(status)
        })

    async def list_probes(self) -> List[Dict[str, Any]]:
        """获取探针列表"""
        probes = await mysql_service.fetchall(
            """SELECT node_id, name, ip_address, status, last_seen,
                      current_rule_version, system_status, created_at
               FROM probe_nodes
               ORDER BY created_at DESC"""
        )

        # 获取在线探针集合
        online_probes = await redis_service.get_online_probes()
        now = datetime.utcnow()

        result = []
        for probe in probes:
            # 转换 datetime 对象
            probe_dict = dict(probe)
            last_seen = probe_dict.get('last_seen')

            if probe_dict.get('last_seen'):
                probe_dict['last_seen'] = probe_dict['last_seen'].isoformat()
            if probe_dict.get('created_at'):
                probe_dict['created_at'] = probe_dict['created_at'].isoformat()
            if probe_dict.get('system_status'):
                try:
                    probe_dict['system_status'] = json.loads(probe_dict['system_status'])
                except:
                    pass

            # 检查是否在线（基于 last_seen 时间判断）
            # 如果超过 PROBE_OFFLINE_TIMEOUT 秒没有心跳，则标记为离线
            if last_seen and (now - last_seen).total_seconds() < PROBE_OFFLINE_TIMEOUT:
                probe_dict['status'] = 'online'
            else:
                probe_dict['status'] = 'offline'
                # 从在线集合中移除（清理过期数据）
                if probe_dict['node_id'] in online_probes:
                    await redis_service.remove_online_probe(probe_dict['node_id'])

            # 获取探针实例
            instances = await mysql_service.fetchall(
                """SELECT instance_id, probe_type, interface, status, last_seen, metrics
                   FROM probe_instances WHERE node_id = %s""",
                (probe_dict['node_id'],)
            )
            probe_dict['instances'] = []
            for inst in instances:
                inst_dict = dict(inst)
                if inst_dict.get('last_seen'):
                    inst_dict['last_seen'] = inst_dict['last_seen'].isoformat()
                if inst_dict.get('metrics'):
                    try:
                        inst_dict['metrics'] = json.loads(inst_dict['metrics'])
                    except:
                        pass
                probe_dict['instances'].append(inst_dict)

            result.append(probe_dict)

        return result

    async def get_probe(self, probe_id: str) -> Optional[Dict[str, Any]]:
        """获取探针详情"""
        probe = await mysql_service.fetchone(
            """SELECT node_id, name, ip_address, status, last_seen,
                      current_rule_version, system_status, created_at
               FROM probe_nodes WHERE node_id = %s""",
            (probe_id,)
        )

        if not probe:
            return None

        probe_dict = dict(probe)
        if probe_dict.get('last_seen'):
            probe_dict['last_seen'] = probe_dict['last_seen'].isoformat()
        if probe_dict.get('created_at'):
            probe_dict['created_at'] = probe_dict['created_at'].isoformat()
        if probe_dict.get('system_status'):
            try:
                probe_dict['system_status'] = json.loads(probe_dict['system_status'])
            except:
                pass

        # 获取探针实例
        instances = await mysql_service.fetchall(
            """SELECT instance_id, probe_type, interface, status, last_seen, metrics
               FROM probe_instances WHERE node_id = %s""",
            (probe_id,)
        )
        probe_dict['instances'] = []
        for inst in instances:
            inst_dict = dict(inst)
            if inst_dict.get('last_seen'):
                inst_dict['last_seen'] = inst_dict['last_seen'].isoformat()
            if inst_dict.get('metrics'):
                try:
                    inst_dict['metrics'] = json.loads(inst_dict['metrics'])
                except:
                    pass
            probe_dict['instances'].append(inst_dict)

        return probe_dict


probe_service = ProbeService()
