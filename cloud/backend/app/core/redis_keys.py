"""Redis缓存键定义"""

from typing import Dict, Any


class RedisKeys:
    """Redis缓存键常量"""

    # ========== 规则相关 ==========
    # 最新规则版本号 (string)
    RULE_VERSION_LATEST = "rule:version:latest"

    # 规则内容缓存 (string) - rule:content:{version}
    RULE_CONTENT_PREFIX = "rule:content:"

    # 分类统计 (hash) - {category_type: json_stats}
    RULE_CATEGORIES = "rule:categories"

    # 单条规则详情 (hash) - rule:sid:{sid}
    RULE_SID_PREFIX = "rule:sid:"

    # 下载进度 (hash) - {status, progress, message, task_id}
    RULE_DOWNLOAD_PROGRESS = "rule:download:progress"

    # 规则变更预览缓存 (string) - JSON格式
    RULE_CHANGE_PREVIEW = "rule:change:preview"

    # ========== 测试相关 ==========
    # 测试状态 (hash) - test:{test_id}:status
    TEST_STATUS_PREFIX = "test:"
    TEST_STATUS_SUFFIX = ":status"

    # 测试进度 (hash) - test:{test_id}:progress - {total, completed, success, failed}
    TEST_PROGRESS_SUFFIX = ":progress"

    # ========== 任务相关 ==========
    # 探针待执行任务队列 (list) - probe:{probe_id}:tasks
    PROBE_TASKS_PREFIX = "probe:"
    PROBE_TASKS_SUFFIX = ":tasks"

    # 任务状态 (string) - task:{task_id}:status
    TASK_STATUS_PREFIX = "task:"
    TASK_STATUS_SUFFIX = ":status"

    # ========== 探针相关 (已有) ==========
    # 探针状态 (hash) - probe:status:{probe_id}
    PROBE_STATUS_PREFIX = "probe:status:"

    # 在线探针集合 (set)
    PROBE_ONLINE = "probe:online"

    # ========== 辅助方法 ==========
    @staticmethod
    def rule_content(version: str) -> str:
        """获取规则内容缓存键"""
        return f"{RedisKeys.RULE_CONTENT_PREFIX}{version}"

    @staticmethod
    def rule_sid(sid: int) -> str:
        """获取规则SID缓存键"""
        return f"{RedisKeys.RULE_SID_PREFIX}{sid}"

    @staticmethod
    def test_status(test_id: str) -> str:
        """获取测试状态缓存键"""
        return f"{RedisKeys.TEST_STATUS_PREFIX}{test_id}{RedisKeys.TEST_STATUS_SUFFIX}"

    @staticmethod
    def test_progress(test_id: str) -> str:
        """获取测试进度缓存键"""
        return f"{RedisKeys.TEST_STATUS_PREFIX}{test_id}{RedisKeys.TEST_PROGRESS_SUFFIX}"

    @staticmethod
    def probe_tasks(probe_id: str) -> str:
        """获取探针任务队列键"""
        return f"{RedisKeys.PROBE_TASKS_PREFIX}{probe_id}{RedisKeys.PROBE_TASKS_SUFFIX}"

    @staticmethod
    def task_status(task_id: str) -> str:
        """获取任务状态键"""
        return f"{RedisKeys.TASK_STATUS_PREFIX}{task_id}{RedisKeys.TASK_STATUS_SUFFIX}"

    @staticmethod
    def probe_status(probe_id: str) -> str:
        """获取探针状态键"""
        return f"{RedisKeys.PROBE_STATUS_PREFIX}{probe_id}"


class RedisTTL:
    """Redis缓存过期时间配置(秒)"""

    # 规则相关
    RULE_CATEGORIES = 3600  # 1小时
    RULE_SID = 600  # 10分钟
    RULE_CONTENT = 3600  # 1小时
    RULE_DOWNLOAD_PROGRESS = 300  # 5分钟
    RULE_CHANGE_PREVIEW = 1800  # 30分钟

    # 测试相关
    TEST_STATUS = 3600  # 1小时
    TEST_PROGRESS = 3600  # 1小时

    # 任务相关
    TASK_STATUS = 3600  # 1小时

    # 探针相关
    PROBE_STATUS = 600  # 10分钟


class DownloadStatus:
    """下载状态枚举"""
    IDLE = "idle"
    DOWNLOADING = "downloading"
    PARSING = "parsing"
    COMPARING = "comparing"
    READY = "ready"
    ERROR = "error"


def get_download_progress_data(
    status: str,
    progress: float = 0,
    message: str = "",
    task_id: str = "",
    total_bytes: int = 0,
    downloaded_bytes: int = 0,
) -> Dict[str, Any]:
    """构建下载进度数据"""
    return {
        "status": status,
        "progress": progress,
        "message": message,
        "task_id": task_id,
        "total_bytes": total_bytes,
        "downloaded_bytes": downloaded_bytes,
    }


def get_test_progress_data(
    total: int = 0,
    completed: int = 0,
    success: int = 0,
    failed: int = 0,
    running: int = 0,
) -> Dict[str, Any]:
    """构建测试进度数据"""
    return {
        "total": total,
        "completed": completed,
        "success": success,
        "failed": failed,
        "running": running,
        "pending": total - completed - running,
    }
