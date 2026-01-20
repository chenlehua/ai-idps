"""规则下载服务 - 从ET Open下载规则"""

import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass
import uuid

import httpx

from app.services.redis_service import RedisService
from app.core.redis_keys import RedisKeys, RedisTTL, DownloadStatus, get_download_progress_data

logger = logging.getLogger(__name__)


@dataclass
class DownloadResult:
    """下载结果"""
    success: bool
    content: str = ""
    checksum: str = ""
    size: int = 0
    error: Optional[str] = None
    download_time_ms: int = 0


class RuleDownloadService:
    """规则下载服务"""

    # ET Open 规则下载地址
    ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules"

    # 备用地址
    ET_OPEN_MIRRORS = [
        "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules",
        "https://rules.emergingthreats.net/open/suricata-6.0/emerging-all.rules",
    ]

    # 下载超时时间 (秒)
    DOWNLOAD_TIMEOUT = 300

    # 连接超时时间 (秒)
    CONNECT_TIMEOUT = 30

    def __init__(self, redis_service: Optional[RedisService] = None):
        """初始化下载服务

        Args:
            redis_service: Redis 服务实例
        """
        self.redis_service = redis_service
        self._current_task_id: Optional[str] = None
        self._cancel_requested = False

    async def start_download(
        self,
        force: bool = False,
        progress_callback: Optional[Callable[[float, str], Awaitable[None]]] = None
    ) -> str:
        """启动下载任务

        Args:
            force: 是否强制重新下载
            progress_callback: 进度回调函数 (progress: 0-100, message: str)

        Returns:
            任务ID
        """
        # 检查是否有正在进行的下载
        if self.redis_service:
            current_status = await self.get_download_status()
            if current_status.get('status') == DownloadStatus.DOWNLOADING and not force:
                logger.warning("Download already in progress")
                return current_status.get('task_id', '')

        # 生成任务ID
        task_id = str(uuid.uuid4())
        self._current_task_id = task_id
        self._cancel_requested = False

        # 更新状态为下载中
        await self._update_progress(
            DownloadStatus.DOWNLOADING,
            0,
            "正在连接规则源...",
            task_id
        )

        # 启动后台下载任务
        asyncio.create_task(self._download_rules(task_id, progress_callback))

        return task_id

    async def get_download_status(self) -> dict:
        """获取下载状态

        Returns:
            下载状态字典
        """
        if not self.redis_service:
            return get_download_progress_data(DownloadStatus.IDLE)

        try:
            data = await self.redis_service.hgetall(RedisKeys.RULE_DOWNLOAD_PROGRESS)
            if not data:
                return get_download_progress_data(DownloadStatus.IDLE)

            return {
                'status': data.get('status', DownloadStatus.IDLE),
                'progress': float(data.get('progress', 0)),
                'message': data.get('message', ''),
                'task_id': data.get('task_id', ''),
                'total_bytes': int(data.get('total_bytes', 0)),
                'downloaded_bytes': int(data.get('downloaded_bytes', 0)),
            }
        except Exception as e:
            logger.error(f"Failed to get download status: {e}")
            return get_download_progress_data(DownloadStatus.IDLE)

    async def cancel_download(self) -> bool:
        """取消下载

        Returns:
            是否成功取消
        """
        self._cancel_requested = True

        if self.redis_service:
            await self._update_progress(
                DownloadStatus.IDLE,
                0,
                "下载已取消"
            )

        return True

    async def _download_rules(
        self,
        task_id: str,
        progress_callback: Optional[Callable[[float, str], Awaitable[None]]] = None
    ) -> DownloadResult:
        """执行下载

        Args:
            task_id: 任务ID
            progress_callback: 进度回调

        Returns:
            下载结果
        """
        start_time = datetime.now()
        content = ""
        urls_to_try = [self.ET_OPEN_URL] + self.ET_OPEN_MIRRORS

        for url in urls_to_try:
            if self._cancel_requested:
                return DownloadResult(success=False, error="下载已取消")

            try:
                logger.info(f"Downloading rules from {url}")
                await self._update_progress(
                    DownloadStatus.DOWNLOADING,
                    5,
                    f"正在从 {url} 下载规则...",
                    task_id
                )

                result = await self._download_from_url(url, task_id, progress_callback)
                if result.success:
                    # 更新为解析状态
                    await self._update_progress(
                        DownloadStatus.READY,
                        100,
                        f"下载完成，共 {result.size / 1024 / 1024:.2f} MB",
                        task_id
                    )

                    # 保存到 Redis 缓存
                    if self.redis_service:
                        await self.redis_service.set(
                            f"rule:downloaded:{task_id}",
                            result.content,
                            ex=RedisTTL.RULE_CHANGE_PREVIEW
                        )

                    return result

            except Exception as e:
                logger.warning(f"Failed to download from {url}: {e}")
                continue

        # 所有 URL 都失败
        error_msg = "所有规则源下载失败"
        await self._update_progress(
            DownloadStatus.ERROR,
            0,
            error_msg,
            task_id
        )

        elapsed = (datetime.now() - start_time).total_seconds() * 1000
        return DownloadResult(
            success=False,
            error=error_msg,
            download_time_ms=int(elapsed)
        )

    async def _download_from_url(
        self,
        url: str,
        task_id: str,
        progress_callback: Optional[Callable[[float, str], Awaitable[None]]] = None
    ) -> DownloadResult:
        """从指定 URL 下载

        Args:
            url: 下载地址
            task_id: 任务ID
            progress_callback: 进度回调

        Returns:
            下载结果
        """
        start_time = datetime.now()

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=self.CONNECT_TIMEOUT,
                read=self.DOWNLOAD_TIMEOUT,
                write=30.0,
                pool=30.0
            ),
            follow_redirects=True
        ) as client:
            # 发送请求
            async with client.stream('GET', url) as response:
                response.raise_for_status()

                # 获取文件大小
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                chunks = []

                # 流式下载
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    if self._cancel_requested:
                        raise asyncio.CancelledError("Download cancelled")

                    chunks.append(chunk)
                    downloaded += len(chunk)

                    # 更新进度
                    if total_size > 0:
                        progress = min(95, (downloaded / total_size) * 90 + 5)
                        message = f"已下载 {downloaded / 1024 / 1024:.2f} MB / {total_size / 1024 / 1024:.2f} MB"
                    else:
                        progress = 50
                        message = f"已下载 {downloaded / 1024 / 1024:.2f} MB"

                    await self._update_progress(
                        DownloadStatus.DOWNLOADING,
                        progress,
                        message,
                        task_id,
                        total_size,
                        downloaded
                    )

                    if progress_callback:
                        await progress_callback(progress, message)

                # 合并内容
                content = b''.join(chunks).decode('utf-8', errors='ignore')
                checksum = hashlib.sha256(content.encode()).hexdigest()

                elapsed = (datetime.now() - start_time).total_seconds() * 1000

                return DownloadResult(
                    success=True,
                    content=content,
                    checksum=checksum,
                    size=len(content),
                    download_time_ms=int(elapsed)
                )

    async def _update_progress(
        self,
        status: str,
        progress: float,
        message: str,
        task_id: str = "",
        total_bytes: int = 0,
        downloaded_bytes: int = 0
    ):
        """更新下载进度

        Args:
            status: 状态
            progress: 进度 (0-100)
            message: 消息
            task_id: 任务ID
            total_bytes: 总字节数
            downloaded_bytes: 已下载字节数
        """
        if not self.redis_service:
            return

        try:
            data = get_download_progress_data(
                status=status,
                progress=progress,
                message=message,
                task_id=task_id,
                total_bytes=total_bytes,
                downloaded_bytes=downloaded_bytes
            )

            await self.redis_service.hset(
                RedisKeys.RULE_DOWNLOAD_PROGRESS,
                mapping={k: str(v) for k, v in data.items()}
            )
            await self.redis_service.expire(
                RedisKeys.RULE_DOWNLOAD_PROGRESS,
                RedisTTL.RULE_DOWNLOAD_PROGRESS
            )
        except Exception as e:
            logger.error(f"Failed to update progress: {e}")

    async def get_cached_download(self, task_id: str) -> Optional[str]:
        """获取缓存的下载内容

        Args:
            task_id: 任务ID

        Returns:
            下载的规则内容
        """
        if not self.redis_service:
            return None

        try:
            return await self.redis_service.get(f"rule:downloaded:{task_id}")
        except Exception as e:
            logger.error(f"Failed to get cached download: {e}")
            return None

    async def download_sync(self) -> DownloadResult:
        """同步下载规则 (阻塞直到完成)

        Returns:
            下载结果
        """
        task_id = str(uuid.uuid4())
        self._current_task_id = task_id
        self._cancel_requested = False

        return await self._download_rules(task_id, None)
