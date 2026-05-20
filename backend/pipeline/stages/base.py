"""
Base Stage — all pipeline stages inherit from this class.
Provides: structured logging, status management, result storage.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Any, Dict
import logging
import asyncio

from models.database import StageStatus

logger = logging.getLogger(__name__)


class BaseStage(ABC):
    """Abstract base class for all pipeline stages"""

    name: str = "base"
    display_name: str = "Base Stage"
    order: int = 0

    def __init__(self, run_id: int, ws_manager, db_session):
        self.run_id = run_id
        self.ws = ws_manager
        self.db = db_session
        self.status = StageStatus.PENDING
        self.result: Dict[str, Any] = {}
        self.log_buffer: list[str] = []
        self.stage_db_id: Optional[int] = None
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None

    async def log(self, message: str, level: str = "INFO"):
        """Emit a log line to WebSocket and buffer"""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        line = f"[{timestamp}] [{level}] {message}"
        self.log_buffer.append(line)
        await self.ws.send_log(self.run_id, self.name, line)
        if level == "ERROR":
            logger.error(f"[Run {self.run_id}][{self.name}] {message}")
        else:
            logger.info(f"[Run {self.run_id}][{self.name}] {message}")

    async def log_subprocess(self, process) -> int:
        """Stream subprocess output line by line"""
        async def read_stream(stream, level):
            while True:
                line = await stream.readline()
                if not line:
                    break
                await self.log(line.decode().rstrip(), level)

        await asyncio.gather(
            read_stream(process.stdout, "INFO"),
            read_stream(process.stderr, "WARN"),
        )
        return await process.wait()

    async def run_cmd(self, cmd: list[str], cwd: str = None) -> tuple[int, str, str]:
        """Run a command and stream its output"""
        await self.log(f"$ {' '.join(cmd)}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout_lines = []
        stderr_lines = []

        async def read(stream, buf, level):
            leftover = ""
            while True:
                try:
                    chunk = await stream.read(8192)
                    if not chunk:
                        if leftover:
                            line_stripped = leftover.strip()
                            if line_stripped:
                                buf.append(line_stripped)
                                await self.log(line_stripped, level)
                        break
                    
                    decoded = leftover + chunk.decode(errors="ignore")
                    lines = []
                    start = 0
                    for i, char in enumerate(decoded):
                        if char in ('\n', '\r'):
                            lines.append(decoded[start:i])
                            start = i + 1
                    leftover = decoded[start:]
                    
                    for line in lines:
                        line_stripped = line.strip()
                        if line_stripped:
                            buf.append(line_stripped)
                            await self.log(line_stripped, level)
                except Exception:
                    break

        async def monitor_cancellation():
            try:
                from pipeline.runner import CANCELLED_RUNS
                while proc.returncode is None:
                    if self.run_id in CANCELLED_RUNS:
                        await self.log("Cancellation request detected. Terminating process...", "WARN")
                        try:
                            proc.terminate()
                            await asyncio.sleep(1)
                            if proc.returncode is None:
                                proc.kill()
                        except Exception as e:
                            await self.log(f"Failed to terminate process: {e}", "ERROR")
                        break
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                pass

        monitor_task = asyncio.create_task(monitor_cancellation())
        try:
            await asyncio.gather(
                read(proc.stdout, stdout_lines, "INFO"),
                read(proc.stderr, stderr_lines, "WARN"),
            )
            rc = await proc.wait()
        finally:
            monitor_task.cancel()

        return rc, "\n".join(stdout_lines), "\n".join(stderr_lines)

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main stage logic. Receives shared pipeline context dict.
        Returns updated context dict.
        Must set self.result before returning.
        """
        pass

    async def __call__(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Entry point called by the pipeline runner"""
        self.started_at = datetime.utcnow()
        self.status = StageStatus.RUNNING
        await self.ws.send_stage_update(self.run_id, self.name, "running")
        await self.log(f"▶  Stage started: {self.display_name}")

        try:
            context = await self.execute(context)
            if self.status == StageStatus.RUNNING:
                self.status = StageStatus.PASS
            await self.log(f" Stage completed: {self.display_name}")
        except StageFailure as e:
            self.status = StageStatus.FAIL
            await self.log(f" Stage FAILED: {e}", "ERROR")
            context["failed_stage"] = self.name
            context["failure_reason"] = str(e)
        except StageWarning as e:
            self.status = StageStatus.WARN
            await self.log(f"  Stage WARNING: {e}", "WARN")
        except Exception as e:
            self.status = StageStatus.ERROR
            await self.log(f"💥 Stage ERROR: {e}", "ERROR")
            context["failed_stage"] = self.name
            context["failure_reason"] = str(e)
            raise
        finally:
            self.finished_at = datetime.utcnow()
            duration = (self.finished_at - self.started_at).total_seconds()
            await self.ws.send_stage_update(
                self.run_id, self.name, self.status.value,
                {"duration": duration, "result": self.result}
            )

        return context


class StageFailure(Exception):
    """Raised when a stage fails (blocks pipeline)"""
    pass


class StageWarning(Exception):
    """Raised when a stage has warnings (pipeline continues)"""
    pass
