"""
WebSocket Manager — broadcasts pipeline events to all connected clients
"""
from typing import Dict, Set
from fastapi import WebSocket
import json
import asyncio
import logging

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections per run_id"""

    def __init__(self):
        # run_id → set of connected websockets
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        # Global listeners (dashboard overview)
        self.global_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket, run_id: int):
        await websocket.accept()
        if run_id not in self.active_connections:
            self.active_connections[run_id] = set()
        self.active_connections[run_id].add(websocket)
        logger.info(f"WS connected for run {run_id}")

    async def connect_global(self, websocket: WebSocket):
        await websocket.accept()
        self.global_connections.add(websocket)

    def disconnect(self, websocket: WebSocket, run_id: int):
        if run_id in self.active_connections:
            self.active_connections[run_id].discard(websocket)
            if not self.active_connections[run_id]:
                del self.active_connections[run_id]

    def disconnect_global(self, websocket: WebSocket):
        self.global_connections.discard(websocket)

    async def broadcast_to_run(self, run_id: int, event: dict):
        """Send event to all clients watching a specific run"""
        if run_id not in self.active_connections:
            return
        dead = set()
        for ws in self.active_connections[run_id]:
            try:
                await ws.send_json(event)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active_connections[run_id].discard(ws)

    async def broadcast_global(self, event: dict):
        """Send event to global dashboard listeners"""
        dead = set()
        for ws in self.global_connections:
            try:
                await ws.send_json(event)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.global_connections.discard(ws)

    async def send_log(self, run_id: int, stage_name: str, line: str):
        await self.broadcast_to_run(run_id, {
            "event": "stage_log",
            "run_id": run_id,
            "stage_name": stage_name,
            "log_line": line,
        })

    async def send_stage_update(self, run_id: int, stage_name: str, status: str, data: dict = None):
        payload = {
            "event": "stage_update",
            "run_id": run_id,
            "stage_name": stage_name,
            "stage_status": status,
            "data": data or {},
        }
        await self.broadcast_to_run(run_id, payload)
        await self.broadcast_global(payload)

    async def send_run_complete(self, run_id: int, status: str, summary: dict):
        payload = {
            "event": "run_complete",
            "run_id": run_id,
            "status": status,
            "summary": summary,
        }
        await self.broadcast_to_run(run_id, payload)
        await self.broadcast_global(payload)


# Singleton instance
ws_manager = ConnectionManager()
