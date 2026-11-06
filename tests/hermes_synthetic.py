"""Synthetic Hermes-state DB builders for the read-only adapter tests.

These create NEW sqlite files in a temp directory only. Nothing here opens, reads,
or copies a real Hermes state database.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 32

_MIN_SESSIONS = (
    "id TEXT PRIMARY KEY, source TEXT NOT NULL, started_at REAL NOT NULL,"
    " ended_at REAL, end_reason TEXT, cwd TEXT, git_repo_root TEXT,"
    " profile_name TEXT, archived INTEGER, hidden INTEGER, title TEXT,"
    " message_count INTEGER"
)
_MIN_MESSAGES = (
    "id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,"
    " role TEXT NOT NULL, content TEXT, tool_call_id TEXT, tool_name TEXT,"
    " timestamp REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1"
)


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def create_store(
    path: Path,
    *,
    schema_version: int = SCHEMA_VERSION,
    sessions_sql: str = _MIN_SESSIONS,
    messages_sql: str = _MIN_MESSAGES,
    extra_session_columns: tuple[str, ...] = (),
    extra_message_columns: tuple[str, ...] = (),
) -> sqlite3.Connection:
    """新建一个合成库（文件必须不存在或调用方自己清空）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (schema_version,))
    # 表形状在 execute **之前**组合：这些串全是测试内部常量，绝不来自被测适配器，
    # 也不与任何真实库或凭据接触。组合发生在 execute 调用之外，避免把拼装当成语句模板。
    sessions = sessions_sql
    messages = messages_sql
    if extra_session_columns:
        sessions += "," + ",".join(extra_session_columns)
    if extra_message_columns:
        messages += "," + ",".join(extra_message_columns)
    sessions_ddl = "CREATE TABLE sessions (" + sessions + ")"
    messages_ddl = "CREATE TABLE messages (" + messages + ")"
    conn.execute(sessions_ddl)
    conn.execute(messages_ddl)
    conn.commit()
    return conn


def add_session(
    conn: sqlite3.Connection,
    session_id: str,
    *,
    source: str = "hermes",
    started_at: float | None = None,
    ended_at: float | None = None,
    end_reason: str | None = None,
    cwd: str | None = "/synthetic/project",
    git_repo_root: str | None = "/synthetic/project",
    profile_name: str | None = "default",
    archived: int = 0,
    hidden: int = 0,
    title: str | None = None,
    message_count: int = 0,
) -> None:
    conn.execute(
        "INSERT INTO sessions (id, source, started_at, ended_at, end_reason, cwd,"
        " git_repo_root, profile_name, archived, hidden, title, message_count)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            session_id,
            source,
            started_at if started_at is not None else time.time(),
            ended_at,
            end_reason,
            cwd,
            git_repo_root,
            profile_name,
            archived,
            hidden,
            title,
            message_count,
        ),
    )
    conn.commit()


def add_message(
    conn: sqlite3.Connection,
    session_id: str,
    role: str,
    content: object,
    *,
    timestamp: object = None,
    tool_call_id: str | None = None,
    tool_name: str | None = None,
    active: object = 1,
) -> int:
    cur = conn.execute(
        "INSERT INTO messages (session_id, role, content, tool_call_id, tool_name,"
        " timestamp, active) VALUES (?,?,?,?,?,?,?)",
        (
            session_id,
            role,
            content,
            tool_call_id,
            tool_name,
            time.time() if timestamp is None else timestamp,
            active,
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)
