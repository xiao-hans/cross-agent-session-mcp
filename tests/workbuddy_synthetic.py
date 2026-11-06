"""合成夹具：WorkBuddy SQLite 索引库 + 正文行（只写临时目录，绝不触碰真实 ``~/.workbuddy``）。

造库按源码取证的真实列名（``sessions`` 40 列 / ``messages`` 14 列），正文按计划 §5.5
注入 `body_lines`：正文文件布局未逐字核实，因此这里造的正文行只是**契约测试**的输入，
不代表真实磁盘形状。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

SOURCE = "workbuddy"
SESSION = "wb-session-0001"
PROJECT = "D:/synthetic/workbuddy-project"
OTHER_PROJECT = "D:/synthetic/other-workbuddy-project"
STORE_NAME = "index.db"

#: `sessions` 的已核实列集（sources/workbuddy.py 的 WORKBUDDY_SCHEMA_COLUMNS）。
SESSION_COLUMNS: tuple[str, ...] = (
    "automation_id",
    "bootstrap_completed_at",
    "completed_at",
    "context_model",
    "created_at",
    "deleted_at",
    "effective_tier_id",
    "executor_id",
    "id",
    "is_playground",
    "last_active_at",
    "model",
    "mode",
    "parent_session_id",
    "permission_mode",
    "plan_enabled",
    "project_path",
    "provider",
    "reasoning_effort",
    "role",
    "runtime_source",
    "scenario_id",
    "scheduled_task_run_id",
    "session_id",
    "source",
    "source_mode",
    "started_at",
    "status",
    "sub_agent_id",
    "team_id",
    "team_role",
    "title",
    "todo_enabled",
    "turn_count",
    "updated_at",
    "version",
    "workspace_id",
    "wbs_base_url",
    "workbuddy_base_url",
    "znote_token",
)

MESSAGE_COLUMNS: tuple[str, ...] = (
    "content",
    "conversation_id",
    "created_at",
    "hidden",
    "id",
    "model",
    "reasoning_content",
    "role",
    "session_id",
    "source_app",
    "source_channel",
    "token_usage",
    "tool_calls",
    "updated_at",
)


def _quote_ident(name: str) -> str:
    """列名引用（夹具只使用本模块常量里的已核实列名）。"""
    return '"' + name.replace('"', '""') + '"'


def connect(path: Path | str) -> sqlite3.Connection:
    """按适配器同样的方式打开库（WAL 容忍、只读语义由调用方负责）。"""
    return sqlite3.connect(str(path))


def build_store(
    path: Path,
    *,
    user_version: int = 22,
    with_messages_table: bool = True,
    with_aux_tables: bool = True,
    extra_sessions: tuple[tuple[str, str] | tuple[str, str, str], ...] = (),
) -> sqlite3.Connection:
    """建库建表，返回打开的连接（调用方负责写数据并提交）。

    适配器把 `workspaces / session_usage / automation_runs / migration_meta / sessions` 全
    都列为必需表（缺任一 ⇒ schema 不认识），因此夹具默认补齐这四张辅助表，让正路径能跑
    到索引取数；`with_aux_tables=False` 用来专门造缺表故障。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA user_version = {int(user_version)}")  # pi-lens-ignore: python-sql-injection
    columns = ",\n".join(f"{_quote_ident(name)} TEXT" for name in SESSION_COLUMNS)
    conn.execute(f"CREATE TABLE sessions (\n{columns}\n)")  # pi-lens-ignore: python-sql-injection
    if with_messages_table:
        message_columns = ",\n".join(
            f"{_quote_ident(name)} TEXT" for name in MESSAGE_COLUMNS
        )
        conn.execute(f"CREATE TABLE messages (\n{message_columns}\n)")  # pi-lens-ignore: python-sql-injection
    if with_aux_tables:
        conn.execute('CREATE TABLE workspaces ("path" TEXT, "last_opened_at" TEXT)')
        conn.execute(
            'CREATE TABLE session_usage ("session_id" TEXT, "used" TEXT, "size" TEXT,'
            ' "updated_at" TEXT, "credit_json" TEXT)'
        )
        conn.execute(
            'CREATE TABLE automation_runs ("thread_id" TEXT, "automation_id" TEXT,'
            ' "status" TEXT, "read_at" TEXT, "thread_title" TEXT, "source_cwd" TEXT,'
            ' "runs_json" TEXT, "result_success" TEXT, "metadata_json" TEXT,'
            ' "created_at" TEXT, "updated_at" TEXT, "failure_code" TEXT,'
            ' "reason_code" TEXT)'
        )
        conn.execute('CREATE TABLE migration_meta ("key" TEXT, "value" TEXT)')
    conn.commit()
    for entry in extra_sessions:
        session_id, status = entry[0], entry[1]
        deleted_at = entry[2] if len(entry) > 2 else None
        conn.execute(
            "INSERT INTO sessions (id, title, status, deleted_at) VALUES (?, ?, ?, ?)",
            (session_id, f"extra {session_id}", status, deleted_at),
        )
    conn.commit()
    return conn


def add_session(
    conn: sqlite3.Connection,
    *,
    session_id: str = SESSION,
    title: str = "needle session",
    status: str = "active",
    source_mode: str = "cli",
    project_path: str = PROJECT,
    deleted_at: str | None = None,
    is_playground: int | None = None,
    executor_id: str | None = None,
    **fields: Any,
) -> None:
    """插入一行会话索引（默认形态：CLI、活跃、有项目路径）。"""
    row: dict[str, Any] = {
        "id": session_id,
        "title": title,
        "status": status,
        "source_mode": source_mode,
        "project_path": project_path,
        "deleted_at": deleted_at,
        "executor_id": executor_id,
    }
    if is_playground is not None:
        row["is_playground"] = is_playground
    row.update(fields)
    names = list(row)
    columns = ", ".join(_quote_ident(n) for n in names)
    placeholders = ", ".join("?" for _ in names)
    conn.execute(  # pi-lens-ignore: python-sql-injection
        f"INSERT INTO sessions ({columns}) VALUES ({placeholders})",  # pi-lens-ignore: python-sql-injection
        tuple(row[n] for n in names),
    )
    conn.commit()


def add_message(
    conn: sqlite3.Connection,
    *,
    session_id: str = SESSION,
    role: str = "user",
    content: str = "needle in the index",
    hidden: int = 0,
    **fields: Any,
) -> None:
    row = {
        "session_id": session_id,
        "role": role,
        "content": content,
        "hidden": hidden,
        "created_at": "2026-03-01T10:00:00.000Z",
    }
    row.update(fields)
    names = list(row)
    columns = ", ".join(_quote_ident(n) for n in names)
    placeholders = ", ".join("?" for _ in names)
    conn.execute(  # pi-lens-ignore: python-sql-injection
        f"INSERT INTO messages ({columns}) VALUES ({placeholders})",  # pi-lens-ignore: python-sql-injection
        tuple(row[n] for n in names),
    )
    conn.commit()


def body_lines(rows: list[dict[str, Any]]) -> list[str]:
    """正文 JSONL 行（注入用）：每行一个记录对象。"""
    return [json.dumps(row, ensure_ascii=False) for row in rows]


def flat_body_lines(texts: list[str], *, role: str = "user") -> list[str]:
    """扁平生产形态行：content 为字符串，且带 created_at（无时间戳会被质量码判 MISSING_TIMESTAMP）。"""

    return [
        json.dumps(
            {"role": role, "content": text, "created_at": "2026-01-01T00:00:00.000Z"},
            ensure_ascii=False,
        )
        for text in texts
    ]


def nested_body_lines(pairs: list[tuple[str, str]]) -> list[str]:
    return body_lines(
        [{"message": {"role": role, "content": content}} for role, content in pairs]
    )


def add_messages(
    conn_or_path: sqlite3.Connection | Path,
    session_id: str,
    rows: list[tuple[str, str]],
) -> None:
    """批量插入索引消息行（连接或库路径都可，路径形态自行开关并提交）。"""
    if isinstance(conn_or_path, sqlite3.Connection):
        conn = conn_or_path
        for role, content in rows:
            add_message(conn, session_id=session_id, role=role, content=content)
        return
    conn = sqlite3.connect(str(conn_or_path))
    try:
        for role, content in rows:
            add_message(conn, session_id=session_id, role=role, content=content)
    finally:
        conn.close()


def create_store(
    path: Path,
    *,
    user_version: int = 22,
    session_id: str = SESSION,
    project_path: str = PROJECT,
    extra_sessions: tuple[tuple[str, str] | tuple[str, str, str], ...] = (),
) -> Path:
    """造一个完整可用的索引库（默认会话一行 + 辅助表齐备），返回路径。"""
    conn = build_store(
        path,
        user_version=user_version,
        extra_sessions=extra_sessions,
    )
    add_session(conn, session_id=session_id, project_path=project_path)
    conn.close()
    return path


def write_store(
    root: Path,
    *,
    store_name: str = STORE_NAME,
    **build_kwargs: Any,
) -> Path:
    """在 ``root`` 下造一个空索引库文件并返回路径。"""
    path = root / store_name
    conn = build_store(path, **build_kwargs)
    conn.close()
    return path


def corrupt_store(path: Path) -> Path:
    """把库文件截断成非 SQLite 字节（访问故障路径夹具）。"""
    raw = path.read_bytes()
    path.write_bytes(raw[: max(0, len(raw) // 3)] + b"\x00" * 16)
    return path


def missing_table_store(path: Path, *, drop: str = "messages") -> Path:
    """删掉某张表后重新落盘（缺表夹具）；``drop`` 只接受已核实的表名。"""
    allowed = {"sessions", "messages"}
    if drop not in allowed:
        raise ValueError(f"unknown fixture table: {drop!r}")
    conn = sqlite3.connect(str(path))
    conn.execute(f'DROP TABLE IF EXISTS "{drop}"')  # pi-lens-ignore: python-sql-injection
    conn.commit()
    conn.close()
    return path


def unknown_column_store(path: Path) -> Path:
    """在 7 列 SELECT 面完整的前提下再造一份带未知列的 sessions 表。

    P1-4 收紧后必填列 = 全部 7 个 SELECT 列，缺列会先触发 `SCHEMA_UNKNOWN_COLUMNS`。
    要单独验证「多余列只计入 unknown_columns、不致命」，必须**保留全部声明列**再附加
    `mystery_column`（多列而不缺列）；缺列故障由 `test_wb01_missing_required_column_...`
    专门覆盖。
    """
    conn = sqlite3.connect(str(path))
    conn.execute("DROP TABLE sessions")
    declared = ",\n".join(f"{_quote_ident(name)} TEXT" for name in SESSION_COLUMNS)
    conn.execute(
        f"CREATE TABLE sessions (\n{declared},\n mystery_column TEXT\n)"  # pi-lens-ignore: python-sql-injection
    )
    conn.commit()
    conn.close()
    return path


def sessions_table_only(path: Path) -> Path:
    """只有 sessions、没有 messages 的库。"""
    return missing_table_store(path, drop="messages")
