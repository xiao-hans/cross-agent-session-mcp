# Cross-Agent Session Retrieval MCP (cross-agent-session-mcp)

Cross-agent session retrieval service providing safe, read-only session search and snippet extraction across AI agent CLI/IDE sessions (Hermes, Pi, Claude Code CLI, Cursor Agent CLI, Codex, DSH, WorkBuddy).

## Features

- **Strict Fail-Closed Policy Enforcement**: Project-root binding and storage-root binding are decoupled. Explicit white-listed authorization only.
- **Data Minimization & Redaction**: Built-in multi-pattern redaction engine for API keys, bearer tokens, passwords, private keys, and userinfo.
- **Reference Token Lifecycle**: Results return opaque tokens (`ctxref:...`) with process-level bounded ledgers; clients cannot forge line numbers or probe unauthorized file paths.
- **Standard MCP Stdio Service**: Exposes three read-only tools:
  - `list_sources`: Query configured and bound agent sources.
  - `search_sessions`: Structured session content search with time-windowing and project scoping.
  - `read_session_context`: Controlled context expansion around an opaque search result token.

## Usage

Run the stdio host with an approved configuration:

```bash
python run_host.py --config /path/to/host-config.json
```
