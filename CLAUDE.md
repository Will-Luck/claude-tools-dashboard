# Claude Tools Dashboard

Live token-savings wallboard for RTK, Headroom, jCodeMunch, and jDocMunch. Single-file Flask app with SSE streaming.

## Build & Run

```bash
cd /home/lns/claude-tools-dashboard
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # flask, python-dotenv

# Configure (only override what differs from defaults)
cp .env.example .env
# Production .env just sets PORT=62891

python app.py                     # http://0.0.0.0:62891
```

Dependencies: Python 3, Flask, python-dotenv. No systemd service or Docker in production -- runs as a bare process.

## Architecture

Single file: `app.py` (~1500 lines). Everything lives here -- collectors, SSE endpoint, and inline HTML/CSS/JS.

**Collectors** (four parallel data sources):
- `collect_rtk()` -- reads RTK SQLite DB at `~/.local/share/rtk/history.db`
- `collect_headroom()` -- polls Headroom proxy stats at `http://127.0.0.1:8787`
- `collect_jcodemunch()` -- reads `~/.code-index/_savings.json` and index DBs
- `collect_jdocmunch()` -- reads `~/.doc-index/` savings and index stats

**Data flow:**
1. `DashboardCollector` (daemon thread) calls `collect_all()` every 0.25s
2. `collect_all()` runs all four collectors, tracks sparklines, merges history, calculates weekly savings
3. `GET /events` SSE endpoint pushes snapshots to the browser every `SSE_INTERVAL` (default 2s)
4. `GET /` serves the inline HTML dashboard
5. `GET /health` returns `{"status": "ok"}`

**Weekly savings** are tracked via `~/.cache/claude-tools-dashboard/` cache files, using the Anthropic usage API (`collect_claude_usage()`) for reset timing.

**Environment variables** (all optional, see `.env.example`):
`PORT`, `HEADROOM_URL`, `RTK_DB_PATH`, `RTK_BIN`, `JCODEMUNCH_INDEX_DIR`, `JCODEMUNCH_BIN`, `JDOCMUNCH_INDEX_DIR`, `JDOCMUNCH_BIN`, `SSE_INTERVAL`, `COLLECTOR_INTERVAL`, `CLAUDE_CREDENTIALS`, `WEEKLY_CACHE_DIR`

## Conventions

- All UI is inline in the `HTML` constant -- no separate static files or templates
- Security: `_sanitise_cmd()` redacts secrets from shell commands before they reach the frontend
- Collectors never raise -- they return `None` on failure, and `collect_all()` falls back to last-good data
- Version strings are resolved once at startup via `resolve_versions_once()` to avoid subprocess work on the hot path
- Sparkline buffers use `collections.deque` with a 120-entry cap

## Release workflow

Gitea is the squash authority. All merges happen via Gitea PRs. Never squash-merge on GitHub -- squashing the same branch twice (once per remote) produces two different commits with identical content, and the next PR conflicts on shared files (`CHANGELOG.md` is a reliable offender).

Remotes here: `gitea` = Gitea, `origin` = GitHub. Default branch: `master`.

1. Open the PR on Gitea, get CI green, merge (squash).
2. Smoke-test locally -- for the dashboard this is `uv run python dashboard.py` + a browser check that SSE updates work.
3. Fast-forward GitHub: `git push origin gitea/master:master`. No GitHub PR needed.
4. Cut the release tag: move `[Unreleased]` -> `[X.Y.Z] - YYYY-MM-DD` in `CHANGELOG.md`, commit on `master`, `git tag -a vX.Y.Z -m "..."`, push tag to both remotes.

External GitHub contributor? Pull their branch, push to Gitea, open a Gitea PR, squash there, fast-forward GitHub. Their GitHub PR auto-closes as "merged".
