"""Tests for app.py correctness and secrets handling.

Four test groups:
  1. TestSanitiseCmd — _sanitise_cmd + _SECRET_PATTERNS hardening
  2. TestGhostWindow — _reset_in_future + _scrub_stale_windows
  3. TestGroupHistory — _group_history burst-collapse logic
  4. TestWeeklyCache — weekly cache rotation in collect_all
"""

import app
from hypothesis import given, strategies as st, settings


def test_import_app():
    """Smoke: the app module imports cleanly and exposes its Flask app."""
    assert hasattr(app, "app")
    assert callable(app.app)


# ======================================================================
# TestSanitiseCmd — existing patterns (regression net)
# ======================================================================


class TestSanitiseCmdExistingPatterns:
    """Lock in the current six patterns so we don't break them during hardening."""

    def test_docker_env_flag_short(self):
        result = app._sanitise_cmd("docker run -e SECRET_KEY=hunter2 myimg")
        assert "hunter2" not in result
        assert "-e SECRET_KEY=***" in result

    def test_docker_env_flag_long(self):
        result = app._sanitise_cmd("docker run --env API_TOKEN=abc123 myimg")
        assert "abc123" not in result
        assert "--env API_TOKEN=***" in result

    def test_keyword_env_var(self):
        result = app._sanitise_cmd("export PASSWORD=letmein")
        assert "letmein" not in result
        assert "PASSWORD=***" in result

    def test_keyword_env_var_case_insensitive(self):
        result = app._sanitise_cmd("export MyApiKey=supersecret")
        assert "supersecret" not in result

    def test_sk_ant_anthropic_key(self):
        result = app._sanitise_cmd("echo sk-ant-abc123def456ghi789")
        assert "sk-ant-abc123def456ghi789" not in result
        assert "sk-ant-***" in result

    def test_authorization_bearer(self):
        result = app._sanitise_cmd("curl -H 'Authorization: Bearer eyJhbGciOi123' api.com")
        assert "eyJhbGciOi123" not in result

    def test_authorization_token(self):
        result = app._sanitise_cmd("curl -H 'Authorization: Token abc123xyz' api.com")
        assert "abc123xyz" not in result

    def test_authorization_basic(self):
        result = app._sanitise_cmd("curl -H 'Authorization: Basic dXNlcjpwYXNz' api.com")
        assert "dXNlcjpwYXNz" not in result

    def test_x_api_key_header(self):
        result = app._sanitise_cmd("curl -H 'X-API-Key: sekrit123' api.com")
        assert "sekrit123" not in result

    def test_x_auth_token_header(self):
        result = app._sanitise_cmd("curl -H 'X-Auth-Token: token99' api.com")
        assert "token99" not in result

    def test_curl_u_credentials(self):
        result = app._sanitise_cmd("curl -u admin:hunter2 https://example.com")
        assert "hunter2" not in result

    def test_benign_command_unchanged(self):
        cmd = "git status && docker ps && ls -la /tmp"
        assert app._sanitise_cmd(cmd) == cmd

    def test_none_input(self):
        assert app._sanitise_cmd(None) is None

    def test_empty_string(self):
        assert app._sanitise_cmd("") == ""


# ======================================================================
# TestSanitiseCmd — new patterns (will fail until Task 5 implements them)
# ======================================================================


class TestSanitiseCmdNewPatterns:
    """Secrets that currently slip through. These fail until _SECRET_PATTERNS is extended."""

    def test_github_personal_token(self):
        cmd = "gh auth login --with-token ghp_abcdefghij1234567890abcdefghij1234567890"
        result = app._sanitise_cmd(cmd)
        assert "ghp_abcdefghij1234567890abcdefghij1234567890" not in result

    def test_github_oauth_token(self):
        cmd = "echo gho_abcdefghij1234567890abcdefghij1234567890"
        result = app._sanitise_cmd(cmd)
        assert "gho_abcdefghij1234567890abcdefghij1234567890" not in result

    def test_gitlab_personal_token(self):
        cmd = "curl -H 'PRIVATE-TOKEN: glpat-xxxxxxxxxxxxxxxxxxxx' gitlab.com"
        result = app._sanitise_cmd(cmd)
        assert "glpat-xxxxxxxxxxxxxxxxxxxx" not in result

    def test_slack_bot_token(self):
        cmd = "curl -d token=xoxb-1234567890-abcdefghij slack.com/api/chat"
        result = app._sanitise_cmd(cmd)
        assert "xoxb-1234567890-abcdefghij" not in result

    def test_slack_user_token(self):
        cmd = "echo xoxp-1234567890-abcdefghij"
        result = app._sanitise_cmd(cmd)
        assert "xoxp-1234567890-abcdefghij" not in result

    def test_generalised_sk_provider_key(self):
        cmd = "curl -H 'X-Key: sk-or-abcdef1234567890xyz' api.openrouter.ai"
        result = app._sanitise_cmd(cmd)
        assert "sk-or-abcdef1234567890xyz" not in result

    def test_url_embedded_credentials(self):
        cmd = "git clone https://will:hunter2@github.com/repo.git"
        result = app._sanitise_cmd(cmd)
        assert "hunter2" not in result
        assert "will" in result  # username preserved; only password redacted

    def test_json_api_key(self):
        cmd = 'curl -d \'{"api_key": "sk_live_abc123xyz789"}\' example.com'
        result = app._sanitise_cmd(cmd)
        assert "sk_live_abc123xyz789" not in result

    def test_json_access_token(self):
        cmd = 'curl -d \'{"access_token":"eyJhbGci1234567890"}\' example.com'
        result = app._sanitise_cmd(cmd)
        assert "eyJhbGci1234567890" not in result

    def test_naked_hex_40_char(self):
        """The Gitea-token shape we saw in session: 40-char hex, no prefix."""
        cmd = "rtk proxy curl -H 'Authorization: token 81d89def1444595593923933845b56581a3aa8a3' gitea"
        result = app._sanitise_cmd(cmd)
        assert "81d89def1444595593923933845b56581a3aa8a3" not in result

    def test_naked_hex_32_char(self):
        cmd = "echo abcdef01234567890abcdef0123456789"
        result = app._sanitise_cmd(cmd)
        assert "abcdef01234567890abcdef0123456789" not in result

    def test_short_git_sha_preserved(self):
        """7-char SHAs must survive — they're useful and not secrets."""
        cmd = "git show a1b2c3d"
        assert app._sanitise_cmd(cmd) == cmd

    def test_eight_char_git_sha_preserved(self):
        cmd = "git log a1b2c3d4..HEAD"
        assert app._sanitise_cmd(cmd) == cmd


# ======================================================================
# TestSanitiseCmd — property-based on long hex tokens
# ======================================================================


class TestSanitiseCmdProperty:
    """Hypothesis: any all-lowercase hex token ≥32 chars, embedded in any command,
    must not survive _sanitise_cmd."""

    @given(
        hex_token=st.text(alphabet="abcdef0123456789", min_size=32, max_size=80),
        before=st.sampled_from(["", "echo ", "curl -H 'X: ", "rtk proxy curl "]),
        after=st.sampled_from(["", "' api.com", " done", " && echo ok"]),
    )
    @settings(max_examples=200, deadline=None)
    def test_long_hex_tokens_always_redacted(self, hex_token, before, after):
        cmd = before + hex_token + after
        result = app._sanitise_cmd(cmd)
        assert hex_token not in result, f"Hex token survived in: {result!r}"


# ======================================================================
# TestGhostWindow — _reset_in_future + _scrub_stale_windows
# ======================================================================

from datetime import datetime, timedelta, timezone


class TestResetInFuture:
    """_reset_in_future(iso_ts) → True iff iso_ts is a parseable ISO-8601 in the future (UTC)."""

    def test_future_timestamp_returns_true(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        assert app._reset_in_future(future) is True

    def test_past_timestamp_returns_false(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert app._reset_in_future(past) is False

    def test_none_returns_false(self):
        assert app._reset_in_future(None) is False

    def test_empty_string_returns_false(self):
        assert app._reset_in_future("") is False

    def test_garbage_returns_false(self):
        assert app._reset_in_future("not-a-date") is False

    def test_very_far_future(self):
        far_future = "2099-01-01T00:00:00+00:00"
        assert app._reset_in_future(far_future) is True

    def test_exact_now_returns_false(self):
        # Strict > comparison: an exact now timestamp (no future delta) should be False.
        # We construct a timestamp a microsecond in the past to avoid flake.
        just_past = (datetime.now(timezone.utc) - timedelta(microseconds=1)).isoformat()
        assert app._reset_in_future(just_past) is False


class TestScrubStaleWindows:
    """_scrub_stale_windows nulls out pct+reset pairs whose reset is in the past."""

    def _future(self, hours=1):
        return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()

    def _past(self, hours=1):
        return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    def test_none_input_returns_none(self):
        assert app._scrub_stale_windows(None) is None

    def test_empty_dict_unchanged(self):
        assert app._scrub_stale_windows({}) == {}

    def test_all_fresh_windows_untouched(self):
        usage = {
            "session_pct": 45,
            "session_reset": self._future(),
            "weekly_pct": 62,
            "weekly_reset": self._future(),
            "sonnet_pct": 28,
            "sonnet_reset": self._future(),
            "active": True,
        }
        result = app._scrub_stale_windows(usage)
        assert result["session_pct"] == 45
        assert result["weekly_pct"] == 62
        assert result["sonnet_pct"] == 28

    def test_stale_weekly_scrubbed(self):
        usage = {
            "session_pct": 45,
            "session_reset": self._future(),
            "weekly_pct": 62,
            "weekly_reset": self._past(),
            "sonnet_pct": 28,
            "sonnet_reset": self._future(),
        }
        result = app._scrub_stale_windows(usage)
        assert result["session_pct"] == 45
        assert result["weekly_pct"] is None
        assert result["weekly_reset"] is None
        assert result["sonnet_pct"] == 28

    def test_all_stale_scrubbed(self):
        usage = {
            "session_pct": 45,
            "session_reset": self._past(),
            "weekly_pct": 62,
            "weekly_reset": self._past(),
            "sonnet_pct": 28,
            "sonnet_reset": self._past(),
        }
        result = app._scrub_stale_windows(usage)
        assert result["session_pct"] is None
        assert result["weekly_pct"] is None
        assert result["sonnet_pct"] is None

    def test_reset_missing_pct_preserved(self):
        # If reset key is absent entirely, pct stays untouched (no way to verify staleness).
        usage = {"session_pct": 45, "weekly_pct": 62}
        result = app._scrub_stale_windows(usage)
        assert result["session_pct"] == 45
        assert result["weekly_pct"] == 62


# ======================================================================
# TestGroupHistory — burst-collapse logic
# ======================================================================


def _ts(seconds_ago):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


class TestGroupHistory:
    """_group_history collapses consecutive same-tool same-prefix entries within 10s."""

    def test_empty_input_returns_empty(self):
        assert app._group_history([]) == []

    def test_single_entry_passes_through(self):
        entry = {"time": _ts(0), "tool": "rtk", "cmd": "git status", "saved_tokens": 100, "saved_pct": 50}
        assert app._group_history([entry]) == [entry]

    def test_two_same_prefix_within_10s_collapse(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git status", "saved_tokens": 100, "saved_pct": 50},
            {"time": _ts(3), "tool": "rtk", "cmd": "git diff", "saved_tokens": 200, "saved_pct": 60},
        ]
        result = app._group_history(entries)
        assert len(result) == 1
        assert result[0]["cmd"] == "2x git"
        assert result[0]["saved_tokens"] == 300
        assert result[0]["count"] == 2
        assert result[0]["grouped"] is True

    def test_two_same_prefix_beyond_10s_not_collapsed(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git status", "saved_tokens": 100, "saved_pct": 50},
            {"time": _ts(15), "tool": "rtk", "cmd": "git diff", "saved_tokens": 200, "saved_pct": 60},
        ]
        result = app._group_history(entries)
        assert len(result) == 2

    def test_different_tools_not_collapsed(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git status", "saved_tokens": 100, "saved_pct": 50},
            {"time": _ts(2), "tool": "headroom", "cmd": "git status", "saved_tokens": 200, "saved_pct": 60},
        ]
        assert len(app._group_history(entries)) == 2

    def test_high_savings_breaks_batch(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git diff HEAD", "saved_tokens": 50, "saved_pct": 20},
            {"time": _ts(2), "tool": "rtk", "cmd": "git diff", "saved_tokens": 1500, "saved_pct": 90},
            {"time": _ts(4), "tool": "rtk", "cmd": "git diff", "saved_tokens": 60, "saved_pct": 25},
        ]
        result = app._group_history(entries)
        # High-savings entry stays separate. The surrounding low-savings entries should be
        # returned as-is because the high-entry breaks them into singletons.
        assert len(result) == 3
        assert result[1]["saved_tokens"] == 1500
        assert "grouped" not in result[1]

    def test_weighted_average_pct(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git a", "saved_tokens": 100, "saved_pct": 10},
            {"time": _ts(2), "tool": "rtk", "cmd": "git b", "saved_tokens": 200, "saved_pct": 50},
            {"time": _ts(4), "tool": "rtk", "cmd": "git c", "saved_tokens": 300, "saved_pct": 30},
        ]
        result = app._group_history(entries)
        # Weights are max(saved, 1): 100, 200, 300 → weighted pct = (10*100 + 50*200 + 30*300)/600 = 33.3
        assert len(result) == 1
        assert result[0]["saved_pct"] == 33.3
        assert result[0]["saved_tokens"] == 600

    def test_three_entry_burst(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git a", "saved_tokens": 100, "saved_pct": 10},
            {"time": _ts(2), "tool": "rtk", "cmd": "git b", "saved_tokens": 100, "saved_pct": 10},
            {"time": _ts(4), "tool": "rtk", "cmd": "git c", "saved_tokens": 100, "saved_pct": 10},
        ]
        result = app._group_history(entries)
        assert len(result) == 1
        assert result[0]["cmd"] == "3x git"
        assert result[0]["count"] == 3

    def test_unparseable_timestamp_breaks_batch(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git a", "saved_tokens": 100, "saved_pct": 10},
            {"time": "garbage", "tool": "rtk", "cmd": "git b", "saved_tokens": 200, "saved_pct": 20},
        ]
        result = app._group_history(entries)
        assert len(result) == 2

    def test_singleton_between_groups(self):
        entries = [
            {"time": _ts(0), "tool": "rtk", "cmd": "git a", "saved_tokens": 100, "saved_pct": 10},
            {"time": _ts(2), "tool": "rtk", "cmd": "git b", "saved_tokens": 100, "saved_pct": 10},
            {"time": _ts(3), "tool": "rtk", "cmd": "docker ps", "saved_tokens": 100, "saved_pct": 10},
            {"time": _ts(5), "tool": "rtk", "cmd": "docker ls", "saved_tokens": 100, "saved_pct": 10},
        ]
        result = app._group_history(entries)
        # git burst → "2x git", then docker burst → "2x docker"
        assert len(result) == 2
        assert result[0]["cmd"] == "2x git"
        assert result[1]["cmd"] == "2x docker"


# ======================================================================
# TestWeeklyCache — rotation in collect_all
# ======================================================================

import json
import os


class TestWeeklyCacheRotation:
    """collect_all must rotate the weekly tracker when claude_usage.weekly_reset advances."""

    def _stub_collectors(self, monkeypatch, total_saved):
        """Patch each collect_* to return a minimal valid result with a known total_saved."""
        stub = lambda: {  # noqa: E731
            "active": True,
            "total_saved": total_saved // 4,
            "version": "stub",
            "history": [],
        }
        monkeypatch.setattr(app, "collect_rtk", stub)
        monkeypatch.setattr(app, "collect_headroom", stub)
        monkeypatch.setattr(app, "collect_jcodemunch", stub)
        monkeypatch.setattr(app, "collect_jdocmunch", stub)

    def _stub_usage(self, monkeypatch, weekly_reset):
        monkeypatch.setattr(
            app,
            "collect_claude_usage",
            lambda: {
                "active": True,
                "session_pct": 20,
                "session_reset": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                "weekly_pct": 40,
                "weekly_reset": weekly_reset,
                "sonnet_pct": 10,
                "sonnet_reset": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
            },
        )

    def _configure_cache_dir(self, monkeypatch, tmp_path):
        monkeypatch.setattr(app, "WEEKLY_CACHE_DIR", str(tmp_path))
        return str(tmp_path / "weekly.json")

    def test_first_run_sets_baseline(self, tmp_path, monkeypatch):
        cache_file = self._configure_cache_dir(monkeypatch, tmp_path)
        future_reset = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        self._stub_collectors(monkeypatch, total_saved=1000)
        self._stub_usage(monkeypatch, weekly_reset=future_reset)

        result = app.collect_all()

        assert os.path.exists(cache_file)
        cache = json.load(open(cache_file))
        assert cache["current_week_baseline"] == 1000
        assert cache["weekly_reset_at"] == future_reset
        assert cache["last_week_savings"] == 0
        assert result["weekly"]["this_week"] == 0

    def test_same_reset_no_rotation(self, tmp_path, monkeypatch):
        cache_file = self._configure_cache_dir(monkeypatch, tmp_path)
        reset = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()

        # Seed cache
        json.dump(
            {
                "current_week_baseline": 500,
                "current_week_start": datetime.now(timezone.utc).isoformat(),
                "weekly_reset_at": reset,
                "last_week_savings": 123,
            },
            open(cache_file, "w"),
        )

        self._stub_collectors(monkeypatch, total_saved=800)
        self._stub_usage(monkeypatch, weekly_reset=reset)

        result = app.collect_all()

        cache = json.load(open(cache_file))
        assert cache["current_week_baseline"] == 500  # unchanged
        assert cache["last_week_savings"] == 123      # unchanged
        assert result["weekly"]["this_week"] == 300   # 800 - 500

    def test_reset_advanced_rotates(self, tmp_path, monkeypatch):
        cache_file = self._configure_cache_dir(monkeypatch, tmp_path)
        old_reset = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        new_reset = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

        json.dump(
            {
                "current_week_baseline": 500,
                "current_week_start": datetime.now(timezone.utc).isoformat(),
                "weekly_reset_at": old_reset,
                "last_week_savings": 0,
            },
            open(cache_file, "w"),
        )

        self._stub_collectors(monkeypatch, total_saved=1200)
        self._stub_usage(monkeypatch, weekly_reset=new_reset)

        app.collect_all()

        cache = json.load(open(cache_file))
        assert cache["weekly_reset_at"] == new_reset
        assert cache["last_week_savings"] == 700     # 1200 - 500
        assert cache["last_week_end"] == old_reset
        assert cache["current_week_baseline"] == 1200
