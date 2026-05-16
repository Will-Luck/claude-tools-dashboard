"""Tests for app.py correctness and secrets handling.

Four test groups:
  1. TestSanitiseCmd — _sanitise_cmd + _SECRET_PATTERNS hardening
  2. TestGhostWindow — _reset_in_future + _scrub_stale_windows
  3. TestGroupHistory — _group_history burst-collapse logic
  4. TestWeeklyCache — weekly cache rotation in collect_all
"""

import time

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

    def test_full_git_sha_is_redacted_side_effect(self):
        """Trade-off pin: the 32+ hex rule redacts full 40-char git SHAs as a side
        effect of catching Gitea-style opaque tokens. Locked in so a future tweak
        (e.g. adding a negative lookbehind) is a conscious choice."""
        sha = "a1b2c3d4e5f67890a1b2c3d4e5f67890abcdef01"
        cmd = f"git show {sha}"
        assert sha not in app._sanitise_cmd(cmd)

    def test_sha256_digest_is_redacted_side_effect(self):
        """Trade-off pin: sha256:... docker image digests are redacted. The 64-char
        hex body matches the naked-hex rule. Tightening would need negative
        lookbehind or a dedicated sha256: passthrough rule."""
        digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        cmd = f"docker pull myimage@{digest}"
        assert "1111111111111111111111111111111111111111111111111111111111111111" not in app._sanitise_cmd(cmd)

    def test_legacy_openai_key_no_provider(self):
        """Classic OpenAI sk-<48 alphanumeric> with no provider segment."""
        key = "sk-" + "A" * 48
        cmd = f"curl -H 'X-Key: {key}' api.openai.com"
        assert key not in app._sanitise_cmd(cmd)

    def test_legacy_openai_key_mixed_alphanumeric(self):
        """Legacy OpenAI keys mix upper, lower, and digits with no dashes."""
        key = "sk-abcDEF123" + "X" * 40
        cmd = f"echo {key}"
        assert key not in app._sanitise_cmd(cmd)

    def test_sk_provider_uppercase_segment(self):
        """sk-OR-... (uppercase provider) must match the generalised sk-<prov>- rule."""
        key = "sk-OR-" + "a" * 20
        cmd = f"curl -H 'X-Key: {key}' api.openrouter.ai"
        assert key not in app._sanitise_cmd(cmd)


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

    def test_pct_absent_reset_stale_does_not_materialise_pct(self):
        # Asymmetric-case pin: a stale reset with no corresponding pct key must
        # NOT create the pct key. The scrub preserves absence symmetry.
        usage = {"weekly_reset": self._past()}
        result = app._scrub_stale_windows(usage)
        assert "weekly_pct" not in result
        assert result["weekly_reset"] is None

    def test_pct_absent_reset_fresh_does_not_materialise_pct(self):
        # Control: fresh reset with absent pct leaves both alone (no materialisation).
        usage = {"weekly_reset": self._future()}
        result = app._scrub_stale_windows(usage)
        assert "weekly_pct" not in result
        assert result["weekly_reset"] == usage["weekly_reset"]

    def test_scrub_is_idempotent(self):
        # Locking in implicit idempotence so a future "optimisation" can't break it.
        usage = {
            "session_pct": 45,
            "session_reset": self._future(),
            "weekly_pct": 62,
            "weekly_reset": self._past(),
            "sonnet_pct": 28,
            "sonnet_reset": self._past(),
        }
        once = app._scrub_stale_windows(dict(usage))
        twice = app._scrub_stale_windows(app._scrub_stale_windows(dict(usage)))
        assert once == twice


# ======================================================================
# TestCollectClaudeUsageCacheScrub — end-to-end scrub on cache hit
# ======================================================================


class TestCollectClaudeUsageCacheScrub:
    """collect_claude_usage must scrub stale windows when serving from cache.

    Seeds the module cache with mixed future/past resets and verifies the
    cache-hit return path returns scrubbed data — and that the cache itself
    stays raw (scrubbing is read-side only)."""

    def _future(self, hours=1):
        return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()

    def _past(self, hours=1):
        return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    def test_cache_hit_scrubs_newly_stale_window(self, monkeypatch):
        past = self._past()
        future = self._future()
        seeded = {
            "session_pct": 50,
            "session_reset": future,
            "weekly_pct": 20,
            "weekly_reset": past,    # stale between populate and read
            "sonnet_pct": 30,
            "sonnet_reset": future,
            "active": True,
        }
        monkeypatch.setattr(app, "_usage_cache", dict(seeded))
        monkeypatch.setattr(app, "_usage_cache_time", time.time())

        result = app.collect_claude_usage()

        # Stale weekly window scrubbed
        assert result["weekly_pct"] is None
        assert result["weekly_reset"] is None
        # Fresh windows pass through
        assert result["session_pct"] == 50
        assert result["sonnet_pct"] == 30

    def test_cache_hit_returns_copy_not_shared_cache(self, monkeypatch):
        # Mutating the returned dict must not corrupt the module-level cache.
        past = self._past()
        seeded = {
            "session_pct": 50,
            "session_reset": self._future(),
            "weekly_pct": 20,
            "weekly_reset": past,
            "active": True,
        }
        monkeypatch.setattr(app, "_usage_cache", dict(seeded))
        monkeypatch.setattr(app, "_usage_cache_time", time.time())

        result = app.collect_claude_usage()
        result["session_pct"] = 999  # caller mutates

        # Re-read: cache untouched by caller's mutation
        second = app.collect_claude_usage()
        assert second["session_pct"] == 50


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

    def test_weekly_reset_none_halts_rotation(self, tmp_path, monkeypatch):
        """Intentional-gap pin: once _scrub_stale_windows nulls weekly_reset, the
        rotation branch in collect_all (`if claude_usage and claude_usage.get("weekly_reset"):`)
        does NOT fire — dead windows must not rotate a baseline they cannot verify.

        Consequence documented in _scrub_stale_windows docstring: if Anthropic
        rate-limits past a weekly boundary, the tracker freezes mid-week rather
        than advancing against stale/expired data."""
        cache_file = self._configure_cache_dir(monkeypatch, tmp_path)
        stored_reset = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        stored_start = datetime.now(timezone.utc).isoformat()

        json.dump(
            {
                "current_week_baseline": 500,
                "current_week_start": stored_start,
                "weekly_reset_at": stored_reset,
                "last_week_savings": 42,
            },
            open(cache_file, "w"),
        )

        self._stub_collectors(monkeypatch, total_saved=1500)
        # Simulate a scrubbed snapshot: weekly_reset is None
        self._stub_usage(monkeypatch, weekly_reset=None)

        app.collect_all()

        cache = json.load(open(cache_file))
        # Rotation must NOT have fired
        assert cache["current_week_baseline"] == 500
        assert cache["weekly_reset_at"] == stored_reset
        assert cache["last_week_savings"] == 42
        assert "last_week_end" not in cache  # set only on rotation


# ======================================================================
# TestHeadroomLifetime — v1.3.0: Headroom shows lifetime, not session
# ======================================================================


class FakeResp:
    """Minimal context-manager that mimics urlopen()."""

    def __init__(self, payload):
        import json as _json
        self._body = _json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self):
        return self._body


class TestHeadroomLifetime:
    """Pre-v1.3.0 the card read tokens.saved (session only). v1.3.0 reads lifetime."""

    def _payload(self, lifetime_tokens, lifetime_usd, hit_rate, cache_usd, session_tokens):
        return {
            "tokens": {"saved": session_tokens, "savings_percent": 6.2},
            "compression_cache": {"active_sessions": 1},
            "persistent_savings": {
                "lifetime": {
                    "tokens_saved": lifetime_tokens,
                    "compression_savings_usd": lifetime_usd,
                    "requests": 29520,
                }
            },
            "prefix_cache": {
                "totals": {"hit_rate": hit_rate, "savings_usd": cache_usd}
            },
        }

    def _patch_urls(self, monkeypatch, stats_payload):
        # Two urlopen() calls: /health then /stats. First returns version, second
        # returns the rich stats payload.
        calls = {"i": 0}

        def fake_urlopen(url, timeout=2):
            calls["i"] += 1
            if calls["i"] == 1:
                return FakeResp({"version": "0.5.25", "status": "healthy"})
            return FakeResp(stats_payload)

        monkeypatch.setattr(app, "urlopen", fake_urlopen)

    def test_lifetime_overrides_session(self, monkeypatch):
        """total_saved must come from persistent_savings.lifetime when populated."""
        self._patch_urls(monkeypatch, self._payload(5_072_499_735, 25324.61, 89.4, 13.66, 23236))
        app._headroom_last_total = 0
        app._headroom_history = []
        result = app.collect_headroom()
        assert result["active"] is True
        assert result["total_saved"] == 5_072_499_735
        assert result["lifetime_saved"] == 5_072_499_735
        assert result["lifetime_savings_usd"] == 25324.61
        assert result["session_saved"] == 23236
        assert result["cache_hit_rate"] == 89.4
        assert result["cache_savings_usd"] == 13.66

    def test_fallback_to_session_when_lifetime_empty(self, monkeypatch):
        """Fresh Headroom install: lifetime is zero, so use session value."""
        self._patch_urls(monkeypatch, self._payload(0, 0, None, 0, 23236))
        app._headroom_last_total = 0
        app._headroom_history = []
        result = app.collect_headroom()
        assert result["total_saved"] == 23236
        assert result["lifetime_saved"] == 0
        assert result["session_saved"] == 23236

    def test_cache_hit_rate_can_be_null(self, monkeypatch):
        """If Headroom hasn't seen a cache hit yet, hit_rate is None — not 0."""
        self._patch_urls(monkeypatch, self._payload(100, 1.0, None, 0, 50))
        app._headroom_last_total = 0
        app._headroom_history = []
        result = app.collect_headroom()
        assert result["cache_hit_rate"] is None


# ======================================================================
# TestUsageFromHeadroom — v1.3.0: skip Anthropic API when Headroom has the data
# ======================================================================


class TestUsageFromHeadroom:
    """_usage_from_headroom() avoids a redundant call to /oauth/usage."""

    def _stats_with_window(self, fh_pct, sd_pct, sonnet_pct):
        return {
            "subscription_window": {
                "latest": {
                    "five_hour": {"utilization_pct": fh_pct, "resets_at": "2026-05-17T00:50:00Z"},
                    "seven_day": {"utilization_pct": sd_pct, "resets_at": "2026-05-18T22:00:00Z"},
                    "seven_day_sonnet": {"utilization_pct": sonnet_pct, "resets_at": None},
                }
            }
        }

    def test_reads_subscription_window(self, monkeypatch):
        payload = self._stats_with_window(7.0, 28.0, 0.0)
        monkeypatch.setattr(app, "urlopen", lambda *a, **k: FakeResp(payload))
        result = app._usage_from_headroom()
        assert result is not None
        assert result["source"] == "headroom"
        assert result["session_pct"] == 7.0
        assert result["weekly_pct"] == 28.0
        assert result["sonnet_pct"] == 0.0

    def test_returns_none_when_no_subscription_data(self, monkeypatch):
        monkeypatch.setattr(app, "urlopen", lambda *a, **k: FakeResp({}))
        assert app._usage_from_headroom() is None

    def test_returns_none_when_urlopen_fails(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("connection refused")
        monkeypatch.setattr(app, "urlopen", boom)
        assert app._usage_from_headroom() is None

    def test_collect_usage_prefers_headroom(self, monkeypatch):
        """When Headroom is reachable, no OAuth call is made."""
        payload = self._stats_with_window(7.0, 28.0, 5.0)
        monkeypatch.setattr(app, "urlopen", lambda *a, **k: FakeResp(payload))

        def must_not_call(*a, **k):
            raise AssertionError("OAuth fallback was used despite Headroom being available")

        monkeypatch.setattr(app, "_read_oauth_token", must_not_call)
        app._usage_cache = {}
        app._usage_cache_time = 0
        result = app.collect_claude_usage()
        assert result["session_pct"] == 7.0
        assert result["source"] == "headroom"


# ======================================================================
# TestOverallHealth — v1.3.0: header pulse-dot reflects worst-tool health
# ======================================================================


class TestOverallHealth:
    """Smoke: collect_all() emits overall_health derived from per-tool health.

    Per-tool health is computed from _last_collect_success timestamps inside collect_all:
      - ok:    active AND last_success > 0 AND age < 60s
      - stale: last_success > 0 but stale OR active=False
      - error: last_success == 0 (never succeeded)
    """

    def _stub_all_collectors(self, monkeypatch, active=True):
        """Return active stubs so collect_all populates results without network."""
        stub = lambda: {"active": active, "total_saved": 0, "history": []}
        for name in ("rtk", "headroom", "jcodemunch", "jdocmunch", "jdatamunch"):
            monkeypatch.setattr(app, f"collect_{name}", stub)
        monkeypatch.setattr(app, "collect_claude_usage", lambda: {"active": False})

    def test_all_ok(self, monkeypatch):
        self._stub_all_collectors(monkeypatch, active=True)
        result = app.collect_all()
        assert result["overall_health"] == "ok"

    def test_any_stale_yields_stale(self, monkeypatch):
        """active=False with prior success → stale per the function logic."""
        self._stub_all_collectors(monkeypatch, active=True)
        # Force one tool to be inactive but with prior success in the past
        import time as _time
        app._last_collect_success["jcodemunch"] = _time.time() - 5
        monkeypatch.setattr(
            app, "collect_jcodemunch",
            lambda: {"active": False, "total_saved": 0, "history": []},
        )
        result = app.collect_all()
        assert result["overall_health"] == "stale"

    def test_any_error_yields_error(self, monkeypatch):
        """Collector returns None AND has no prior success → error."""
        self._stub_all_collectors(monkeypatch, active=True)
        # Reset the success ledger to make jdatamunch look brand-new and broken
        app._last_collect_success.pop("jdatamunch", None)
        monkeypatch.setattr(app, "collect_jdatamunch", lambda: None)
        # _last_good must also be empty so it falls back to default-inactive shape
        app._last_good.pop("jdatamunch", None)
        result = app.collect_all()
        assert result["overall_health"] == "error"


# ======================================================================
# TestApiStats — v1.3.0: /api/stats returns snapshot JSON
# ======================================================================


class TestApiStats:
    """The new pull-style JSON endpoint."""

    def test_api_stats_returns_dict(self, monkeypatch):
        # Pre-populate the collector snapshot so we don't need a live tick.
        app._collector._snapshot = {
            "combined_saved": 12345,
            "combined_saved_usd": 1.23,
            "overall_health": "ok",
            "timestamp": "2026-05-16T00:00:00+00:00",
        }
        client = app.app.test_client()
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["combined_saved"] == 12345
        assert body["combined_saved_usd"] == 1.23
        assert body["overall_health"] == "ok"

    def test_api_stats_empty_snapshot(self, monkeypatch):
        app._collector._snapshot = None
        client = app.app.test_client()
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        assert resp.get_json() == {}


# ======================================================================
# TestWeeklySavingsClamp — v1.4.0: negative weekly totals are impossible
# ======================================================================


class TestWeeklySavingsClamp:
    """Regression for the live tools.lucknet.uk bug where Saved Last Week
    showed -5,072,457,996 tokens. Two protections:
      - rotation clamps `last_week_savings = max(0, combined_saved - baseline)`
      - per-tick clamp re-snapshots baseline when `this_week_savings < 0`
    """

    def _stub_collectors_with_total(self, monkeypatch, total):
        """RTK reports `total`, all other collectors zero so we can predict combined_saved."""
        monkeypatch.setattr(app, "collect_rtk", lambda: {"active": True, "total_saved": total, "history": []})
        for n in ("headroom", "jcodemunch", "jdocmunch", "jdatamunch"):
            monkeypatch.setattr(app, f"collect_{n}", lambda: {"active": True, "total_saved": 0, "history": []})

    def test_rotation_never_negative(self, monkeypatch, tmp_path):
        """When baseline is inflated above current combined_saved, last_week clamps to 0."""
        monkeypatch.setattr(app, "WEEKLY_CACHE_DIR", str(tmp_path))
        cache_path = tmp_path / "weekly.json"
        # Pre-seed an inflated baseline (mimics tools.lucknet.uk state).
        import json as _json
        _json.dump({
            "current_week_baseline": 5_000_000_000,
            "weekly_reset_at": "2026-05-11T22:00:00Z",
            "current_week_start": "2026-05-04T22:00:00Z",
            "last_week_savings": 0,
        }, open(cache_path, "w"))

        # Combined is much smaller than baseline now.
        self._stub_collectors_with_total(monkeypatch, 100_000_000)
        # Fresh reset is in the future so the rotation branch fires.
        monkeypatch.setattr(app, "collect_claude_usage", lambda: {
            "active": True, "weekly_reset": "2026-05-18T22:00:00Z"
        })

        result = app.collect_all()
        # No negative numbers ever leave collect_all.
        assert result["weekly"]["last_week"] >= 0
        assert result["weekly"]["this_week"] >= 0

    def test_per_tick_resets_inverted_baseline(self, monkeypatch, tmp_path):
        """If a previous version stored a huge baseline, the next tick re-snapshots."""
        monkeypatch.setattr(app, "WEEKLY_CACHE_DIR", str(tmp_path))
        cache_path = tmp_path / "weekly.json"
        # Pre-seed: same week, baseline is bigger than current combined_saved.
        # No rotation should fire (stored_reset == fresh_reset).
        import json as _json
        _json.dump({
            "current_week_baseline": 5_000_000_000,
            "weekly_reset_at": "2026-05-18T22:00:00Z",
            "current_week_start": "2026-05-11T22:00:00Z",
            "last_week_savings": 0,
        }, open(cache_path, "w"))

        self._stub_collectors_with_total(monkeypatch, 100_000_000)
        monkeypatch.setattr(app, "collect_claude_usage", lambda: {
            "active": True, "weekly_reset": "2026-05-18T22:00:00Z"
        })

        result = app.collect_all()
        # This-week clamps to 0 and the baseline is re-snapshotted.
        assert result["weekly"]["this_week"] == 0
        # Cache file must reflect the re-snapshot.
        cache = _json.load(open(cache_path))
        assert cache["current_week_baseline"] == 100_000_000

    def test_stored_negative_last_week_clamped_on_read(self, monkeypatch, tmp_path):
        """Cache file with legacy negative last_week (e.g. produced by v1.2.2)
        must still display as 0 in v1.4.0+ rather than leaking the negative."""
        monkeypatch.setattr(app, "WEEKLY_CACHE_DIR", str(tmp_path))
        cache_path = tmp_path / "weekly.json"
        import json as _json
        _json.dump({
            "current_week_baseline": 100_000_000,
            "weekly_reset_at": "2026-05-18T22:00:00Z",
            "current_week_start": "2026-05-11T22:00:00Z",
            "last_week_savings": -5_072_457_996,
        }, open(cache_path, "w"))

        self._stub_collectors_with_total(monkeypatch, 100_000_000)
        monkeypatch.setattr(app, "collect_claude_usage", lambda: {
            "active": True, "weekly_reset": "2026-05-18T22:00:00Z"
        })

        result = app.collect_all()
        assert result["weekly"]["last_week"] == 0  # never the cached negative
