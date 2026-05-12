"""Unit tests for d810.headless public API.

These tests verify the API surface and non-IDA-dependent paths.
configure() and start() require D810State → ida_hexrays, so their
full lifecycle tests live in tests/system/.
"""
from unittest.mock import patch

import pytest

from d810.headless import start, stop, status, configure

# Reset module state between tests
@pytest.fixture(autouse=True)
def _reset_headless_state():
    import d810.headless as _h
    _h._state = None
    _h._configured = False
    yield
    _h._state = None
    _h._configured = False


class TestImportSurface:
    def test_headless_module_importable(self):
        import d810.headless
        assert hasattr(d810.headless, "start")
        assert hasattr(d810.headless, "stop")
        assert hasattr(d810.headless, "status")
        assert hasattr(d810.headless, "configure")

    def test_start_is_callable(self):
        assert callable(start)

    def test_stop_is_callable(self):
        assert callable(stop)

    def test_status_returns_dict(self):
        result = status()
        assert isinstance(result, dict)
        assert "started" in result

    def test_configure_accepts_kwargs(self):
        import inspect
        sig = inspect.signature(configure)
        params = set(sig.parameters.keys())
        assert "project" in params
        assert "config_dir" in params
        assert "ida_user_dir" in params


class TestStatusInitial:
    def test_initial_status_not_started(self):
        s = status()
        assert s["started"] is False
        assert s["configured"] is False
        assert s["project"] is None
        assert s["ins_rules"] == 0
        assert s["blk_rules"] == 0


class TestStartWithoutConfigure:
    def test_start_raises_when_not_configured(self):
        with pytest.raises(RuntimeError, match="not configured"):
            start()


class TestStopNoop:
    def test_stop_without_state_is_noop(self):
        stop()  # should not raise

    def test_stop_without_started_is_noop(self):
        # Even with _state set but manager not started, stop is safe
        import d810.headless as _h
        _h._state = None
        _h._configured = False
        stop()
