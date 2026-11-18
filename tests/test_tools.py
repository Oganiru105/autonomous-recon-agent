"""
Run with: pytest

These tests focus on the one thing that matters most for safety: the
allowlist check. They don't require a live target.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.tools import ToolBox  # noqa: E402


class FakeConfig:
    allowed_hosts = ["localhost", "127.0.0.1"]
    max_ports_scanned = 5
    common_paths = ["/robots.txt"]


@pytest.fixture
def toolbox():
    return ToolBox(FakeConfig())


def test_blocks_disallowed_host(toolbox):
    with pytest.raises(PermissionError):
        toolbox.http_request("http://example.com")


def test_blocks_disallowed_host_for_port_scan(toolbox):
    with pytest.raises(PermissionError):
        toolbox.port_scan("example.com")


def test_blocks_disallowed_host_for_dir_brute(toolbox):
    with pytest.raises(PermissionError):
        toolbox.dir_brute("http://example.com")


def test_allows_allowlisted_host_check_passes(toolbox):
    # Should not raise — whether the connection itself succeeds or times
    # out is irrelevant here, only the allowlist gate is under test.
    try:
        toolbox.port_scan("127.0.0.1", ports=[1])
    except PermissionError:
        pytest.fail("Allowlisted host was incorrectly blocked.")
