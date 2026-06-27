"""Tests for the multithreaded port scanner.

Network-dependent tests use a local listening socket on an ephemeral port so the
suite is fast and deterministic — no external hosts required.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from scanner import PortResult, parse_ports, scan, scan_port, service_name


# ---------- port-spec parsing ----------

def test_parse_single_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_comma_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_mixed():
    assert parse_ports("1-3,8080") == [1, 2, 3, 8080]


def test_parse_reversed_range_is_normalized():
    assert parse_ports("5-1") == [1, 2, 3, 4, 5]


def test_parse_dedupes_and_sorts():
    assert parse_ports("80,22,80,443,22") == [22, 80, 443]


def test_parse_clamps_out_of_range():
    # 0 and 70000 are invalid; only valid ports survive
    assert parse_ports("0,70000,443") == [443]


def test_parse_empty_raises():
    with pytest.raises(ValueError):
        parse_ports("")


# ---------- service name resolution ----------

def test_service_name_known_port():
    # 22 should resolve to ssh on essentially every platform
    assert service_name(22) == "ssh"


def test_service_name_unknown_port_is_empty():
    # An ephemeral high port should have no well-known service name
    assert service_name(64999) == ""


# ---------- live scanning against a local socket ----------

@pytest.fixture
def open_port():
    """Open a listening socket on an OS-assigned port; yield its number."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    stop = threading.Event()

    def _accept_loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                continue

    t = threading.Thread(target=_accept_loop, daemon=True)
    t.start()
    time.sleep(0.05)
    yield port
    stop.set()
    srv.close()


def test_scan_port_detects_open(open_port):
    result = scan_port("127.0.0.1", open_port, timeout=0.5, banner=False)
    assert result is not None
    assert result.state == "open"
    assert result.port == open_port


def test_scan_port_closed_returns_none():
    # Port 1 on localhost is almost certainly closed
    result = scan_port("127.0.0.1", 1, timeout=0.3, banner=False)
    assert result is None


def test_scan_finds_open_port_in_range(open_port):
    results = scan("127.0.0.1", [open_port, 1, 2], timeout=0.3, workers=10, banner=False)
    open_numbers = {r.port for r in results}
    assert open_port in open_numbers


def test_scan_results_are_sorted(open_port):
    results = scan("127.0.0.1", list(range(open_port - 2, open_port + 1)),
                   timeout=0.3, workers=5, banner=False)
    ports = [r.port for r in results]
    assert ports == sorted(ports)


def test_port_result_dataclass():
    r = PortResult(port=80, state="open", service="http")
    assert r.port == 80
    assert r.service == "http"
    assert r.banner == ""
