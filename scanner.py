#!/usr/bin/env python3
"""
portscanner — a fast, multithreaded TCP port scanner.

Uses a thread pool to scan many ports concurrently, with optional banner
grabbing and service-name resolution. Designed for authorized network
reconnaissance and security auditing.

Examples:
    python scanner.py scanme.nmap.org
    python scanner.py 192.168.1.1 -p 1-1024 -t 200
    python scanner.py example.com -p 22,80,443,8080 --banner
    python scanner.py 10.0.0.5 -p 1-65535 --json results.json

Ethical use only: scan hosts you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed"
    service: str = ""
    banner: str = ""


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '1-1024', '22,80,443', or '1-100,8080' into a sorted list."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        else:
            p = int(chunk)
            if 1 <= p <= 65535:
                ports.add(p)
    if not ports:
        raise ValueError(f"no valid ports in spec: {spec!r}")
    return sorted(ports)


def service_name(port: int) -> str:
    """Best-effort service name for a TCP port (e.g. 22 -> 'ssh'). Empty if unknown."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def grab_banner(host: str, port: int, timeout: float) -> str:
    """Try to read a short service banner from an open port. Returns '' on failure."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # Some services (HTTP) need a nudge before they speak.
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(256)
            return data.decode("utf-8", errors="replace").strip().split("\n")[0][:120]
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float, banner: bool) -> PortResult | None:
    """Scan a single TCP port. Returns a PortResult if open, else None.

    Uses connect_ex so a closed port returns an error code instead of raising,
    which keeps the hot path fast across thousands of ports.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            result = PortResult(port=port, state="open", service=service_name(port))
            if banner:
                result.banner = grab_banner(host, port, timeout)
            return result
    return None


def scan(
    host: str,
    ports: list[int],
    timeout: float,
    workers: int,
    banner: bool,
) -> list[PortResult]:
    """Scan all ports concurrently with a thread pool. Returns open ports, sorted."""
    open_ports: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, host, port, timeout, banner): port for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports, key=lambda r: r.port)


def resolve_host(target: str) -> str:
    """Resolve a hostname to an IPv4 address, exiting cleanly on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"error: could not resolve host {target!r}", file=sys.stderr)
        sys.exit(2)


def print_report(target: str, host: str, results: list[PortResult], elapsed: float, total: int) -> None:
    print(f"\nScan report for {target} ({host})")
    print(f"Scanned {total} ports in {elapsed:.2f}s — {len(results)} open\n")
    if not results:
        print("  No open ports found.")
        return
    print(f"  {'PORT':<8}{'STATE':<8}{'SERVICE':<14}BANNER")
    print(f"  {'-'*6:<8}{'-'*5:<8}{'-'*7:<14}{'-'*6}")
    for r in results:
        print(f"  {r.port:<8}{r.state:<8}{(r.service or '?'):<14}{r.banner}")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="Fast multithreaded TCP port scanner for authorized security testing.",
    )
    parser.add_argument("target", help="Hostname or IP address to scan.")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan: '1-1024', '22,80,443', or a mix. Default: 1-1024.")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of concurrent worker threads. Default: 100.")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Per-connection timeout in seconds. Default: 0.5.")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt banner grabbing on open ports.")
    parser.add_argument("--json", metavar="FILE",
                        help="Write results to a JSON file.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    host = resolve_host(args.target)
    workers = max(1, min(args.threads, len(ports)))

    start = datetime.now()
    results = scan(host, ports, args.timeout, workers, args.banner)
    elapsed = (datetime.now() - start).total_seconds()

    print_report(args.target, host, results, elapsed, len(ports))

    if args.json:
        payload = {
            "target": args.target,
            "host": host,
            "scanned_at": start.isoformat(),
            "ports_scanned": len(ports),
            "elapsed_seconds": round(elapsed, 3),
            "threads": workers,
            "open_ports": [asdict(r) for r in results],
        }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"Results written to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
