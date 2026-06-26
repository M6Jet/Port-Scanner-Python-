# 🔍 Multithreaded Python Port Scanner

A fast, multithreaded TCP port scanner built in Python for authorized network
reconnaissance and security auditing. It uses a thread pool to scan thousands of
ports concurrently, with service-name resolution, optional banner grabbing, and
machine-readable JSON output.

## Features

- **Concurrent scanning** via a configurable `ThreadPoolExecutor` thread pool
- **Flexible port specs** — ranges (`1-1024`), lists (`22,80,443`), or a mix (`1-100,8080`)
- **Service detection** — resolves well-known port numbers to service names (22 → ssh)
- **Banner grabbing** (`--banner`) to fingerprint services on open ports
- **JSON export** (`--json results.json`) for piping into other tools
- **Clean CLI** with `argparse` — no interactive prompts, fully scriptable
- Graceful handling of unresolvable hosts and invalid input

## Why multithreading matters

A single-threaded scanner waits out the full connection timeout on every closed
or filtered port, one at a time. Against a remote host with a 0.5s timeout, a
1,000-port scan can take several minutes. A thread pool issues many connection
attempts concurrently, so the total scan time is bounded by the slowest *batch*
rather than the *sum* of every port's timeout.

### Benchmark

Measured on my machine against `scanme.nmap.org` (the Nmap project's
scan-permitted test host), scanning ports 1–1024 with a 0.5s timeout:

| Mode                       | Time      |
|----------------------------|-----------|
| Single-threaded (1 worker) | `106.51 s` |
| Multithreaded (200 workers)| `0.72 s` |
| **Speedup**                | **148×**   |

> Reproduce these numbers yourself:
> ```bash
> # single-threaded
> python3 scanner.py scanme.nmap.org -p 1-1024 -t 1 --timeout 0.5
> # multithreaded
> python3 scanner.py scanme.nmap.org -p 1-1024 -t 200 --timeout 0.5
> ```
> The timing line is printed at the end of each scan. Your speedup will vary with
> network latency — slower links show a larger gain, since threads hide more waiting.

## Install

```bash
git clone https://github.com/M6Jet/Port-Scanner-Python-.git
cd Port-Scanner-Python-
# No third-party dependencies required — standard library only.
python3 scanner.py --help
```

## Usage

```bash
# Scan the well-known ports on a host
python3 scanner.py scanme.nmap.org

# Scan a specific range with 200 threads
python3 scanner.py 192.168.1.1 -p 1-65535 -t 200

# Scan a handful of named ports and grab banners
python3 scanner.py example.com -p 22,80,443,8080 --banner

# Export results to JSON
python3 scanner.py 10.0.0.5 -p 1-1024 --json scan.json
```

### Options

| Flag             | Description                                | Default |
|------------------|--------------------------------------------|---------|
| `target`         | Hostname or IP to scan (positional)        | —       |
| `-p, --ports`    | Port spec: `1-1024`, `22,80`, or a mix     | `1-1024`|
| `-t, --threads`  | Concurrent worker threads                  | `100`   |
| `--timeout`      | Per-connection timeout (seconds)           | `0.5`   |
| `--banner`       | Attempt banner grabbing on open ports      | off     |
| `--json FILE`    | Write results to a JSON file               | —       |

## Example output

```
Scan report for scanme.nmap.org (45.33.32.156)
Scanned 1024 ports in 2.13s — 2 open

  PORT    STATE   SERVICE       BANNER
  ------  -----   -------       ------
  22      open    ssh           SSH-2.0-OpenSSH_6.6.1p1 Ubuntu
  80      open    http          HTTP/1.1 200 OK
```

## How it works

Each port is scanned by `socket.connect_ex`, which returns an error code instead
of raising on a closed port — keeping the hot path fast across tens of thousands
of ports. Connection attempts are dispatched to a `ThreadPoolExecutor`, and
results are collected as each future completes. Open ports are then enriched with
a service name and, optionally, a banner.

## ⚠️ Ethical use

This tool is for **authorized** security testing and education only. Only scan
hosts you own or have explicit written permission to test. Unauthorized port
scanning may be illegal in your jurisdiction. `scanme.nmap.org` is provided by
the Nmap project specifically for legal scan testing.

## License

See [LICENSE](LICENSE).
