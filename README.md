# port-scanner

A command-line TCP port scanner written in Python. It tries a full TCP
connection to each requested port, reports the ports that accept one, names
the service for 39 well-known ports, and reads a banner from open ports when
the service sends one.

It uses only `socket`, `threading`, `queue` and `selectors` from the standard
library. `colorama` is the single dependency and is used for coloured output.

## Responsible use

Only scan hosts you own or have explicit permission to scan. Scanning other
people's systems can be illegal and can be logged as hostile activity. The
program prints this reminder on every run.

## Install

Python 3 and colorama. Developed and tested on Python 3.13 on Windows 10; the
test workflow in `.github/workflows` also runs on Linux and Python 3.10.

```
pip install -r requirements.txt
```

## Usage

```
python portscanner.py <target> [--ports 1-1024] [--threads 500]
                      [--output file.txt] [--no-banner] [--timeout 1.0]
                      [--engine threads|select] [--ipv6] [--json] [--version]
```

| Option | Default | Meaning |
|---|---|---|
| `target` | required | Hostname, IPv4 address or IPv6 address. |
| `--ports` | `1-1024` | A range (`1-1024`), a list (`22,80,443`) or both (`22,80,8000-8100`). Valid ports are 1-65535. |
| `--threads` | `500` | Worker threads, 1-1000. Never more than the number of ports. With `--engine select` it is the number of connections in flight, 1-4096. |
| `--output FILE` | none | Write a report to `FILE`: plain text sorted by port, or JSON with `--json`. |
| `--no-banner` | off | Do not try to read banners from open ports. |
| `--timeout` | `1.0` | Seconds to wait for each connection (and for a greeting banner). |
| `--engine` | `threads` | `threads`: one blocking connect per thread. `select`: non-blocking connects multiplexed with `selectors`. |
| `-6`, `--ipv6` | off | Resolve hostnames to IPv6 only. Hostnames otherwise resolve to IPv4 first; IPv6 literals always work. |
| `--json` | off | Print the result as JSON on stdout instead of the table. Warnings and messages go to stderr. |
| `--version` | | Print the version and exit. |

Examples:

```
python portscanner.py 127.0.0.1
python portscanner.py 127.0.0.1 --ports 22,80,443
python portscanner.py 192.168.1.10 --ports 1-1024,3306,8000-8100 --threads 200
python portscanner.py myserver.local --no-banner --timeout 0.5 --output report.txt
python portscanner.py ::1 --ports 1-65535 --engine select --threads 2000
python portscanner.py 127.0.0.1 --ports 1-1024 --json > result.json
```

Open ports are printed as soon as they are found, so the live order follows
completion order. When the scan ends they are listed again sorted by port.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished (whether or not any port was open). |
| 1 | Runtime error: host could not be resolved, or the output file could not be written. |
| 2 | Invalid arguments, such as a bad port or an out-of-range thread count. |
| 130 | Interrupted with Ctrl+C. Results found so far are still printed and written. |

### JSON output

Real output of `--ports 80,41030,41070 --json` against the local test server:

```
{
  "target": "127.0.0.1",
  "ip": "127.0.0.1",
  "ports": "80,41030,41070",
  "ports_total": 3,
  "ports_attempted": 3,
  "status": "complete",
  "started": "2026-10-01T00:36:10",
  "duration_seconds": 0.512,
  "open_ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "banner": "HTTP/1.0 200 OK Server: BenchServer"
    },
    {
      "port": 41030,
      "protocol": "tcp",
      "service": "unknown",
      "banner": ""
    },
    {
      "port": 41070,
      "protocol": "tcp",
      "service": "unknown",
      "banner": "SSH-2.0-BenchServer_1.0"
    }
  ]
}
```

`status` is `complete` or `interrupted`. Open ports are sorted by port.

## How it works

1. `--ports` is parsed into a sorted list of unique ports. Malformed input is
   rejected with a message naming the bad entry.
2. The target is resolved once, before scanning. Hostnames prefer IPv4; use
   `--ipv6` to require IPv6.
3. The ports are put into a `queue.Queue`. Worker threads take ports from it
   until it is empty.
4. **Threads engine (default).** Each worker opens a new socket, sets the
   timeout and calls `connect_ex()`. A return value of 0 means the port is
   open, unless the socket connected to itself (same local and remote address).
   That can happen when the OS picks the scanned port as the source port for a
   connection to the same host, and it is not counted as open.
5. **Select engine.** Each thread keeps up to 400 non-blocking connects in
   flight and waits on them with `selectors`, so one thread does the work of
   hundreds. Connections that succeed are handed to a short-lived helper thread
   to read the banner, at most as many helpers as the loop has connections;
   beyond that the banner is read inline. File-descriptor exhaustion makes the
   loop retry instead of losing ports.
6. For open ports (unless `--no-banner`) a banner is read:
   - Ports 80, 8000, 8008, 8080 and 8888: sends `HEAD / HTTP/1.0` and reads
     the reply. TLS ports (443, 8443) are not probed.
   - Ports 21, 22 and 25 (FTP, SSH, SMTP) announce themselves, so it only
     listens, for up to `--timeout` seconds.
   - Any other open port is listened to for at most 0.5 seconds (or
     `--timeout` if that is shorter).
   - The bytes received are reduced to printable ASCII, whitespace runs become
     one space, and the result is cut to 200 characters. Binary data is
     handled the same way and cannot break the output.
7. A lock is taken only when a port turns out to be open, to append the result
   and print it.
8. Ctrl+C stops the workers after their current port. The scanner prints what
   it has found, marks the report as interrupted and exits with code 130.

### Windows loopback

On Windows, a connection to a closed port on the same machine is refused only
after about 2 seconds, because the OS resends the SYN twice. For targets that
are loopback addresses (`127.0.0.0/8`, `::1`) the scanner turns that off for
each socket with the `SIO_TCP_INITIAL_RTO` option, through `ctypes`, and a
closed port is refused in about 15 ms. It is not applied to any other
address: on a real network a dropped SYN would then look like a closed port.

Report file layout (real output from a scan of the local test server):

```
Port scan report
================
Target:      127.0.0.1
Ports:       80,41030,41070,41110,41500 (5 ports)
Started:     2026-10-01 00:14:19
Duration:    0.51 s
Status:      complete
Open ports:  4

PORT      STATE  SERVICE         BANNER
80/tcp    open   http            HTTP/1.0 200 OK Server: BenchServer
41030/tcp open   unknown
41070/tcp open   unknown         SSH-2.0-BenchServer_1.0
41110/tcp open   unknown
```

## Tests

```
python -m unittest
```

The tests cover port parsing, banner cleanup, scanning local listening
sockets with both engines (IPv4 and IPv6), the HTTP HEAD path, self-connect
handling, the Windows loopback option, JSON output, Ctrl+C handling and the
command-line error paths. They only connect to 127.0.0.1 and ::1.

## Limitations

- TCP connect scan only. The full handshake is completed, so the scan shows
  up in the target's logs.
- Service names come from the port number, not from the traffic.
- A port that drops packets (filtered) and a closed port both report as not
  open; the scanner does not tell them apart.
- Each open connection is closed right after the banner read; nothing is sent
  to non-HTTP services.
- With the threads engine, `--threads` above about 1000 is refused because
  every thread holds a socket and many systems limit open descriptors to
  1024. The select engine copes with descriptor limits by slowing down.
- Against a remote host, scan time is roughly `ceil(ports / concurrency) *
  timeout` for ports that do not answer, so `--threads` and `--timeout` are
  the settings that matter.

## Benchmark

`benchmark.py` scans only 127.0.0.1. It starts a test server in a separate
process with 219 listening ports, then times the scanner against a plain
version of the original design (Queue, N daemon threads, one lock around
results, `task_done()`/`join()`, the same timeout for connect and banner read,
target passed to `connect_ex()` as given). The baseline is a reconstruction
from the project description, not the original code. Each result is checked
against the ports the test server opened, or, for the full-range scan, against
the other implementation, before its time is recorded.

```
python benchmark.py            # about 8 minutes
python benchmark.py --runs 1   # quick pass
```

Conditions: Windows 10 Pro (10.0.19045), AMD Ryzen 7 5825U (8 cores, 16
threads), 15.3 GB RAM, Python 3.13.7, loopback only, timeout 1.0 s unless
stated. Implementations alternate within a scenario; values are medians in
seconds over 3 to 5 runs. The 1024-port workload is port 80 plus 41000-42022,
with 19 open (1 HTTP, 6 that send a greeting, 12 silent).

| Scenario | old | new, no loopback fix | new | new, select engine |
|---|---|---|---|---|
| 1024 ports, 100 threads | 11.11 | 11.10 | 0.58 | 0.61 |
| 1024 ports, 500 threads | | 3.04 | 0.58 | 0.56 |
| 200 ports, all open and silent, 100 threads | 2.05 | | 1.05 | 1.08 |
| 200 ports, all open, `--no-banner` | 0.022 | | 0.030 | 0.027 |
| all 65535 ports, 500 threads (243 open) | | | 3.94 | 3.66 |

"No loopback fix" switches off the Windows option described above, which is
how a non-loopback Windows target behaves. Without it, thread count and
timeout decide the time (1024 ports, "old" / "new, no loopback fix"):

| Threads | 50 | 200 | 500 | 1000 |
|---|---|---|---|---|
| old | 21.21 | 6.07 | 3.04 | 2.02 |
| new, no loopback fix | 21.24 | 6.07 | 3.04 | 2.03 |

With 100 threads and no loopback fix, timeouts of 0.25 s, 0.5 s, 1.0 s and
2.5 s gave 2.85 s, 5.63 s, 11.10 s and 22.42 s.

What the numbers show:

- The 11.1 s to 0.58 s difference comes only from the Windows loopback fix and
  only applies to loopback targets. The remaining 0.58 s is the 0.5 s banner
  wait on silent open ports.
- Without the fix, the time is `ceil(ports / threads) * timeout`, and the new
  code is no faster than the baseline at any thread count. That is the case
  for any non-loopback target on Windows, although these numbers were measured
  on loopback only.
- The banner wait is the other measured gain: the old design waits the full
  timeout on every silent open port, the new one at most 0.5 s.
- The select engine is not measurably faster than the threads engine in any
  scenario here. What it changes is how many threads are needed, which was not
  measured.
- Connection setup and locking costs are too small to measure here. On the
  open-ports-only case without banners the new code is about 5 to 8 ms slower
  over 200 ports.
- Connect timeouts against filtered remote hosts cannot be measured without
  scanning something other than this computer, so they were not measured.
  Linux and macOS were not benchmarked.
