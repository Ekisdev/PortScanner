# port-scanner

A command-line TCP port scanner written in Python. It tries a full TCP
connection to each requested port, reports the ports that accept one, names
the service for 39 well-known ports, and reads a banner from open ports when
the service sends one.

It uses only `socket`, `threading` and `queue` from the standard library.
`colorama` is the single dependency and is used for coloured output.

## Responsible use

Only scan hosts you own or have explicit permission to scan. Scanning other
people's systems can be illegal and can be logged as hostile activity. The
program prints this reminder on every run.

## Install

Python 3 and colorama. Developed and tested on Python 3.13 on Windows 10.

```
pip install -r requirements.txt
```

## Usage

```
python portscanner.py <target> [--ports 1-1024] [--threads 100]
                      [--output file.txt] [--no-banner] [--timeout 1.0]
```

| Option | Default | Meaning |
|---|---|---|
| `target` | required | Hostname or IPv4 address. |
| `--ports` | `1-1024` | A range (`1-1024`), a list (`22,80,443`) or both (`22,80,8000-8100`). Valid ports are 1-65535. |
| `--threads` | `100` | Worker threads, 1-1000. Never more than the number of ports. |
| `--output FILE` | none | Write a plain-text report to `FILE`, sorted by port. |
| `--no-banner` | off | Do not try to read banners from open ports. |
| `--timeout` | `1.0` | Seconds to wait for each connection (and for a greeting banner). |

Examples:

```
python portscanner.py 127.0.0.1
python portscanner.py 127.0.0.1 --ports 22,80,443
python portscanner.py 192.168.1.10 --ports 1-1024,3306,8000-8100 --threads 200
python portscanner.py myserver.local --no-banner --timeout 0.5 --output report.txt
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

## How it works

1. `--ports` is parsed into a sorted list of unique ports. Malformed input is
   rejected with a message naming the bad entry.
2. The target is resolved to an IPv4 address once, before scanning.
3. The ports are put into a `queue.Queue`. Up to `--threads` worker threads
   take ports from it until it is empty.
4. Each worker opens a new socket, sets the timeout and calls `connect_ex()`.
   A return value of 0 means the port is open, unless the socket connected to
   itself (same local and remote address). That can happen when the OS picks
   the scanned port as the source port for a connection to the same host, and
   is not counted as open.
5. For open ports (unless `--no-banner`) it reads a banner:
   - Port 80: sends `HEAD / HTTP/1.0` and reads the reply.
   - Ports 21, 22 and 25 (FTP, SSH, SMTP) announce themselves, so it only
     listens, for up to `--timeout` seconds.
   - Any other open port is listened to for at most 0.5 seconds (or
     `--timeout` if that is shorter).
   - The bytes received are reduced to printable ASCII, whitespace runs become
     one space, and the result is cut to 200 characters. Binary data is
     handled the same way and cannot break the output.
6. A lock is taken only when a port turns out to be open, to append the result
   and print it.
7. Ctrl+C stops the workers after their current port. The scanner prints what
   it has found, marks the report as interrupted and exits with code 130.

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
sockets, the HTTP HEAD path, Ctrl+C handling and the command-line error paths.
They only connect to 127.0.0.1.

## Limitations

- TCP connect scan only. The full handshake is completed, so the scan shows
  up in the target's logs.
- IPv4 only.
- Service names come from the port number, not from the traffic.
- A port that drops packets (filtered) and a closed port both report as not
  open; the scanner does not tell them apart.
- On Windows, connecting to a closed port on the same machine takes about
  2 seconds to be refused because the OS retries the connection. With the
  default 1 second timeout each such port therefore costs one full timeout,
  and scan time is roughly `ceil(ports / threads) * timeout`.

## Benchmark

`benchmark.py` scans only 127.0.0.1 (and `localhost`). It starts a test server
in a separate process with 219 listening ports, then times the scanner against
a plain version of the original design (Queue, N daemon threads, one lock
around results, `task_done()`/`join()`, the same timeout for connect and banner
read, target passed to `connect_ex()` as given). The baseline is a
reconstruction from the project description, not the original code. Both must
return the expected open ports before a time is recorded.

```
python benchmark.py            # about 10 minutes
python benchmark.py --runs 1   # quick pass
```

Conditions for the numbers below: Windows 10 Pro (10.0.19045), AMD Ryzen 7 5825U
(8 cores, 16 threads), 15.3 GB RAM, Python 3.13.7, loopback only, timeout 1.0 s
unless stated. Old and new runs alternate; values are medians in seconds. The
1024-port workload is port 80 plus 41000-42022, with 19 open (1 HTTP, 6 that
send a greeting, 12 silent).

| Scenario | Old | New |
|---|---|---|
| 1024 ports, 100 threads, banners on | 11.11 | 11.11 |
| same, `--no-banner` | 11.09 | 11.10 |
| same, target `localhost` | 11.13 | 11.11 |
| 200 ports, all open and silent, 100 threads, banners on | 2.06 | 1.05 |
| 200 ports, all open, `--no-banner` | 0.022 | 0.028 |
| 1024 ports, 50 threads | 21.21 | 21.24 |
| 1024 ports, 200 threads | 6.08 | 6.05 |
| 1024 ports, 500 threads | 3.03 | 3.04 |
| 1024 ports, 1000 threads | 2.03 | 2.03 |

New only, 1024 ports, 100 threads, varying `--timeout`: 0.25 s gives 2.85 s,
0.5 s gives 5.64 s, 1.0 s gives 11.11 s, 2.5 s gives 22.34 s.

What the numbers show:

- Where closed ports dominate, old and new take the same time. On Windows a
  closed local port is refused only after about 2.04 s, so each one costs
  `min(timeout, 2.04 s)`. Total time is `ceil(ports / threads) * timeout`, and
  only `--threads` and `--timeout` change it.
- The measured gain is in banner waits. The old design waits the full timeout
  on every silent open port; the new one waits at most 0.5 s.
- Connection setup and locking are too small to measure here. On the
  open-port-only case without banners, the new version is not faster (about
  6 ms slower over 200 ports).
- Connect timeouts against filtered remote hosts cannot be measured without
  scanning something other than this computer, so they were not measured.
