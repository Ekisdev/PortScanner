#!/usr/bin/env python3
"""Multithreaded TCP connect port scanner.

Built on the standard library (socket, threading, queue, selectors); colorama
is used only for coloured output. Only scan hosts you own or have permission
to scan.

Usage:
    python portscanner.py <target> [--ports 1-1024] [--threads 500]
                          [--output file.txt] [--no-banner] [--timeout 1.0]
                          [--engine threads|select] [--ipv6] [--json]
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import math
import queue
import selectors
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, Sequence

from colorama import Fore, init as colorama_init

__version__ = "1.0.0"

DEFAULT_PORTS = "1-1024"
DEFAULT_THREADS = 500
DEFAULT_TIMEOUT = 1.0
MAX_THREADS = 1000  # threads engine: one thread and one socket per connection
MAX_CONCURRENCY = 4096  # select engine: connections in flight
MAX_TIMEOUT = 300.0
MAX_PORT = 65535
ENGINES = ("threads", "select")

# Ports that get an HTTP HEAD request. TLS ports (443, 8443) are not probed.
HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8888})
# Services that send a greeting as soon as the connection opens. They get the
# full --timeout to do so; any other open port is only listened to briefly.
SPEAK_FIRST_PORTS = frozenset({21, 22, 25})
BANNER_SILENT_WAIT = 0.5
BANNER_READ_BYTES = 1024
BANNER_MAX_CHARS = 200

# Each selector loop handles at most this many connections. Windows select()
# is limited to 512 sockets, so stay below that.
SELECT_LOOP_CAPACITY = 400

# After Ctrl+C, wait at most this long for in-flight connections to finish.
INTERRUPT_GRACE = 2.0

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2  # also used by argparse for invalid arguments
EXIT_INTERRUPTED = 130

COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}

WARNING_TEXT = (
    "Only scan hosts you own or have explicit permission to scan. "
    "Unauthorised scanning may be illegal."
)

# connect_ex() results meaning "still connecting" on a non-blocking socket.
_CONNECT_IN_PROGRESS = frozenset(
    getattr(errno, name)
    for name in ("EINPROGRESS", "EWOULDBLOCK", "EALREADY", "WSAEWOULDBLOCK")
    if hasattr(errno, name)
)


class PortSpecError(ValueError):
    """Raised when a --ports value cannot be parsed."""


class ResolveError(Exception):
    """Raised when the target cannot be resolved to an address."""


@dataclass(frozen=True)
class Target:
    """A resolved scan target."""

    host: str  # as given on the command line
    ip: str
    family: int  # socket.AF_INET or socket.AF_INET6
    extra: tuple = ()  # IPv6 flow info and scope id, empty for IPv4
    loopback: bool = False

    def address(self, port: int) -> tuple:
        """Return the socket address tuple for ``port``."""
        return (self.ip, port) + self.extra


@dataclass(frozen=True)
class PortResult:
    """An open port with its service name and (possibly empty) banner."""

    port: int
    service: str
    banner: str


@dataclass
class ScanResult:
    """Outcome of a scan. ``open_ports`` is sorted by port number."""

    open_ports: list[PortResult]
    total: int
    attempted: int
    elapsed: float
    interrupted: bool


# --------------------------------------------------------------------------
# Parsing and formatting helpers
# --------------------------------------------------------------------------

def _parse_port_number(text: str, entry: str) -> int:
    text = text.strip()
    if not (text.isascii() and text.isdigit()):
        raise PortSpecError(
            f"invalid port entry {entry!r}: expected a number or a range such as 1-1024"
        )
    number = int(text)
    if not 1 <= number <= MAX_PORT:
        raise PortSpecError(f"port {number} is out of range (1-{MAX_PORT})")
    return number


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification into a sorted list of unique ports.

    The spec is a comma-separated list of single ports and inclusive ranges,
    for example ``"22,80,443"``, ``"1-1024"`` or ``"22,80,8000-8100"``.
    Raises PortSpecError with a readable message if it is malformed.
    """
    ports: set[int] = set()
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            raise PortSpecError(f"empty entry in port list {spec!r}")
        first, dash, last = entry.partition("-")
        start = _parse_port_number(first, entry)
        end = _parse_port_number(last, entry) if dash else start
        if start > end:
            raise PortSpecError(f"invalid range {entry!r}: start is greater than end")
        ports.update(range(start, end + 1))
    return sorted(ports)


# Maps every byte outside printable ASCII to a space. Binary data and control
# characters therefore cannot break the terminal or the report file.
_PRINTABLE_ASCII = bytes(b if 32 <= b < 127 else 32 for b in range(256))


def clean_banner(data: bytes) -> str:
    """Squash raw banner bytes into a single line of at most 200 characters.

    Non-printable bytes and runs of whitespace (including newlines) become a
    single space.
    """
    text = data.translate(_PRINTABLE_ASCII).decode("ascii")
    return " ".join(text.split())[:BANNER_MAX_CHARS].rstrip()


def service_name(port: int) -> str:
    """Return the well-known service name for ``port``, or ``"unknown"``."""
    return COMMON_PORTS.get(port, "unknown")


def format_row(result: PortResult, with_banner: bool = True) -> str:
    """Format one open port as a fixed-width table row."""
    row = f"{f'{result.port}/tcp':<10}{'open':<7}{result.service:<16}"
    if with_banner:
        row += result.banner
    return row.rstrip()


def table_header(with_banner: bool = True) -> str:
    """Return the header line matching ``format_row``."""
    header = f"{'PORT':<10}{'STATE':<7}{'SERVICE':<16}"
    return (header + "BANNER") if with_banner else header.rstrip()


def _target_label(target: Target) -> str:
    return target.host if target.host == target.ip else f"{target.host} ({target.ip})"


def format_report(target: Target, port_spec: str, result: ScanResult, started: datetime) -> str:
    """Build the plain-text report written by --output (sorted by port)."""
    if result.interrupted:
        status = f"interrupted ({result.attempted} of {result.total} ports attempted)"
    else:
        status = "complete"
    lines = [
        "Port scan report",
        "================",
        f"Target:      {_target_label(target)}",
        f"Ports:       {port_spec} ({result.total} ports)",
        f"Started:     {started:%Y-%m-%d %H:%M:%S}",
        f"Duration:    {result.elapsed:.2f} s",
        f"Status:      {status}",
        f"Open ports:  {len(result.open_ports)}",
        "",
    ]
    if result.open_ports:
        lines.append(table_header())
        lines.extend(format_row(r) for r in result.open_ports)
    else:
        lines.append("No open ports found.")
    return "\n".join(lines) + "\n"


def format_json(target: Target, port_spec: str, result: ScanResult, started: datetime) -> str:
    """Build the JSON document printed by --json (open ports sorted by port)."""
    document = {
        "target": target.host,
        "ip": target.ip,
        "ports": port_spec,
        "ports_total": result.total,
        "ports_attempted": result.attempted,
        "status": "interrupted" if result.interrupted else "complete",
        "started": started.isoformat(timespec="seconds"),
        "duration_seconds": round(result.elapsed, 3),
        "open_ports": [
            {"port": r.port, "protocol": "tcp", "service": r.service, "banner": r.banner}
            for r in result.open_ports
        ],
    }
    return json.dumps(document, indent=2) + "\n"


# --------------------------------------------------------------------------
# Target resolution and socket helpers
# --------------------------------------------------------------------------

def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


def resolve_target(host: str, prefer_ipv6: bool = False) -> Target:
    """Resolve ``host`` (name, IPv4 or IPv6 literal) to a single address.

    Names that have both kinds of address resolve to IPv4 unless
    ``prefer_ipv6`` is set, in which case only an IPv6 address is accepted.
    Raises ResolveError if the host cannot be resolved.
    """
    if not host.strip():
        raise ResolveError("the target host is empty")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ResolveError(f"cannot resolve host {host!r}: {exc}") from None
    addresses: dict[int, tuple] = {}
    for family, _, _, _, sockaddr in infos:
        addresses.setdefault(family, sockaddr)
    order = (socket.AF_INET6,) if prefer_ipv6 else (socket.AF_INET, socket.AF_INET6)
    for family in order:
        if family in addresses:
            sockaddr = addresses[family]
            return Target(host, sockaddr[0], family, tuple(sockaddr[2:]), _is_loopback(sockaddr[0]))
    kind = "IPv6" if prefer_ipv6 else "IPv4 or IPv6"
    raise ResolveError(f"host {host!r} has no {kind} address")


def _make_syn_retransmit_disabler() -> Callable[[socket.socket], None]:
    """Return a function that stops Windows retrying refused connections.

    After a connection is refused, Windows resends the SYN twice, so a closed
    port on the same machine is only reported after about 2 seconds. The
    SIO_TCP_INITIAL_RTO option turns that off for one socket. It is applied
    only to loopback targets, where packets are never lost; on a real network
    a dropped SYN would otherwise show up as a closed port. On other platforms
    the returned function does nothing.
    """
    if sys.platform != "win32":
        return lambda sock: None

    import ctypes
    from ctypes import wintypes

    sio_tcp_initial_rto = 0x98000011
    unspecified_rtt = 0xFFFF
    no_syn_retransmissions = 0xFE

    class RtoParameters(ctypes.Structure):
        _fields_ = [("Rtt", ctypes.c_ushort), ("MaxSynRetransmissions", ctypes.c_ubyte)]

    ws2_32 = ctypes.WinDLL("ws2_32")
    ioctl = ws2_32.WSAIoctl
    ioctl.restype = ctypes.c_int
    ioctl.argtypes = [
        ctypes.c_size_t, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p, ctypes.c_void_p,
    ]

    def disable(sock: socket.socket) -> None:
        params = RtoParameters(unspecified_rtt, no_syn_retransmissions)
        returned = wintypes.DWORD(0)
        # A non-zero result (option unsupported on old Windows) only means the
        # default behaviour is kept, so it is ignored.
        ioctl(sock.fileno(), sio_tcp_initial_rto, ctypes.byref(params),
              ctypes.sizeof(params), None, 0, ctypes.byref(returned), None, None)

    return disable


_disable_syn_retransmit = _make_syn_retransmit_disabler()


def _connected_to_itself(sock: socket.socket) -> bool:
    """True if a "successful" connect was really a TCP self-connect.

    When the ephemeral source port chosen by the OS equals the destination
    port on the same host, TCP simultaneous open makes connect() succeed
    against the socket itself although nothing is listening.
    """
    return sock.getsockname() == sock.getpeername()


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Read a banner from an already-connected socket; return "" on failure.

    HTTP ports get a HEAD request. Every other port is only listened to: SSH,
    FTP and SMTP announce themselves on connect. Silent services cost at most
    ``BANNER_SILENT_WAIT`` seconds (never more than ``timeout``).
    """
    try:
        if port in HTTP_PORTS:
            sock.settimeout(timeout)
            host_header = f"[{host}]" if ":" in host and not host.startswith("[") else host
            request = f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("ascii", "replace"))
        elif port in SPEAK_FIRST_PORTS:
            sock.settimeout(timeout)
        else:
            sock.settimeout(min(timeout, BANNER_SILENT_WAIT))
        return clean_banner(sock.recv(BANNER_READ_BYTES))
    except OSError:  # timeout, reset, broken pipe
        return ""


def scan_port(
    target: Target, port: int, timeout: float, grab: bool = True
) -> Optional[PortResult]:
    """Try a blocking TCP connect to ``port``; return a PortResult if it is open."""
    try:
        with socket.socket(target.family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if target.loopback:
                _disable_syn_retransmit(sock)
            if sock.connect_ex(target.address(port)) != 0 or _connected_to_itself(sock):
                return None
            banner = grab_banner(sock, target.host, port, timeout) if grab else ""
    except OSError:
        return None
    return PortResult(port, service_name(port), banner)


def _join_all(workers: Sequence[threading.Thread], deadline: Optional[float] = None) -> None:
    """Wait for workers in short slices so Ctrl+C stays responsive on Windows."""
    for worker in workers:
        while worker.is_alive():
            if deadline is not None and time.monotonic() >= deadline:
                return
            worker.join(0.1)


def _select_loop(
    target: Target,
    tasks: "queue.Queue[int]",
    capacity: int,
    timeout: float,
    grab: bool,
    record: Callable[[PortResult], None],
    stop: threading.Event,
) -> None:
    """Keep up to ``capacity`` non-blocking connects in flight on one thread.

    Used by the ``select`` engine. Connections that succeed are handed to a
    short-lived helper thread to read the banner, so a silent service never
    stalls the loop.
    """
    selector = selectors.DefaultSelector()
    pending: dict[socket.socket, tuple[int, float]] = {}  # socket -> (port, deadline)
    helpers: list[threading.Thread] = []

    def finish_open(sock: socket.socket, port: int) -> None:
        with sock:
            banner = grab_banner(sock, target.host, port, timeout) if grab else ""
        record(PortResult(port, service_name(port), banner))

    def settle(sock: socket.socket, port: int) -> None:
        """Handle a connect attempt that has completed, successfully or not."""
        helpers[:] = [h for h in helpers if h.is_alive()]
        try:
            connected = (
                sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
                and not _connected_to_itself(sock)
            )
        except OSError:
            connected = False
        if not connected:
            sock.close()
        elif grab and len(helpers) < capacity:
            helper = threading.Thread(target=finish_open, args=(sock, port), daemon=True)
            helper.start()
            helpers.append(helper)
        else:  # no banner wanted, or too many helpers running: do it here
            finish_open(sock, port)

    def start_connects() -> bool:
        """Fill the window. Returns False if the OS ran out of sockets."""
        nonlocal capacity
        while len(pending) < capacity and not stop.is_set():
            try:
                port = tasks.get_nowait()
            except queue.Empty:
                return True
            try:
                sock = socket.socket(target.family, socket.SOCK_STREAM)
            except OSError:  # out of file descriptors: retry as connections finish
                tasks.put(port)
                capacity = max(1, len(pending))
                return False
            sock.setblocking(False)
            if target.loopback:
                _disable_syn_retransmit(sock)
            try:
                code = sock.connect_ex(target.address(port))
            except OSError:
                sock.close()
                continue
            if code in _CONNECT_IN_PROGRESS:
                selector.register(sock, selectors.EVENT_WRITE)
                pending[sock] = (port, time.monotonic() + timeout)
            elif code == 0:
                settle(sock, port)
            else:  # refused immediately
                sock.close()
        return True

    try:
        while not stop.is_set():
            starved = not start_connects()
            if not pending:
                if starved:
                    time.sleep(0.05)
                    continue
                break
            next_deadline = min(deadline for _, deadline in pending.values())
            wait = min(0.1, max(0.0, next_deadline - time.monotonic()))
            for key, _ in selector.select(wait):
                sock = key.fileobj
                port, _ = pending.pop(sock)
                selector.unregister(sock)
                settle(sock, port)
            now = time.monotonic()
            for sock in [s for s, (_, deadline) in pending.items() if deadline <= now]:
                del pending[sock]
                selector.unregister(sock)
                sock.close()
    finally:
        for sock in pending:
            sock.close()
        selector.close()
        _join_all(helpers)


def scan(
    target: Target,
    ports: Sequence[int],
    *,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    grab_banners: bool = True,
    engine: str = "threads",
    on_open: Optional[Callable[[PortResult], None]] = None,
) -> ScanResult:
    """Scan ``ports`` on ``target``.

    Ports are put in a Queue and worker threads pull from it until it is
    empty. With ``engine="threads"`` each worker makes one blocking connect at
    a time. With ``engine="select"`` ``threads`` is the number of connections
    in flight, spread over as few selector-driven threads as possible.
    ``on_open`` is called (under a lock, so calls never interleave) as soon as
    an open port is found. A KeyboardInterrupt does not propagate: the scan
    stops and the partial result is returned with ``interrupted=True``.
    """
    if engine not in ENGINES:
        raise ValueError(f"unknown engine {engine!r}; choose from {', '.join(ENGINES)}")
    tasks: queue.Queue[int] = queue.Queue()
    for port in ports:
        tasks.put(port)
    total = tasks.qsize()

    found: list[PortResult] = []
    found_lock = threading.Lock()  # taken only when a port is open
    stop = threading.Event()

    def record(result: PortResult) -> None:
        with found_lock:
            found.append(result)
            if on_open is not None:
                on_open(result)

    def blocking_worker() -> None:
        while not stop.is_set():
            try:
                port = tasks.get_nowait()
            except queue.Empty:
                return
            result = scan_port(target, port, timeout, grab_banners)
            if result is not None:
                record(result)

    concurrency = max(1, min(threads, total))
    if engine == "threads":
        bodies = [blocking_worker] * concurrency
    else:
        loops = -(-concurrency // SELECT_LOOP_CAPACITY)
        capacity = -(-concurrency // loops)

        def selector_worker() -> None:
            _select_loop(target, tasks, capacity, timeout, grab_banners, record, stop)

        bodies = [selector_worker] * loops
    workers = [threading.Thread(target=body, daemon=True) for body in bodies]

    started = time.perf_counter()
    interrupted = False
    for thread in workers:
        thread.start()
    try:
        _join_all(workers)
    except KeyboardInterrupt:
        interrupted = True
        stop.set()
        try:
            _join_all(workers, time.monotonic() + INTERRUPT_GRACE)
        except KeyboardInterrupt:
            pass
    elapsed = time.perf_counter() - started

    with found_lock:
        open_ports = sorted(found, key=lambda r: r.port)
    return ScanResult(open_ports, total, total - tasks.qsize(), elapsed, interrupted)


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def _thread_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a whole number") from None
    if not 1 <= count <= MAX_CONCURRENCY:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_CONCURRENCY}")
    return count


def _timeout_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if not (math.isfinite(seconds) and 0 < seconds <= MAX_TIMEOUT):
        raise argparse.ArgumentTypeError(f"must be greater than 0 and at most {MAX_TIMEOUT:g}")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description="Multithreaded TCP connect port scanner.",
        epilog=WARNING_TEXT,
    )
    parser.add_argument("target", help="hostname, IPv4 address or IPv6 address to scan")
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help="ports to scan: a range (1-1024), a list (22,80,443) or both "
        "(22,80,8000-8100); default %(default)s",
    )
    parser.add_argument(
        "--threads",
        type=_thread_count,
        default=DEFAULT_THREADS,
        help="number of worker threads (1-%d), or of connections in flight with "
        "--engine select (1-%d); default %%(default)s" % (MAX_THREADS, MAX_CONCURRENCY),
    )
    parser.add_argument("--output", metavar="FILE", help="write a report to FILE")
    parser.add_argument(
        "--no-banner", action="store_true", help="do not try to read banners from open ports"
    )
    parser.add_argument(
        "--timeout",
        type=_timeout_seconds,
        default=DEFAULT_TIMEOUT,
        help="per-connection timeout in seconds; default %(default)s",
    )
    parser.add_argument(
        "--engine",
        choices=ENGINES,
        default="threads",
        help="threads: one blocking connect per thread (default); "
        "select: non-blocking connects multiplexed with select/epoll",
    )
    parser.add_argument(
        "-6", "--ipv6", action="store_true", help="resolve hostnames to IPv6 addresses only"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the result as JSON on stdout instead of the table "
        "(--output then also receives JSON)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _err(message: str) -> None:
    print(f"{Fore.RED}error: {message}", file=sys.stderr)


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        ports = parse_ports(args.ports)
    except PortSpecError as exc:
        parser.error(str(exc))  # prints usage, exits with EXIT_USAGE
    if args.engine == "threads" and args.threads > MAX_THREADS:
        parser.error(f"argument --threads: must be at most {MAX_THREADS} with --engine threads")

    print(f"{Fore.YELLOW}Warning: {WARNING_TEXT}", file=sys.stderr)

    try:
        target = resolve_target(args.target, prefer_ipv6=args.ipv6)
    except ResolveError as exc:
        _err(str(exc))
        return EXIT_ERROR

    report_file = None
    if args.output:
        try:
            report_file = open(args.output, "w", encoding="utf-8")
        except OSError as exc:
            _err(f"cannot write to {args.output!r}: {exc.strerror or exc}")
            return EXIT_ERROR

    started = datetime.now()
    # In --json mode stdout carries only the JSON document.
    info = sys.stderr if args.json else sys.stdout
    concurrency = min(args.threads, len(ports))
    if args.engine == "threads":
        workers = f"{concurrency} threads"
    else:
        workers = f"up to {concurrency} connections in flight (select)"
    if not args.json:
        print(
            f"{Fore.CYAN}Scanning {_target_label(target)}: {len(ports)} ports, {workers}, "
            f"timeout {args.timeout:g}s, banners {'off' if args.no_banner else 'on'}"
        )
        print(table_header())

    def show(result: PortResult) -> None:
        print(f"{Fore.GREEN}{format_row(result)}", flush=True)

    result = scan(
        target,
        ports,
        threads=args.threads,
        timeout=args.timeout,
        grab_banners=not args.no_banner,
        engine=args.engine,
        on_open=None if args.json else show,
    )

    if args.json:
        sys.stdout.write(format_json(target, args.ports, result, started))
        sys.stdout.flush()
        if result.interrupted:
            print(f"{Fore.YELLOW}Interrupted after {result.attempted} of {result.total} ports.",
                  file=info)
    else:
        print()
        if result.interrupted:
            print(
                f"{Fore.YELLOW}Interrupted after {result.attempted} of {result.total} ports "
                f"({result.elapsed:.2f} s). Results so far:"
            )
        else:
            print(f"{Fore.CYAN}Scan complete: {result.total} ports in {result.elapsed:.2f} s.")
        if result.open_ports:
            print(f"{len(result.open_ports)} open port(s), sorted by port:")
            print(table_header(with_banner=False))
            for item in result.open_ports:
                print(format_row(item, with_banner=False))
        else:
            print("No open ports found.")

    exit_code = EXIT_INTERRUPTED if result.interrupted else EXIT_OK
    if report_file is not None:
        document = (format_json if args.json else format_report)(
            target, args.ports, result, started
        )
        try:
            with report_file:
                report_file.write(document)
            print(f"Report written to {args.output}", file=info)
        except OSError as exc:
            _err(f"cannot write report to {args.output!r}: {exc.strerror or exc}")
            exit_code = EXIT_ERROR
    return exit_code


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point. Returns the process exit code."""
    colorama_init(autoreset=True)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args, parser)
    except KeyboardInterrupt:  # Ctrl+C before the scan started
        print(f"{Fore.YELLOW}Interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
