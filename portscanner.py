#!/usr/bin/env python3
"""Multithreaded TCP connect port scanner.

Built on the standard library (socket, threading, queue); colorama is used
only for coloured output. Only scan hosts you own or have permission to scan.

Usage:
    python portscanner.py <target> [--ports 1-1024] [--threads 100]
                          [--output file.txt] [--no-banner] [--timeout 1.0]
"""

from __future__ import annotations

import argparse
import math
import queue
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, Sequence

from colorama import Fore, init as colorama_init

DEFAULT_PORTS = "1-1024"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 1.0
MAX_THREADS = 1000
MAX_TIMEOUT = 300.0
MAX_PORT = 65535

HTTP_PORT = 80
# Services that send a greeting as soon as the connection opens. They get the
# full --timeout to do so; any other open port is only listened to briefly.
SPEAK_FIRST_PORTS = frozenset({21, 22, 25})
BANNER_SILENT_WAIT = 0.5
BANNER_READ_BYTES = 1024
BANNER_MAX_CHARS = 200

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


class PortSpecError(ValueError):
    """Raised when a --ports value cannot be parsed."""


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


def format_report(
    target: str,
    ip: str,
    port_spec: str,
    result: ScanResult,
    started: datetime,
) -> str:
    """Build the plain-text report written by --output (sorted by port)."""
    host = target if target == ip else f"{target} ({ip})"
    if result.interrupted:
        status = f"interrupted ({result.attempted} of {result.total} ports attempted)"
    else:
        status = "complete"
    lines = [
        "Port scan report",
        "================",
        f"Target:      {host}",
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


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Read a banner from an already-connected socket; return "" on failure.

    Port 80 gets an HTTP HEAD request. Every other port is only listened to:
    SSH, FTP and SMTP announce themselves on connect. Silent services cost
    at most ``BANNER_SILENT_WAIT`` seconds (never more than ``timeout``).
    """
    try:
        if port == HTTP_PORT:
            sock.settimeout(timeout)
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("ascii", "replace"))
        elif port in SPEAK_FIRST_PORTS:
            sock.settimeout(timeout)
        else:
            sock.settimeout(min(timeout, BANNER_SILENT_WAIT))
        return clean_banner(sock.recv(BANNER_READ_BYTES))
    except OSError:  # timeout, reset, broken pipe
        return ""


def _connected_to_itself(sock: socket.socket) -> bool:
    """True if a "successful" connect was really a TCP self-connect.

    When the ephemeral source port chosen by the OS equals the destination
    port on the same host, TCP simultaneous open makes connect() succeed
    against the socket itself although nothing is listening.
    """
    return sock.getsockname() == sock.getpeername()


def scan_port(
    ip: str, port: int, timeout: float, host: str, grab: bool = True
) -> Optional[PortResult]:
    """Try a TCP connect to ``ip:port``; return a PortResult if it is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0 or _connected_to_itself(sock):
                return None
            banner = grab_banner(sock, host, port, timeout) if grab else ""
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


def scan(
    ip: str,
    ports: Sequence[int],
    *,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    grab_banners: bool = True,
    host: Optional[str] = None,
    on_open: Optional[Callable[[PortResult], None]] = None,
) -> ScanResult:
    """Scan ``ports`` on ``ip`` with a pool of worker threads.

    Ports are put in a Queue and workers pull from it until it is empty.
    ``on_open`` is called (under a lock, so calls never interleave) as soon as
    an open port is found. A KeyboardInterrupt does not propagate: the scan
    stops and the partial result is returned with ``interrupted=True``.
    """
    host = host or ip
    tasks: queue.Queue[int] = queue.Queue()
    for port in ports:
        tasks.put(port)
    total = tasks.qsize()

    found: list[PortResult] = []
    found_lock = threading.Lock()  # taken only when a port is open
    stop = threading.Event()

    def worker() -> None:
        while not stop.is_set():
            try:
                port = tasks.get_nowait()
            except queue.Empty:
                return
            result = scan_port(ip, port, timeout, host, grab_banners)
            if result is not None:
                with found_lock:
                    found.append(result)
                    if on_open is not None:
                        on_open(result)

    workers = [
        threading.Thread(target=worker, daemon=True)
        for _ in range(max(1, min(threads, total)))
    ]
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
    if not 1 <= count <= MAX_THREADS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_THREADS}")
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
    parser.add_argument("target", help="hostname or IPv4 address to scan")
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
        help=f"number of worker threads, 1-{MAX_THREADS}; default %(default)s",
    )
    parser.add_argument("--output", metavar="FILE", help="write a plain-text report to FILE")
    parser.add_argument(
        "--no-banner", action="store_true", help="do not try to read banners from open ports"
    )
    parser.add_argument(
        "--timeout",
        type=_timeout_seconds,
        default=DEFAULT_TIMEOUT,
        help="per-connection timeout in seconds; default %(default)s",
    )
    return parser


def _err(message: str) -> None:
    print(f"{Fore.RED}error: {message}", file=sys.stderr)


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        ports = parse_ports(args.ports)
    except PortSpecError as exc:
        parser.error(str(exc))  # prints usage, exits with EXIT_USAGE

    print(f"{Fore.YELLOW}Warning: {WARNING_TEXT}", file=sys.stderr)

    try:
        ip = socket.gethostbyname(args.target)
    except (socket.gaierror, UnicodeError) as exc:
        _err(f"cannot resolve host {args.target!r}: {exc}")
        return EXIT_ERROR

    report_file = None
    if args.output:
        try:
            report_file = open(args.output, "w", encoding="utf-8")
        except OSError as exc:
            _err(f"cannot write to {args.output!r}: {exc.strerror or exc}")
            return EXIT_ERROR

    started = datetime.now()
    target_label = args.target if args.target == ip else f"{args.target} ({ip})"
    print(
        f"{Fore.CYAN}Scanning {target_label}: {len(ports)} ports, "
        f"{min(args.threads, len(ports))} threads, timeout {args.timeout:g}s, "
        f"banners {'off' if args.no_banner else 'on'}"
    )
    print(table_header())

    def show(result: PortResult) -> None:
        print(f"{Fore.GREEN}{format_row(result)}", flush=True)

    result = scan(
        ip,
        ports,
        threads=args.threads,
        timeout=args.timeout,
        grab_banners=not args.no_banner,
        host=args.target,
        on_open=show,
    )

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
        try:
            with report_file:
                report_file.write(format_report(args.target, ip, args.ports, result, started))
            print(f"Report written to {args.output}")
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
