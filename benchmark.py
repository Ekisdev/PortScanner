#!/usr/bin/env python3
"""Benchmark portscanner against a plain version of the original design.

Only 127.0.0.1 (and its alias "localhost") is ever scanned. A separate
process opens a fixed set of listening sockets; both implementations scan the
same ports and must return the same results before their times are compared.

    python benchmark.py                   # all scenarios (about 10 minutes)
    python benchmark.py --runs 1          # quick pass
    python benchmark.py --scenario sweep  # only scenarios whose key contains "sweep"

The plain baseline is a reconstruction from the project description, not the
lost original: a Queue of ports, N daemon threads, one fresh socket per port,
a lock around the results list, task_done()/join(), the same timeout for
connect and banner read, and the target passed to connect_ex as given.
"""

from __future__ import annotations

import argparse
import os
import platform
import queue
import socket
import statistics
import subprocess
import sys
import threading
import time

import portscanner

BASE = 41000  # 1023 consecutive ports from here, plus port 80
HEAVY_BASE = 43000  # 200 silent listeners for the "open-heavy" scenarios
HEAVY_COUNT = 200

SSH_GREETING = b"SSH-2.0-BenchServer_1.0\r\n"
HTTP_REPLY = b"HTTP/1.0 200 OK\r\nServer: BenchServer\r\n\r\n"

SILENT = [BASE + 30 + 80 * i for i in range(12)]
GREETING = [BASE + 70 + 160 * i for i in range(6)]
HEAVY = [HEAVY_BASE + i for i in range(HEAVY_COUNT)]

MAIN_SPEC = f"80,{BASE}-{BASE + 1022}"  # 1024 ports: 1005 closed, 19 open
HEAVY_SPEC = f"{HEAVY_BASE}-{HEAVY_BASE + HEAVY_COUNT - 1}"  # 200 ports, all open


# --------------------------------------------------------------------------
# Test server (runs in its own process so it does not share the GIL)
# --------------------------------------------------------------------------

def _handle(conn: socket.socket, kind: str) -> None:
    try:
        if kind == "greeting":
            conn.sendall(SSH_GREETING)
        elif kind == "http":
            conn.recv(1024)
            conn.sendall(HTTP_REPLY)
        while conn.recv(1024):  # hold the connection open until the client closes
            pass
    except OSError:
        pass
    finally:
        conn.close()


def _accept_loop(listener: socket.socket, kind: str) -> None:
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=_handle, args=(conn, kind), daemon=True).start()


def serve() -> None:
    """Bind every benchmark port on 127.0.0.1, print READY, then run forever."""
    plan = [(p, "silent") for p in SILENT + HEAVY] + [(p, "greeting") for p in GREETING]
    plan.append((80, "http"))
    bound = []
    for port, kind in plan:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError as exc:
            print(f"warning: cannot bind port {port}: {exc}", file=sys.stderr, flush=True)
            listener.close()
            continue
        listener.listen(128)
        threading.Thread(target=_accept_loop, args=(listener, kind), daemon=True).start()
        bound.append(port)
    print("READY " + ",".join(map(str, bound)), flush=True)
    while True:
        time.sleep(3600)


def start_server() -> tuple[subprocess.Popen, dict[int, str]]:
    """Start the test server; return the process and {port: expected banner}."""
    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--serve"],
        stdout=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline()
    if not line.startswith("READY"):
        proc.kill()
        sys.exit("test server failed to start")
    bound = {int(p) for p in line.split()[1].split(",")}
    expected = {}
    for port in bound:
        if port in GREETING:
            expected[port] = portscanner.clean_banner(SSH_GREETING)
        elif port == 80:
            expected[port] = portscanner.clean_banner(HTTP_REPLY)
        else:
            expected[port] = ""
    return proc, expected


# --------------------------------------------------------------------------
# The two implementations under test
# --------------------------------------------------------------------------

def old_design_scan(target, ports, threads, timeout, grab_banners):
    """Plain version of the original design (see module docstring)."""
    tasks: queue.Queue = queue.Queue()
    lock = threading.Lock()
    results = []
    for port in ports:
        tasks.put(port)

    def worker():
        while True:
            port = tasks.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                try:
                    if sock.connect_ex((target, port)) == 0:
                        banner = ""
                        if grab_banners:
                            try:
                                if port == 80:
                                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                                banner = portscanner.clean_banner(sock.recv(1024))
                            except OSError:
                                pass
                        with lock:
                            results.append((port, banner))
                finally:
                    sock.close()
            except OSError:
                pass
            finally:
                tasks.task_done()

    for _ in range(threads):
        threading.Thread(target=worker, daemon=True).start()
    tasks.join()
    return sorted(results)


def new_design_scan(target, ports, threads, timeout, grab_banners):
    """The current portscanner.scan, including the one-off name resolution."""
    ip = socket.gethostbyname(target)
    result = portscanner.scan(
        ip, ports, threads=threads, timeout=timeout, grab_banners=grab_banners, host=target
    )
    return [(r.port, r.banner) for r in result.open_ports]


IMPLEMENTATIONS = {"old": old_design_scan, "new": new_design_scan}


# --------------------------------------------------------------------------
# Scenarios and runner
# --------------------------------------------------------------------------

class Scenario:
    def __init__(self, key, title, spec, threads, timeout, banners, runs, impls=("old", "new"),
                 target="127.0.0.1"):
        self.key, self.title, self.spec = key, title, spec
        self.threads, self.timeout, self.banners = threads, timeout, banners
        self.runs, self.impls, self.target = runs, impls, target


def build_scenarios():
    scenarios = [
        Scenario("main", "1024 ports, 19 open, banners on", MAIN_SPEC, 100, 1.0, True, 5),
        Scenario("main-nobanner", "1024 ports, 19 open, --no-banner", MAIN_SPEC, 100, 1.0, False, 5),
        Scenario("hostname", "as main, target 'localhost' instead of 127.0.0.1", MAIN_SPEC, 100, 1.0,
                 True, 3, target="localhost"),
        Scenario("heavy", "200 ports, all open and silent, banners on", HEAVY_SPEC, 100, 1.0, True, 5),
        Scenario("heavy-nobanner", "200 ports, all open, --no-banner", HEAVY_SPEC, 100, 1.0, False, 5),
    ]
    for threads in (50, 200, 500, 1000):
        scenarios.append(Scenario(f"sweep-threads-{threads}",
                                  f"thread sweep: 1024 ports, {threads} threads", MAIN_SPEC,
                                  threads, 1.0, True, 3))
    for timeout in (0.25, 0.5, 2.5):
        scenarios.append(Scenario(f"sweep-timeout-{timeout}",
                                  f"timeout sweep: 1024 ports, timeout {timeout:g}s", MAIN_SPEC,
                                  100, timeout, True, 2, impls=("new",)))
    return scenarios


def run_scenario(scenario, expected_open, runs_override):
    ports = portscanner.parse_ports(scenario.spec)
    wanted = {p: (b if scenario.banners else "") for p, b in expected_open.items() if p in set(ports)}
    runs = runs_override or scenario.runs
    times = {name: [] for name in scenario.impls}
    for _ in range(runs):
        for name in scenario.impls:  # alternate implementations to spread drift evenly
            start = time.perf_counter()
            found = IMPLEMENTATIONS[name](scenario.target, ports, scenario.threads, scenario.timeout,
                                          scenario.banners)
            times[name].append(time.perf_counter() - start)
            if dict(found) != wanted:
                missing = sorted(set(wanted) - {p for p, _ in found})
                extra = sorted({p for p, _ in found} - set(wanted))
                print(f"  WARNING {name}: result differs from expected "
                      f"(missing {missing}, unexpected {extra})", flush=True)
    return times, len(wanted)


def print_environment():
    print("Environment")
    print(f"  platform : {platform.platform()}")
    print(f"  python   : {platform.python_version()}")
    print(f"  cpus     : {os.cpu_count()} logical ({platform.processor()})")
    print("  target   : 127.0.0.1 / localhost only, test server in a separate process")
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--runs", type=int, help="override the number of runs per scenario")
    parser.add_argument("--scenario", help="only run scenarios whose key contains this text")
    args = parser.parse_args()
    if args.serve:
        serve()
        return

    print_environment()
    server, expected = start_server()
    try:
        print(f"Test server listening on {len(expected)} ports "
              f"(80 http, {len(GREETING)} with greeting, {len(SILENT) + len(HEAVY)} silent)\n")
        print("| scenario | impl | runs | median s | min s | max s | open found |")
        print("|---|---|---|---|---|---|---|")
        for scenario in build_scenarios():
            if args.scenario and args.scenario not in scenario.key:
                continue
            times, open_count = run_scenario(scenario, expected, args.runs)
            for name, values in times.items():
                print(f"| {scenario.title} | {name} | {len(values)} | {statistics.median(values):.3f} | "
                      f"{min(values):.3f} | {max(values):.3f} | {open_count} |", flush=True)
    finally:
        server.kill()


if __name__ == "__main__":
    main()
