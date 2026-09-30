"""Unit tests for portscanner. Everything runs against 127.0.0.1 only."""

import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import portscanner
from portscanner import PortSpecError, clean_banner, parse_ports

LOCAL = portscanner.resolve_target("127.0.0.1")


class ParsePortsTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range_is_inclusive(self):
        self.assertEqual(parse_ports("20-23"), [20, 21, 22, 23])

    def test_list(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_mixed_list_and_range(self):
        self.assertEqual(parse_ports("443,22,80-82"), [22, 80, 81, 82, 443])

    def test_duplicates_and_overlaps_are_removed(self):
        self.assertEqual(parse_ports("80,79-81,80"), [79, 80, 81])

    def test_whitespace_is_ignored(self):
        self.assertEqual(parse_ports(" 22 , 80 - 81 "), [22, 80, 81])

    def test_default_range_size(self):
        self.assertEqual(len(parse_ports(portscanner.DEFAULT_PORTS)), 1024)

    def test_limits(self):
        self.assertEqual(parse_ports("1,65535"), [1, 65535])

    def test_invalid_specs(self):
        for spec in ["", "0", "65536", "abc", "80-20", "1,,2", "1-", "-5", "1-2-3",
                     "22,", "80.5", "1-99999", "²"]:
            with self.subTest(spec=spec):
                with self.assertRaises(PortSpecError):
                    parse_ports(spec)

    def test_error_message_names_the_bad_entry(self):
        with self.assertRaisesRegex(PortSpecError, "'http'"):
            parse_ports("22,http")


class CleanBannerTests(unittest.TestCase):
    def test_newlines_and_runs_of_whitespace_become_one_space(self):
        data = b"SSH-2.0-OpenSSH_9.6\r\n\r\n  next\tline \n"
        self.assertEqual(clean_banner(data), "SSH-2.0-OpenSSH_9.6 next line")

    def test_truncated_to_200_characters(self):
        self.assertEqual(len(clean_banner(b"A" * 1000)), 200)

    def test_truncation_leaves_no_trailing_space(self):
        data = b"A" * 199 + b" B"
        self.assertEqual(clean_banner(data), "A" * 199)

    def test_binary_data_does_not_crash(self):
        data = bytes(range(256))
        result = clean_banner(data)
        self.assertTrue(result.isprintable())
        self.assertNotIn("\n", result)
        self.assertLessEqual(len(result), 200)

    def test_binary_between_text_keeps_the_text(self):
        self.assertEqual(clean_banner(b"\x00\x0a5.7.33\x00\x00mysql\xff"), "5.7.33 mysql")

    def test_empty_and_unprintable_only(self):
        self.assertEqual(clean_banner(b""), "")
        self.assertEqual(clean_banner(b"\x00\x01\x02\xff"), "")


class ServiceNameTests(unittest.TestCase):
    def test_at_least_35_named_ports(self):
        self.assertGreaterEqual(len(portscanner.COMMON_PORTS), 35)

    def test_known_and_unknown(self):
        self.assertEqual(portscanner.service_name(22), "ssh")
        self.assertEqual(portscanner.service_name(443), "https")
        self.assertEqual(portscanner.service_name(54321), "unknown")


class Listener:
    """A local TCP listener that optionally sends a greeting (IPv4 by default)."""

    def __init__(self, greeting=b"", family=socket.AF_INET):
        self.greeting = greeting
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._clients = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            self._clients.append(client)  # keep it open, like a silent service
            if self.greeting:
                try:
                    client.sendall(self.greeting)
                except OSError:
                    pass

    def close(self):
        self.sock.close()
        for client in self._clients:
            client.close()


def unused_port():
    """A port nothing is listening on (bound briefly, then released)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ScanLocalSocketTests(unittest.TestCase):
    def setUp(self):
        self.listeners = []

    def tearDown(self):
        for listener in self.listeners:
            listener.close()

    def listen(self, greeting=b""):
        listener = Listener(greeting)
        self.listeners.append(listener)
        return listener

    def test_open_port_with_banner(self):
        listener = self.listen(b"220 mail.test ESMTP ready\r\n")
        result = portscanner.scan_port(LOCAL, listener.port, 1.0)
        self.assertEqual(result.port, listener.port)
        self.assertEqual(result.banner, "220 mail.test ESMTP ready")

    def test_no_banner_flag_skips_reading(self):
        listener = self.listen(b"hello\r\n")
        result = portscanner.scan_port(LOCAL, listener.port, 1.0, grab=False)
        self.assertIsNotNone(result)
        self.assertEqual(result.banner, "")

    def test_silent_open_port_gives_empty_banner_within_silent_wait(self):
        listener = self.listen()
        result = portscanner.scan_port(LOCAL, listener.port, 5.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.banner, "")

    def test_closed_port_returns_none(self):
        self.assertIsNone(portscanner.scan_port(LOCAL, unused_port(), 0.3))

    def test_scan_finds_only_open_ports_sorted_and_reports_live(self):
        listeners = [self.listen(b"one\r\n"), self.listen(b"two\r\n"), self.listen()]
        open_ports = sorted(listener.port for listener in listeners)
        closed = [unused_port() for _ in range(5)]
        live = []
        result = portscanner.scan(
            LOCAL,
            sorted(closed + open_ports, reverse=True),
            threads=8,
            timeout=0.5,
            on_open=live.append,
        )
        self.assertEqual([r.port for r in result.open_ports], open_ports)
        self.assertEqual(sorted(r.port for r in live), open_ports)
        self.assertEqual(result.total, 8)
        self.assertEqual(result.attempted, 8)
        self.assertFalse(result.interrupted)

    def test_self_connect_is_not_reported_as_open(self):
        # Binding a socket to a port and connecting to that same port makes
        # TCP connect to itself, which is what an unlucky ephemeral source
        # port does during a scan of the local machine.
        port = unused_port()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.settimeout(2.0)
        try:
            self.assertEqual(sock.connect_ex(("127.0.0.1", port)), 0)
            self.assertTrue(portscanner._connected_to_itself(sock))
        finally:
            sock.close()

    def test_real_connection_is_not_a_self_connect(self):
        listener = self.listen()
        with socket.create_connection(("127.0.0.1", listener.port), timeout=2.0) as sock:
            self.assertFalse(portscanner._connected_to_itself(sock))

    def test_more_threads_than_ports(self):
        listener = self.listen()
        result = portscanner.scan(LOCAL, [listener.port], threads=500, timeout=0.5)
        self.assertEqual([r.port for r in result.open_ports], [listener.port])

    def test_http_head_request_on_port_80(self):
        client, server = socket.socketpair()
        seen = []

        def fake_http_server():
            seen.append(server.recv(1024))
            server.sendall(b"HTTP/1.0 200 OK\r\nServer: testd\r\nContent-Length: 0\r\n\r\n")

        thread = threading.Thread(target=fake_http_server)
        thread.start()
        try:
            banner = portscanner.grab_banner(client, "example.test", 80, 2.0)
        finally:
            thread.join()
            client.close()
            server.close()
        self.assertTrue(seen[0].startswith(b"HEAD / HTTP/1.0\r\n"))
        self.assertIn(b"Host: example.test\r\n", seen[0])
        self.assertEqual(banner, "HTTP/1.0 200 OK Server: testd Content-Length: 0")

    def test_head_request_only_on_plain_http_ports(self):
        cases = [(80, True), (8000, True), (8008, True), (8080, True), (8888, True),
                 (443, False), (8443, False)]
        for port, expect_request in cases:
            with self.subTest(port=port):
                client, server = socket.socketpair()
                try:
                    portscanner.grab_banner(client, "h", port, 0.2)
                    server.settimeout(0.2)
                    try:
                        sent = server.recv(1024)
                    except socket.timeout:
                        sent = b""
                    self.assertEqual(sent.startswith(b"HEAD / HTTP/1.0"), expect_request)
                finally:
                    client.close()
                    server.close()

    def test_ipv6_host_header_is_bracketed(self):
        client, server = socket.socketpair()
        try:
            portscanner.grab_banner(client, "::1", 80, 0.2)
            self.assertIn(b"Host: [::1]\r\n", server.recv(1024))
        finally:
            client.close()
            server.close()

    def test_connection_reset_during_banner_read_does_not_crash(self):
        client, server = socket.socketpair()
        server.close()
        try:
            self.assertEqual(portscanner.grab_banner(client, "h", 22, 0.5), "")
        finally:
            client.close()


def ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::1", 0))
        return True
    except OSError:
        return False


class ResolveTargetTests(unittest.TestCase):
    def test_ipv4_literal(self):
        target = portscanner.resolve_target("127.0.0.1")
        self.assertEqual((target.ip, target.family), ("127.0.0.1", socket.AF_INET))
        self.assertTrue(target.loopback)
        self.assertEqual(target.address(80), ("127.0.0.1", 80))

    def test_non_loopback_literal_is_not_flagged(self):
        # TEST-NET-1: parsed only, never contacted.
        self.assertFalse(portscanner.resolve_target("192.0.2.1").loopback)

    def test_ipv6_literal(self):
        target = portscanner.resolve_target("::1")
        self.assertEqual(target.family, socket.AF_INET6)
        self.assertTrue(target.loopback)
        self.assertEqual(target.address(80)[:2], ("::1", 80))

    def test_ipv6_only_flag_rejects_ipv4_literal(self):
        with self.assertRaisesRegex(portscanner.ResolveError, "no IPv6 address"):
            portscanner.resolve_target("127.0.0.1", prefer_ipv6=True)

    def test_names_prefer_ipv4(self):
        infos = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
                 (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with mock.patch.object(portscanner.socket, "getaddrinfo", return_value=infos):
            self.assertEqual(portscanner.resolve_target("example.test").family, socket.AF_INET)
            self.assertEqual(portscanner.resolve_target("example.test", True).family,
                             socket.AF_INET6)

    def test_failures_become_resolve_errors(self):
        with mock.patch.object(portscanner.socket, "getaddrinfo",
                               side_effect=socket.gaierror(11001, "getaddrinfo failed")):
            with self.assertRaisesRegex(portscanner.ResolveError, "cannot resolve host"):
                portscanner.resolve_target("no-such-host.test")
        with self.assertRaises(portscanner.ResolveError):
            portscanner.resolve_target("  ")


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.listeners = [Listener(b"one\r\n"), Listener(), Listener(b"SSH-2.0-x\r\n")]

    def tearDown(self):
        for listener in self.listeners:
            listener.close()

    def test_engines_agree(self):
        open_ports = sorted(listener.port for listener in self.listeners)
        ports = sorted(open_ports + [unused_port() for _ in range(20)])
        results = {}
        for engine in portscanner.ENGINES:
            result = portscanner.scan(LOCAL, ports, threads=50, timeout=0.5, engine=engine)
            results[engine] = [(r.port, r.banner) for r in result.open_ports]
            self.assertFalse(result.interrupted)
            self.assertEqual(result.attempted, len(ports))
        self.assertEqual([p for p, _ in results["select"]], open_ports)
        self.assertEqual(results["select"], results["threads"])
        self.assertIn("SSH-2.0-x", [b for _, b in results["select"]])

    def test_select_engine_with_more_ports_than_one_loop_holds(self):
        listener_ports = {listener.port for listener in self.listeners}
        extra = set(range(20000, 20000 + portscanner.SELECT_LOOP_CAPACITY + 200))
        ports = sorted(listener_ports | extra)
        result = portscanner.scan(LOCAL, ports, threads=1000, timeout=0.5, engine="select")
        self.assertTrue(listener_ports <= {r.port for r in result.open_ports})
        self.assertEqual(result.attempted, len(ports))

    def test_select_engine_bounds_banner_threads_but_finds_every_port(self):
        silent = [Listener() for _ in range(12)]
        try:
            ports = sorted(listener.port for listener in silent)
            before = threading.active_count()
            peak = []
            real_grab = portscanner.grab_banner

            def watching_grab(*args, **kwargs):
                peak.append(threading.active_count() - before)
                return real_grab(*args, **kwargs)

            with mock.patch.object(portscanner, "grab_banner", side_effect=watching_grab):
                result = portscanner.scan(LOCAL, ports, threads=2, timeout=0.5, engine="select")
        finally:
            for listener in silent:
                listener.close()
        self.assertEqual([r.port for r in result.open_ports], ports)
        # 1 selector thread + at most 2 banner helpers (threads=2), never 12
        self.assertLessEqual(max(peak), 3 + 1)

    def test_select_engine_no_banner(self):
        result = portscanner.scan(LOCAL, [self.listeners[0].port], threads=4, timeout=0.5,
                                  engine="select", grab_banners=False)
        self.assertEqual([r.banner for r in result.open_ports], [""])

    def test_select_engine_survives_running_out_of_sockets(self):
        real_socket = socket.socket
        failures = []

        def flaky(*args, **kwargs):
            if len(failures) < 5:
                failures.append(1)
                raise OSError(24, "Too many open files")
            return real_socket(*args, **kwargs)

        open_ports = sorted(listener.port for listener in self.listeners)
        with mock.patch.object(portscanner.socket, "socket", side_effect=flaky):
            result = portscanner.scan(LOCAL, open_ports, threads=10, timeout=0.5, engine="select")
        self.assertEqual(len(failures), 5)
        self.assertEqual([r.port for r in result.open_ports], open_ports)

    def test_unknown_engine(self):
        with self.assertRaises(ValueError):
            portscanner.scan(LOCAL, [80], engine="nope")

    def test_select_engine_interrupt(self):
        with mock.patch.object(portscanner, "_join_all", side_effect=[KeyboardInterrupt, None]):
            result = portscanner.scan(LOCAL, [self.listeners[0].port], threads=1, timeout=0.5,
                                      engine="select")
        self.assertTrue(result.interrupted)


@unittest.skipUnless(sys.platform == "win32", "the refusal delay is specific to Windows")
class WindowsLoopbackTests(unittest.TestCase):
    def test_closed_loopback_ports_are_refused_immediately(self):
        # Without the SIO_TCP_INITIAL_RTO option each closed port takes ~2 s on
        # Windows, so 300 ports with 50 threads would need about 12 s.
        started = time.perf_counter()
        for engine in portscanner.ENGINES:
            portscanner.scan(LOCAL, range(30000, 30300), threads=50, timeout=1.0, engine=engine)
        self.assertLess(time.perf_counter() - started, 4.0)

    def test_option_is_not_applied_to_other_hosts(self):
        other = portscanner.Target("192.0.2.1", "192.0.2.1", socket.AF_INET)
        with mock.patch.object(portscanner, "_disable_syn_retransmit") as disable:
            with mock.patch.object(portscanner.socket.socket, "connect_ex", return_value=1):
                portscanner.scan_port(other, 80, 0.1)
        disable.assert_not_called()


@unittest.skipUnless(ipv6_available(), "IPv6 loopback is not available")
class IPv6Tests(unittest.TestCase):
    def test_scan_ipv6_loopback(self):
        listener = Listener(b"SSH-2.0-v6\r\n", family=socket.AF_INET6)
        try:
            target = portscanner.resolve_target("::1")
            for engine in portscanner.ENGINES:
                result = portscanner.scan(target, [listener.port, unused_port()], threads=4,
                                          timeout=0.5, engine=engine)
                self.assertEqual([(r.port, r.banner) for r in result.open_ports],
                                 [(listener.port, "SSH-2.0-v6")])
        finally:
            listener.close()


class InterruptTests(unittest.TestCase):
    def test_ctrl_c_returns_partial_results_without_traceback(self):
        listener = Listener()
        try:
            # First wait is interrupted (as Ctrl+C would); the second, bounded
            # wait after stop is a no-op so the test does not depend on timing.
            with mock.patch.object(portscanner, "_join_all", side_effect=[KeyboardInterrupt, None]):
                result = portscanner.scan(LOCAL, [listener.port], threads=1, timeout=0.5)
        finally:
            listener.close()
        self.assertTrue(result.interrupted)
        self.assertIsInstance(result.open_ports, list)

    def test_main_exit_code_on_interrupt(self):
        listener = Listener()
        try:
            with mock.patch.object(portscanner, "_join_all", side_effect=[KeyboardInterrupt, None]):
                code, out, err = run_main(["127.0.0.1", "--ports", str(listener.port), "--timeout", "0.5"])
        finally:
            listener.close()
        self.assertEqual(code, portscanner.EXIT_INTERRUPTED)
        self.assertIn("Interrupted", out)
        self.assertNotIn("Traceback", out + err)


def run_main(argv):
    """Run portscanner.main, returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = portscanner.main(argv)
        except SystemExit as exc:  # argparse exits on usage errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CommandLineTests(unittest.TestCase):
    def test_report_is_sorted_by_port(self):
        listeners = [Listener(b"SSH-2.0-test\r\n"), Listener(), Listener(b"hi\r\n")]
        ports = sorted(listener.port for listener in listeners)
        handle, path = tempfile.mkstemp(suffix=".txt")
        os.close(handle)
        try:
            spec = ",".join(str(p) for p in reversed(ports))
            code, out, _ = run_main(["127.0.0.1", "--ports", spec, "--output", path, "--timeout", "0.5"])
            with open(path, encoding="utf-8") as fh:
                report = fh.read()
        finally:
            os.remove(path)
            for listener in listeners:
                listener.close()
        self.assertEqual(code, portscanner.EXIT_OK)
        positions = [report.index(f"{port}/tcp") for port in ports]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Status:      complete", report)
        self.assertIn("SSH-2.0-test", report)
        self.assertIn(f"{ports[0]}/tcp", out)

    def test_bad_port_spec_is_a_usage_error(self):
        code, _, err = run_main(["127.0.0.1", "--ports", "70000"])
        self.assertEqual(code, portscanner.EXIT_USAGE)
        self.assertIn("out of range", err)
        self.assertNotIn("Traceback", err)

    def test_bad_thread_and_timeout_values(self):
        for flag, value in [("--threads", "0"), ("--threads", "x"), ("--timeout", "0"),
                            ("--timeout", "-1"), ("--timeout", "nan")]:
            with self.subTest(flag=flag, value=value):
                code, _, _ = run_main(["127.0.0.1", flag, value])
                self.assertEqual(code, portscanner.EXIT_USAGE)

    def test_unresolvable_host(self):
        # Patched so the test never touches the network.
        with mock.patch.object(portscanner.socket, "getaddrinfo",
                               side_effect=socket.gaierror(11001, "getaddrinfo failed")):
            code, _, err = run_main(["no-such-host.test", "--ports", "80"])
        self.assertEqual(code, portscanner.EXIT_ERROR)
        self.assertIn("cannot resolve host 'no-such-host.test'", err)
        self.assertNotIn("Traceback", err)

    def test_unwritable_output_path_fails_before_scanning(self):
        with mock.patch.object(portscanner, "scan") as scan:
            code, _, err = run_main(["127.0.0.1", "--ports", "80", "--output",
                                     os.path.join(tempfile.gettempdir(), "no-such-dir-xyz", "r.txt")])
        self.assertEqual(code, portscanner.EXIT_ERROR)
        self.assertIn("cannot write to", err)
        scan.assert_not_called()

    def test_defaults(self):
        args = portscanner.build_parser().parse_args(["x"])
        self.assertEqual(
            (args.threads, args.ports, args.timeout, args.engine, args.ipv6, args.json),
            (500, "1-1024", 1.0, "threads", False, False))

    def test_thread_limit_depends_on_engine(self):
        code, _, err = run_main(["127.0.0.1", "--threads", "1001"])
        self.assertEqual(code, portscanner.EXIT_USAGE)
        self.assertIn("at most 1000", err)
        code, _, _ = run_main(["127.0.0.1", "--threads", "4097", "--engine", "select"])
        self.assertEqual(code, portscanner.EXIT_USAGE)
        listener = Listener()
        try:
            code, out, _ = run_main(["127.0.0.1", "--ports", str(listener.port),
                                     "--threads", "4096", "--engine", "select",
                                     "--timeout", "0.5"])
        finally:
            listener.close()
        self.assertEqual(code, portscanner.EXIT_OK)
        self.assertIn(f"{listener.port}/tcp", out)

    def test_version(self):
        code, out, _ = run_main(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(portscanner.__version__, out)

    def test_ipv6_flag_with_ipv4_literal_is_an_error(self):
        code, _, err = run_main(["127.0.0.1", "--ipv6", "--ports", "80"])
        self.assertEqual(code, portscanner.EXIT_ERROR)
        self.assertIn("no IPv6 address", err)

    def test_json_output(self):
        listeners = [Listener(b"SSH-2.0-j\r\n"), Listener()]
        ports = sorted(listener.port for listener in listeners)
        handle, path = tempfile.mkstemp(suffix=".json")
        os.close(handle)
        try:
            code, out, err = run_main(["127.0.0.1", "--ports", ",".join(map(str, reversed(ports))),
                                       "--json", "--output", path, "--timeout", "0.5"])
            with open(path, encoding="utf-8") as fh:
                from_file = json.load(fh)
        finally:
            os.remove(path)
            for listener in listeners:
                listener.close()
        self.assertEqual(code, portscanner.EXIT_OK)
        document = json.loads(out)  # stdout is only the JSON document
        self.assertEqual(document, from_file)
        self.assertEqual([p["port"] for p in document["open_ports"]], ports)
        self.assertEqual(document["status"], "complete")
        self.assertEqual(document["ports_total"], 2)
        self.assertEqual(set(document["open_ports"][0]),
                         {"port", "protocol", "service", "banner"})
        banners = {p["port"]: p["banner"] for p in document["open_ports"]}
        self.assertIn("SSH-2.0-j", banners.values())
        self.assertIn("permission", err)

    def test_json_interrupted_status(self):
        listener = Listener()
        try:
            with mock.patch.object(portscanner, "_join_all",
                                   side_effect=[KeyboardInterrupt, None]):
                code, out, _ = run_main(["127.0.0.1", "--ports", str(listener.port), "--json",
                                         "--timeout", "0.5"])
        finally:
            listener.close()
        self.assertEqual(code, portscanner.EXIT_INTERRUPTED)
        self.assertEqual(json.loads(out)["status"], "interrupted")

    def test_responsible_use_warning_is_printed(self):
        _, _, err = run_main(["127.0.0.1", "--ports", str(unused_port()), "--timeout", "0.2"])
        self.assertIn("permission", err)


if __name__ == "__main__":
    unittest.main()
