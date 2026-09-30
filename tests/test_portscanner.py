"""Unit tests for portscanner. Everything runs against 127.0.0.1 only."""

import contextlib
import io
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

import portscanner
from portscanner import PortSpecError, clean_banner, parse_ports


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
    """A local TCP listener on 127.0.0.1 that optionally sends a greeting."""

    def __init__(self, greeting=b""):
        self.greeting = greeting
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
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
        result = portscanner.scan_port("127.0.0.1", listener.port, 1.0, "127.0.0.1")
        self.assertEqual(result.port, listener.port)
        self.assertEqual(result.banner, "220 mail.test ESMTP ready")

    def test_no_banner_flag_skips_reading(self):
        listener = self.listen(b"hello\r\n")
        result = portscanner.scan_port("127.0.0.1", listener.port, 1.0, "127.0.0.1", grab=False)
        self.assertIsNotNone(result)
        self.assertEqual(result.banner, "")

    def test_silent_open_port_gives_empty_banner_within_silent_wait(self):
        listener = self.listen()
        result = portscanner.scan_port("127.0.0.1", listener.port, 5.0, "127.0.0.1")
        self.assertIsNotNone(result)
        self.assertEqual(result.banner, "")

    def test_closed_port_returns_none(self):
        self.assertIsNone(portscanner.scan_port("127.0.0.1", unused_port(), 0.3, "127.0.0.1"))

    def test_scan_finds_only_open_ports_sorted_and_reports_live(self):
        listeners = [self.listen(b"one\r\n"), self.listen(b"two\r\n"), self.listen()]
        open_ports = sorted(listener.port for listener in listeners)
        closed = [unused_port() for _ in range(5)]
        live = []
        result = portscanner.scan(
            "127.0.0.1",
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
        result = portscanner.scan("127.0.0.1", [listener.port], threads=500, timeout=0.5)
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

    def test_connection_reset_during_banner_read_does_not_crash(self):
        client, server = socket.socketpair()
        server.close()
        try:
            self.assertEqual(portscanner.grab_banner(client, "h", 22, 0.5), "")
        finally:
            client.close()


class InterruptTests(unittest.TestCase):
    def test_ctrl_c_returns_partial_results_without_traceback(self):
        listener = Listener()
        try:
            # First wait is interrupted (as Ctrl+C would); the second, bounded
            # wait after stop is a no-op so the test does not depend on timing.
            with mock.patch.object(portscanner, "_join_all", side_effect=[KeyboardInterrupt, None]):
                result = portscanner.scan("127.0.0.1", [listener.port], threads=1, timeout=0.5)
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
        with mock.patch.object(portscanner.socket, "gethostbyname",
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

    def test_responsible_use_warning_is_printed(self):
        _, _, err = run_main(["127.0.0.1", "--ports", str(unused_port()), "--timeout", "0.2"])
        self.assertIn("permission", err)


if __name__ == "__main__":
    unittest.main()
