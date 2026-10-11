"""Tests for hg_agent_proxy.py and the HG_SSH_MODE=proxy transport (stdlib only).

Run:  cd tools/mcp && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v tests
"""

from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MCP_DIR = os.path.dirname(HERE)
PROXY = os.path.join(MCP_DIR, "hg_agent_proxy.py")
sys.path.insert(0, MCP_DIR)
sys.path.insert(0, HERE)

import hg_agent_proxy as px  # noqa: E402
import hiveguard_mcp as hg  # noqa: E402
from test_hiveguard_mcp import ROUTES, TOKEN, FakeDaemon, J  # noqa: E402


class ProxyBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.daemon = FakeDaemon()
        fd, cls.token_file = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(TOKEN + "\n")

    @classmethod
    def tearDownClass(cls):
        cls.daemon.stop()
        os.unlink(cls.token_file)

    def setUp(self):
        self.daemon.requests.clear()

    def argv(self, token_file=None, url=None):
        return ["--url", url or self.daemon.url, "--token-file", token_file or self.token_file, "--no-syslog"]

    def proxy(self, req, token_file=None, url=None, env=None):
        raw = req if isinstance(req, bytes) else json.dumps(req).encode()
        out = io.BytesIO()
        code = px.main(self.argv(token_file, url), io.BytesIO(raw), out, env or {})
        text = out.getvalue().decode("ascii")
        self.assertNotIn(TOKEN, text)
        self.assertEqual(text.count("\n"), 1)
        return json.loads(text), code


class ProxyValidationTests(ProxyBase):
    REFUSED = [
        ({"method": "DELETE", "path": "/api/agent/bans"}, 403),
        ({"method": "PUT", "path": "/api/agent/config"}, 403),
        ({"method": "POST", "path": "/api/agent/overview", "body": {}}, 403),
        ({"method": "POST", "path": "/api/bans", "body": {"subject": "1.2.3.4/32"}}, 403),
        ({"method": "GET", "path": "/api/config"}, 403),
        ({"method": "GET", "path": "/metrics"}, 403),
        ({"method": "GET", "path": "/api/agent/../config"}, 403),
        ({"method": "GET", "path": "/api/agent//overview"}, 403),
        ({"method": "GET", "path": "/api/agent/x%2e%2e"}, 403),
        ({"method": "GET", "path": "/api/agent/overview\n"}, 403),
        ({"method": "GET", "path": "/api/agent/overview?x=1"}, 403),
        ({"method": "GET", "path": "/api/agentX/overview"}, 403),
        ({"method": "GET", "path": "/api/agent/overview", "extra": 1}, 400),
        ({"method": "GET", "path": "/api/agent/overview", "body": {"a": 1}}, 400),
        ({"method": "GET", "path": "/api/agent/bans", "query": {"token": "x"}}, 403),
        ({"method": "GET", "path": "/api/agent/bans", "query": {"q": "a\r\nX-Evil: 1"}}, 400),
        ({"method": "GET", "path": "/api/agent/bans", "query": {"bad key": "1"}}, 400),
        ({"method": "GET", "path": "/api/agent/bans", "query": {"q": {"nested": 1}}}, 400),
        ({"method": "GET", "path": "/api/agent/stream", "stream_seconds": 999}, 400),
        ({"method": "GET", "path": "/api/agent/overview", "stream_seconds": 5}, 400),
        ({"method": "POST", "path": "/api/agent/stream"}, 403),
        ({"method": 1, "path": "/api/agent/overview"}, 403),
        ({"path": "/api/agent/overview"}, 403),
        ({"method": "GET"}, 400),
        (["GET", "/api/agent/overview"], 400),
        (b"{not json", 400),
        (b"\xff\xfe", 400),
    ]

    def test_refusals_never_reach_daemon(self):
        for req, status in self.REFUSED:
            with self.subTest(req=req):
                reply, code = self.proxy(req)
                self.assertEqual(reply["status"], status, reply)
                self.assertEqual(code, 2)
                self.assertTrue(reply["proxy_error"])
                self.assertIn("hg-agent-proxy", json.loads(reply["body"])["error"])
        self.assertEqual(self.daemon.requests, [])

    def test_body_size_limit(self):
        big = {"method": "POST", "path": "/api/agent/config/validate", "body": {"content": "x" * (1024 * 1024)}}
        reply, _ = self.proxy(big)
        self.assertEqual(reply["status"], 413)
        reply, _ = self.proxy(b" " * (px.MAX_REQUEST_BYTES + 10))
        self.assertEqual(reply["status"], 413)
        self.assertEqual(self.daemon.requests, [])

    def test_validate_request_normalises(self):
        r = px.validate_request(json.dumps({"method": "get", "path": "/api/agent/bans",
                                            "query": {"limit": 5, "subnet_only": True, "q": None,
                                                      "types": ["signal", "ban_added"]}}).encode())
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["query"], [("limit", "5"), ("subnet_only", "true"), ("types", "signal,ban_added")])
        self.assertIsNone(r["body"])
        self.assertIsNone(r["stream_seconds"])
        r = px.validate_request(b'{"method":"GET","path":"/api/agent/stream"}')
        self.assertEqual(r["stream_seconds"], px.DEFAULT_STREAM_SECONDS)
        for path in sorted(px.READ_POSTS):
            px.validate_request(json.dumps({"method": "POST", "path": path, "body": {}}).encode())

    def test_bad_options(self):
        for argv in (["--bogus"], ["--url", "ftp://x"], ["--timeout", "0"]):
            out = io.BytesIO()
            self.assertEqual(px.main(argv + ["--no-syslog"], io.BytesIO(b"{}"), out, {}), 2)
            self.assertEqual(json.loads(out.getvalue())["status"], 500)

    def test_python38_syntax(self):
        with open(PROXY, encoding="utf-8") as fh:
            ast.parse(fh.read(), filename=PROXY, feature_version=(3, 8))


class ProxyForwardTests(ProxyBase):
    def test_get_with_query(self):
        reply, code = self.proxy({"method": "GET", "path": "/api/agent/bans", "query": {"limit": 5, "q": "a b"}})
        self.assertEqual(code, 0)
        self.assertEqual(reply["status"], 200)
        self.assertIn("json", reply["content_type"])
        self.assertFalse(reply["truncated"])
        self.assertEqual(json.loads(reply["body"])["total"], 3)
        req = self.daemon.last()
        self.assertEqual(req["headers"]["authorization"], f"Bearer {TOKEN}")
        self.assertEqual(req["query"], {"limit": "5", "q": "a b"})

    def test_read_only_posts(self):
        body = {"source": "nginx", "group_by": "ip", "filter": {"ip": "203.0.113.0/24"}}
        reply, _ = self.proxy({"method": "POST", "path": "/api/agent/logs/stats", "body": body})
        self.assertEqual(reply["status"], 200)
        self.assertEqual(json.loads(self.daemon.last()["body"]), body)
        self.assertEqual(self.daemon.last()["headers"]["content-type"], "application/json")
        reply, _ = self.proxy({"method": "POST", "path": "/api/agent/config/validate", "body": {"content": "x"}})
        self.assertTrue(json.loads(reply["body"])["valid"])

    def test_daemon_errors_pass_through(self):
        reply, code = self.proxy({"method": "GET", "path": "/api/agent/nope"})
        self.assertEqual((reply["status"], code), (404, 0))
        self.assertNotIn("proxy_error", reply)
        key = ("GET", "/api/agent/overview")
        self.daemon.routes[key] = (429, "application/json", b'{"error":"slow down"}', {"Retry-After": "9"})
        try:
            reply, _ = self.proxy({"method": "GET", "path": "/api/agent/overview"})
        finally:
            self.daemon.routes[key] = ROUTES[key]
        self.assertEqual((reply["status"], reply["retry_after"]), (429, "9"))

    def test_token_never_echoed(self):
        key = ("GET", "/api/agent/leak")
        self.daemon.routes[key] = J(200, {"echo": f"Authorization: Bearer {TOKEN}"})
        try:
            reply, _ = self.proxy({"method": "GET", "path": "/api/agent/leak"})
        finally:
            self.daemon.routes.pop(key)
        self.assertEqual(json.loads(reply["body"])["echo"], "Authorization: Bearer <token>")

    def test_token_problems(self):
        reply, code = self.proxy({"method": "GET", "path": "/api/agent/overview"}, token_file="/nonexistent/tok")
        self.assertEqual((reply["status"], code), (500, 2))
        self.assertIn("not found", reply["proxy_error"])
        with tempfile.NamedTemporaryFile("w") as fh:
            fh.write("  \n")
            fh.flush()
            reply, _ = self.proxy({"method": "GET", "path": "/api/agent/overview"}, token_file=fh.name)
        self.assertIn("empty or malformed", reply["proxy_error"])
        self.assertEqual(self.daemon.requests, [])

    def test_unreachable(self):
        reply, code = self.proxy({"method": "GET", "path": "/api/agent/overview"}, url="http://127.0.0.1:1")
        self.assertEqual((reply["status"], code), (502, 2))

    def test_stream_time_limited(self):
        t0 = time.monotonic()
        reply, _ = self.proxy({"method": "GET", "path": "/api/agent/stream", "query": {"types": "signal"},
                               "stream_seconds": 1})
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(reply["status"], 200)
        self.assertIn("event: ban_added", reply["body"])
        self.assertEqual(self.daemon.last()["headers"]["accept"], "text/event-stream")

    def test_subprocess_ignores_original_command(self):
        env = dict(os.environ, SSH_ORIGINAL_COMMAND="cat /etc/hiveguard/agent-token; rm -rf /",
                   HG_AGENT_TOKEN_FILE=self.token_file, HG_AGENT_URL=self.daemon.url,
                   HG_AGENT_PROXY_SYSLOG="0", PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run([sys.executable, PROXY], input=b'{"method":"GET","path":"/api/agent/overview"}',
                              capture_output=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(TOKEN.encode(), proc.stdout + proc.stderr)
        self.assertEqual(proc.stderr, b"")
        self.assertEqual(json.loads(proc.stdout)["status"], 200)
        self.assertEqual(len(self.daemon.requests), 1)


class ProxyTransportTests(ProxyBase):
    def make(self, allow_write=False, token_file=None, **extra):
        env = {"HG_SSH": "hgagent@node-a.example.org", "HG_SSH_MODE": "proxy", "HG_TIMEOUT": "10",
               "HG_TOKEN_FILE": "/nonexistent/local-token", "HG_NODE_LABEL": "node-a"}
        if allow_write:
            env["HG_MCP_ALLOW_WRITE"] = "1"
        env.update(extra)
        cfg = hg.Config.from_env(env)
        self.calls = []

        def runner(argv, **kw):
            self.calls.append((argv, kw["input"]))
            self.assertEqual(argv[0], "ssh")
            self.assertIn("BatchMode=yes", argv)
            self.assertIn("ControlPath=~/.ssh/hg-mcp-%C", argv)
            self.assertEqual(argv[-2], "hgagent@node-a.example.org")
            return subprocess.run([sys.executable, PROXY] + self.argv(token_file), input=kw["input"],
                                  stdout=kw["stdout"], stderr=kw["stderr"], timeout=kw["timeout"])

        srv = hg.Server(cfg, hg.ProxyTransport(cfg, runner))
        return srv

    def call(self, srv, name, args=None):
        resp = srv.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": name, "arguments": args or {}}})
        return resp["result"]

    def test_default_server_picks_proxy_transport(self):
        srv = hg.Server(hg.Config.from_env({"HG_SSH": "hgagent@h", "HG_SSH_MODE": "proxy"}))
        self.assertIsInstance(srv.transport, hg.ProxyTransport)
        self.assertEqual(srv.transport.ssh_argv()[-1], "hg-agent-proxy")
        srv = hg.Server(hg.Config.from_env({"HG_SSH": "admin@h"}))
        self.assertIsInstance(srv.transport, hg.SshTransport)
        with self.assertRaises(ValueError):
            hg.Config.from_env({"HG_SSH": "a@h", "HG_SSH_MODE": "telnet"})
        with self.assertRaises(ValueError):
            hg.Config.from_env({"HG_SSH_MODE": "proxy"})
        cfg = hg.Config.from_env({"HG_SSH": "admin@h", "HG_SSH_MODE": "proxy", "HG_SSH_TOKEN_FILE": "/etc/x y",
                                  "HG_SSH_PROXY_CMD": "/usr/local/bin/hg-agent-proxy"})
        self.assertEqual(hg.ProxyTransport(cfg).ssh_argv()[-1],
                         "/usr/local/bin/hg-agent-proxy --token-file '/etc/x y'")

    def test_reads_through_proxy(self):
        srv = self.make()
        r = self.call(srv, "hg_overview")
        self.assertFalse(r["isError"], r)
        self.assertEqual(r["structuredContent"]["node"]["name"], "node-a")
        sent = json.loads(self.calls[-1][1])
        self.assertEqual(sent, {"method": "GET", "path": "/api/agent/overview"})
        self.assertNotIn(TOKEN.encode(), self.calls[-1][1])
        r = self.call(srv, "hg_bans", {"since": "6h", "limit": 5})
        self.assertEqual(json.loads(self.calls[-1][1])["query"], {"since": "6h", "limit": "5"})
        self.assertEqual(self.daemon.last()["query"], {"since": "6h", "limit": "5"})
        r = self.call(srv, "hg_log_stats", {"source": "nginx", "group_by": "ip", "ip": "203.0.113.0/24"})
        self.assertFalse(r["isError"], r)
        self.assertEqual(r["structuredContent"]["data_trust"], hg.DATA_TRUST_NOTE)
        self.assertEqual(json.loads(self.daemon.last()["body"])["filter"], {"ip": "203.0.113.0/24"})
        r = self.call(srv, "hg_ip", {"ip": "203.0.113.5"})
        self.assertFalse(r["isError"], r)
        r = self.call(srv, "hg_stream_sample", {"seconds": 1})
        self.assertFalse(r["isError"], r)
        self.assertEqual(r["structuredContent"]["result"]["count"], 3)
        self.assertEqual(json.loads(self.calls[-1][1])["stream_seconds"], 1)

    def test_fallbacks_for_non_agent_endpoints(self):
        srv = self.make()
        h = self.call(srv, "hg_health")
        self.assertFalse(h["isError"], h)
        self.assertEqual(h["structuredContent"]["info"]["name"], "node-a")
        p = self.call(srv, "hg_plugins")
        self.assertFalse(p["isError"], p)
        self.assertIn("proxy mode", p["structuredContent"]["note"])
        for name in ("hg_metrics", "hg_whitelist"):
            r = self.call(srv, name)
            self.assertTrue(r["isError"])
            self.assertIn("HG_SSH_MODE=proxy", r["content"][0]["text"])
        r = self.call(srv, "hg_config_get")  # /api/agent/config missing on the fake daemon -> 404
        self.assertTrue(r["isError"])
        self.assertIn("404", r["content"][0]["text"])
        self.assertTrue(all(json.loads(c[1])["path"].startswith("/api/agent/") for c in self.calls))

    def test_writes_refused_before_ssh(self):
        srv = self.make(allow_write=True)
        for name, args in (("hg_ban", {"subject": "203.0.113.5", "duration_secs": 60, "reason": "x"}),
                           ("hg_unban", {"subject": "203.0.113.5"}),
                           ("hg_whitelist_add", {"cidr": "10.1.0.0/16"}),
                           ("hg_config_put", {"content": "node: {}\n"})):
            r = self.call(srv, name, args)
            self.assertTrue(r["isError"], name)
            self.assertIn("proxy", r["content"][0]["text"])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.daemon.requests, [])

    def test_proxy_errors_surface(self):
        srv = self.make(token_file="/nonexistent/tok")
        r = self.call(srv, "hg_overview")
        self.assertTrue(r["isError"])
        self.assertIn("token file /nonexistent/tok not found", r["content"][0]["text"])

    def test_ssh_failure_and_garbage(self):
        cfg = hg.Config.from_env({"HG_SSH": "hgagent@h", "HG_SSH_MODE": "proxy"})
        cp = subprocess.CompletedProcess
        t = hg.ProxyTransport(cfg, lambda argv, **kw: cp(argv, 255, b"", b"Permission denied (publickey)"))
        with self.assertRaises(hg.ApiError) as ctx:
            t.request("GET", "/api/agent/overview")
        self.assertIn("Permission denied", str(ctx.exception))
        t = hg.ProxyTransport(cfg, lambda argv, **kw: cp(argv, 0, b"Welcome to Ubuntu\n", b""))
        with self.assertRaises(hg.ApiError) as ctx:
            t.request("GET", "/api/agent/overview")
        self.assertIn("non-JSON", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
