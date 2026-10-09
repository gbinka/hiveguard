"""Tests for hiveguard_mcp.py against a fake HiveGuard daemon (stdlib only).

Run:  cd tools/mcp && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v tests
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
MCP_DIR = os.path.dirname(HERE)
SCRIPT = os.path.join(MCP_DIR, "hiveguard_mcp.py")
sys.path.insert(0, MCP_DIR)

import hiveguard_mcp as hg  # noqa: E402

hg.log.addHandler(logging.NullHandler())  # keep expected tracebacks out of test output
hg.log.propagate = False

TOKEN = "test-token-123"

METRICS_TEXT = """# HELP hiveguard_events_processed Events processed.
# TYPE hiveguard_events_processed counter
hiveguard_events_processed_total{source="nginx"} 1234567
hiveguard_events_processed_total{source="firewall"} 999
hiveguard_events_processed_created{source="nginx"} 1.7e9
hiveguard_active_bans 1463
hiveguard_memory_bytes 8.5e7
process_cpu_seconds_total 12.5
# EOF
"""

SSE_BODY = (
    ": keep-alive\n\n"
    "event: signal\n"
    'data: {"ip":"203.0.113.5","severity":90,"confidence":80,"detector":"path_probe","reason":"x","timestamp":"t"}\n\n'
    "event: ban_added\n"
    'data: {"subject":"203.0.113.5/32","severity":150,"reason":"x","created_at":"t","expires_at":null,'
    '"source":"detector:path_probe"}\n\n'
    "event: ban_removed\n"
    'data: {"subject":"198.51.100.1/32"}\n\n'
)


def J(status, obj):
    return (status, "application/json", json.dumps(obj).encode())


ROUTES = {
    ("GET", "/api/health"): J(200, {"status": "ok", "uptime_secs": 5}),
    ("GET", "/api/info"): J(200, {"node_name": "etno", "daemon_version": "0.1.0", "uptime_secs": 5,
                                  "total_bans": 3}),
    ("GET", "/api/agent/overview"): J(200, {"node": {"name": "etno"}, "bans": {"total": 3},
                                            "log_sources": ["nginx", "ssh", "firewall"]}),
    ("GET", "/api/agent/bans"): J(200, {"total": 3, "matched": 1, "limit": 100, "offset": 0, "items": []}),
    ("GET", "/api/agent/threats"): J(200, {"buffered": 500, "matched": 0, "items": []}),
    ("GET", "/api/agent/logs/sources"): J(200, {"sources": [{"name": "nginx", "kind": "file"}]}),
    ("POST", "/api/agent/logs/query"): J(200, {"source": "nginx", "matched": 1, "items": [{"raw": "x"}]}),
    ("POST", "/api/agent/logs/stats"): J(200, {"source": "nginx", "groups": []}),
    ("POST", "/api/agent/ip"): J(200, {"ip": "203.0.113.5", "whitelisted": False}),
    ("GET", "/api/agent/journal"): J(200, {"unit": "hiveguard", "items": []}),
    ("GET", "/api/agent/detectors"): J(200, {"detectors": []}),
    ("GET", "/api/agent/catalog"): J(200, {"plugins": []}),
    ("GET", "/api/plugins"): J(200, [{"id": "source.file.nginx", "kind": "Source", "health": "Running"}]),
    ("GET", "/api/whitelist"): J(200, {"entries": ["10.0.0.0/8"]}),
    ("GET", "/api/config"): J(200, {"content": "node:\n  name: etno\n"}),
    ("PUT", "/api/config"): J(503, {"error": "config directory is read-only"}),
    ("POST", "/api/agent/config/validate"): J(200, {"valid": True, "errors": [], "warnings": []}),
    ("POST", "/api/bans"): J(201, {"status": "created"}),
    ("POST", "/api/whitelist"): J(201, {"message": "Whitelisted 10.1.0.0/16"}),
    ("GET", "/metrics"): (200, "application/openmetrics-text; version=1.0.0; charset=utf-8",
                          METRICS_TEXT.encode()),
}
PUBLIC = {"/api/health", "/metrics"}


class FakeDaemon:
    def __init__(self):
        self.requests: list[dict] = []
        self.routes = dict(ROUTES)
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # silence
                pass

            def _handle(self):
                parts = urllib.parse.urlsplit(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                rec = {"method": self.command, "path": parts.path, "raw_path": self.path,
                       "query": dict(urllib.parse.parse_qsl(parts.query)),
                       "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body}
                fake.requests.append(rec)
                if parts.path not in PUBLIC and rec["headers"].get("authorization") != f"Bearer {TOKEN}":
                    return self._send(401, "application/json", b'{"error":"Unauthorized"}')
                if parts.path == "/api/agent/stream":
                    return self._sse()
                if self.command == "DELETE" and parts.path.startswith("/api/bans/"):
                    return self._send(204, "", b"")
                if self.command == "DELETE" and parts.path.startswith("/api/whitelist/"):
                    return self._send(200, "application/json", b'{"message":"removed"}')
                route = fake.routes.get((self.command, parts.path))
                if route is None:
                    return self._send(404, "application/json",
                                      json.dumps({"error": f"unknown log source `{parts.path}`"}).encode())
                self._send(*route)

            def _send(self, status, ctype, body):
                self.send_response(status)
                if ctype:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _sse(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(SSE_BODY.encode())
                self.wfile.flush()
                time.sleep(0.3)
                self.close_connection = True

            do_GET = do_POST = do_PUT = do_DELETE = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def last(self, path_prefix: str | None = None) -> dict:
        reqs = [r for r in self.requests if path_prefix is None or r["path"].startswith(path_prefix)]
        return reqs[-1]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.daemon = FakeDaemon()

    @classmethod
    def tearDownClass(cls):
        cls.daemon.stop()

    def setUp(self):
        self.daemon.requests.clear()
        self._id = 0

    def make(self, **env) -> hg.Server:
        base = {"HG_URL": self.daemon.url, "HG_TOKEN": TOKEN, "HG_TIMEOUT": "10"}
        base.update(env)
        base = {k: v for k, v in base.items() if v is not None}
        return hg.Server(hg.Config.from_env(base))

    def rpc(self, srv, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        return srv.dispatch(msg)

    def call(self, srv, name, args=None):
        resp = self.rpc(srv, "tools/call", {"name": name, "arguments": args or {}})
        self.assertIn("result", resp, resp)
        return resp["result"]


class ProtocolTests(Base):
    def test_initialize_default_and_echo(self):
        srv = self.make(HG_NODE_LABEL="node-a")
        r = self.rpc(srv, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "t", "version": "1"}})["result"]
        self.assertEqual(r["protocolVersion"], "2025-06-18")
        self.assertEqual(r["serverInfo"]["name"], "hiveguard-mcp")
        for cap in ("tools", "prompts", "resources"):
            self.assertIn(cap, r["capabilities"])
        self.assertIn("node-a", r["instructions"])
        for v in ("2025-03-26", "2024-11-05"):
            self.assertEqual(self.rpc(srv, "initialize", {"protocolVersion": v})["result"]["protocolVersion"], v)
        self.assertEqual(self.rpc(srv, "initialize", {"protocolVersion": "1999-01-01"})["result"]
                         ["protocolVersion"], hg.LATEST_PROTOCOL)

    def test_initialized_notification_no_reply_and_ping(self):
        srv = self.make()
        self.assertIsNone(self.rpc(srv, "notifications/initialized", notify=True))
        self.assertTrue(srv.initialized)
        self.assertEqual(self.rpc(srv, "ping")["result"], {})

    def test_malformed_line(self):
        srv = self.make()
        out = json.loads(srv.handle_line("{not json"))
        self.assertEqual(out["error"]["code"], -32700)
        self.assertIsNone(out["id"])
        self.assertIsNone(srv.handle_line("   "))
        out = json.loads(srv.handle_line(b"\xff\xfe\n"))
        self.assertEqual(out["error"]["code"], -32700)

    def test_invalid_request(self):
        srv = self.make()
        self.assertEqual(json.loads(srv.handle_line("[1]"))[0]["error"]["code"], -32600)
        self.assertEqual(json.loads(srv.handle_line('{"jsonrpc":"2.0","id":4}'))["error"]["code"], -32600)

    def test_unknown_method(self):
        srv = self.make()
        r = self.rpc(srv, "does/not/exist")
        self.assertEqual(r["error"]["code"], -32601)
        self.assertIsNone(self.rpc(srv, "does/not/exist", notify=True))

    def test_unknown_tool_is_protocol_error(self):
        srv = self.make()
        r = self.rpc(srv, "tools/call", {"name": "nope", "arguments": {}})
        self.assertEqual(r["error"]["code"], -32602)

    def test_tools_list_schemas(self):
        srv = self.make(HG_NODE_LABEL="node-b")
        tools = self.rpc(srv, "tools/list")["result"]["tools"]
        names = {t["name"] for t in tools}
        expected = {"hg_overview", "hg_health", "hg_bans", "hg_threats", "hg_log_sources", "hg_log_query",
                    "hg_log_stats", "hg_ip", "hg_journal", "hg_detectors", "hg_catalog", "hg_plugins",
                    "hg_whitelist", "hg_config_get", "hg_config_validate", "hg_metrics", "hg_stream_sample",
                    "hg_ban", "hg_unban", "hg_whitelist_add", "hg_whitelist_remove", "hg_config_put"}
        self.assertEqual(names, expected)
        allowed_types = {"object", "string", "integer", "boolean", "array", "number"}

        def check(schema, where):
            self.assertIn(schema.get("type"), allowed_types, where)
            if schema["type"] == "object":
                for k, sub in (schema.get("properties") or {}).items():
                    check(sub, f"{where}.{k}")
                for r in schema.get("required", []):
                    self.assertIn(r, schema["properties"], where)
                if isinstance(schema.get("additionalProperties"), dict):
                    check(schema["additionalProperties"], where + ".*")
            if schema["type"] == "array":
                check(schema["items"], where + "[]")
            if "enum" in schema:
                self.assertTrue(schema["enum"] and len(set(schema["enum"])) == len(schema["enum"]), where)

        for t in tools:
            self.assertTrue(t["description"].startswith("[HiveGuard node: node-b]"), t["name"])
            self.assertTrue(t["title"])
            self.assertEqual(t["inputSchema"]["type"], "object")
            check(t["inputSchema"], t["name"])
            ann = t["annotations"]
            for k in ("readOnlyHint", "destructiveHint", "idempotentHint"):
                self.assertIsInstance(ann[k], bool)
            json.dumps(t)
        by = {t["name"]: t for t in tools}
        self.assertIn("ip", by["hg_log_stats"]["inputSchema"]["properties"]["group_by"]["enum"])
        self.assertEqual(by["hg_log_stats"]["inputSchema"]["required"], ["source", "group_by"])
        self.assertEqual(by["hg_bans"]["inputSchema"]["properties"]["source"]["enum"], ["detector", "peer", "admin"])
        self.assertIn("Detector", by["hg_catalog"]["inputSchema"]["properties"]["kind"]["enum"])
        self.assertFalse(by["hg_ban"]["annotations"]["readOnlyHint"])
        self.assertTrue(by["hg_unban"]["annotations"]["destructiveHint"])
        self.assertTrue(by["hg_overview"]["annotations"]["readOnlyHint"])

    def test_prompts(self):
        srv = self.make(HG_NODE_LABEL="etno")
        prompts = self.rpc(srv, "prompts/list")["result"]["prompts"]
        self.assertEqual([p["name"] for p in prompts], ["daily_security_review"])
        r = self.rpc(srv, "prompts/get", {"name": "daily_security_review", "arguments": {"hours": "12"}})["result"]
        text = r["messages"][0]["content"]["text"]
        self.assertEqual(r["messages"][0]["role"], "user")
        self.assertIn('since="12h"', text)
        self.assertIn("etno", text)
        order = [text.index(t) for t in ("hg_overview", "hg_journal", "hg_threats", "hg_log_stats", "hg_ip",
                                         "hg_detectors", "hg_config_validate")]
        self.assertEqual(order, sorted(order))
        self.assertLessEqual(len(text.splitlines()), 60)
        d = self.rpc(srv, "prompts/get", {"name": "daily_security_review"})["result"]
        self.assertIn('since="24h"', d["messages"][0]["content"]["text"])
        self.assertEqual(self.rpc(srv, "prompts/get", {"name": "x"})["error"]["code"], -32602)
        self.assertEqual(self.rpc(srv, "prompts/get", {"name": "daily_security_review",
                                                       "arguments": {"hours": "abc"}})["error"]["code"], -32602)

    def test_resources(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "AGENT_API.md")
            with open(p, "w") as fh:
                fh.write("# Agent API\n")
            srv = self.make(HG_DOCS=d)
            res = self.rpc(srv, "resources/list")["result"]["resources"]
            self.assertEqual([r["uri"] for r in res], ["hiveguard://agent-api"])
            r = self.rpc(srv, "resources/read", {"uri": "hiveguard://agent-api"})["result"]
            self.assertEqual(r["contents"][0]["text"], "# Agent API\n")
            self.assertEqual(self.rpc(srv, "resources/read", {"uri": "x://y"})["error"]["code"], -32002)

    def test_resources_empty_when_doc_missing(self):
        srv = self.make(HG_DOCS="/nonexistent/AGENT_API.md")
        orig = hg.find_agent_doc
        hg.find_agent_doc = lambda cfg, script_path=None: None
        try:
            self.assertEqual(self.rpc(srv, "resources/list")["result"]["resources"], [])
        finally:
            hg.find_agent_doc = orig


class ToolTests(Base):
    def test_overview_and_auth_header(self):
        srv = self.make()
        r = self.call(srv, "hg_overview")
        self.assertFalse(r["isError"])
        self.assertEqual(r["structuredContent"]["node"]["name"], "etno")
        self.assertEqual(json.loads(r["content"][0]["text"])["bans"]["total"], 3)
        req = self.daemon.last()
        self.assertEqual((req["method"], req["path"]), ("GET", "/api/agent/overview"))
        self.assertEqual(req["headers"]["authorization"], f"Bearer {TOKEN}")

    def test_bans_query_params(self):
        srv = self.make()
        r = self.call(srv, "hg_bans", {"source": "detector", "detector": "ssh_bruteforce", "since": "6h",
                                       "subnet_only": True, "sort": "severity", "order": "asc", "limit": 50,
                                       "offset": 10, "q": "wp-login"})
        self.assertFalse(r["isError"], r)
        q = self.daemon.last()["query"]
        self.assertEqual(q, {"source": "detector", "detector": "ssh_bruteforce", "since": "6h",
                             "subnet_only": "true", "sort": "severity", "order": "asc", "limit": "50",
                             "offset": "10", "q": "wp-login"})

    def test_bans_invalid_enum_and_unknown_arg(self):
        srv = self.make()
        r = self.call(srv, "hg_bans", {"sort": "bogus"})
        self.assertTrue(r["isError"])
        self.assertIn("sort", r["content"][0]["text"])
        r = self.call(srv, "hg_bans", {"nope": 1})
        self.assertTrue(r["isError"])
        self.assertEqual(self.daemon.requests, [])

    def test_threats(self):
        srv = self.make()
        self.call(srv, "hg_threats", {"ip": "203.0.113.0/24", "min_severity": "50"})
        self.assertEqual(self.daemon.last()["query"], {"ip": "203.0.113.0/24", "min_severity": "50"})

    def test_log_query_posts_json(self):
        srv = self.make()
        args = {"source": "nginx", "since": "6h", "grep": "wp-login|xmlrpc", "ip": "203.0.113.0/24",
                "fields": {"status": "4xx", "method": "POST"}, "limit": 200, "parse": False}
        r = self.call(srv, "hg_log_query", args)
        self.assertFalse(r["isError"], r)
        req = self.daemon.last()
        self.assertEqual((req["method"], req["path"]), ("POST", "/api/agent/logs/query"))
        self.assertEqual(req["headers"]["content-type"], "application/json")
        self.assertEqual(json.loads(req["body"]), args)

    def test_log_query_requires_source(self):
        r = self.call(self.make(), "hg_log_query", {"grep": "x"})
        self.assertTrue(r["isError"])
        self.assertIn("source", r["content"][0]["text"])

    def test_log_stats(self):
        srv = self.make()
        args = {"source": "nginx", "since": "24h", "filter": {"fields": {"status": "4xx"}}, "group_by": "path",
                "top": 10, "buckets": "1h"}
        self.assertFalse(self.call(srv, "hg_log_stats", args)["isError"])
        self.assertEqual(json.loads(self.daemon.last()["body"]), args)
        r = self.call(srv, "hg_log_stats", {"source": "nginx", "group_by": "country"})
        self.assertTrue(r["isError"])

    def test_ip(self):
        srv = self.make()
        self.call(srv, "hg_ip", {"ip": "203.0.113.5", "since": "24h"})
        self.assertEqual(json.loads(self.daemon.last()["body"]), {"ip": "203.0.113.5", "since": "24h"})
        r = self.call(srv, "hg_ip", {"ip": "203.0.113.0/24"})
        self.assertTrue(r["isError"])

    def test_journal_catalog_misc(self):
        srv = self.make()
        self.call(srv, "hg_journal", {"priority": 4, "since": "24h"})
        self.assertEqual(self.daemon.last()["query"], {"priority": "4", "since": "24h"})
        self.call(srv, "hg_catalog", {"kind": "detector"})
        self.assertEqual(self.daemon.last()["query"], {"kind": "Detector"})
        r = self.call(srv, "hg_plugins")
        self.assertEqual(r["structuredContent"]["items"][0]["id"], "source.file.nginx")
        for name, path in (("hg_log_sources", "/api/agent/logs/sources"), ("hg_detectors", "/api/agent/detectors"),
                           ("hg_whitelist", "/api/whitelist")):
            self.assertFalse(self.call(srv, name)["isError"])
            self.assertEqual(self.daemon.last()["path"], path)

    def test_config_get_returns_yaml_text(self):
        r = self.call(self.make(), "hg_config_get")
        self.assertEqual(r["content"][0]["text"], "node:\n  name: etno\n")
        self.assertEqual(r["structuredContent"]["content"], "node:\n  name: etno\n")

    def test_config_validate(self):
        srv = self.make()
        r = self.call(srv, "hg_config_validate", {"content": "node: {}\n"})
        self.assertTrue(r["structuredContent"]["valid"])
        self.assertEqual(json.loads(self.daemon.last()["body"]), {"content": "node: {}\n"})

    def test_error_mapping_404(self):
        srv = self.make()
        self.daemon.routes.pop(("GET", "/api/agent/detectors"))
        try:
            r = self.call(srv, "hg_detectors")
        finally:
            self.daemon.routes[("GET", "/api/agent/detectors")] = ROUTES[("GET", "/api/agent/detectors")]
        self.assertTrue(r["isError"])
        self.assertIn("404", r["content"][0]["text"])
        self.assertIn("unknown log source", r["content"][0]["text"])
        self.assertEqual(r["structuredContent"]["status"], 404)

    def test_error_401(self):
        r = self.call(self.make(HG_TOKEN="wrong"), "hg_overview")
        self.assertTrue(r["isError"])
        self.assertIn("401", r["content"][0]["text"])
        self.assertIn("token", r["content"][0]["text"])

    def test_unreachable_daemon(self):
        r = self.call(self.make(HG_URL="http://127.0.0.1:1"), "hg_overview")
        self.assertTrue(r["isError"])
        self.assertIn("cannot reach", r["content"][0]["text"])

    def test_missing_token(self):
        srv = self.make(HG_TOKEN=None, HG_TOKEN_FILE="/nonexistent/agent-token")
        r = self.call(srv, "hg_overview")
        self.assertTrue(r["isError"])
        self.assertIn("no API token", r["content"][0]["text"])
        self.assertEqual(self.daemon.requests, [])
        # health and metrics work without a token
        h = self.call(srv, "hg_health")
        self.assertFalse(h["isError"], h)
        self.assertEqual(h["structuredContent"]["health"]["status"], "ok")
        self.assertNotIn("info", h["structuredContent"])
        self.assertFalse(self.call(srv, "hg_metrics")["isError"])
        self.assertTrue(all("authorization" not in r["headers"] for r in self.daemon.requests))

    def test_token_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(TOKEN + "\n")
        try:
            srv = self.make(HG_TOKEN=None, HG_TOKEN_FILE=fh.name)
            h = self.call(srv, "hg_health")
            self.assertEqual(h["structuredContent"]["info"]["node_name"], "etno")
            self.assertEqual(self.daemon.last()["headers"]["authorization"], f"Bearer {TOKEN}")
        finally:
            os.unlink(fh.name)

    def test_metrics_parsing(self):
        r = self.call(self.make(), "hg_metrics")
        s = r["structuredContent"]
        self.assertEqual(s["hiveguard"]['hiveguard_events_processed_total{source="nginx"}'], 1234567)
        self.assertEqual(s["hiveguard"]["hiveguard_active_bans"], 1463)
        self.assertEqual(s["hiveguard"]["hiveguard_memory_bytes"], 85000000)
        self.assertNotIn("process_cpu_seconds_total", s["hiveguard"])
        self.assertFalse(any(k.startswith("hiveguard_events_processed_created") for k in s["hiveguard"]))
        r = self.call(self.make(), "hg_metrics", {"filter": "firewall"})
        self.assertEqual(r["structuredContent"]["lines"], ['hiveguard_events_processed_total{source="firewall"} 999'])
        self.assertTrue(self.call(self.make(), "hg_metrics", {"filter": "("})["isError"])

    def test_stream_sample(self):
        srv = self.make()
        r = self.call(srv, "hg_stream_sample", {"seconds": 2, "types": ["signal", "ban_added"]})
        self.assertFalse(r["isError"], r)
        s = r["structuredContent"]
        self.assertEqual(s["count"], 3)
        self.assertEqual(s["by_type"], {"signal": 1, "ban_added": 1, "ban_removed": 1})
        self.assertEqual(s["events"][0]["data"]["ip"], "203.0.113.5")
        self.assertEqual(self.daemon.last()["query"], {"types": "signal,ban_added"})
        r = self.call(srv, "hg_stream_sample", {"seconds": 999})
        self.assertTrue(r["isError"])

    def test_sse_parser_chunked(self):
        p = hg.SseParser()
        evs = []
        for ch in SSE_BODY:
            evs += p.feed(ch)
        evs += p.finish()
        self.assertEqual([e.event for e in evs], ["signal", "ban_added", "ban_removed"])

    def test_tool_exception_is_error_not_crash(self):
        srv = self.make()
        orig = hg.TOOLS_BY_NAME["hg_overview"].handler
        hg.TOOLS_BY_NAME["hg_overview"].handler = lambda s, a: 1 / 0
        try:
            r = self.call(srv, "hg_overview")
        finally:
            hg.TOOLS_BY_NAME["hg_overview"].handler = orig
        self.assertTrue(r["isError"])
        self.assertIn("ZeroDivisionError", r["content"][0]["text"])


class WriteTests(Base):
    def test_writes_disabled(self):
        srv = self.make()
        for name, args in (("hg_ban", {"subject": "1.2.3.4", "duration_secs": 60, "reason": "t"}),
                           ("hg_unban", {"subject": "1.2.3.4"}), ("hg_whitelist_add", {"cidr": "10.0.0.1"}),
                           ("hg_whitelist_remove", {"cidr": "10.0.0.1"}), ("hg_config_put", {"content": "x"})):
            r = self.call(srv, name, args)
            self.assertTrue(r["isError"], name)
            self.assertIn("HG_MCP_ALLOW_WRITE=1", r["content"][0]["text"])
        self.assertEqual(self.daemon.requests, [])

    def test_unban_path_encoding(self):
        srv = self.make(HG_MCP_ALLOW_WRITE="1")
        r = self.call(srv, "hg_unban", {"subject": "1.2.3.4"})
        self.assertFalse(r["isError"], r)
        req = self.daemon.last()
        self.assertEqual(req["method"], "DELETE")
        self.assertEqual(req["raw_path"], "/api/bans/1.2.3.4%2F32")

    def test_ban_body(self):
        srv = self.make(HG_MCP_ALLOW_WRITE="1")
        r = self.call(srv, "hg_ban", {"subject": "2001:db8::1", "duration_secs": 3600, "reason": "scan"})
        self.assertFalse(r["isError"], r)
        req = self.daemon.last()
        self.assertEqual((req["method"], req["path"]), ("POST", "/api/bans"))
        self.assertEqual(json.loads(req["body"]),
                         {"subject": "2001:db8::1/128", "duration": {"secs": 3600, "nanos": 0}, "reason": "scan"})
        self.assertTrue(self.call(srv, "hg_ban", {"subject": "nope", "duration_secs": 1, "reason": "x"})["isError"])

    def test_whitelist_and_config_put(self):
        srv = self.make(HG_MCP_ALLOW_WRITE="1")
        self.call(srv, "hg_whitelist_add", {"cidr": "10.1.2.3/16"})
        self.assertEqual(json.loads(self.daemon.last()["body"]), {"cidr": "10.1.0.0/16"})
        self.call(srv, "hg_whitelist_remove", {"cidr": "10.1.0.0/16"})
        self.assertEqual(self.daemon.last()["raw_path"], "/api/whitelist/10.1.0.0%2F16")
        r = self.call(srv, "hg_config_put", {"content": "node: {}\n"})
        self.assertTrue(r["isError"])
        self.assertIn("read-only", r["content"][0]["text"])
        self.assertEqual(self.daemon.last()["method"], "PUT")


@unittest.skipUnless(shutil.which("curl") and shutil.which("sh"), "needs curl and sh")
class SshModeTests(Base):
    """Run SshTransport's generated script locally with `sh -s` instead of ssh."""

    def make_ssh(self, token=None, remote_token_file=None, runner_log=None):
        env = {"HG_URL": self.daemon.url, "HG_SSH": "admin@example", "HG_TIMEOUT": "10",
               "HG_TOKEN": token, "HG_TOKEN_FILE": "/nonexistent/agent-token",
               "HG_SSH_TOKEN_FILE": remote_token_file}
        cfg = hg.Config.from_env({k: v for k, v in env.items() if v is not None})

        def runner(argv, **kw):
            if runner_log is not None:
                runner_log.append((argv, kw["input"].decode()))
            self.assertEqual(argv[-1], "sh -s")
            return subprocess.run(["sh", "-s"], input=kw["input"], stdout=kw["stdout"], stderr=kw["stderr"],
                                  timeout=kw["timeout"])

        return hg.Server(cfg, hg.SshTransport(cfg, runner))

    def test_ssh_local_token_not_in_argv(self):
        logs = []
        srv = self.make_ssh(token=TOKEN, runner_log=logs)
        r = self.call(srv, "hg_log_query", {"source": "nginx", "grep": 'a"b\\c'})
        self.assertFalse(r["isError"], r)
        self.assertEqual(json.loads(self.daemon.last()["body"]), {"source": "nginx", "grep": 'a"b\\c'})
        self.assertEqual(self.daemon.last()["headers"]["authorization"], f"Bearer {TOKEN}")
        argv, script = logs[-1]
        self.assertNotIn(TOKEN, " ".join(argv))
        self.assertIn(TOKEN, script)
        self.assertIn("BatchMode=yes", argv)

    def test_ssh_remote_token_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(TOKEN + "\n")
        try:
            logs = []
            srv = self.make_ssh(remote_token_file=fh.name, runner_log=logs)
            r = self.call(srv, "hg_bans", {"limit": 5})
            self.assertFalse(r["isError"], r)
            self.assertEqual(self.daemon.last()["query"], {"limit": "5"})
            self.assertNotIn(TOKEN, logs[-1][1])
            r = self.call(srv, "hg_unban", {"subject": "1.2.3.4"})  # writes still gated
            self.assertTrue(r["isError"])
        finally:
            os.unlink(fh.name)

    def test_ssh_remote_token_missing(self):
        srv = self.make_ssh(remote_token_file="/nonexistent/tok")
        r = self.call(srv, "hg_overview")
        self.assertTrue(r["isError"])
        self.assertIn("no API token on admin@example", r["content"][0]["text"])
        self.assertFalse(self.call(srv, "hg_metrics")["isError"])

    def test_ssh_error_and_stream(self):
        srv = self.make_ssh(token=TOKEN)
        self.daemon.routes.pop(("GET", "/api/agent/catalog"))
        try:
            r = self.call(srv, "hg_catalog")
        finally:
            self.daemon.routes[("GET", "/api/agent/catalog")] = ROUTES[("GET", "/api/agent/catalog")]
        self.assertTrue(r["isError"])
        self.assertIn("404", r["content"][0]["text"])
        r = self.call(srv, "hg_stream_sample", {"seconds": 1})
        self.assertFalse(r["isError"], r)
        self.assertEqual(r["structuredContent"]["count"], 3)

    def test_ssh_unreachable(self):
        cfg = hg.Config.from_env({"HG_URL": "http://127.0.0.1:1", "HG_SSH": "x@y", "HG_TOKEN": TOKEN,
                                  "HG_TIMEOUT": "5"})
        srv = hg.Server(cfg, hg.SshTransport(cfg, lambda argv, **kw: subprocess.run(
            ["sh", "-s"], input=kw["input"], stdout=kw["stdout"], stderr=kw["stderr"], timeout=kw["timeout"])))
        r = self.call(srv, "hg_overview")
        self.assertTrue(r["isError"])
        self.assertIn("could not reach", r["content"][0]["text"])


class SubprocessSmokeTest(Base):
    def test_stdio_roundtrip(self):
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "hg_overview", "arguments": {}}},
        ]
        stdin = "\n".join(json.dumps(m) for m in lines) + "\nnot-json\n"
        env = dict(os.environ, HG_URL=self.daemon.url, HG_TOKEN=TOKEN, HG_MCP_LOG="debug",
                   PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run([sys.executable, SCRIPT], input=stdin.encode(), capture_output=True, env=env,
                              timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        out = [json.loads(line) for line in proc.stdout.decode().splitlines()]
        self.assertEqual([o.get("id") for o in out], [1, 2, 3, None])
        self.assertEqual(out[0]["result"]["protocolVersion"], "2025-03-26")
        self.assertGreaterEqual(len(out[1]["result"]["tools"]), 22)
        self.assertFalse(out[2]["result"]["isError"])
        self.assertEqual(out[3]["error"]["code"], -32700)
        self.assertNotIn(TOKEN, proc.stderr.decode())


if __name__ == "__main__":
    unittest.main()
