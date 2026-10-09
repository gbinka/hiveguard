#!/usr/bin/env python3
"""hiveguard-mcp: stdio MCP server for the HiveGuard daemon (ui.rest plugin).

Zero dependencies (Python >= 3.10 stdlib only). Speaks MCP as newline-delimited
JSON-RPC 2.0 on stdin/stdout and forwards tool calls to the daemon's REST API
(operator endpoints + the Agent API described in docs/AGENT_API.md), either
directly over HTTP or through `ssh user@host sh -s` + remote curl.

Environment:
  HG_URL              daemon base URL (default http://127.0.0.1:8443)
  HG_TOKEN            bearer token (never put it in argv)
  HG_TOKEN_FILE       file with the token (default /etc/hiveguard/agent-token)
  HG_SSH              user@host: run requests via ssh + remote curl
  HG_SSH_TOKEN_FILE   token file on the remote host (default /etc/hiveguard/agent-token)
  HG_TIMEOUT          request timeout in seconds (default 60)
  HG_MCP_ALLOW_WRITE  1 enables ban/unban/whitelist/config writes (default off)
  HG_NODE_LABEL       free text identifying the node (shown in descriptions)
  HG_DOCS             path to AGENT_API.md (file or directory)
  HG_TLS_INSECURE     1 disables TLS verification for https HG_URL
  HG_MCP_LOG          debug|info|warn (stderr logging, default warn)
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

SERVER_NAME = "hiveguard-mcp"
SERVER_VERSION = "0.1.0"
LATEST_PROTOCOL = "2025-06-18"
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_URL = "http://127.0.0.1:8443"
DEFAULT_TOKEN_FILE = "/etc/hiveguard/agent-token"
STREAM_MAX_SECONDS = 120
STREAM_MAX_EVENTS = 5000
STREAM_MAX_BYTES = 8 * 1024 * 1024
AGENT_API_URI = "hiveguard://agent-api"

log = logging.getLogger(SERVER_NAME)

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
RESOURCE_NOT_FOUND = -32002


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def _env_bool(env: dict, name: str) -> bool:
    return str(env.get(name, "")).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    url: str = DEFAULT_URL
    token: str | None = None
    token_file: str = DEFAULT_TOKEN_FILE
    token_file_explicit: bool = False
    ssh: str | None = None
    ssh_token_file: str = DEFAULT_TOKEN_FILE
    timeout: float = 60.0
    allow_write: bool = False
    node_label: str = ""
    docs: str | None = None
    tls_insecure: bool = False

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Config":
        env = dict(os.environ if env is None else env)
        try:
            timeout = float(env.get("HG_TIMEOUT") or 60)
            if timeout <= 0:
                raise ValueError
        except ValueError:
            log.warning("invalid HG_TIMEOUT=%r, using 60", env.get("HG_TIMEOUT"))
            timeout = 60.0
        return cls(
            url=(env.get("HG_URL") or DEFAULT_URL).rstrip("/"),
            token=(env.get("HG_TOKEN") or "").strip() or None,
            token_file=env.get("HG_TOKEN_FILE") or DEFAULT_TOKEN_FILE,
            token_file_explicit=bool(env.get("HG_TOKEN_FILE")),
            ssh=(env.get("HG_SSH") or "").strip() or None,
            ssh_token_file=env.get("HG_SSH_TOKEN_FILE") or DEFAULT_TOKEN_FILE,
            timeout=timeout,
            allow_write=_env_bool(env, "HG_MCP_ALLOW_WRITE"),
            node_label=(env.get("HG_NODE_LABEL") or "").strip(),
            docs=env.get("HG_DOCS") or None,
            tls_insecure=_env_bool(env, "HG_TLS_INSECURE"),
        )

    def local_token(self) -> tuple[str | None, str | None]:
        """Return (token, problem). Token from HG_TOKEN, else HG_TOKEN_FILE."""
        if self.token:
            return self.token, None
        path = self.token_file
        try:
            with open(path, "r", encoding="utf-8") as fh:
                tok = fh.read().strip()
        except FileNotFoundError:
            return None, f"token file {path} not found"
        except PermissionError:
            return None, f"token file {path} is not readable (permission denied)"
        except OSError as exc:
            return None, f"cannot read token file {path}: {exc}"
        if not tok:
            return None, f"token file {path} is empty"
        return tok, None


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #


class ApiError(Exception):
    """Daemon returned an error status, or the request could not be made."""

    def __init__(self, message: str, status: int | None = None, payload: Any = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


@dataclass
class HttpResult:
    status: int
    content_type: str
    body: bytes

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def is_json(self) -> bool:
        return "json" in (self.content_type or "").lower()

    def parsed(self) -> Any:
        """JSON if it parses, else the decoded text."""
        txt = self.text()
        if not txt.strip():
            return None
        try:
            return json.loads(txt)
        except ValueError:
            return txt


@dataclass
class SseEvent:
    event: str
    data: Any
    id: str | None = None

    def as_dict(self) -> dict:
        d = {"event": self.event, "data": self.data}
        if self.id is not None:
            d["id"] = self.id
        return d


class SseParser:
    """Incremental text/event-stream parser."""

    def __init__(self) -> None:
        self._buf = ""
        self._event = None
        self._data: list[str] = []
        self._id = None

    def feed(self, chunk: str) -> list[SseEvent]:
        self._buf += chunk.replace("\r\n", "\n").replace("\r", "\n")
        out: list[SseEvent] = []
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            ev = self._line(line)
            if ev is not None:
                out.append(ev)
        return out

    def finish(self) -> list[SseEvent]:
        out = []
        if self._buf:
            ev = self._line(self._buf)
            self._buf = ""
            if ev is not None:
                out.append(ev)
        ev = self._line("")
        if ev is not None:
            out.append(ev)
        return out

    def _line(self, line: str) -> SseEvent | None:
        if line == "":
            if not self._data and self._event is None:
                return None
            raw = "\n".join(self._data)
            try:
                data: Any = json.loads(raw) if raw else None
            except ValueError:
                data = raw
            ev = SseEvent(self._event or "message", data, self._id)
            self._event, self._data, self._id = None, [], None
            return ev
        if line.startswith(":"):
            return None  # comment / keep-alive
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "event":
            self._event = value
        elif name == "data":
            self._data.append(value)
        elif name == "id":
            self._id = value
        return None


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class HttpTransport:
    """Direct HTTP(S) to HG_URL using http.client."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        parts = urllib.parse.urlsplit(cfg.url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"HG_URL must be http(s)://host[:port], got {cfg.url!r}")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.prefix = parts.path.rstrip("/")

    def describe(self) -> str:
        return f"http {self.cfg.url}"

    def _conn(self, timeout: float) -> http.client.HTTPConnection:
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            if self.cfg.tls_insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def _headers(self, auth: bool, accept: str, has_body: bool) -> dict:
        headers = {"Accept": accept, "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}"}
        if has_body:
            headers["Content-Type"] = "application/json"
        if auth:
            tok, problem = self.cfg.local_token()
            if not tok:
                raise ApiError(
                    "no API token available ("
                    + (problem or "unset")
                    + "); set HG_TOKEN or HG_TOKEN_FILE (or use HG_SSH so the token is read on the server)"
                )
            headers.update(_auth_header(tok))
        return headers

    def request(self, method: str, target: str, body: Any = None, auth: bool = True,
                accept: str = "application/json") -> HttpResult:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = self._headers(auth, accept, data is not None)
        conn = self._conn(self.cfg.timeout)
        try:
            conn.request(method, self.prefix + target, body=data, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
            return HttpResult(resp.status, resp.getheader("Content-Type") or "", payload)
        except (OSError, http.client.HTTPException) as exc:
            raise ApiError(f"cannot reach HiveGuard at {self.cfg.url}: {exc}") from exc
        finally:
            conn.close()

    def stream(self, target: str, seconds: float, max_events: int) -> tuple[HttpResult | None, list[SseEvent], bool]:
        headers = self._headers(True, "text/event-stream", False)
        headers["Cache-Control"] = "no-cache"
        deadline = time.monotonic() + seconds
        conn = self._conn(min(self.cfg.timeout, seconds + 5))
        events: list[SseEvent] = []
        truncated = False
        try:
            conn.request("GET", self.prefix + target, headers=headers)
            resp = conn.getresponse()
            ctype = resp.getheader("Content-Type") or ""
            if resp.status != 200:
                return HttpResult(resp.status, ctype, resp.read()), [], False
            parser = SseParser()
            total = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
                try:
                    chunk = resp.read1(65536)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                total += len(chunk)
                events.extend(parser.feed(chunk.decode("utf-8", errors="replace")))
                if len(events) >= max_events or total >= STREAM_MAX_BYTES:
                    truncated = True
                    break
            if not truncated:
                events.extend(parser.finish())
            truncated = truncated or len(events) > max_events
            return HttpResult(200, ctype, b""), events[:max_events], truncated
        except (OSError, http.client.HTTPException) as exc:
            if events:
                return HttpResult(200, "text/event-stream", b""), events, truncated
            raise ApiError(f"cannot reach HiveGuard at {self.cfg.url}: {exc}") from exc
        finally:
            conn.close()


def _curl_quote(value: str) -> str:
    """Quote a value for a curl config file (-K)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r") + '"'


META_MARK = "__HGMETA__"
NOTOKEN_MARK = "__HG_NOTOKEN__"


class SshTransport:
    """Runs curl on the remote host. The script (incl. token and body) goes over
    ssh stdin to `sh -s`; curl reads its options via `-K -` from a pipe, so the
    token never appears in any argv, locally or remotely."""

    def __init__(self, cfg: Config, runner: Callable[..., subprocess.CompletedProcess] | None = None):
        self.cfg = cfg
        self.runner = runner or subprocess.run

    def describe(self) -> str:
        return f"ssh {self.cfg.ssh} -> {self.cfg.url}"

    def ssh_argv(self) -> list[str]:
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=600",
            "-o", "ControlPath=~/.ssh/hg-mcp-%C",
            str(self.cfg.ssh),
            "sh -s",
        ]

    def build_script(self, method: str, target: str, body: Any, auth: bool, accept: str,
                     max_time: float, no_buffer: bool = False) -> str:
        delim = "HGEOF_" + secrets.token_hex(8)
        url = self.cfg.url + target
        lines = [
            f"url = {_curl_quote(url)}",
            f"request = {_curl_quote(method)}",
            "silent",
            "show-error",
            f"max-time = {int(max_time)}",
            f"header = {_curl_quote('Accept: ' + accept)}",
            f"header = {_curl_quote('User-Agent: ' + SERVER_NAME + '/' + SERVER_VERSION)}",
            f"write-out = {_curl_quote(chr(10) + META_MARK + ' %{http_code} %{content_type}' + chr(10))}",
        ]
        if no_buffer:
            lines.append("no-buffer")
        if body is not None:
            lines.append(f"header = {_curl_quote('Content-Type: application/json')}")
            lines.append(f"data-binary = {_curl_quote(json.dumps(body, ensure_ascii=False))}")
        cfg_text = "\n".join(lines)
        while delim in cfg_text:  # pragma: no cover - astronomically unlikely
            delim = "HGEOF_" + secrets.token_hex(8)

        script = ["set -u", "hg_tok=''"]
        if auth:
            tok, _ = self.cfg.local_token()
            if tok:
                # Escaped for curl's config syntax, then shell-quoted; lives only in the stdin script.
                esc = tok.replace("\\", "\\\\").replace('"', '\\"')
                script.append(f"hg_tok={shlex.quote(esc)}")
            else:
                tf = shlex.quote(self.cfg.ssh_token_file)
                script.append(
                    f"if [ -r {tf} ]; then hg_tok=$(tr -d '\\r\\n' < {tf}); "
                    f"else echo '{NOTOKEN_MARK} {self.cfg.ssh_token_file}' >&2; exit 97; fi"
                )
        script.append("{")
        script.append(f"cat <<'{delim}'")
        script.append(cfg_text)
        script.append(delim)
        if auth:
            script.append("printf 'header = \"Authorization: Bearer %s\"\\n' \"$hg_tok\"")
        script.append("} | curl -K -")
        return "\n".join(script) + "\n"

    def _run(self, script: str, timeout: float) -> subprocess.CompletedProcess:
        try:
            return self.runner(
                self.ssh_argv(), input=script.encode("utf-8"),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise ApiError("ssh binary not found on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise ApiError(f"ssh to {self.cfg.ssh} timed out after {timeout:.0f}s") from exc

    def _split(self, proc: subprocess.CompletedProcess) -> tuple[bytes, int | None, str, str]:
        """Split curl output into (body, http_code|None, content_type, stderr)."""
        out = proc.stdout or b""
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        if proc.returncode == 97 or NOTOKEN_MARK in err:
            raise ApiError(
                f"no API token on {self.cfg.ssh}: {self.cfg.ssh_token_file} is missing or not readable "
                "by the ssh user (create it with `sudo install -m 0640 -o root -g <user> ...`), "
                "or set HG_TOKEN locally"
            )
        marker = ("\n" + META_MARK + " ").encode()
        idx = out.rfind(marker)
        if idx < 0:
            if proc.returncode == 255:
                raise ApiError(f"ssh to {self.cfg.ssh} failed: {err or 'exit 255'}")
            return out, None, "", err
        meta = out[idx + len(marker):].decode("utf-8", errors="replace").strip()
        code_s, _, ctype = meta.partition(" ")
        try:
            code: int | None = int(code_s)
        except ValueError:
            code = None
        return out[:idx], code, ctype.strip(), err

    def request(self, method: str, target: str, body: Any = None, auth: bool = True,
                accept: str = "application/json") -> HttpResult:
        script = self.build_script(method, target, body, auth, accept, self.cfg.timeout)
        proc = self._run(script, self.cfg.timeout + 20)
        payload, code, ctype, err = self._split(proc)
        if not code:  # curl could not connect (http_code 000) or produced nothing
            raise ApiError(
                f"curl on {self.cfg.ssh} could not reach {self.cfg.url}: "
                f"{err or 'exit ' + str(proc.returncode)}"
            )
        return HttpResult(code, ctype, payload)

    def stream(self, target: str, seconds: float, max_events: int) -> tuple[HttpResult | None, list[SseEvent], bool]:
        script = self.build_script("GET", target, None, True, "text/event-stream", seconds + 2, no_buffer=True)
        proc = self._run(script, seconds + 30)
        payload, code, ctype, err = self._split(proc)
        if code and code != 200:
            return HttpResult(code, ctype, payload), [], False
        if not code and not payload:
            raise ApiError(f"stream via {self.cfg.ssh} failed: {err or 'exit ' + str(proc.returncode)}")
        # curl exits 28 (max-time reached) in the normal case; that is expected.
        parser = SseParser()
        events = parser.feed(payload[:STREAM_MAX_BYTES].decode("utf-8", errors="replace"))
        events.extend(parser.finish())
        truncated = len(events) > max_events or len(payload) > STREAM_MAX_BYTES
        return HttpResult(200, ctype, b""), events[:max_events], truncated


# --------------------------------------------------------------------------- #
# Tool definitions
# --------------------------------------------------------------------------- #

TIME_DESC = ("RFC 3339 timestamp (2026-10-09T05:00:00Z) or relative age like 90s, 15m, 6h, 7d "
             "(meaning now minus that)")

LOG_FIELDS_SCHEMA = {
    "type": "object",
    "description": (
        "Parsed-field filters. Keys: status (exact, or 4xx/5xx), method, path, user_agent, user, port, "
        "proto, event_type (e.g. AuthFailure, Http4xx). A value starting with ^, containing | or ending "
        "with $ is a regex; otherwise exact match."
    ),
    "additionalProperties": {"type": "string"},
}

GROUP_BY = ["ip", "ip24", "ip48", "path", "status", "method", "user_agent", "user", "port", "proto",
            "event_type", "hour", "minute", "day"]
PLUGIN_KINDS = ["Source", "Detector", "Enforcer", "Notifier", "SiemSink", "Cti", "ScoringEngine", "UiServer"]
JOURNAL_PRIORITIES = ["0", "1", "2", "3", "4", "5", "6", "7",
                      "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
STREAM_TYPES = ["signal", "ban_added", "ban_removed"]


def _obj(props: dict, required: list[str] | None = None) -> dict:
    s: dict = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        s["required"] = required
    return s


def _str(desc: str, **kw) -> dict:
    return {"type": "string", "description": desc, **kw}


def _int(desc: str, **kw) -> dict:
    return {"type": "integer", "description": desc, **kw}


def _bool(desc: str) -> dict:
    return {"type": "boolean", "description": desc}


@dataclass
class Tool:
    name: str
    title: str
    description: str
    schema: dict
    handler: Callable[["Server", dict], Any]
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True

    def definition(self, label: str) -> dict:
        desc = self.description
        if label:
            desc = f"[HiveGuard node: {label}] {desc}"
        return {
            "name": self.name,
            "title": self.title,
            "description": desc,
            "inputSchema": self.schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": False,
            },
        }


class ToolError(Exception):
    """Raised by handlers for a user-facing tool failure (isError result)."""


@dataclass
class TextResult:
    """Handler return value that should be shown as plain text (not JSON)."""
    text: str
    structured: dict | None = None


def _q(args: dict, keys: list[str]) -> dict:
    out = {}
    for k in keys:
        v = args.get(k)
        if v is None:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        elif isinstance(v, list):
            v = ",".join(str(x) for x in v)
        out[k] = str(v)
    return out


def _body(args: dict, keys: list[str]) -> dict:
    return {k: args[k] for k in keys if k in args and args[k] is not None}


def normalize_cidr(subject: str) -> str:
    s = str(subject).strip()
    try:
        if "/" in s:
            return str(ipaddress.ip_network(s, strict=False))
        addr = ipaddress.ip_address(s)
        return f"{addr}/{addr.max_prefixlen}"
    except ValueError as exc:
        raise ToolError(f"not a valid IP address or CIDR: {subject!r}") from exc


def _path_seg(cidr: str) -> str:
    return urllib.parse.quote(cidr, safe="")


# --- handlers ---------------------------------------------------------------


def h_overview(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/agent/overview")


def h_health(srv: "Server", a: dict) -> Any:
    out: dict = {"transport": srv.transport.describe(), "health": srv.api("GET", "/api/health", auth=False)}
    if srv.token_possibly_available():
        try:
            out["info"] = srv.api("GET", "/api/info")
        except ApiError as exc:
            out["info_error"] = str(exc)
    else:
        out["info_error"] = "no token configured; /api/info skipped"
    return out


def h_bans(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/agent/bans", query=_q(a, [
        "source", "detector", "since", "until", "subnet_only", "permanent_only", "q", "sort", "order",
        "limit", "offset"]))


def h_threats(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/agent/threats", query=_q(a, [
        "since", "until", "detector", "ip", "min_severity", "limit", "offset"]))


def h_log_sources(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/agent/logs/sources")


def h_log_query(srv: "Server", a: dict) -> Any:
    return srv.api("POST", "/api/agent/logs/query",
                   body=_body(a, ["source", "since", "until", "grep", "ip", "fields", "limit", "parse"]))


def h_log_stats(srv: "Server", a: dict) -> Any:
    return srv.api("POST", "/api/agent/logs/stats",
                   body=_body(a, ["source", "since", "until", "filter", "group_by", "top", "buckets"]))


def h_ip(srv: "Server", a: dict) -> Any:
    ip = str(a["ip"]).strip()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise ToolError(f"not a valid IP address: {a['ip']!r} (use hg_log_stats group_by ip24 for subnets)") from exc
    body = {"ip": ip}
    if a.get("since") is not None:
        body["since"] = a["since"]
    return srv.api("POST", "/api/agent/ip", body=body)


def h_journal(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/agent/journal", query=_q(a, ["unit", "since", "until", "priority", "grep", "limit"]))


def h_detectors(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/agent/detectors")


def h_catalog(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/agent/catalog", query=_q(a, ["kind"]))


def h_plugins(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/plugins")


def h_whitelist(srv: "Server", a: dict) -> Any:
    return srv.api("GET", "/api/whitelist")


def h_config_get(srv: "Server", a: dict) -> Any:
    res = srv.api("GET", "/api/config")
    if isinstance(res, dict) and isinstance(res.get("content"), str):
        return TextResult(res["content"], res)
    return res


def h_config_validate(srv: "Server", a: dict) -> Any:
    return srv.api("POST", "/api/agent/config/validate", body={"content": a["content"]})


_METRIC_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+(\S+)(?:\s+\S+)?$")


def parse_metrics(text: str, pattern: str | None = None) -> dict:
    rx = None
    if pattern:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            raise ToolError(f"invalid filter regex: {exc}") from exc
    lines: list[str] = []
    values: dict[str, float] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if rx and not rx.search(line):
            continue
        lines.append(line)
        m = _METRIC_RE.match(line)
        if not m:
            continue
        name, labels, val = m.group(1), m.group(2) or "", m.group(3)
        if not name.startswith("hiveguard_") or name.endswith("_created"):
            continue
        try:
            num = float(val)
        except ValueError:
            continue
        values[name + labels] = int(num) if num.is_integer() and abs(num) < 2 ** 53 else num
    return {"filter": pattern, "matched_lines": len(lines), "hiveguard": values, "lines": lines}


def h_metrics(srv: "Server", a: dict) -> Any:
    res = srv.transport.request("GET", "/metrics", auth=False, accept="text/plain, application/openmetrics-text")
    if res.status >= 400:
        raise srv.error_from(res, "GET", "/metrics")
    return parse_metrics(res.text(), a.get("filter"))


def h_stream_sample(srv: "Server", a: dict) -> Any:
    seconds = int(a.get("seconds") or 10)
    seconds = max(1, min(STREAM_MAX_SECONDS, seconds))
    max_events = int(a.get("max_events") or 1000)
    max_events = max(1, min(STREAM_MAX_EVENTS, max_events))
    target = "/api/agent/stream"
    q = _q(a, ["types"])
    if q:
        target += "?" + urllib.parse.urlencode(q)
    started = time.monotonic()
    res, events, truncated = srv.transport.stream(target, seconds, max_events)
    if res is not None and res.status >= 400:
        raise srv.error_from(res, "GET", "/api/agent/stream")
    counts: dict[str, int] = {}
    for ev in events:
        counts[ev.event] = counts.get(ev.event, 0) + 1
    return {
        "seconds": seconds,
        "elapsed_secs": round(time.monotonic() - started, 2),
        "count": len(events),
        "by_type": counts,
        "truncated": truncated,
        "events": [e.as_dict() for e in events],
    }


def h_ban(srv: "Server", a: dict) -> Any:
    subject = normalize_cidr(a["subject"])
    secs = int(a["duration_secs"])
    if secs < 1:
        raise ToolError("duration_secs must be >= 1")
    reason = str(a["reason"]).strip()
    if not reason:
        raise ToolError("reason must not be empty")
    res = srv.api("POST", "/api/bans",
                  body={"subject": subject, "duration": {"secs": secs, "nanos": 0}, "reason": reason})
    return {"subject": subject, "duration_secs": secs, "response": res}


def h_unban(srv: "Server", a: dict) -> Any:
    subject = normalize_cidr(a["subject"])
    res = srv.api("DELETE", f"/api/bans/{_path_seg(subject)}")
    return {"subject": subject, "status": "removed (DELETE is idempotent; 204 even if it was not banned)",
            "response": res}


def h_whitelist_add(srv: "Server", a: dict) -> Any:
    cidr = normalize_cidr(a["cidr"])
    return srv.api("POST", "/api/whitelist", body={"cidr": cidr})


def h_whitelist_remove(srv: "Server", a: dict) -> Any:
    cidr = normalize_cidr(a["cidr"])
    return srv.api("DELETE", f"/api/whitelist/{_path_seg(cidr)}")


def h_config_put(srv: "Server", a: dict) -> Any:
    return srv.api("PUT", "/api/config", body={"content": a["content"]})


LIMIT_DESC = "Max items to return"
OFFSET_DESC = "Items to skip (pagination)"

TOOLS: list[Tool] = [
    Tool(
        "hg_overview", "Situation report",
        "One-call situation report of this HiveGuard node: node/version/uptime, ban totals (permanent, subnets, "
        "expiring, created in 1h/24h, by source and detector), recent threat signals with top IPs, Prometheus "
        "counters (events per source, detection signals, bans created/expired, peers, memory), plugin health, "
        "unhealthy sources and the names of log sources usable with hg_log_query/hg_log_stats. Cheap (no log "
        "scanning). Call this FIRST in any investigation or daily review.",
        _obj({}), h_overview),
    Tool(
        "hg_health", "Daemon health",
        "Liveness check: GET /api/health (works without a token) plus /api/info (node name, version, uptime, "
        "total bans) when a token is available. Use to verify connectivity/auth before other tools or when "
        "other tools fail.",
        _obj({}), h_health),
    Tool(
        "hg_bans", "List/filter bans",
        "Filter, sort and count the active ban set (GET /api/agent/bans). Returns total, matched, per-source and "
        "per-detector counts and the requested page of items {subject, severity, reason, created_at, "
        "expires_at|null, source}. Use to answer 'what did HiveGuard block', 'which detector bans the most', "
        "'is subnet X banned', 'what was banned since 6h'.",
        _obj({
            "source": _str("Ban origin", enum=["detector", "peer", "admin"]),
            "detector": _str("Core detector name, e.g. ssh_bruteforce, path_probe, http_flood"),
            "since": _str("created_at >= this. " + TIME_DESC),
            "until": _str("created_at <= this. " + TIME_DESC),
            "subnet_only": _bool("Only subnet bans (prefix shorter than /32 or /128)"),
            "permanent_only": _bool("Only bans without expiry"),
            "q": _str("Substring of subject or reason"),
            "sort": _str("Sort key (default created_at)", enum=["created_at", "expires_at", "severity", "subject"]),
            "order": _str("Sort order (default desc)", enum=["desc", "asc"]),
            "limit": _int(LIMIT_DESC + " (default 100, max = agent.max_results, 5000 by default)",
                          minimum=1, maximum=5000),
            "offset": _int(OFFSET_DESC, minimum=0),
        }), h_bans),
    Tool(
        "hg_threats", "Recent detection signals",
        "Filter the in-memory ring buffer of the 500 newest detection signals (GET /api/agent/threats), whether "
        "or not they produced a ban. Returns matched items, counts by detector and top IPs with severity and "
        "first/last seen. Use to see what detectors are currently firing and on whom. Default window 1h.",
        _obj({
            "since": _str("Default 1h. " + TIME_DESC),
            "until": _str(TIME_DESC),
            "detector": _str("Core detector name, e.g. path_probe"),
            "ip": _str("Exact IP or CIDR"),
            "min_severity": _int("Minimum severity (0-255)", minimum=0, maximum=255),
            "limit": _int(LIMIT_DESC + " (default 200)", minimum=1, maximum=5000),
            "offset": _int(OFFSET_DESC, minimum=0),
        }), h_threats),
    Tool(
        "hg_log_sources", "Readable log sources",
        "List the log sources the daemon can read for analysis (auto-discovered from source.* plugins plus "
        "agent.log_sources): name, kind (file|journal), format, path, existence, size, mtime, whether a rotated "
        "file is available. Call before hg_log_query/hg_log_stats to learn valid `source` names.",
        _obj({}), h_log_sources),
    Tool(
        "hg_log_query", "Search raw logs",
        "Return the newest N matching lines (chronological) of ONE log source that the daemon tails "
        "(POST /api/agent/logs/query), optionally parsed into ts/ip/event_type/fields. Use to look at concrete "
        "requests/attempts: e.g. POSTs to /wp-login.php, sshd failures for user root, ufw blocks on port 23. "
        "Check `truncated` and window.first_line_ts: the backward scan is capped by agent.max_scan_bytes. "
        "For counts/top-N use hg_log_stats instead.",
        _obj({
            "source": _str("Source name from hg_log_sources / hg_overview.log_sources, e.g. nginx, ssh, firewall, "
                           "journal:hiveguard"),
            "since": _str("Default 1h. " + TIME_DESC),
            "until": _str(TIME_DESC + " (default now)"),
            "grep": _str("Regex (Rust regex syntax, no backtracking) matched against the raw line"),
            "ip": _str("Exact IP or CIDR matched against the parsed source IP"),
            "fields": LOG_FIELDS_SCHEMA,
            "limit": _int(LIMIT_DESC + " (newest N matching lines)", minimum=1, maximum=5000),
            "parse": _bool("false returns raw lines only (faster); default true"),
        }, ["source"]), h_log_query),
    Tool(
        "hg_log_stats", "Aggregate logs",
        "Aggregate one log source over a window (POST /api/agent/logs/stats): top-N groups by ip / ip24 / path / "
        "status / port / user / ... with counts, pct and first/last seen, plus an optional time series. "
        "Grouping by ip/ip24/ip48 adds a per-IP behaviour profile (4xx/5xx counts, distinct paths and UAs, "
        "sample path/UA, banned, whitelisted) - the best tool to find attackers HiveGuard has NOT banned. "
        "Typical: nginx group_by ip, then path with fields.status=4xx; firewall group_by port; ssh group_by user.",
        _obj({
            "source": _str("Source name from hg_log_sources"),
            "since": _str("Default 1h. " + TIME_DESC),
            "until": _str(TIME_DESC + " (default now)"),
            "filter": _obj({
                "ip": _str("Exact IP or CIDR"),
                "grep": _str("Regex on the raw line"),
                "fields": LOG_FIELDS_SCHEMA,
            }),
            "group_by": _str("Grouping key", enum=GROUP_BY),
            "top": _int("Number of groups to return (default 25)", minimum=1, maximum=5000),
            "buckets": _str("Add a time series of matched counts with this bucket size",
                            enum=["5m", "15m", "1h", "1d"]),
        }, ["source", "group_by"]), h_log_stats),
    Tool(
        "hg_ip", "Investigate one IP",
        "Everything the daemon knows about one address across all sources (POST /api/agent/ip): current ban "
        "record, whitelist status, threat signals by detector, per-source log activity (counts, statuses, top "
        "paths, user agents, firewall ports). Use on the top suspects from hg_log_stats/hg_threats before "
        "recommending a ban or a config change.",
        _obj({
            "ip": _str("IPv4 or IPv6 address (not a CIDR)"),
            "since": _str("Log window, default 24h. " + TIME_DESC),
        }, ["ip"]), h_ip),
    Tool(
        "hg_journal", "Daemon journal",
        "Read the systemd journal of the hiveguard unit (or another allowed unit) via journalctl "
        "(GET /api/agent/journal). Use priority=warning to see the daemon's own warnings/errors (source "
        "restarts, nft failures, config problems, gossip errors). 503 when journalctl is not readable.",
        _obj({
            "unit": _str("Unit name (default hiveguard; must be in agent.journal_units or a source.journald unit)"),
            "since": _str("Default 1h. " + TIME_DESC),
            "until": _str(TIME_DESC),
            "priority": _str("Max priority shown: 0-7 or emerg|alert|crit|err|warning|notice|info|debug",
                             enum=JOURNAL_PRIORITIES),
            "grep": _str("Regex on MESSAGE"),
            "limit": _int(LIMIT_DESC + " (default 200, newest)", minimum=1, maximum=5000),
        }), h_journal),
    Tool(
        "hg_detectors", "Detector configuration",
        "Loaded detector plugins with their EFFECTIVE configuration (exactly the plugins: entry), JSON schema "
        "with defaults, and signal/ban counters, plus the scoring engine config (e.g. ban_severity_threshold). "
        "Use to judge whether thresholds are too loose for the attacks seen in the logs.",
        _obj({}), h_detectors),
    Tool(
        "hg_catalog", "Plugin catalogue",
        "Every plugin LINKED into this binary, enabled or not, with description, docs_url, enabled flag, "
        "instance count and config keys (GET /api/agent/catalog). Use to recommend modules that would help "
        "against an observed attack but are currently disabled (enabled=false).",
        _obj({
            "kind": _str("Filter by plugin kind (case-insensitive)", enum=PLUGIN_KINDS),
        }), h_catalog),
    Tool(
        "hg_plugins", "Plugin health",
        "Running plugin instances with kind, health and version (GET /api/plugins). Use to spot failed or "
        "degraded sources/enforcers.",
        _obj({}), h_plugins),
    Tool(
        "hg_whitelist", "Whitelist entries",
        "Current whitelist (CIDRs never banned) (GET /api/whitelist). Check before proposing a ban.",
        _obj({}), h_whitelist),
    Tool(
        "hg_config_get", "Read config.yaml",
        "Return the daemon's config.yaml text (GET /api/config). Use as the base for hardening proposals: edit "
        "the text keeping comments/indentation, then validate with hg_config_validate. Note: may contain "
        "secrets references - do not echo it wholesale to third parties.",
        _obj({}), h_config_get),
    Tool(
        "hg_config_validate", "Validate config (dry-run)",
        "Dry-run validation of a full config.yaml text (POST /api/agent/config/validate): YAML parse, config "
        "validation, plugin resolution and schema checks. Never writes. Returns {valid, errors, warnings, "
        "plugins}. ALWAYS validate a proposed config change before presenting it to the operator.",
        _obj({"content": _str("Complete config.yaml text")}, ["content"]), h_config_validate),
    Tool(
        "hg_metrics", "Prometheus metrics",
        "Fetch /metrics (no token needed). Returns matching sample lines and a parsed map "
        "{'metric{labels}': value} of hiveguard_* series. Use for throughput (events per source), latency, "
        "memory, enforcement counters. Optional regex filter on lines, e.g. 'events_processed|bans_'.",
        _obj({"filter": _str("Python regex applied to metric sample lines")}), h_metrics),
    Tool(
        "hg_stream_sample", "Sample live events",
        "Listen to the live incremental event stream (SSE GET /api/agent/stream) for N seconds and return the "
        "collected events: signal (every detection), ban_added, ban_removed. Use to watch an attack develop in "
        "real time or to confirm that detectors fire right now. Blocks for `seconds`.",
        _obj({
            "seconds": _int("How long to listen (default 10, max 120)", minimum=1, maximum=STREAM_MAX_SECONDS),
            "types": {"type": "array", "description": "Event types to receive (default all)",
                      "items": {"type": "string", "enum": STREAM_TYPES}, "uniqueItems": True},
            "max_events": _int("Stop after this many events (default 1000)", minimum=1, maximum=STREAM_MAX_EVENTS),
        }), h_stream_sample),
    # ---- mutating ----------------------------------------------------------
    Tool(
        "hg_ban", "Ban an IP/subnet",
        "WRITE: ban an IP or CIDR on this node (POST /api/bans). Bare IPs become /32 or /128. Applies to this "
        "node; do not assume it replicates to cluster peers. Only with explicit operator approval. Requires "
        "HG_MCP_ALLOW_WRITE=1.",
        _obj({
            "subject": _str("IP or CIDR, e.g. 203.0.113.5 or 203.0.113.0/24"),
            "duration_secs": _int("Ban duration in seconds (e.g. 3600, 86400)", minimum=1),
            "reason": _str("Human-readable reason recorded with the ban"),
        }, ["subject", "duration_secs", "reason"]), h_ban,
        read_only=False, destructive=False, idempotent=True),
    Tool(
        "hg_unban", "Remove a ban",
        "WRITE: remove a ban on this node (DELETE /api/bans/{cidr}). Bare IPs become /32 or /128; the subject "
        "must match the banned prefix exactly (check hg_bans). Local to this node. Requires HG_MCP_ALLOW_WRITE=1.",
        _obj({"subject": _str("IP or CIDR exactly as banned")}, ["subject"]), h_unban,
        read_only=False, destructive=True, idempotent=True),
    Tool(
        "hg_whitelist_add", "Whitelist a CIDR",
        "WRITE: add a CIDR to the whitelist (POST /api/whitelist). Persists across restarts (WAL) but is not "
        "written to config.yaml; local to this node. Requires HG_MCP_ALLOW_WRITE=1.",
        _obj({"cidr": _str("IP or CIDR")}, ["cidr"]), h_whitelist_add,
        read_only=False, destructive=False, idempotent=True),
    Tool(
        "hg_whitelist_remove", "Remove whitelist entry",
        "WRITE: remove a CIDR from the whitelist (DELETE /api/whitelist/{cidr}). Requires HG_MCP_ALLOW_WRITE=1.",
        _obj({"cidr": _str("CIDR exactly as listed by hg_whitelist")}, ["cidr"]), h_whitelist_remove,
        read_only=False, destructive=True, idempotent=True),
    Tool(
        "hg_config_put", "Replace config.yaml",
        "WRITE: replace config.yaml (PUT /api/config). The daemon validates and writes atomically, but changes "
        "take effect only after a daemon RESTART; returns 503 when /etc is read-only (systemd ProtectSystem) - "
        "then the operator must apply it by hand. Validate with hg_config_validate first and never apply "
        "without explicit operator approval. Requires HG_MCP_ALLOW_WRITE=1.",
        _obj({"content": _str("Complete config.yaml text")}, ["content"]), h_config_put,
        read_only=False, destructive=True, idempotent=True),
]

TOOLS_BY_NAME = {t.name: t for t in TOOLS}


# --------------------------------------------------------------------------- #
# Argument validation (small JSON-Schema subset)
# --------------------------------------------------------------------------- #


def validate_args(schema: dict, args: Any, path: str = "arguments") -> Any:
    """Validate/coerce `args` against the subset of JSON Schema used above."""
    typ = schema.get("type")
    if typ == "object":
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise ToolError(f"{path} must be an object")
        props = schema.get("properties")
        out = {}
        for req in schema.get("required", []):
            if args.get(req) is None:
                raise ToolError(f"missing required argument {path}.{req}" if path != "arguments"
                                else f"missing required argument '{req}'")
        for k, v in args.items():
            if props is not None and k in props:
                if v is None:
                    continue
                out[k] = validate_args(props[k], v, f"{path}.{k}")
            elif props is not None and schema.get("additionalProperties") is False:
                raise ToolError(f"unknown argument {path}.{k}; allowed: {', '.join(sorted(props))}")
            else:
                extra = schema.get("additionalProperties")
                out[k] = validate_args(extra, v, f"{path}.{k}") if isinstance(extra, dict) else v
        return out
    if typ == "string":
        if isinstance(args, bool) or not isinstance(args, (str, int, float)):
            raise ToolError(f"{path} must be a string")
        s = args if isinstance(args, str) else str(args)
        enum = schema.get("enum")
        if enum:
            for e in enum:
                if s == e or s.lower() == str(e).lower():
                    return e
            raise ToolError(f"{path} must be one of {enum}, got {s!r}")
        return s
    if typ == "integer":
        if isinstance(args, bool):
            raise ToolError(f"{path} must be an integer")
        if isinstance(args, float) and args.is_integer():
            args = int(args)
        if isinstance(args, str) and re.fullmatch(r"-?\d+", args.strip()):
            args = int(args.strip())
        if not isinstance(args, int):
            raise ToolError(f"{path} must be an integer")
        if "minimum" in schema and args < schema["minimum"]:
            raise ToolError(f"{path} must be >= {schema['minimum']}")
        if "maximum" in schema and args > schema["maximum"]:
            raise ToolError(f"{path} must be <= {schema['maximum']}")
        return args
    if typ == "boolean":
        if isinstance(args, str) and args.lower() in ("true", "false", "1", "0"):
            return args.lower() in ("true", "1")
        if not isinstance(args, bool):
            raise ToolError(f"{path} must be a boolean")
        return args
    if typ == "array":
        if isinstance(args, str):
            args = [x.strip() for x in args.split(",") if x.strip()]
        if not isinstance(args, list):
            raise ToolError(f"{path} must be an array")
        items = schema.get("items") or {}
        vals = [validate_args(items, v, f"{path}[{i}]") for i, v in enumerate(args)]
        if schema.get("uniqueItems"):
            vals = list(dict.fromkeys(vals))
        return vals
    return args


# --------------------------------------------------------------------------- #
# Prompts / resources
# --------------------------------------------------------------------------- #

PROMPTS = [
    {
        "name": "daily_security_review",
        "title": "Daily HiveGuard security review",
        "description": "Morning review of the last N hours on this HiveGuard node: attacks, whether they were "
                       "blocked, config tightening proposals and recommended disabled modules.",
        "arguments": [
            {"name": "hours", "description": "Review window in hours (default 24)", "required": False},
            {"name": "node", "description": "Node label to put in the report title (optional)", "required": False},
        ],
    }
]


def daily_review_text(hours: int, node: str) -> str:
    w = f"{hours}h"
    who = node or "this node"
    return f"""Run the daily HiveGuard security review for {who}, window = last {hours} hours (use since="{w}").
Use only the hg_* tools of this server; they are read-only unless stated otherwise.

1. hg_overview - note version/uptime, ban totals, bans created in 24h, threat counters,
   unhealthy_sources, plugin health, and the list of log_sources.
2. hg_journal priority="warning" since="{w}" - daemon warnings/errors (source restarts, nft
   failures, gossip/peer errors, config warnings). Summarise recurring messages.
3. hg_threats since="{w}" and hg_bans since="{w}" - what detectors fired, top IPs, which bans
   resulted (by_detector / by_source, subnet bans).
4. hg_log_stats for every file source from step 1 (since="{w}"):
   a. group_by="ip" (top 25) - look at extras: banned=false with many 4xx, many distinct paths,
      scripted user agents => attacker NOT blocked.
   b. nginx-like sources: group_by="path" with filter.fields.status="4xx" - probing patterns
      (wp-login, .env, .git, phpmyadmin, xmlrpc, cgi-bin ...).
   c. firewall: group_by="port" - scanned ports; ssh: group_by="user" - brute-forced users.
   Add buckets="1h" when you need to see when a wave started.
5. hg_ip on the top 5-10 suspects (prefer unbanned ones with high counts); confirm with a short
   hg_log_query (limit 20) if the pattern is unclear.
6. hg_detectors and hg_catalog - compare what was seen with detector thresholds and with modules
   that are linked but disabled (catalog enabled=false).

Write the report (markdown) with these sections:
- Summary: 3-5 bullets, overall risk level.
- Attack attempts found: table (source IP/subnet, type, volume, time span, evidence).
- Blocked by HiveGuard?: for each attack, banned (which detector, when) / partially / NOT blocked,
  with the reason (threshold too high, no detector covers it, whitelisted, source not tailed).
- Daemon health: journal warnings, unhealthy sources, anything that blinds detection.
- Config tightening proposals: concrete YAML diffs. Start from hg_config_get, edit the text, and
  run hg_config_validate on the full result; report valid/errors/warnings. NEVER apply changes
  (no hg_config_put, hg_ban, hg_unban, whitelist changes) - the operator decides.
- Recommended modules: disabled-but-linked plugins from hg_catalog that address observed attacks,
  with a minimal config snippet (validated the same way).
- Open questions for the operator.

Rules: cite numbers from tool output, do not invent data; if a tool fails (404/503), say so and
continue; keep each tool result focused (use limit/top) to save context.
"""


def find_agent_doc(cfg: Config, script_path: str | None = None) -> str | None:
    candidates: list[str] = []
    if cfg.docs:
        p = os.path.expanduser(cfg.docs)
        candidates.append(os.path.join(p, "AGENT_API.md") if os.path.isdir(p) else p)
    here = os.path.dirname(os.path.abspath(script_path or __file__))
    candidates += [
        os.path.join(here, "AGENT_API.md"),
        os.path.join(here, "docs", "AGENT_API.md"),
        os.path.normpath(os.path.join(here, "..", "..", "docs", "AGENT_API.md")),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _compact(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


class Server:
    def __init__(self, cfg: Config | None = None, transport: Any = None):
        self.cfg = cfg or Config.from_env()
        if transport is None:
            transport = SshTransport(self.cfg) if self.cfg.ssh else HttpTransport(self.cfg)
        self.transport = transport
        self.initialized = False
        self.protocol_version = LATEST_PROTOCOL
        self.doc_path = find_agent_doc(self.cfg)

    # ---- API helpers -------------------------------------------------------

    def token_possibly_available(self) -> bool:
        if self.cfg.ssh:
            return True
        tok, _ = self.cfg.local_token()
        return bool(tok)

    def error_from(self, res: HttpResult, method: str, path: str) -> ApiError:
        payload = res.parsed()
        msg = None
        if isinstance(payload, dict):
            msg = payload.get("error") or payload.get("message")
        if msg is None and isinstance(payload, str) and payload.strip():
            msg = payload.strip()[:500]
        hint = ""
        if res.status == 401:
            hint = " (token rejected: check HG_TOKEN / HG_TOKEN_FILE / remote token file)"
        elif res.status == 404 and path.startswith("/api/agent/") and not msg:
            hint = " (endpoint missing: this daemon may predate the Agent API)"
        elif res.status == 503:
            hint = " (subsystem not available on this daemon)"
        return ApiError(f"HiveGuard API error {res.status} on {method} {path}: {msg or 'no details'}{hint}",
                        res.status, payload)

    def api(self, method: str, path: str, query: dict | None = None, body: Any = None,
            auth: bool = True) -> Any:
        target = path
        if query:
            target += "?" + urllib.parse.urlencode(query)
        log.debug("-> %s %s", method, target)
        res = self.transport.request(method, target, body=body, auth=auth)
        log.debug("<- %s %s %s (%d bytes)", res.status, method, path, len(res.body))
        if res.status >= 400:
            raise self.error_from(res, method, path)
        return res.parsed()

    # ---- JSON-RPC ----------------------------------------------------------

    def handle_line(self, line: str | bytes) -> str | None:
        """Process one input line; return the response line (no newline) or None."""
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError:
                return _compact(self._error(None, PARSE_ERROR, "Parse error: invalid UTF-8"))
        if not line.strip():
            return None
        try:
            msg = json.loads(line)
        except ValueError as exc:
            return _compact(self._error(None, PARSE_ERROR, f"Parse error: {exc}"))
        if isinstance(msg, list):
            if not msg:
                return _compact(self._error(None, INVALID_REQUEST, "Invalid Request: empty batch"))
            out = [r for r in (self.dispatch(m) for m in msg) if r is not None]
            return _compact(out) if out else None
        resp = self.dispatch(msg)
        return None if resp is None else _compact(resp)

    @staticmethod
    def _error(rid: Any, code: int, message: str, data: Any = None) -> dict:
        err: dict = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": rid, "error": err}

    def dispatch(self, msg: Any) -> dict | None:
        if not isinstance(msg, dict):
            return self._error(None, INVALID_REQUEST, "Invalid Request: expected an object")
        is_notification = "id" not in msg
        rid = msg.get("id")
        method = msg.get("method")
        if not isinstance(method, str):
            if "result" in msg or "error" in msg:
                return None  # a response to something we never sent; ignore
            return None if is_notification else self._error(rid, INVALID_REQUEST, "Invalid Request: no method")
        params = msg.get("params")
        if params is None:
            params = {}
        try:
            if not isinstance(params, dict):
                raise RpcError(INVALID_PARAMS, "params must be an object")
            result = self._route(method, params, is_notification)
        except RpcError as exc:
            return None if is_notification else self._error(rid, exc.code, exc.message, exc.data)
        except Exception as exc:  # never crash the server
            log.exception("internal error in %s", method)
            return None if is_notification else self._error(rid, INTERNAL_ERROR, f"Internal error: {exc}")
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _route(self, method: str, params: dict, notification: bool) -> Any:
        if method.startswith("notifications/"):
            if method == "notifications/initialized":
                self.initialized = True
            return None
        handler = {
            "initialize": self.m_initialize,
            "ping": lambda p: {},
            "tools/list": self.m_tools_list,
            "tools/call": self.m_tools_call,
            "prompts/list": self.m_prompts_list,
            "prompts/get": self.m_prompts_get,
            "resources/list": self.m_resources_list,
            "resources/read": self.m_resources_read,
            "resources/templates/list": lambda p: {"resourceTemplates": []},
            "logging/setLevel": self.m_set_level,
        }.get(method)
        if handler is None:
            raise RpcError(METHOD_NOT_FOUND, f"Method not found: {method}")
        return handler(params)

    # ---- methods -----------------------------------------------------------

    def instructions(self) -> str:
        node = self.cfg.node_label or "(unlabelled)"
        writes = "ENABLED" if self.cfg.allow_write else "disabled (read-only)"
        return (
            f"HiveGuard IDS/IP-banning daemon, node {node}, via {self.transport.describe()}. "
            f"Mutating tools (hg_ban, hg_unban, hg_whitelist_*, hg_config_put): {writes}. "
            "Start with hg_overview; use hg_log_stats to find attackers, hg_ip to profile one address, "
            "hg_detectors/hg_catalog for configuration and disabled modules, hg_config_validate before "
            "proposing any config change. Time params accept RFC 3339 or relative ages (15m, 6h, 7d). "
            "The prompt daily_security_review contains the full morning-review playbook."
        )

    def m_initialize(self, p: dict) -> dict:
        requested = p.get("protocolVersion")
        self.protocol_version = requested if requested in SUPPORTED_PROTOCOLS else LATEST_PROTOCOL
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {}, "prompts": {}, "resources": {}, "logging": {}},
            "serverInfo": {"name": SERVER_NAME, "title": "HiveGuard" + (f" ({self.cfg.node_label})"
                                                                         if self.cfg.node_label else ""),
                           "version": SERVER_VERSION},
            "instructions": self.instructions(),
        }

    def m_set_level(self, p: dict) -> dict:
        lvl = str(p.get("level", "warning")).lower()
        mapping = {"debug": logging.DEBUG, "info": logging.INFO, "notice": logging.INFO,
                   "warning": logging.WARNING, "error": logging.ERROR}
        log.setLevel(mapping.get(lvl, logging.WARNING))
        return {}

    def m_tools_list(self, p: dict) -> dict:
        return {"tools": [t.definition(self.cfg.node_label) for t in TOOLS]}

    def m_tools_call(self, p: dict) -> dict:
        name = p.get("name")
        tool = TOOLS_BY_NAME.get(name) if isinstance(name, str) else None
        if tool is None:
            raise RpcError(INVALID_PARAMS, f"Unknown tool: {name}")
        try:
            if not tool.read_only and not self.cfg.allow_write:
                raise ToolError(f"{tool.name}: writes disabled; start with HG_MCP_ALLOW_WRITE=1")
            args = validate_args(tool.schema, p.get("arguments"))
            result = tool.handler(self, args)
        except (ToolError, ApiError) as exc:
            out: dict = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
            if isinstance(exc, ApiError) and isinstance(exc.payload, dict):
                out["structuredContent"] = {"status": exc.status, **exc.payload}
            return out
        except Exception as exc:  # defensive: tool bugs must not kill the server
            log.exception("tool %s failed", tool.name)
            return {"content": [{"type": "text", "text": f"{tool.name} failed: {type(exc).__name__}: {exc}"}],
                    "isError": True}
        return self._tool_result(result)

    @staticmethod
    def _tool_result(result: Any) -> dict:
        if isinstance(result, TextResult):
            out: dict = {"content": [{"type": "text", "text": result.text}], "isError": False}
            if result.structured is not None:
                out["structuredContent"] = result.structured
            return out
        if isinstance(result, str):
            return {"content": [{"type": "text", "text": result}], "isError": False}
        if result is None:
            result = {"ok": True}
        out = {"content": [{"type": "text", "text": _compact(result)}], "isError": False}
        out["structuredContent"] = result if isinstance(result, dict) else {"items": result}
        return out

    def m_prompts_list(self, p: dict) -> dict:
        return {"prompts": PROMPTS}

    def m_prompts_get(self, p: dict) -> dict:
        name = p.get("name")
        if name != "daily_security_review":
            raise RpcError(INVALID_PARAMS, f"Unknown prompt: {name}")
        args = p.get("arguments") or {}
        try:
            hours = int(str(args.get("hours") or 24).strip())
            if hours < 1 or hours > 24 * 31:
                raise ValueError
        except ValueError as exc:
            raise RpcError(INVALID_PARAMS, "hours must be an integer between 1 and 744") from exc
        node = str(args.get("node") or self.cfg.node_label or "").strip()
        return {
            "description": f"Daily HiveGuard security review ({hours}h){' for ' + node if node else ''}",
            "messages": [{"role": "user", "content": {"type": "text", "text": daily_review_text(hours, node)}}],
        }

    def m_resources_list(self, p: dict) -> dict:
        self.doc_path = find_agent_doc(self.cfg)
        if not self.doc_path:
            return {"resources": []}
        return {"resources": [{
            "uri": AGENT_API_URI,
            "name": "AGENT_API.md",
            "title": "HiveGuard Agent API reference",
            "description": "Contract of the /api/agent/* endpoints the hg_* tools call",
            "mimeType": "text/markdown",
        }]}

    def m_resources_read(self, p: dict) -> dict:
        uri = p.get("uri")
        path = find_agent_doc(self.cfg)
        if uri != AGENT_API_URI or not path:
            raise RpcError(RESOURCE_NOT_FOUND, f"Resource not found: {uri}", {"uri": uri})
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        return {"contents": [{"uri": AGENT_API_URI, "mimeType": "text/markdown", "text": text}]}


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #


def _setup_logging() -> None:
    lvl = (os.environ.get("HG_MCP_LOG") or "warn").strip().lower()
    level = {"debug": logging.DEBUG, "info": logging.INFO, "warn": logging.WARNING,
             "warning": logging.WARNING, "error": logging.ERROR}.get(lvl, logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(level)
    log.propagate = False


def serve(stdin=None, stdout=None, server: Server | None = None) -> int:
    inp = stdin if stdin is not None else sys.stdin.buffer
    out = stdout if stdout is not None else sys.stdout.buffer
    srv = server or Server()
    log.info("%s %s started (%s)", SERVER_NAME, SERVER_VERSION, srv.transport.describe())
    for raw in iter(inp.readline, b""):
        try:
            resp = srv.handle_line(raw)
        except Exception as exc:  # pragma: no cover - handle_line already guards
            log.exception("unhandled error")
            resp = _compact(Server._error(None, INTERNAL_ERROR, f"Internal error: {exc}"))
        if resp is not None:
            out.write(resp.encode("utf-8") + b"\n")
            out.flush()
    log.info("stdin closed, exiting")
    return 0


def main() -> int:
    _setup_logging()
    real_stdout = sys.stdout.buffer
    # Anything printed by accident must not corrupt the JSON-RPC channel.
    sys.stdout = sys.stderr
    try:
        server = Server()
    except ValueError as exc:
        log.error("configuration error: %s", exc)
        return 2
    try:
        return serve(sys.stdin.buffer, real_stdout, server)
    except KeyboardInterrupt:
        return 0
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
