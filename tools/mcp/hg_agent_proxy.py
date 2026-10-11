#!/usr/bin/env python3
"""hg-agent-proxy: restricted forwarder from ssh to the HiveGuard Agent API.

Meant to be the forced command of a dedicated, unprivileged account (e.g.
`hgagent`) in ~/.ssh/authorized_keys:

    restrict,command="/usr/local/bin/hg-agent-proxy" ssh-ed25519 AAAA... agent@laptop

The client (hiveguard_mcp.py with HG_SSH_MODE=proxy) writes ONE JSON request
to stdin and closes it:

    {"method": "GET"|"POST", "path": "/api/agent/...", "query": {...},
     "body": {...}, "stream_seconds": n}

and gets ONE JSON line on stdout:

    {"status": 200, "content_type": "application/json", "body": "<text>",
     "truncated": false, "retry_after": "5"?, "proxy_error": "..."?}

Only reads are forwarded: GET on /api/agent/*, POST only on the read-only
query endpoints (logs/query, logs/stats, ip, config/validate). The bearer token
is read from a root-owned file (default /etc/hiveguard/agent-token, ideally
the read-only `agent.read_token_file`) and never written to stdout/stderr.
SSH_ORIGINAL_COMMAND is ignored (only logged to syslog).

Python >= 3.8, standard library only.

Options / environment (option wins):
  --token-file PATH   HG_AGENT_TOKEN_FILE   default /etc/hiveguard/agent-token
  --url URL           HG_AGENT_URL          default http://127.0.0.1:8443
  --timeout SECS      HG_AGENT_TIMEOUT      default 60 (per request)
  --no-syslog         HG_AGENT_PROXY_SYSLOG=0
"""

import http.client
import json
import os
import re
import signal
import socket
import sys
import time
import urllib.parse

VERSION = "1.0"
DEFAULT_TOKEN_FILE = "/etc/hiveguard/agent-token"
DEFAULT_URL = "http://127.0.0.1:8443"
DEFAULT_TIMEOUT = 60.0
MAX_REQUEST_BYTES = 1024 * 1024 + 64 * 1024   # whole stdin document
MAX_BODY_BYTES = 1024 * 1024                  # serialized `body`
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_STREAM_SECONDS = 120
DEFAULT_STREAM_SECONDS = 10
MAX_QUERY_KEYS = 32
MAX_QUERY_VALUE = 4096
STREAM_PATH = "/api/agent/stream"
READ_POSTS = frozenset({
    "/api/agent/logs/query",
    "/api/agent/logs/stats",
    "/api/agent/ip",
    "/api/agent/config/validate",
})
REQUEST_KEYS = frozenset({"method", "path", "query", "body", "stream_seconds"})
PATH_RE = re.compile(r"/api/agent/[A-Za-z0-9_\-/]+")
QUERY_KEY_RE = re.compile(r"[A-Za-z0-9_]{1,64}")
CONTROL_RE = re.compile("[\x00-\x1f\x7f-\x9f]")
TOKEN_RE = re.compile(r"[\x21-\x7e]{8,1024}")


class ProxyError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status
        self.message = message


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #


def parse_options(argv, env):
    opts = {
        "token_file": env.get("HG_AGENT_TOKEN_FILE") or DEFAULT_TOKEN_FILE,
        "url": env.get("HG_AGENT_URL") or DEFAULT_URL,
        "timeout": env.get("HG_AGENT_TIMEOUT") or DEFAULT_TIMEOUT,
        "syslog": str(env.get("HG_AGENT_PROXY_SYSLOG", "1")).strip().lower() not in ("0", "false", "no", "off"),
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--token-file", "--url", "--timeout") and i + 1 < len(argv):
            opts[a[2:].replace("-", "_")] = argv[i + 1]
            i += 2
            continue
        if a == "--no-syslog":
            opts["syslog"] = False
        elif a == "--version":
            opts["version"] = True
        else:
            raise ProxyError(500, "invalid proxy option (check the forced command in authorized_keys)")
        i += 1
    try:
        opts["timeout"] = float(opts["timeout"])
        if not 0 < opts["timeout"] <= 600:
            raise ValueError
    except ValueError:
        raise ProxyError(500, "invalid proxy timeout")
    parts = urllib.parse.urlsplit(str(opts["url"]))
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.query or parts.fragment:
        raise ProxyError(500, "invalid proxy url")
    opts["scheme"] = parts.scheme
    opts["host"] = parts.hostname
    opts["port"] = parts.port or (443 if parts.scheme == "https" else 80)
    opts["prefix"] = parts.path.rstrip("/")
    return opts


# --------------------------------------------------------------------------- #
# Request validation
# --------------------------------------------------------------------------- #


def _query_value(key, v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        v = ",".join(v)
    if not isinstance(v, str):
        raise ProxyError(400, "query value for %s must be a string, number or boolean" % key)
    if len(v) > MAX_QUERY_VALUE:
        raise ProxyError(413, "query value for %s is too long" % key)
    if CONTROL_RE.search(v):
        raise ProxyError(400, "query value for %s contains control characters" % key)
    return v


def validate_request(raw):
    """Parse and validate the stdin document; return a normalized dict."""
    if len(raw) > MAX_REQUEST_BYTES:
        raise ProxyError(413, "request larger than %d bytes" % MAX_REQUEST_BYTES)
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProxyError(400, "request must be one JSON object (UTF-8)")
    if not isinstance(req, dict):
        raise ProxyError(400, "request must be a JSON object")
    unknown = sorted(set(req) - REQUEST_KEYS)
    if unknown:
        raise ProxyError(400, "unknown request keys: %s" % ", ".join(k[:32] for k in unknown[:5]))

    method = req.get("method")
    if not isinstance(method, str) or method.upper() not in ("GET", "POST"):
        raise ProxyError(403, "method not allowed (only GET, and POST on read-only query endpoints)")
    method = method.upper()

    path = req.get("path")
    if not isinstance(path, str) or len(path) > 256:
        raise ProxyError(400, "path must be a string of at most 256 characters")
    if CONTROL_RE.search(path) or ".." in path or "//" in path:
        raise ProxyError(403, "path rejected (control characters, '..' or '//')")
    if not path.startswith("/api/agent/") or not PATH_RE.fullmatch(path):
        raise ProxyError(403, "path not allowed (only /api/agent/*, characters A-Z a-z 0-9 _ - /)")
    if method == "POST" and path not in READ_POSTS:
        raise ProxyError(403, "POST allowed only on %s" % ", ".join(sorted(READ_POSTS)))

    query = req.get("query")
    if query is None:
        query = {}
    if not isinstance(query, dict):
        raise ProxyError(400, "query must be an object")
    if len(query) > MAX_QUERY_KEYS:
        raise ProxyError(400, "too many query parameters")
    clean_query = []
    for k, v in query.items():
        if not isinstance(k, str) or not QUERY_KEY_RE.fullmatch(k):
            raise ProxyError(400, "invalid query parameter name")
        if k.lower() == "token":
            raise ProxyError(403, "query parameter `token` is not allowed (the proxy authenticates)")
        if v is None:
            continue
        clean_query.append((k, _query_value(k, v)))

    body = req.get("body")
    body_bytes = None
    if body is not None:
        if method != "POST":
            raise ProxyError(400, "body is only allowed with POST")
        body_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
        if len(body_bytes) > MAX_BODY_BYTES:
            raise ProxyError(413, "body larger than %d bytes" % MAX_BODY_BYTES)

    stream_seconds = None
    if path == STREAM_PATH:
        if method != "GET":
            raise ProxyError(403, "stream is GET only")
        s = req.get("stream_seconds", DEFAULT_STREAM_SECONDS)
        if isinstance(s, bool) or not isinstance(s, (int, float)) or not 1 <= s <= MAX_STREAM_SECONDS:
            raise ProxyError(400, "stream_seconds must be a number between 1 and %d" % MAX_STREAM_SECONDS)
        stream_seconds = float(s)
    elif req.get("stream_seconds") is not None:
        raise ProxyError(400, "stream_seconds is only valid for %s" % STREAM_PATH)

    return {"method": method, "path": path, "query": clean_query, "body": body_bytes,
            "stream_seconds": stream_seconds}


# --------------------------------------------------------------------------- #
# Token + forwarding
# --------------------------------------------------------------------------- #


def read_token(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(4097)
    except FileNotFoundError:
        raise ProxyError(500, "token file %s not found" % path)
    except PermissionError:
        raise ProxyError(500, "token file %s is not readable by this account" % path)
    except OSError:
        raise ProxyError(500, "cannot read token file %s" % path)
    try:
        tok = data.decode("ascii").strip()
    except UnicodeDecodeError:
        tok = ""
    if not TOKEN_RE.fullmatch(tok):
        raise ProxyError(500, "token file %s is empty or malformed" % path)
    return tok


def _connection(opts, timeout):
    if opts["scheme"] == "https":
        import ssl
        return http.client.HTTPSConnection(opts["host"], opts["port"], timeout=timeout,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(opts["host"], opts["port"], timeout=timeout)


def forward(opts, req, token):
    target = opts["prefix"] + req["path"]
    if req["query"]:
        target += "?" + urllib.parse.urlencode(req["query"])
    stream = req["stream_seconds"] is not None
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "text/event-stream" if stream else "application/json",
        "User-Agent": "hg-agent-proxy/" + VERSION,
    }
    if stream:
        headers["Cache-Control"] = "no-cache"
    if req["body"] is not None:
        headers["Content-Type"] = "application/json"
    timeout = opts["timeout"]
    conn = _connection(opts, min(timeout, req["stream_seconds"] + 5) if stream else timeout)
    try:
        try:
            conn.request(req["method"], target, body=req["body"], headers=headers)
            resp = conn.getresponse()
        except socket.timeout:
            raise ProxyError(504, "HiveGuard API did not answer within %.0f s" % timeout)
        except (OSError, http.client.HTTPException):
            raise ProxyError(502, "cannot reach the HiveGuard API at %s:%s" % (opts["host"], opts["port"]))
        out = {"status": resp.status, "content_type": resp.getheader("Content-Type") or ""}
        retry_after = resp.getheader("Retry-After")
        if retry_after:
            out["retry_after"] = retry_after[:32]
        truncated = False
        if stream and resp.status == 200:
            deadline = time.monotonic() + req["stream_seconds"]
            chunks, total = [], 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if conn.sock is not None:
                    conn.sock.settimeout(remaining)
                try:
                    chunk = resp.read1(65536)
                except (socket.timeout, OSError, http.client.HTTPException):
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_STREAM_BYTES:
                    truncated = True
                    break
            data = b"".join(chunks)[:MAX_STREAM_BYTES]
        else:
            try:
                data = resp.read(MAX_RESPONSE_BYTES + 1)
            except socket.timeout:
                raise ProxyError(504, "HiveGuard API response timed out")
            except (OSError, http.client.HTTPException):
                raise ProxyError(502, "HiveGuard API connection failed while reading the response")
            if len(data) > MAX_RESPONSE_BYTES:
                data, truncated = data[:MAX_RESPONSE_BYTES], True
        body = data.decode("utf-8", errors="replace")
        if token in body:  # defence in depth: never relay the token
            body = body.replace(token, "<token>")
        out["body"] = body
        out["truncated"] = truncated
        return out
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def _syslog(enabled, message):
    if not enabled:
        return
    try:
        import syslog
        syslog.openlog("hg-agent-proxy", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_INFO, message)
    except Exception:
        pass


def _client():
    conn = os.environ.get("SSH_CONNECTION", "").split()
    return conn[0] if conn else "local"


def _error_reply(exc):
    return {"status": exc.status, "content_type": "application/json",
            "body": json.dumps({"error": "hg-agent-proxy: " + exc.message}),
            "proxy_error": exc.message}


def _alarm(signum, frame):
    raise ProxyError(504, "hg-agent-proxy hard time limit reached")


def run(argv, stdin, env):
    """Return (reply dict, exit code, syslog flag)."""
    use_syslog = True
    try:
        opts = parse_options(argv, env)
        use_syslog = opts["syslog"]
        if opts.get("version"):
            return {"status": 200, "content_type": "text/plain", "body": "hg-agent-proxy " + VERSION}, 0, False
        original = env.get("SSH_ORIGINAL_COMMAND")
        if original:
            shown = CONTROL_RE.sub("?", original)[:120]
            _syslog(use_syslog, "ignoring SSH_ORIGINAL_COMMAND from %s: %r" % (_client(), shown))
        req = validate_request(stdin.read(MAX_REQUEST_BYTES + 1))
        token = read_token(opts["token_file"])
        limit = opts["timeout"] + (req["stream_seconds"] or 0) + 10
        if hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, _alarm)
            signal.alarm(int(limit) + 1)
        try:
            reply = forward(opts, req, token)
        finally:
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)
        _syslog(use_syslog, "%s %s %s -> %s (%d bytes)" % (_client(), req["method"], req["path"],
                                                           reply["status"], len(reply["body"])))
        return reply, 0, use_syslog
    except ProxyError as exc:
        _syslog(use_syslog, "%s refused/failed: %s" % (_client(), exc.message))
        return _error_reply(exc), 2, use_syslog
    except Exception as exc:  # never print a traceback (could contain request data)
        err = ProxyError(500, "internal proxy error (%s)" % type(exc).__name__)
        _syslog(use_syslog, "%s %s" % (_client(), err.message))
        return _error_reply(err), 2, use_syslog


def main(argv=None, stdin=None, stdout=None, env=None):
    reply, code, _ = run(sys.argv[1:] if argv is None else argv,
                         stdin if stdin is not None else sys.stdin.buffer,
                         dict(os.environ) if env is None else env)
    out = stdout if stdout is not None else sys.stdout.buffer
    out.write(json.dumps(reply, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")
    out.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
