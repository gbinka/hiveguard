# hiveguard-mcp

A stdio [MCP](https://modelcontextprotocol.io) server that lets an AI agent
(Claude Code, Claude Desktop, any MCP client) analyse a HiveGuard node: bans,
detection signals, the raw logs the daemon tails, its journal, detector
configuration, the catalogue of linked-but-disabled plugins, Prometheus
metrics and the live event stream.

- Single file, `hiveguard_mcp.py`, Python >= 3.10, **standard library only**.
- Talks to the daemon's REST API (`ui.rest` plugin, default
  `http://127.0.0.1:8443`): the operator endpoints (`/api/*`) and the Agent API
  (`/api/agent/*`, contract in [`docs/AGENT_API.md`](../../docs/AGENT_API.md)).
- MCP over stdio: newline-delimited JSON-RPC 2.0, protocol `2025-06-18`
  (also `2025-03-26`, `2024-11-05`). Exposes tools, one prompt
  (`daily_security_review`) and one resource (`hiveguard://agent-api`, the
  AGENT_API.md text when it is found next to the script, in `../../docs/` or at
  `HG_DOCS`).
- **Read-only by default.** Mutating tools are listed but refuse to run unless
  `HG_MCP_ALLOW_WRITE=1`.

## Token

The API needs the `ui.rest` bearer token (`/api/health` and `/metrics` do not).
On the server the operator keeps it in a root-owned file readable only by the
user the agent logs in as:

```bash
# on the HiveGuard host; the token is the ui.rest auth_token from config.yaml
sudo install -m 0640 -o root -g <agent-user> /dev/stdin /etc/hiveguard/agent-token <<'EOF'
<TOKEN>
EOF
```

(or create the file with an editor; anything that keeps the token out of shell
history and argv). Never pass the token on a command line: not to this script,
not to `ssh`, not to `curl -H`. Use `HG_TOKEN_FILE`, an env var set by the MCP
client from a secret store, or the remote token file (`HG_SSH` mode).

## Three ways to run it

### (a) Locally, through an ssh tunnel

```bash
ssh -N -L 8443:127.0.0.1:8443 admin@node-a.example.org &      # keep running
install -m 0600 /dev/stdin ~/.config/hiveguard/etno.token <<'EOF'
<TOKEN>
EOF
claude mcp add --transport stdio hg-etno \
  --env HG_TOKEN_FILE=$HOME/.config/hiveguard/etno.token \
  --env HG_NODE_LABEL=node-a \
  -- python3 /path/to/hiveguard/tools/mcp/hiveguard_mcp.py
```

For several nodes use different local ports (`-L 8444:127.0.0.1:8443`) and
`HG_URL=http://127.0.0.1:8444`.

### (b) `HG_SSH` mode: nothing installed on the server

The script runs locally and, per request, executes `ssh user@host 'sh -s'`.
The shell script it sends **on stdin** runs `curl -K -` on the server; curl's
options (URL, headers, body) come through a pipe, so the token appears in no
argv on either side. When no local token is configured, the remote script reads
it from `HG_SSH_TOKEN_FILE` (default `/etc/hiveguard/agent-token`, see above).
ssh uses `BatchMode=yes` and a persistent control master
(`~/.ssh/hg-mcp-%C`, 10 min), so only the first call pays for the handshake.
The server needs only `sh` and `curl`.

```bash
claude mcp add --transport stdio hg-node-b \
  --env HG_SSH=admin@node-b.example.org --env HG_NODE_LABEL=node-b \
  -- python3 /path/to/hiveguard/tools/mcp/hiveguard_mcp.py
```

Requirements: key-based ssh login (BatchMode cannot ask for passwords) and the
ssh user in the group that owns `/etc/hiveguard/agent-token`.

### (c) Server-side, MCP over ssh stdio

Copy the script to the server (e.g. `/opt/hiveguard/mcp/hiveguard_mcp.py`, plus
`docs/AGENT_API.md` next to it for the resource) and let ssh carry the MCP
stream itself. The script then reads `/etc/hiveguard/agent-token` locally on
the server and talks to `127.0.0.1:8443` directly.

```bash
claude mcp add --transport stdio hg-etno -- \
  ssh admin@node-a.example.org python3 /opt/hiveguard/mcp/hiveguard_mcp.py
```

Environment for the remote process goes on the remote command line
(`ssh host env HG_NODE_LABEL=etno python3 ...`); never put `HG_TOKEN` there.

### `.mcp.json` form (project-scoped)

```json
{
  "mcpServers": {
    "hg-etno": {
      "type": "stdio",
      "command": "python3",
      "args": ["tools/mcp/hiveguard_mcp.py"],
      "env": {
        "HG_SSH": "admin@node-a.example.org",
        "HG_NODE_LABEL": "node-a"
      }
    },
    "hg-node-b": {
      "type": "stdio",
      "command": "ssh",
      "args": ["admin@node-b.example.org", "env", "HG_NODE_LABEL=node-b",
               "python3", "/opt/hiveguard/mcp/hiveguard_mcp.py"]
    }
  }
}
```

Use one server entry per node; `HG_NODE_LABEL` is prefixed to every tool
description and shown in `initialize` instructions, so the agent knows which
host it is talking to.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `HG_URL` | `http://127.0.0.1:8443` | ui.rest base URL (in `HG_SSH` mode: as seen from the server) |
| `HG_TOKEN` | - | bearer token (prefer `HG_TOKEN_FILE`) |
| `HG_TOKEN_FILE` | `/etc/hiveguard/agent-token` | file holding the token, read and stripped when `HG_TOKEN` is unset |
| `HG_SSH` | - | `user@host`: send requests via ssh + remote curl |
| `HG_SSH_TOKEN_FILE` | `/etc/hiveguard/agent-token` | token file on the remote host, used when no local token exists |
| `HG_TIMEOUT` | `60` | per-request timeout in seconds (log queries can be slow) |
| `HG_MCP_ALLOW_WRITE` | off | `1` enables `hg_ban`, `hg_unban`, `hg_whitelist_add/remove`, `hg_config_put` |
| `HG_NODE_LABEL` | - | free-text node name for descriptions/instructions |
| `HG_DOCS` | - | path to `AGENT_API.md` (file or directory) for the resource |
| `HG_TLS_INSECURE` | off | `1` skips certificate checks for an `https://` `HG_URL` |
| `HG_MCP_LOG` | `warn` | `debug`/`info`/`warn` logging to stderr (stdout carries only JSON-RPC) |

## Tools

Time parameters (`since`, `until`) accept RFC 3339 or relative ages (`90s`,
`15m`, `6h`, `7d`).

| Tool | Endpoint | Use it for |
|---|---|---|
| `hg_overview` | GET /api/agent/overview | first call: bans, threats, counters, plugin health, log sources |
| `hg_health` | GET /api/health (+ /api/info) | connectivity/auth check |
| `hg_bans` | GET /api/agent/bans | filter/sort/count bans (source, detector, since, subnet_only, q ...) |
| `hg_threats` | GET /api/agent/threats | recent detection signals (ring buffer of 500), top IPs |
| `hg_log_sources` | GET /api/agent/logs/sources | which log sources can be queried |
| `hg_log_query` | POST /api/agent/logs/query | newest N matching raw/parsed lines of one source |
| `hg_log_stats` | POST /api/agent/logs/stats | top-N by ip/ip24/path/status/port/user..., per-IP profiles, time series |
| `hg_ip` | POST /api/agent/ip | everything known about one address |
| `hg_journal` | GET /api/agent/journal | daemon's own journal (warnings/errors) |
| `hg_detectors` | GET /api/agent/detectors | effective detector config, schemas, counters, scoring config |
| `hg_catalog` | GET /api/agent/catalog | all linked plugins incl. disabled ones |
| `hg_plugins` | GET /api/plugins | running instances and health |
| `hg_whitelist` | GET /api/whitelist | whitelist entries |
| `hg_config_get` | GET /api/config | config.yaml text |
| `hg_config_validate` | POST /api/agent/config/validate | dry-run validation of a full config text |
| `hg_metrics` | GET /metrics | sample lines (optional regex) + parsed `hiveguard_*` map |
| `hg_stream_sample` | GET /api/agent/stream (SSE) | collect live signal/ban events for N s (max 120) |
| `hg_ban` (write) | POST /api/bans | ban IP/CIDR for `duration_secs` (bare IP -> /32 or /128) |
| `hg_unban` (write) | DELETE /api/bans/{cidr} | remove a ban (`/` sent as `%2F`) |
| `hg_whitelist_add` (write) | POST /api/whitelist | whitelist a CIDR |
| `hg_whitelist_remove` (write) | DELETE /api/whitelist/{cidr} | remove whitelist entry |
| `hg_config_put` (write) | PUT /api/config | replace config.yaml (needs a daemon restart; 503 when /etc is read-only) |

Results come back as compact JSON text plus `structuredContent`; daemon errors
(`{"error": ...}` with 4xx/5xx) become `isError: true` results carrying the
daemon's message.

## Prompt: `daily_security_review`

Arguments `hours` (default 24) and `node`. Produces the morning-review
playbook: overview -> journal warnings -> threats + bans -> log stats per
source (ip, 4xx paths, firewall ports) -> `hg_ip` on top suspects -> detectors
and catalogue -> report (attacks found, blocked or not, validated config
tightening proposals, recommended disabled modules). It never applies changes.

## Safety notes

- Read-only by default; even with `HG_MCP_ALLOW_WRITE=1` the tool descriptions
  tell the agent to act only on explicit operator approval. Bans and whitelist
  changes made through the REST API are local to the node.
- The token never goes into argv (local or remote), logs, or tool output.
- The Agent API itself is bounded on the daemon side (scan byte caps, result
  caps, allow-listed paths, linear-time regexes); this server adds argument
  validation and timeouts on top.
- `hg_config_get` returns the full config; treat it as sensitive.

## Tests

```bash
cd tools/mcp && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v tests
```

The suite runs a fake daemon (`http.server`) in a thread, drives
`Server.dispatch()` in-process, executes the `HG_SSH` script locally through
`sh -s` + real curl (skipped without curl), and does one subprocess stdio smoke
test.
