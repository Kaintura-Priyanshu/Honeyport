# Honeypot

A lightweight, dependency-light honeypot that runs decoy network services
(SSH, Telnet, FTP, HTTP, and a generic banner-grab service) to observe and
log scanning and credential-stuffing activity against your network.

Each service presents a realistic banner and just enough protocol chatter
to draw out usernames, passwords, and HTTP requests from bots/scanners —
then logs everything and disconnects. **No commands are ever actually
executed and no real authentication happens.**

## Features

- Multiple simultaneous decoy services, configured in one YAML file
- Async I/O (Python `asyncio`) — handles many concurrent connections cheaply
- Structured JSON-lines logging (`logs/honeypot_events.jsonl`) alongside a
  human-readable log
- Optional webhook alerting (e.g. Slack/Discord) when an IP crosses an
  attempt threshold within a time window
- Built-in log analyzer for quick summaries (top IPs, top credentials, etc.)
- Docker / docker-compose support for one-command deployment
- Runs entirely on unprivileged ports by default (safe to run as non-root)

##  Important safety & legal notes

- Only deploy this on infrastructure you **own or are explicitly authorized
  to monitor**. Running a honeypot against traffic you don't have rights to
  intercept may violate local law.
- Isolate the honeypot host/VM from your real infrastructure (separate VLAN,
  cloud security group, or dedicated VM/container) so a compromised decoy
  can't be used to pivot anywhere sensitive.
- This tool logs source IPs and any credentials attackers submit. Treat the
  log files as sensitive data and handle/store them accordingly (they may
  contain real, reused passwords).
- The decoy services are intentionally shallow — they do not implement real
  protocol handshakes (e.g. real SSH key exchange), so they will not fool a
  sophisticated, targeted attacker. This is aimed at opportunistic scanners,
  bots, and credential-stuffing traffic, not a substitute for a full
  interaction honeypot like Cowrie.

## Quick start

### Run locally with Python

```bash
git clone <your-repo-url>
cd honeypot-project
pip install -r requirements.txt
python3 src/honeypot.py --config config/config.yaml
```

### Run with Docker Compose

```bash
docker compose up -d --build
```

Logs will be written to `./logs/` on the host (mounted as a volume).

## Configuration

Edit `config/config.yaml` to add, remove, or change services:

```yaml
services:
  - name: ssh
    port: 2222
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    type: ssh
```

Supported `type` values: `ssh`, `telnet`, `ftp`, `http`, `generic`.

To bind to the real well-known ports (22, 21, 23, 80), either:
- run the container/process as root (or with `CAP_NET_BIND_SERVICE`), or
- keep the decoys on high ports and forward the real ports to them with
  `iptables`/your cloud provider's port-forwarding rules — this keeps the
  Python process unprivileged.

### Alerting

Set `alerting.enabled: true` and provide a `webhook_url` (Slack/Discord
incoming webhook format) in `config/config.yaml` to get near-real-time
notifications when an IP exceeds `attempt_threshold` connections within
`alert_window_seconds`.

## Analyzing captured data

```bash
python3 src/analyze_logs.py logs/honeypot_events.jsonl
```

This prints the top source IPs, events by service, and the most commonly
attempted username/password pairs — a quick way to see what credential
lists attackers are cycling through.

## Project structure

```
.
├── config/
│   └── config.yaml         # service definitions, logging, alerting
├── src/
│   ├── honeypot.py         # entrypoint — starts all configured services
│   ├── handlers.py         # per-protocol decoy logic (SSH/Telnet/FTP/HTTP/generic)
│   ├── logger.py           # structured logging + webhook alerting
│   └── analyze_logs.py     # summarizes captured events
├── logs/                   # created at runtime (gitignored)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Extending

- Add a new decoy protocol by writing a handler function in `handlers.py`
  matching the `(reader, writer, banner, logger, service_name, peer)`
  signature, registering it in the `HANDLERS` dict, and referencing its
  `type` in `config.yaml`.
- Ship logs to a SIEM by tailing `logs/honeypot_events.jsonl` (each line is
  a self-contained JSON object) with something like Filebeat/Fluent Bit.


