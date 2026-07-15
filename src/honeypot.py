#!/usr/bin/env python3
"""
Lightweight multi-protocol honeypot.

Spins up decoy TCP services (SSH, Telnet, FTP, HTTP, and generic banner
services) as defined in config/config.yaml, logs every connection and
credential attempt, and optionally sends webhook alerts.

Usage:
    python3 src/honeypot.py [--config config/config.yaml]

This is for defensive/research use on infrastructure you own or are
authorized to monitor -- e.g. to observe scanning/credential-stuffing
activity on an isolated network segment or cloud instance.
"""

import argparse
import asyncio
import signal
import sys

import yaml

from logger import HoneypotLogger
from handlers import HANDLERS


def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


async def start_service(svc, logger):
    name = svc["name"]
    port = svc["port"]
    banner = svc.get("banner", "")
    svc_type = svc.get("type", "generic")
    handler_fn = HANDLERS.get(svc_type, HANDLERS["generic"])

    async def _on_connect(reader, writer):
        peer = writer.get_extra_info("peername")
        peer = (peer[0], peer[1]) if peer else ("unknown", 0)
        try:
            await handler_fn(reader, writer, banner, logger, name, peer)
        except Exception as exc:
            logger.log_event(name, "handler_error", peer[0], peer[1], {"error": str(exc)})
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    try:
        server = await asyncio.start_server(_on_connect, "0.0.0.0", port)
    except OSError as exc:
        print(f"[!] Could not bind {name} on port {port}: {exc}", file=sys.stderr)
        return None

    print(f"[+] {name} decoy listening on 0.0.0.0:{port}")
    return server


async def main_async(config_path):
    cfg = load_config(config_path)
    logger = HoneypotLogger(cfg)

    services = cfg.get("services", [])
    if not services:
        print("No services defined in config. Exiting.", file=sys.stderr)
        return

    servers = []
    for svc in services:
        server = await start_service(svc, logger)
        if server:
            servers.append(server)

    if not servers:
        print("No services could be started (check ports/permissions).", file=sys.stderr)
        return

    stop_event = asyncio.Event()

    def _handle_stop(*_):
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_stop)
        except NotImplementedError:
            # signal handlers aren't available on all platforms (e.g. Windows)
            pass

    await stop_event.wait()
    print("\n[*] Shutting down honeypot...")
    for server in servers:
        server.close()
    await asyncio.gather(*(s.wait_closed() for s in servers))


def main():
    parser = argparse.ArgumentParser(description="Run the multi-protocol honeypot.")
    parser.add_argument(
        "--config", default="config/config.yaml",
        help="Path to config file (default: config/config.yaml)"
    )
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args.config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
