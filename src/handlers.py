"""
Fake service handlers.

Each handler pretends to be a real service just long enough to capture
what an attacker/scanner sends (usernames, passwords, HTTP requests, etc.)
before logging it and closing the connection. None of these handlers
actually authenticate, execute, or proxy anything -- they are decoys only.
"""

import asyncio


async def _read_line(reader, timeout=15):
    try:
        data = await asyncio.wait_for(reader.readline(), timeout=timeout)
        return data.decode(errors="replace").strip()
    except (asyncio.TimeoutError, ConnectionError):
        return None


async def handle_ssh(reader, writer, banner, logger, service_name, peer):
    ip, port = peer
    writer.write((banner + "\r\n").encode())
    await writer.drain()

    # Real SSH clients send their own version string right after the banner.
    client_banner = await _read_line(reader)
    logger.log_event(service_name, "connect", ip, port, {"client_banner": client_banner})

    # We don't implement the real SSH key-exchange; most bots/scanners just
    # probe the banner exchange and disconnect, or attempt to send garbage
    # credentials in cleartext hoping for a naive implementation.
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=10)
        if data:
            logger.log_event(service_name, "raw_data", ip, port, {"data": data[:128].hex()})
    except (asyncio.TimeoutError, ConnectionError):
        pass


async def handle_telnet(reader, writer, banner, logger, service_name, peer):
    ip, port = peer
    writer.write((banner + "\r\nlogin: ").encode())
    await writer.drain()

    username = await _read_line(reader)
    if username is None:
        return

    writer.write(b"Password: ")
    await writer.drain()
    password = await _read_line(reader)

    logger.log_event(
        service_name, "login_attempt", ip, port,
        {"username": username, "password": password}
    )

    writer.write(b"\r\nLogin incorrect\r\n")
    await writer.drain()


async def handle_ftp(reader, writer, banner, logger, service_name, peer):
    ip, port = peer
    writer.write((banner + "\r\n").encode())
    await writer.drain()

    username = None
    for _ in range(4):
        line = await _read_line(reader)
        if line is None:
            break
        if line.upper().startswith("USER"):
            username = line[5:].strip()
            writer.write(b"331 Please specify the password.\r\n")
            await writer.drain()
        elif line.upper().startswith("PASS"):
            password = line[5:].strip()
            logger.log_event(
                service_name, "login_attempt", ip, port,
                {"username": username, "password": password}
            )
            writer.write(b"530 Login incorrect.\r\n")
            await writer.drain()
        elif line.upper().startswith("QUIT"):
            writer.write(b"221 Goodbye.\r\n")
            await writer.drain()
            break
        else:
            writer.write(b"500 Unknown command.\r\n")
            await writer.drain()


async def handle_http(reader, writer, banner, logger, service_name, peer):
    ip, port = peer
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
    except (asyncio.TimeoutError, ConnectionError):
        return

    request_line = request_line.decode(errors="replace").strip()
    headers = {}
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
        except (asyncio.TimeoutError, ConnectionError):
            break
        line = line.decode(errors="replace").strip()
        if not line:
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    logger.log_event(
        service_name, "http_request", ip, port,
        {"request_line": request_line, "headers": headers}
    )

    body = (
        "<html><head><title>Welcome</title></head>"
        "<body><h1>It works!</h1></body></html>"
    )
    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Server: {banner}\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n{body}"
    )
    writer.write(response.encode())
    await writer.drain()


async def handle_generic(reader, writer, banner, logger, service_name, peer):
    """Generic banner-grab style decoy for arbitrary TCP services (e.g. databases)."""
    ip, port = peer
    writer.write((banner + "\r\n").encode())
    await writer.drain()

    try:
        data = await asyncio.wait_for(reader.read(256), timeout=10)
        if data:
            logger.log_event(service_name, "raw_data", ip, port, {"data": data[:128].hex()})
    except (asyncio.TimeoutError, ConnectionError):
        pass


HANDLERS = {
    "ssh": handle_ssh,
    "telnet": handle_telnet,
    "ftp": handle_ftp,
    "http": handle_http,
    "generic": handle_generic,
}
