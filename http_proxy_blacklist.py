#!/usr/bin/env python3

"""
Лаба 4 (доп): HTTP-прокси с журналированием и фильтрацией по чёрному списку.

Поддерживается только HTTP. HTTPS/CONNECT не требуется и возвращает 501.

Чёрный список задаётся в конфигурационном файле и может содержать:
- домены (blocked_domains) — блокировка по host (точное совпадение или по суффиксу)
- URL (blocked_urls) — блокировка по префиксу полного URL (scheme://host[:port]/path?query)

Если ресурс заблокирован, прокси возвращает предопределённую HTML-страницу и код 403.
"""

import argparse
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit


CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"


@dataclass
class ParsedRequest:
    method: str
    raw_target: str
    version: str
    headers: Dict[str, str]  # lower-case keys
    header_items: Tuple[Tuple[str, str], ...]  # original-cased order-preserving
    host: str
    port: int
    path: str
    absolute_url: str  # normalized for logging/matching


@dataclass
class ProxyConfig:
    blocked_domains: List[str]
    blocked_urls: List[str]


def load_config(path: str) -> ProxyConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    blocked_domains = raw.get("blocked_domains", [])
    blocked_urls = raw.get("blocked_urls", [])
    if not isinstance(blocked_domains, list) or not all(isinstance(x, str) for x in blocked_domains):
        raise ValueError("config: blocked_domains must be a list of strings")
    if not isinstance(blocked_urls, list) or not all(isinstance(x, str) for x in blocked_urls):
        raise ValueError("config: blocked_urls must be a list of strings")
    return ProxyConfig(
        blocked_domains=[x.strip().lower().strip(".") for x in blocked_domains if x.strip()],
        blocked_urls=[x.strip() for x in blocked_urls if x.strip()],
    )


def _recv_until(sock: socket.socket, marker: bytes, limit: int = 256 * 1024) -> bytes:
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise ValueError("Header too large")
    return bytes(buf)


def _parse_headers(header_block: bytes) -> Tuple[str, str, str, Tuple[Tuple[str, str], ...], Dict[str, str]]:
    head, _sep, _rest = header_block.partition(HEADER_END)
    lines = head.split(CRLF)
    if not lines or not lines[0]:
        raise ValueError("Empty request")
    request_line = lines[0].decode("iso-8859-1", errors="strict")
    parts = request_line.split()
    if len(parts) != 3:
        raise ValueError(f"Bad request line: {request_line!r}")
    method, target, version = parts

    items: List[Tuple[str, str]] = []
    headers_lc: Dict[str, str] = {}
    for raw in lines[1:]:
        if not raw:
            continue
        line = raw.decode("iso-8859-1", errors="ignore")
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.lstrip(" \t")
        items.append((name, value))
        headers_lc[name.lower()] = value
    return method, target, version, tuple(items), headers_lc


def _determine_upstream(target: str, headers_lc: Dict[str, str]) -> Tuple[str, int, str, str]:
    """
    Returns (host, port, path, absolute_url).
    Supports absolute-form and origin-form.
    """
    if target.startswith("http://") or target.startswith("https://"):
        u = urlsplit(target)
        if not u.hostname:
            raise ValueError("No hostname in absolute URL")
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path = f"{path}?{u.query}"
        absolute_url = f"{u.scheme}://{host}:{port}{path}"
        return host, port, path, absolute_url

    host_hdr = headers_lc.get("host")
    if not host_hdr:
        raise ValueError("Missing Host header")
    host_port = host_hdr.strip()
    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        port = int(port_s)
    else:
        host = host_port
        port = 80

    path = target if target else "/"
    if not path.startswith("/"):
        path = "/" + path
    absolute_url = f"http://{host}:{port}{path}"
    return host, port, path, absolute_url


def parse_client_request(client_sock: socket.socket) -> Tuple[ParsedRequest, bytes]:
    raw = _recv_until(client_sock, HEADER_END)
    if not raw:
        raise ValueError("Client closed")
    header_block, _sep, remainder = raw.partition(HEADER_END)
    header_bytes = header_block + HEADER_END

    method, target, version, header_items, headers_lc = _parse_headers(header_bytes)
    host, port, path, absolute_url = _determine_upstream(target, headers_lc)
    return (
        ParsedRequest(
            method=method,
            raw_target=target,
            version=version,
            headers=headers_lc,
            header_items=header_items,
            host=host,
            port=port,
            path=path,
            absolute_url=absolute_url,
        ),
        remainder,
    )


def build_upstream_request(req: ParsedRequest) -> bytes:
    request_line = f"{req.method} {req.path} {req.version}\r\n"

    out_lines = [request_line]
    seen_host = False
    for name, value in req.header_items:
        nlc = name.lower()
        if nlc in {"proxy-connection", "proxy-authorization"}:
            continue
        if nlc == "connection":
            continue
        if nlc == "host":
            seen_host = True
        out_lines.append(f"{name}: {value}\r\n")

    if not seen_host:
        out_lines.append(f"Host: {req.host}:{req.port}\r\n")

    out_lines.append("Connection: close\r\n")
    out_lines.append("\r\n")
    return "".join(out_lines).encode("iso-8859-1")


def _read_response_headers(upstream: socket.socket) -> Tuple[bytes, int, bytes]:
    raw = _recv_until(upstream, HEADER_END)
    if not raw:
        raise ValueError("Upstream closed before response")
    header_block, _sep, remainder = raw.partition(HEADER_END)
    header_bytes = header_block + HEADER_END

    first = header_block.split(CRLF, 1)[0].decode("iso-8859-1", errors="replace")
    parts = first.split()
    status = 0
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0
    return header_bytes, status, remainder


def _relay_stream(src: socket.socket, dst: socket.socket, initial: bytes = b"") -> None:
    if initial:
        dst.sendall(initial)
    while True:
        chunk = src.recv(64 * 1024)
        if not chunk:
            return
        dst.sendall(chunk)


def _domain_is_blocked(host: str, blocked_domains: List[str]) -> bool:
    """
    Блокировка по домену:
    - точное совпадение
    - или суффикс: example.com блокирует a.example.com
    """
    h = host.lower().strip(".")
    for d in blocked_domains:
        if h == d or h.endswith("." + d):
            return True
    return False


def _url_is_blocked(url: str, blocked_urls: List[str]) -> bool:
    """Блокировка по URL: совпадение по префиксу (startsWith)."""
    for u in blocked_urls:
        if url.startswith(u):
            return True
    return False


def is_blocked(req: ParsedRequest, cfg: ProxyConfig) -> bool:
    return _domain_is_blocked(req.host, cfg.blocked_domains) or _url_is_blocked(req.absolute_url, cfg.blocked_urls)


def build_block_page(blocked_url: str) -> bytes:
    body = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>Доступ запрещён</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 40px; }}
    .box {{ max-width: 720px; padding: 20px 24px; border: 1px solid #ddd; border-radius: 10px; }}
    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>Доступ к ресурсу заблокирован</h1>
    <p>Запрошенный адрес находится в чёрном списке прокси-сервера:</p>
    <p><code>{blocked_url}</code></p>
    <p>Код ошибки: <b>403 Forbidden</b></p>
  </div>
</body>
</html>
""".encode("utf-8")

    hdr = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        + b"\r\n"
    )
    return hdr + body


def handle_client(
    client_sock: socket.socket,
    client_addr: Tuple[str, int],
    connect_timeout_s: float,
    cfg: ProxyConfig,
) -> None:
    upstream: Optional[socket.socket] = None
    try:
        try:
            req, body_remainder = parse_client_request(client_sock)
        except ValueError:
            return

        if req.method.upper() == "CONNECT":
            client_sock.sendall(
                b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
            return

        if is_blocked(req, cfg):
            client_sock.sendall(build_block_page(req.absolute_url))
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] {client_addr[0]}:{client_addr[1]} -> {req.absolute_url} => 403 (BLOCKED)")
            return

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(connect_timeout_s)
        upstream.connect((req.host, req.port))
        upstream.settimeout(None)

        upstream.sendall(build_upstream_request(req))
        if body_remainder:
            upstream.sendall(body_remainder)

        client_sock.settimeout(0.2)
        try:
            while True:
                chunk = client_sock.recv(64 * 1024)
                if not chunk:
                    break
                upstream.sendall(chunk)
                if len(chunk) < 64 * 1024:
                    break
        except socket.timeout:
            pass
        finally:
            client_sock.settimeout(None)

        resp_header_bytes, status_code, resp_remainder = _read_response_headers(upstream)
        client_sock.sendall(resp_header_bytes)

        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {client_addr[0]}:{client_addr[1]} -> {req.absolute_url} => {status_code}")

        _relay_stream(upstream, client_sock, initial=resp_remainder)
    except OSError:
        return
    finally:
        try:
            client_sock.close()
        except OSError:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass


def serve(listen_host: str, listen_port: int, connect_timeout_s: float, cfg: ProxyConfig) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(128)

    print(f"HTTP proxy listening on {listen_host}:{listen_port} (HTTP only; blacklist enabled)")

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr, connect_timeout_s, cfg),
                daemon=True,
            )
            t.start()
    finally:
        server.close()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HTTP proxy with logging + blacklist (lab 4 extra)")
    p.add_argument("--listen-host", default="127.0.0.1", help="Host/IP to listen on")
    p.add_argument("--listen-port", type=int, default=8080, help="TCP port to listen on")
    p.add_argument("--connect-timeout", type=float, default=5.0, help="Upstream connect timeout (seconds)")
    p.add_argument("--config", default="config.json", help="Path to JSON config with blacklist")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)
    serve(args.listen_host, args.listen_port, args.connect_timeout, cfg)


if __name__ == "__main__":
    main()

