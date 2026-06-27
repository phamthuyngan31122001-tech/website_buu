import base64
import os
import socket
import sys
import threading

if len(sys.argv) != 3:
    sys.stderr.write("Usage: proxy_connect.py <host> <port>\n")
    sys.exit(2)

proxy_host = os.environ.get("TUNNEL_PROXY_HOST")
proxy_port = os.environ.get("TUNNEL_PROXY_PORT")
proxy_user = os.environ.get("TUNNEL_PROXY_USER")
proxy_password = os.environ.get("TUNNEL_PROXY_PASSWORD")

if not proxy_host or not proxy_port:
    sys.stderr.write("TUNNEL_PROXY_HOST and TUNNEL_PROXY_PORT are required.\n")
    sys.exit(2)

try:
    proxy_port = int(proxy_port)
except ValueError:
    sys.stderr.write("TUNNEL_PROXY_PORT must be a number.\n")
    sys.exit(2)

host, port = sys.argv[1], int(sys.argv[2])

sock = socket.create_connection((proxy_host, proxy_port), timeout=30)
sock.settimeout(None)
# TCP keepalive để proxy/firewall không cắt kết nối idle
sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
try:
    sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 20000, 5000))  # Windows: enable, 20s idle, 5s interval
except (AttributeError, OSError):
    pass
headers = [
    f"CONNECT {host}:{port} HTTP/1.1",
    f"Host: {host}:{port}",
]
if proxy_user or proxy_password:
    auth = base64.b64encode(f"{proxy_user or ''}:{proxy_password or ''}".encode()).decode()
    headers.append(f"Proxy-Authorization: Basic {auth}")
req = "\r\n".join(headers) + "\r\n\r\n"
sock.sendall(req.encode())

resp = b""
while b"\r\n\r\n" not in resp:
    chunk = sock.recv(1)
    if not chunk:
        sys.exit(1)
    resp += chunk

if b"200" not in resp:
    sys.stderr.write(f"Proxy error: {resp.decode(errors='replace')}\n")
    sys.exit(1)

def sock_to_stdout():
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except Exception:
        pass

def stdin_to_sock():
    try:
        while True:
            data = sys.stdin.buffer.read1(4096)
            if not data:
                break
            sock.sendall(data)
    except Exception:
        pass

t1 = threading.Thread(target=sock_to_stdout, daemon=True)
t2 = threading.Thread(target=stdin_to_sock, daemon=True)
t1.start()
t2.start()
t1.join()
t2.join()
