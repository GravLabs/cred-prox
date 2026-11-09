#!/usr/bin/env python3
"""Fault 8 (plan 5.5): bounded slow-client pressure. Standard library only, hard caps on
sockets and duration; exits by itself. Points at the soak host's published port."""
import argparse
import socket
import time

p = argparse.ArgumentParser()
p.add_argument("--host", default="127.0.0.1")
p.add_argument("--port", type=int, default=18080)
p.add_argument("--sockets", type=int, default=64)
p.add_argument("--seconds", type=int, default=120)
a = p.parse_args()
a.sockets = min(a.sockets, 64)   # hard cap, even if invoked wrong
a.seconds = min(a.seconds, 600)

open_socks = []
end = time.time() + a.seconds
while time.time() < end and len(open_socks) < a.sockets:
    try:
        s = socket.create_connection((a.host, a.port), timeout=5)
        s.sendall(b"GET /vendor/echo?probe=slowloris HTTP/1.1\r\nHost: soak\r\n")
        open_socks.append(s)
    except OSError:
        time.sleep(0.5)

drip = 0
while time.time() < end:
    for s in list(open_socks):
        try:
            drip += 1
            s.sendall(b"X-" + str(drip % 1000).encode() + b": x\r\n")
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            open_socks.remove(s)
    time.sleep(2)

for s in open_socks:
    try:
        s.close()
    except OSError:
        pass
print(f"SLOWLORIS-DONE held<= {a.sockets} sockets for {a.seconds}s")
