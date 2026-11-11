"""Bounded DNS diagnostics for example.com; never changes scanner DNS policy."""
import json
import queue
import socket
import sys
import threading
from pathlib import Path

import dns.exception
import dns.resolver
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.security.ssrf import validate_ip

HOST = "example.com"


def observation(operation):
    try:
        addresses = sorted(set(validate_ip(str(ip)) for ip in operation()))
        return {"status": "COMPLETE" if addresses else "NO_ANSWER", "public_addresses": addresses}
    except dns.resolver.NoAnswer:
        return {"status": "NO_ANSWER"}
    except (dns.exception.Timeout, TimeoutError):
        return {"status": "TIMEOUT"}
    except Exception as exc:
        # Never print upstream exception text, network credentials or user inputs.
        return {"status": "FAILED", "error_type": type(exc).__name__}


def system_observation():
    result = queue.Queue(maxsize=1)
    worker = threading.Thread(target=lambda: result.put(observation(lambda: [row[4][0] for row in socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)])), daemon=True)
    worker.start()
    try:
        return result.get(timeout=4)
    except queue.Empty:
        return {"status": "TIMEOUT"}


def main():
    print(json.dumps({"host": HOST, "system_getaddrinfo": system_observation()}), flush=True)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 3.0
    print(json.dumps({"configured_resolver_count": len(resolver.nameservers)}), flush=True)
    for tcp in (False, True):
        for record in ("A", "AAAA"):
            result = observation(lambda: resolver.resolve(HOST, record, tcp=tcp, search=False, lifetime=3.0))
            print(json.dumps({"transport": "TCP" if tcp else "UDP", "record": record, **result}), flush=True)
    print("Diagnostics only: no DNS fallback, policy change, target connection, scan, storage write or chain operation was performed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit("DNS diagnostics failed: " + type(exc).__name__) from None
