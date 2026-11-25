#!/usr/bin/env python3
"""Scan a host for open TCP ports.

Tries a TCP connect to each port in the given range (or list) and
reports which ports are open. Uses threads for speed. Only scan hosts
you own or have permission to scan.
"""
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_one(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except (OSError, socket.timeout):
        return port, False


def main():
    parser = argparse.ArgumentParser(
        description="Scan a host for open TCP ports.")
    parser.add_argument("host", nargs="?", default="127.0.0.1",
                        help="Host to scan (default: 127.0.0.1)")
    parser.add_argument("--ports", default="1-1024",
                        help="Ports to scan: range '1-1024', list '22,80,443', "
                             "or 'common' (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Connection timeout in seconds (default: 0.5)")
    parser.add_argument("--workers", type=int, default=100,
                        help="Parallel connection threads (default: 100)")
    parser.add_argument("--open-only", action="store_true",
                        help="Only list open ports (default behaviour)")
    parser.add_argument("--show-closed", action="store_true",
                        help="Also list closed ports")
    args = parser.parse_args()

    if args.ports == "common":
        ports = sorted(COMMON_PORTS)
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print("Error: --ports must be like '22,80,443' or '1-1024'",
                  file=sys.stderr)
            return 1
    if not ports:
        print("Error: no valid ports to scan", file=sys.stderr)
        return 1

    try:
        target = socket.gethostbyname(args.host)
    except socket.gaierror as exc:
        print(f"Error: cannot resolve host {args.host}: {exc}", file=sys.stderr)
        return 1

    print(f"Scanning {args.host} ({target}): {len(ports)} port(s)...")
    open_ports, closed = [], []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(scan_one, target, p, args.timeout): p
                   for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            (open_ports if is_open else closed).append(port)

    open_ports.sort()
    if open_ports:
        print(f"\nOpen ({len(open_ports)}):")
        for port in open_ports:
            service = COMMON_PORTS.get(port, "")
            print(f"  {port}/tcp  open  {service}")
    else:
        print("\nNo open ports found.")
    if args.show_closed:
        print(f"\nClosed ({len(sorted(closed))}): {', '.join(map(str, sorted(closed)))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
