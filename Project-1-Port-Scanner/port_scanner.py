"""
CODTECH Cybersecurity Internship
Project 1: TCP Port Scanner

Features:
- Scans TCP ports on an authorized target.
- Supports IP addresses and hostnames.
- Allows custom port ranges.
- Uses multithreading for faster scanning.
- Identifies common services by port number.
- Saves results automatically to a text report.

IMPORTANT:
Only scan systems you own or have explicit permission to test.
"""

import socket
import ipaddress
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


# Common TCP services
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "Microsoft RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}


def validate_target(target):
    """Validate an IP address or resolve a hostname."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except (socket.gaierror, OSError):
            raise ValueError(
                "Target could not be resolved. Check the IP address or hostname."
            )


def scan_port(target_ip, port, timeout=0.3):
    """Check whether a TCP port accepts a connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            return result == 0
    except OSError:
        return False


def save_report(report):
    """Save the scan report in the scan_results directory."""
    os.makedirs("scan_results", exist_ok=True)

    filename = datetime.now().strftime(
        "scan_results/scan_%Y%m%d_%H%M%S.txt"
    )

    with open(filename, "w", encoding="utf-8") as file:
        file.write(report)

    return filename


def main():
    print("\n" + "=" * 55)
    print("             CODTECH TCP PORT SCANNER")
    print("=" * 55)
    print("Only scan systems you own or are authorized to test.\n")

    target = input(
        "Enter target IP address or hostname [127.0.0.1]: "
    ).strip()

    if not target:
        target = "127.0.0.1"

    try:
        target_ip = validate_target(target)
    except ValueError as error:
        print(f"\nError: {error}")
        return

    try:
        start_port = int(input("Starting port [1]: ") or "1")
        end_port = int(input("Ending port [1024]: ") or "1024")
    except ValueError:
        print("\nError: Enter port numbers using digits only.")
        return

    # Validate port range
    if not (
        1 <= start_port <= 65535
        and 1 <= end_port <= 65535
    ):
        print("\nError: Ports must be between 1 and 65535.")
        return

    if start_port > end_port:
        print("\nError: Starting port cannot exceed ending port.")
        return

    if end_port - start_port + 1 > 5000:
        print("\nError: Scan a maximum of 5000 ports per run.")
        return

    timeout = 0.3
    started = datetime.now()

    print("\n" + "=" * 55)
    print(f"Target entered : {target}")
    print(f"Resolved IP    : {target_ip}")
    print(f"Port range     : {start_port}-{end_port}")
    print("Scan status    : Running...")
    print("=" * 55)

    open_ports = []

    def check_port(port):
        """Return the port and whether it is open."""
        return port, scan_port(target_ip, port, timeout)

    # Scan multiple ports concurrently
    try:
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(
                check_port,
                range(start_port, end_port + 1)
            )

            for port, is_open in results:
                if is_open:
                    service = COMMON_SERVICES.get(
                        port, "Unknown"
                    )

                    open_ports.append((port, service))

                    print(
                        f"[OPEN] Port {port:<5} "
                        f"Service: {service}"
                    )

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return

    elapsed = (datetime.now() - started).total_seconds()

    # Sort results by port number
    open_ports.sort(key=lambda item: item[0])

    if not open_ports:
        print("\nNo open TCP ports were detected in this range.")

    # Prepare the report
    report_lines = [
        "CODTECH TCP PORT SCANNER REPORT",
        "=" * 45,
        f"Target entered: {target}",
        f"Resolved IP: {target_ip}",
        f"Scan started: {started.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Port range: {start_port}-{end_port}",
        f"Open ports found: {len(open_ports)}",
        f"Duration: {elapsed:.2f} seconds",
        "",
        "OPEN PORTS",
        "-" * 45,
    ]

    if open_ports:
        for port, service in open_ports:
            report_lines.append(
                f"Port {port}: {service}"
            )
    else:
        report_lines.append(
            "No open TCP ports detected in the selected range."
        )

    report_lines.extend([
        "",
        "NOTES",
        "-" * 45,
        "This report records TCP connection scan results.",
        "A detected open port does not automatically indicate a vulnerability.",
        "Service names are inferred from common port assignments.",
        "Results may vary depending on firewall and network settings.",
        "Scan only systems you own or have permission to test.",
    ])

    report = "\n".join(report_lines)

    try:
        report_path = save_report(report)
    except OSError as error:
        print(f"\nCould not save report: {error}")
        return

    # Display summary
    print("\n" + "=" * 55)
    print("                  SCAN SUMMARY")
    print("=" * 55)
    print(f"Target          : {target_ip}")
    print(f"Ports scanned   : {end_port - start_port + 1}")
    print(f"Open ports found: {len(open_ports)}")
    print(f"Duration        : {elapsed:.2f} seconds")
    print(f"Report saved to : {report_path}")
    print("=" * 55)
    print("Scan completed successfully.\n")


if __name__ == "__main__":
    main()
