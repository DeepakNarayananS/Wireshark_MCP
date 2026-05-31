"""Wireshark MCP server.

Wireshark itself has no built-in MCP, so this server exposes the ``tshark``
CLI (bundled with Wireshark) as a small set of MCP tools for capturing and
analysing network traffic.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

from fastmcp import FastMCP

from .tshark import (
    PCAPParser,
    TsharkError,
    TsharkWrapper,
    threat_level,
    validate_bpf_filter,
    validate_display_filter,
    validate_duration,
    validate_interface,
    validate_packet_count,
    validate_pcap_file,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("wireshark-mcp")

mcp = FastMCP("wireshark-mcp")


# Curated default field sets for decode_protocol, keyed by protocol token.
# Each value is the handful of fields an analyst would jot down when triaging
# that protocol. frame.number comes first for ordering.
_PROTOCOL_FIELDS = {
    "http": ["frame.number", "ip.src", "ip.dst", "http.request.method",
             "http.request.uri", "http.host", "http.response.code"],
    "dns": ["frame.number", "ip.src", "ip.dst", "dns.flags.response",
            "dns.qry.name", "dns.qry.type", "dns.a"],
    "tls": ["frame.number", "ip.src", "ip.dst", "tls.handshake.type",
            "tls.handshake.extensions_server_name"],
    "icmp": ["frame.number", "ip.src", "ip.dst", "icmp.type", "icmp.code"],
    "arp": ["frame.number", "arp.opcode", "arp.src.proto_ipv4",
            "arp.dst.proto_ipv4", "arp.src.hw_mac"],
}
# Protocols whose base filter differs from the bare token.
_PROTOCOL_BASE_FILTER = {"http": "http.request or http.response",
                         "tls": "tls.handshake"}


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

@mcp.tool
def check_installation() -> dict:
    """Check that tshark is installed and return its path and version."""
    try:
        tshark = TsharkWrapper()
        return {"status": "success", "tshark_path": tshark.tshark_path,
                "version": tshark.version()}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

@mcp.tool
def list_network_interfaces() -> dict:
    """List available network interfaces for packet capture."""
    try:
        interfaces = TsharkWrapper().list_interfaces()
        return {"status": "success", "count": len(interfaces),
                "interfaces": interfaces}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def capture_packets(
    interface: str,
    duration: int = 30,
    packet_count: int = 0,
    bpf_filter: str = "",
) -> dict:
    """Capture live traffic from an interface to a PCAP file.

    Args:
        interface: Interface name or index (see list_network_interfaces).
        duration: Capture length in seconds (0-3600, default 30).
        packet_count: Max packets to capture (0 = unlimited).
        bpf_filter: Optional capture filter, e.g. 'tcp port 80'.
    """
    for valid, error in (
        validate_interface(interface),
        validate_duration(duration),
        validate_packet_count(packet_count),
        validate_bpf_filter(bpf_filter),
    ):
        if not valid:
            return {"status": "failed", "error": error}

    if duration == 0 and packet_count == 0:
        duration = 30

    output_dir = os.path.expanduser(os.path.join("~", "Documents", "Wireshark_Captures"))
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(
        output_dir, f"capture_{datetime.now():%Y%m%d_%H%M%S}.pcap"
    )

    try:
        result = TsharkWrapper().capture_packets(
            interface=interface, output_file=output_file,
            packet_count=packet_count, bpf_filter=bpf_filter, duration=duration,
        )
        return {"status": "success", "interface": interface,
                "duration": duration, "filter": bpf_filter, **result}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

@mcp.tool
def analyze_pcap(pcap_file: str) -> dict:
    """Run a combined DNS, IP and protocol analysis on a PCAP file."""
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    try:
        parser = PCAPParser()
        dns = parser.extract_dns_queries(pcap_file)
        ips = parser.extract_ip_addresses(pcap_file)
        protocols = parser.get_protocol_breakdown(pcap_file)
        return {
            "status": "success", "file": pcap_file,
            "dns": dns, "ip_addresses": ips, "protocols": protocols,
            "summary": {
                "total_dns_queries": dns.get("total_queries", 0),
                "unique_domains": dns.get("unique_domains", 0),
                "internal_ips": len(ips.get("internal_ips", [])),
                "external_ips": len(ips.get("external_ips", [])),
                "top_protocol": (protocols.get("most_common") or [("Unknown", 0)])[0][0],
            },
        }
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def extract_dns_queries(pcap_file: str) -> dict:
    """Extract DNS queries from a PCAP file."""
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    try:
        return {"status": "success", "file": pcap_file,
                "data": PCAPParser().extract_dns_queries(pcap_file)}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def extract_ip_addresses(pcap_file: str) -> dict:
    """Extract IP addresses and communication patterns from a PCAP file."""
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    try:
        return {"status": "success", "file": pcap_file,
                "data": PCAPParser().extract_ip_addresses(pcap_file)}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def get_protocol_statistics(pcap_file: str) -> dict:
    """Get the protocol distribution of a PCAP file."""
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    try:
        return {"status": "success", "file": pcap_file,
                "data": PCAPParser().get_protocol_breakdown(pcap_file)}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def apply_display_filter(pcap_file: str, filter: str, packet_count: int = 20) -> dict:
    """Apply a Wireshark display filter to a PCAP and preview matching packets.

    Args:
        pcap_file: Path to the .pcap/.pcapng file.
        filter: Wireshark display filter, e.g. 'http.request', 'tcp.port == 443'.
        packet_count: Max packets to return (default 20, capped at 200).
    """
    for valid, error in (validate_pcap_file(pcap_file), validate_display_filter(filter)):
        if not valid:
            return {"status": "failed", "error": error}
    packet_count = max(1, min(packet_count, 200))
    try:
        packets = PCAPParser().tshark.read_packets_json(
            pcap_file, display_filter=filter, limit=packet_count
        )
        return {"status": "success", "file": pcap_file, "filter": filter,
                "matched": len(packets), "packets": packets}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def decode_protocol(
    pcap_file: str,
    protocol: str,
    fields: list[str] | None = None,
    filter: str = "",
    packet_count: int = 50,
) -> dict:
    """Extract protocol fields as a compact table (token-efficient view).

    Args:
        pcap_file: Path to the .pcap/.pcapng file.
        protocol: Known protocol with curated fields (http, dns, tls, icmp, arp)
            or any Wireshark display filter when you also pass `fields`.
        fields: Optional explicit field list (max 20). Required for protocols
            without curated defaults.
        filter: Optional extra display filter ANDed with the protocol filter.
        packet_count: Max rows to return (default 50, capped at 200).
    """
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}

    key = protocol.strip().lower()
    if fields:
        if len(fields) > 20:
            return {"status": "failed", "error": "Maximum 20 fields allowed"}
        use_fields = fields
        base_filter = protocol
    elif key in _PROTOCOL_FIELDS:
        use_fields = _PROTOCOL_FIELDS[key]
        base_filter = _PROTOCOL_BASE_FILTER.get(key, key)
    else:
        return {"status": "failed",
                "error": f"Protocol '{protocol}' has no curated fields; "
                         f"pass an explicit 'fields' list. "
                         f"Known: {', '.join(sorted(_PROTOCOL_FIELDS))}"}

    for valid, error in (validate_display_filter(base_filter),
                         validate_display_filter(filter)):
        if not valid:
            return {"status": "failed", "error": error}
    combined = f"({base_filter}) and ({filter})" if filter else base_filter
    packet_count = max(1, min(packet_count, 200))

    try:
        rows = PCAPParser().tshark.read_fields(
            pcap_file, fields=use_fields, display_filter=combined, limit=packet_count
        )
        return {"status": "success", "file": pcap_file, "protocol": protocol,
                "filter": combined, "fields": use_fields,
                "count": len(rows), "rows": rows}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def follow_stream(pcap_file: str, protocol: str = "tcp", stream_id: int = 0) -> dict:
    """Reassemble a TCP or UDP stream and return its ASCII payload.

    Args:
        pcap_file: Path to the .pcap/.pcapng file.
        protocol: 'tcp' or 'udp'.
        stream_id: Stream index to follow (default 0).
    """
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    if protocol not in ("tcp", "udp"):
        return {"status": "failed", "error": "protocol must be 'tcp' or 'udp'"}
    try:
        payload = PCAPParser().tshark.follow_stream(pcap_file, protocol, stream_id)
        return {"status": "success", "file": pcap_file, "protocol": protocol,
                "stream_id": stream_id, "payload": payload.strip()}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


@mcp.tool
def expert_info(pcap_file: str, severity: str = "warn") -> dict:
    """Run tshark expert analysis (anomalies, warnings, errors) on a PCAP.

    Args:
        pcap_file: Path to the .pcap/.pcapng file.
        severity: Minimum severity to report: chat, note, warn or error.
    """
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    if severity not in ("chat", "note", "warn", "error"):
        return {"status": "failed",
                "error": "severity must be chat, note, warn or error"}
    try:
        report = PCAPParser().tshark.expert_info(pcap_file, severity)
        return {"status": "success", "file": pcap_file, "severity": severity,
                "report": report.strip() or "No expert info entries found."}
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


# ---------------------------------------------------------------------------
# Threat detection
# ---------------------------------------------------------------------------

@mcp.tool
def detect_threats(pcap_file: str) -> dict:
    """Detect indicators of compromise and assign a risk score."""
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    try:
        iocs = PCAPParser().extract_iocs(pcap_file)
        return {
            "status": "success", "file": pcap_file,
            "indicators": {
                "suspicious_domains": iocs["suspicious_domains"],
                "suspicious_ports": iocs["suspicious_ports"],
                "external_ips": iocs["external_ips"],
                "high_traffic_ips": iocs["high_traffic_ips"],
            },
            "risk_assessment": {
                "overall_risk_score": iocs["risk_score"],
                "threat_level": threat_level(iocs["risk_score"]),
            },
        }
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

@mcp.tool
def generate_security_report(pcap_file: str) -> dict:
    """Generate a security-focused report with findings and mitigations."""
    valid, error = validate_pcap_file(pcap_file)
    if not valid:
        return {"status": "failed", "error": error}
    try:
        parser = PCAPParser()
        iocs = parser.extract_iocs(pcap_file)
        dns = parser.extract_dns_queries(pcap_file)
        ips = parser.extract_ip_addresses(pcap_file)

        mitigations = []
        if iocs["suspicious_domains"]:
            mitigations.append("Enable DNS filtering/blocking for flagged domains")
        if iocs["suspicious_ports"]:
            mitigations.append("Add firewall rules for the suspicious ports")
        if iocs["external_ips"]:
            mitigations.append("Apply egress filtering on external connections")
        mitigations.append("Enable endpoint detection and response (EDR)")

        return {
            "status": "success",
            "report": {
                "timestamp": datetime.now().isoformat(),
                "pcap_file": pcap_file,
                "risk_level": threat_level(iocs["risk_score"]),
                "risk_score": iocs["risk_score"],
                "findings": {
                    "total_dns_queries": dns.get("total_queries", 0),
                    "unique_domains": dns.get("unique_domains", 0),
                    "internal_ips": len(ips.get("internal_ips", [])),
                    "external_ips": len(ips.get("external_ips", [])),
                    "suspicious_domains": iocs["suspicious_domains"],
                    "suspicious_ports": iocs["suspicious_ports"],
                },
                "mitigations": mitigations,
            },
        }
    except TsharkError as exc:
        return {"status": "failed", "error": str(exc)}


def main() -> None:
    """Entry point used by ``python -m wireshark_mcp.server``."""
    logger.info("Starting Wireshark MCP server")
    mcp.run()


if __name__ == "__main__":
    main()
