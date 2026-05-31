"""Core engine for Wireshark MCP.

Wireshark has no native MCP, so this module drives the ``tshark`` CLI
(installed with Wireshark) to capture live traffic and parse PCAP files.

It contains three pieces:
    * validators       - small input checks
    * TsharkWrapper     - thin wrapper around the tshark executable
    * PCAPParser        - turns tshark output into structured analysis data
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

_PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")

# tshark field name reused across multiple extractors.
_FIELD_IP_SRC = "ip.src"


def validate_pcap_file(path: str) -> Tuple[bool, Optional[str]]:
    """Check that a PCAP file exists, is readable, has a sane extension and
    is not a path-traversal attempt."""
    if not path:
        return False, "File path is required"
    if ".." in path:
        return False, "Path traversal ('..') is not allowed"
    if not path.lower().endswith(_PCAP_EXTENSIONS):
        return False, "File should have a .pcap, .pcapng or .cap extension"
    if not os.path.isfile(path):
        return False, f"File not found: {path}"
    if not os.access(path, os.R_OK):
        return False, f"File is not readable: {path}"
    return True, None


# Characters that could break out of an argv element if a filter ever reached a
# shell. Comparison/boolean operators (>, <, &&, ||, ==) are valid Wireshark
# display-filter syntax and are safe because tshark is run with an explicit
# argv (never shell=True), so they are intentionally NOT rejected here.
_FILTER_DANGEROUS = (";", "`", "$(", "${", "\n", "\r", "|")


def validate_display_filter(expr: str) -> Tuple[bool, Optional[str]]:
    """Reject shell metacharacters in a Wireshark display filter (-Y)."""
    if not expr:
        return True, None
    if len(expr) > 1000:
        return False, "Display filter too long (max 1000 characters)"
    for token in _FILTER_DANGEROUS:
        if token in expr:
            return False, f"Invalid character in display filter: {token!r}"
    return True, None


def validate_interface(interface: str) -> Tuple[bool, Optional[str]]:
    """Validate a network interface name or numeric index."""
    if not interface:
        return False, "Interface is required"
    if interface.isdigit():
        return True, None
    if not re.match(r"^[a-zA-Z0-9\-_\.]+$", interface):
        return False, "Invalid interface name format"
    return True, None


def validate_duration(duration: int) -> Tuple[bool, Optional[str]]:
    """Validate capture duration in seconds (0-3600)."""
    if not isinstance(duration, int):
        return False, "Duration must be an integer"
    if duration < 0:
        return False, "Duration cannot be negative"
    if duration > 3600:
        return False, "Duration limited to 1 hour (3600 seconds)"
    return True, None


def validate_packet_count(count: int) -> Tuple[bool, Optional[str]]:
    """Validate a packet count limit (0 = unlimited, max 1,000,000)."""
    if not isinstance(count, int):
        return False, "Packet count must be an integer"
    if count < 0:
        return False, "Packet count cannot be negative"
    if count > 1_000_000:
        return False, "Packet count limited to 1,000,000"
    return True, None


def validate_bpf_filter(bpf_filter: str) -> Tuple[bool, Optional[str]]:
    """Basic sanity check on a Berkeley Packet Filter expression."""
    if not bpf_filter:
        return True, None
    if bpf_filter.count("(") != bpf_filter.count(")"):
        return False, "Unbalanced parentheses in BPF filter"
    if ";" in bpf_filter:
        return False, "Semicolons not allowed in BPF filter"
    return True, None


# ---------------------------------------------------------------------------
# tshark wrapper
# ---------------------------------------------------------------------------

class TsharkError(Exception):
    """Raised when a tshark command fails."""


class TsharkWrapper:
    """Thin wrapper around the tshark command-line tool."""

    _COMMON_PATHS = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"C:\Wireshark\tshark.exe",
    ]

    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_path = tshark_path or self._find_tshark()
        if not self.tshark_path:
            raise TsharkError(
                "tshark not found. Install Wireshark or pass an explicit path."
            )

    def _find_tshark(self) -> Optional[str]:
        """Locate tshark on PATH or in common install locations."""
        which = "where" if os.name == "nt" else "which"
        try:
            result = subprocess.run(
                [which, "tshark"], capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()[0]
        except Exception:
            pass

        for path in self._COMMON_PATHS:
            if os.path.exists(path):
                return path
        return None

    def list_interfaces(self) -> List[Dict[str, str]]:
        """Return available capture interfaces from ``tshark -D``."""
        try:
            result = subprocess.run(
                [self.tshark_path, "-D"],
                capture_output=True, text=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise TsharkError("Interface listing timed out")

        if result.returncode != 0:
            raise TsharkError(f"Failed to list interfaces: {result.stderr}")

        interfaces = []
        for line in result.stdout.strip().splitlines():
            parts = line.split(" ", 1)
            if len(parts) >= 2:
                idx = parts[0].rstrip(".")
                name = parts[1]
                interfaces.append(
                    {"index": idx, "name": name, "display": f"{idx}: {name}"}
                )
        return interfaces

    def capture_packets(
        self,
        interface: str,
        output_file: str,
        packet_count: int = 0,
        bpf_filter: str = "",
        duration: int = 0,
    ) -> Dict[str, Any]:
        """Capture packets to ``output_file`` and return basic stats."""
        cmd = [self.tshark_path, "-i", interface, "-w", output_file]
        if packet_count > 0:
            cmd += ["-c", str(packet_count)]
        if duration > 0:
            cmd += ["-a", f"duration:{duration}"]
        if bpf_filter:
            cmd += ["-f", bpf_filter]

        timeout = duration + 10 if duration > 0 else None
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0 and "Capturing" not in result.stderr:
                raise TsharkError(f"Capture failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            pass  # expected when a duration limit is hit

        if not os.path.exists(output_file):
            raise TsharkError("Capture produced no output file")

        size = os.path.getsize(output_file)
        return {"file": output_file, "size_bytes": size,
                "message": f"Captured {size} bytes"}

    def version(self) -> str:
        """Return the first line of ``tshark --version``."""
        out = self._run(["--version"], timeout=10)
        return out.strip().splitlines()[0] if out.strip() else "unknown"

    def _run(self, args: List[str], timeout: Optional[int] = 60) -> str:
        """Run tshark with an explicit argv (never via a shell) and return stdout."""
        try:
            result = subprocess.run(
                [self.tshark_path, *args],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise TsharkError("tshark command timed out")
        if result.returncode != 0:
            raise TsharkError(result.stderr.strip() or "tshark failed")
        return result.stdout

    def read_fields(
        self,
        pcap_file: str,
        fields: List[str],
        display_filter: str = "",
        limit: int = 0,
    ) -> List[Dict[str, str]]:
        """Read selected fields as rows using ``-T fields`` (tab separated).

        Returns a list of dicts keyed by field name. This is the correct,
        robust way to pull specific fields out of tshark (``-T csv`` is not a
        valid output type).
        """
        if not os.path.exists(pcap_file):
            raise TsharkError(f"PCAP file not found: {pcap_file}")

        args = ["-r", pcap_file]
        if display_filter:
            args += ["-Y", display_filter]
        args += ["-T", "fields"]
        for field in fields:
            args += ["-e", field]
        args += ["-E", "header=n", "-E", "separator=\t", "-E", "occurrence=f"]

        out = self._run(args)
        rows: List[Dict[str, str]] = []
        for line in out.splitlines():
            if not line.strip():
                continue
            values = line.split("\t")
            rows.append({f: (values[i] if i < len(values) else "")
                         for i, f in enumerate(fields)})
            if limit and len(rows) >= limit:
                break
        return rows

    def read_packets_json(
        self,
        pcap_file: str,
        display_filter: str = "",
        limit: int = 100,
    ) -> List[dict]:
        """Read full packet detail as parsed ``-T json`` (for previews)."""
        if not os.path.exists(pcap_file):
            raise TsharkError(f"PCAP file not found: {pcap_file}")

        args = ["-r", pcap_file, "-T", "json"]
        if display_filter:
            args += ["-Y", display_filter]
        else:
            args += ["-c", str(limit)]

        out = self._run(args)
        if not out.strip():
            return []
        try:
            packets = json.loads(out)
        except json.JSONDecodeError as exc:
            raise TsharkError(f"Could not parse tshark JSON: {exc}")
        if isinstance(packets, list):
            return packets[:limit]
        return [packets]

    def stat(self, pcap_file: str, z_arg: str) -> str:
        """Run a ``tshark -q -z <z_arg>`` aggregate report and return its text."""
        if not os.path.exists(pcap_file):
            raise TsharkError(f"PCAP file not found: {pcap_file}")
        return self._run(["-r", pcap_file, "-q", "-z", z_arg])

    def follow_stream(self, pcap_file: str, proto: str, stream_id: int) -> str:
        """Reassemble a TCP or UDP stream and return its ASCII payload."""
        if proto not in ("tcp", "udp"):
            raise TsharkError("proto must be 'tcp' or 'udp'")
        return self.stat(pcap_file, f"follow,{proto},ascii,{int(stream_id)}")

    def expert_info(self, pcap_file: str, severity: str = "warn") -> str:
        """Return tshark expert analysis at or above ``severity``."""
        if severity not in ("chat", "note", "warn", "error"):
            raise TsharkError("severity must be chat, note, warn or error")
        return self.stat(pcap_file, f"expert,{severity}")


# ---------------------------------------------------------------------------
# PCAP parser / analysis
# ---------------------------------------------------------------------------

class PCAPParser:
    """Parse and analyse PCAP files via :class:`TsharkWrapper`."""

    MALICIOUS_DOMAIN_KEYWORDS = {
        "botnet", "malware", "c2", "command", "control",
        "exfil", "ransomware", "trojan",
    }
    SUSPICIOUS_PORTS = {22, 23, 135, 139, 445, 3389, 5900,
                        4444, 5555, 6666, 7777, 8888, 9999}
    COMMON_PROTOCOLS = {
        "dns": "DNS", "http": "HTTP", "https": "HTTPS", "tcp": "TCP",
        "udp": "UDP", "icmp": "ICMP", "tls": "TLS/SSL", "ssh": "SSH",
        "ftp": "FTP", "smtp": "SMTP",
    }

    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark = TsharkWrapper(tshark_path)

    # -- DNS -----------------------------------------------------------------
    def extract_dns_queries(self, pcap_file: str) -> Dict[str, Any]:
        """Extract DNS queries and flag suspicious-looking domains."""
        rows = self.tshark.read_fields(
            pcap_file,
            fields=["dns.qry.name", "dns.qry.type", _FIELD_IP_SRC],
            display_filter="dns.flags.response == 0",
        )

        queries: Dict[str, list] = defaultdict(list)
        for row in rows:
            qname = row.get("dns.qry.name", "").strip()
            if not qname:
                continue
            queries[qname].append({"source_ip": row.get(_FIELD_IP_SRC, "")})

        unique_domains = set(queries)
        return {
            "total_queries": sum(len(v) for v in queries.values()),
            "unique_domains": len(unique_domains),
            "queries": dict(queries),
            "suspicious_domains": [
                d for d in sorted(unique_domains) if self._is_suspicious_domain(d)
            ],
        }

    # -- IPs -----------------------------------------------------------------
    def extract_ip_addresses(self, pcap_file: str) -> Dict[str, Any]:
        """Extract IPs, classify internal/external and tally ports."""
        rows = self.tshark.read_fields(
            pcap_file,
            fields=[_FIELD_IP_SRC, "ip.dst", "tcp.dstport", "udp.dstport"],
        )

        internal: set = set()
        external: set = set()
        ip_traffic: Dict[str, int] = defaultdict(int)
        port_traffic: Dict[int, int] = defaultdict(int)

        for row in rows:
            for ip in (row.get(_FIELD_IP_SRC, ""), row.get("ip.dst", "")):
                if ip:
                    ip_traffic[ip] += 1
                    (internal if self._is_private_ip(ip) else external).add(ip)
            for port in (row.get("tcp.dstport", ""), row.get("udp.dstport", "")):
                if port.isdigit():
                    port_traffic[int(port)] += 1

        return {
            "internal_ips": sorted(internal),
            "external_ips": sorted(external),
            "total_unique_ips": len(internal) + len(external),
            "ip_traffic_count": dict(ip_traffic),
            "suspicious_ports": [p for p in port_traffic if p in self.SUSPICIOUS_PORTS],
            "port_traffic": dict(port_traffic),
        }

    # -- Protocols -----------------------------------------------------------
    def get_protocol_breakdown(self, pcap_file: str) -> Dict[str, Any]:
        """Count how often each common protocol appears."""
        rows = self.tshark.read_fields(pcap_file, fields=["frame.protocols"])

        protocols: Counter = Counter()
        for row in rows:
            for proto in row.get("frame.protocols", "").split(":"):
                proto = proto.strip().lower()
                if proto in self.COMMON_PROTOCOLS:
                    protocols[self.COMMON_PROTOCOLS[proto]] += 1

        return {
            "protocols": dict(protocols),
            "most_common": protocols.most_common(5),
        }

    # -- IOCs / risk ---------------------------------------------------------
    def extract_iocs(self, pcap_file: str) -> Dict[str, Any]:
        """Combine DNS + IP data into indicators of compromise and a score."""
        dns = self.extract_dns_queries(pcap_file)
        ips = self.extract_ip_addresses(pcap_file)
        high_traffic = sorted(
            ips.get("ip_traffic_count", {}).items(),
            key=lambda kv: kv[1], reverse=True,
        )[:5]
        return {
            "suspicious_domains": dns.get("suspicious_domains", []),
            "suspicious_ports": ips.get("suspicious_ports", []),
            "external_ips": ips.get("external_ips", []),
            "high_traffic_ips": [ip for ip, _ in high_traffic],
            "risk_score": self._risk_score(dns, ips),
        }

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            return False
        o = [int(p) for p in parts]
        return (
            o[0] == 10
            or (o[0] == 172 and 16 <= o[1] <= 31)
            or (o[0] == 192 and o[1] == 168)
            or o[0] == 127
        )

    @classmethod
    def _is_suspicious_domain(cls, domain: str) -> bool:
        low = domain.lower()
        return any(k in low for k in cls.MALICIOUS_DOMAIN_KEYWORDS)

    @staticmethod
    def _risk_score(dns: Dict[str, Any], ips: Dict[str, Any]) -> float:
        score = 0.0
        score += min(len(dns.get("suspicious_domains", [])) * 0.5, 3.0)
        score += min(len(ips.get("suspicious_ports", [])) * 0.3, 2.0)
        external = len(ips.get("external_ips", []))
        if external > 10:
            score += 2.0
        elif external > 5:
            score += 1.0
        return round(min(score, 10.0), 2)


def threat_level(risk_score: float) -> str:
    """Map a 0-10 risk score to a human-readable level."""
    if risk_score >= 8.0:
        return "CRITICAL"
    if risk_score >= 6.0:
        return "HIGH"
    if risk_score >= 4.0:
        return "MEDIUM"
    if risk_score >= 2.0:
        return "LOW"
    return "INFO"
