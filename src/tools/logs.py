"""Log analysis tools for pfSense MCP server."""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from ..helpers import VALID_LOG_TYPES, parse_filterlog_entry, validate_ip_address
from ..models import QueryFilter
from ..server import get_api_client, logger, mcp
from mcp.types import ToolAnnotations

# SIP signaling ports. RTP (10000-20000) and STUN (3478) are checked via range test.
_SIP_PORTS = {"5060", "5061"}
_STUN_PORTS = {"3478"}
_RTP_LOW = 10000
_RTP_HIGH = 20000


def _classify_voip_port(port: str) -> Optional[str]:
    """Return VOIP traffic type for a port string, or None if not VOIP."""
    if port in _SIP_PORTS:
        return "SIP"
    if port in _STUN_PORTS:
        return "STUN/TURN"
    try:
        p = int(port)
        if _RTP_LOW <= p <= _RTP_HIGH:
            return "RTP"
    except ValueError:
        pass
    return None


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def get_firewall_log(
    lines: int = 20,
    action_filter: Optional[str] = None,
    interface: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_port: Optional[str] = None,
    protocol: Optional[str] = None,
) -> Dict:
    """Get firewall log entries with optional filtering

    Args:
        lines: Number of log lines to retrieve (default 20, max 50)
        action_filter: Filter by action (pass, block, reject)
        interface: Filter by interface (wan, lan, etc.)
        source_ip: Filter by source IP address
        destination_ip: Filter by destination IP address
        destination_port: Filter by destination port
        protocol: Filter by protocol (tcp, udp, icmp)
    """
    client = get_api_client()
    try:
        # The pfSense firewall log model only has a single 'text' field
        # containing the raw log line. We can only filter on text__contains
        # server-side, then do further filtering client-side.
        filters = []

        # Build a text-based server-side filter from the most specific param
        text_search = source_ip or destination_ip or destination_port or action_filter
        if text_search:
            filters.append(QueryFilter("text", text_search, "contains"))

        # Log endpoints don't support sort_by — logs are returned in
        # reverse chronological order by pfSense already
        safe_lines = max(1, min(lines, 50))
        logs = await client.get_firewall_logs(
            lines=safe_lines,
            filters=filters if filters else None,
        )

        # Client-side filtering using parsed filterlog fields for precision.
        # Falls back to substring matching for lines that cannot be parsed.
        entries = logs.get("data") or []
        if entries:
            def _matches(entry):
                text = entry.get("text", "")
                parsed = parse_filterlog_entry(text)
                if parsed:
                    if action_filter and parsed.get("action", "").lower() != action_filter.lower():
                        return False
                    if interface and parsed.get("interface", "").lower() != interface.lower():
                        return False
                    if source_ip and parsed.get("src_ip", "") != source_ip:
                        return False
                    if destination_ip and parsed.get("dst_ip", "") != destination_ip:
                        return False
                    if destination_port and parsed.get("dst_port", "") != destination_port:
                        return False
                    if protocol and parsed.get("protocol", "").lower() != protocol.lower():
                        return False
                else:
                    # Fallback: raw text substring match for non-filterlog lines
                    if action_filter and action_filter.lower() not in text.lower():
                        return False
                    if interface and interface.lower() not in text.lower():
                        return False
                    if source_ip and source_ip not in text:
                        return False
                    if destination_ip and destination_ip not in text:
                        return False
                    if destination_port and destination_port not in text:
                        return False
                    if protocol and protocol.lower() not in text.lower():
                        return False
                return True
            entries = [e for e in entries if _matches(e)]
            logs["data"] = entries

        return {
            "success": True,
            "lines_requested": safe_lines,
            "filters_applied": {
                "action": action_filter,
                "interface": interface,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": protocol,
            },
            "count": len(logs.get("data") or []),
            "log_entries": logs.get("data") or [],
            "links": client.extract_links(logs),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get firewall log: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def analyze_blocked_traffic(
    limit: int = 20,
    group_by_source: bool = True
) -> Dict:
    """Analyze blocked traffic patterns from firewall logs.

    Retrieves recent blocked log entries and groups them by source IP,
    showing hit counts, destination IPs, and a simple threat score.
    Firewall logs are raw text — IPs are extracted via pattern matching.

    Args:
        limit: Number of recent blocked entries to analyze (max 50)
        group_by_source: Group results by source IP with threat scoring
    """
    client = get_api_client()
    try:
        # Get blocked traffic logs (already reverse-chronological)
        safe_limit = max(1, min(limit, 50))
        logs = await client.get_blocked_traffic_logs(lines=safe_limit)

        log_data = logs.get("data") or []

        if group_by_source:
            # Parse structured fields from the raw filterlog CSV format.
            # This correctly extracts src_ip/dst_ip by field position rather
            # than fragile regex ordering, and supports both IPv4 and IPv6.

            source_stats: dict = {}
            for entry in log_data:
                text = entry.get("text", "")
                parsed = parse_filterlog_entry(text)
                src_ip = parsed.get("src_ip", "unknown") if parsed else "unknown"
                dst_ip = parsed.get("dst_ip") if parsed else None

                if src_ip not in source_stats:
                    source_stats[src_ip] = {
                        "count": 0,
                        "destinations": set(),
                        "sample_line": "",
                    }

                source_stats[src_ip]["count"] += 1
                if dst_ip:
                    source_stats[src_ip]["destinations"].add(dst_ip)
                if not source_stats[src_ip]["sample_line"]:
                    source_stats[src_ip]["sample_line"] = text[:200]

            # Convert sets to lists and add threat score (0-10 heuristic: count/5, capped)
            for stats in source_stats.values():
                stats["destinations"] = sorted(stats["destinations"])
                stats["threat_score"] = round(min(10, stats["count"] / 5), 1)

            sorted_sources = sorted(
                source_stats.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )

            analysis = {
                "grouped_by": "source_ip",
                "total_unique_sources": len(source_stats),
                "top_sources": dict(sorted_sources[:20])
            }
        else:
            analysis = {
                "grouped_by": "none",
                "raw_entries": log_data
            }

        return {
            "success": True,
            "entries_analyzed_limit": safe_limit,
            "total_entries_analyzed": len(log_data),
            "analysis": analysis,
            "links": client.extract_links(logs),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to analyze blocked traffic: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def analyze_voip_sessions(
    lines: int = 50,
    interface: Optional[str] = None,
) -> Dict:
    """Analyze firewall logs for VOIP traffic patterns to diagnose call dropouts.

    Scans the firewall log for SIP signaling (UDP 5060/5061), RTP media
    (UDP 10000-20000), and STUN/TURN WebRTC traffic (UDP 3478), then surfaces:
    - Pass vs block counts per traffic type
    - Blocked VOIP entries (the most common cause of random call dropouts)
    - A timeline of VOIP log events for correlation with reported outage windows

    Firewall logging for VOIP traffic must be enabled on your pass rules (or on
    the VOIP floating rules created by setup_voip_qos) for entries to appear here.
    If blocked counts are zero and calls still drop, the issue is likely network
    congestion upstream of pfSense — use setup_voip_qos to prioritize the traffic.

    Args:
        lines: Number of recent log lines to scan (max 50)
        interface: Optional interface filter (wan, lan, etc.)
    """
    client = get_api_client()
    try:
        safe_lines = max(1, min(lines, 50))
        logs = await client.get_firewall_logs(lines=safe_lines)
        entries = logs.get("data") or []

        voip_entries: List[Dict] = []
        blocked_voip: List[Dict] = []
        type_counts: Dict[str, Dict[str, int]] = {}

        for entry in entries:
            text = entry.get("text", "")
            parsed = parse_filterlog_entry(text)
            if not parsed:
                continue

            if interface and parsed.get("interface", "").lower() != interface.lower():
                continue

            # Check source and destination ports for VOIP classification
            voip_type = _classify_voip_port(parsed.get("dst_port", "")) or \
                        _classify_voip_port(parsed.get("src_port", ""))
            if not voip_type:
                continue

            action = parsed.get("action", "pass").lower()
            record = {
                "voip_type": voip_type,
                "action": action,
                "interface": parsed.get("interface"),
                "protocol": parsed.get("protocol"),
                "src_ip": parsed.get("src_ip"),
                "src_port": parsed.get("src_port"),
                "dst_ip": parsed.get("dst_ip"),
                "dst_port": parsed.get("dst_port"),
                "raw": text[:200],
            }
            voip_entries.append(record)

            if voip_type not in type_counts:
                type_counts[voip_type] = {"pass": 0, "block": 0, "other": 0}
            bucket = action if action in ("pass", "block") else "other"
            type_counts[voip_type][bucket] += 1

            if action in ("block", "reject"):
                blocked_voip.append(record)

        has_blocks = len(blocked_voip) > 0
        diagnosis = []
        if has_blocks:
            diagnosis.append(
                f"{len(blocked_voip)} VOIP packet(s) were BLOCKED — this is a likely "
                "cause of call dropouts. Check your firewall rules and ensure VOIP "
                "traffic is permitted on the relevant interfaces."
            )
        if not voip_entries:
            diagnosis.append(
                "No VOIP log entries found. Either VOIP traffic was not logged "
                "(enable 'log' on your VOIP pass rules or use setup_voip_qos) or "
                "no VOIP calls occurred in the sampled window."
            )
        if voip_entries and not has_blocks:
            diagnosis.append(
                "All logged VOIP traffic was passed. If calls still drop, the cause "
                "is likely upstream congestion — use setup_voip_qos to prioritize "
                "SIP/RTP traffic and prevent other traffic from starving calls."
            )

        return {
            "success": True,
            "lines_scanned": safe_lines,
            "interface_filter": interface,
            "voip_entries_found": len(voip_entries),
            "blocked_voip_count": len(blocked_voip),
            "traffic_type_summary": type_counts,
            "blocked_entries": blocked_voip,
            "all_voip_entries": voip_entries,
            "diagnosis": diagnosis,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Failed to analyze VOIP sessions: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def search_logs_by_ip(
    ip_address: str,
    log_type: str = "firewall",
    lines: int = 50,
) -> Dict:
    """Search logs for activity related to a specific IP address

    Args:
        ip_address: IP address to search for
        log_type: Type of logs to search (firewall, system, etc.)
        lines: Number of log lines to retrieve (default 50, max 50)
    """
    # Validate IP address format
    try:
        validate_ip_address(ip_address)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    client = get_api_client()
    try:
        safe_lines = max(1, min(lines, 50))
        if log_type == "firewall":
            # Firewall log model only has 'text' field — use text__contains
            logs = await client.get_logs_by_ip(ip_address, safe_lines)
        else:
            # Validate log_type against allowlist to prevent path traversal
            if log_type not in VALID_LOG_TYPES:
                return {
                    "success": False,
                    "error": f"Invalid log_type '{log_type}'. Must be one of: {', '.join(sorted(VALID_LOG_TYPES))}",
                }
            # Non-firewall log models may have a 'message' field
            filters = [QueryFilter("text", ip_address, "contains")]
            logs = await client.get_logs(
                log_type=log_type,
                lines=safe_lines,
                filters=filters,
            )

        log_entries = logs.get("data") or []

        # Pattern analysis on raw text lines
        # Firewall log entries are raw text; we search for keywords
        if log_type == "firewall" and log_entries:
            patterns = {
                "total_entries": len(log_entries),
                "blocked_count": 0,
                "allowed_count": 0,
            }

            for entry in log_entries:
                text = entry.get("text", "").lower()
                if "block" in text or "reject" in text:
                    patterns["blocked_count"] += 1
                elif "pass" in text:
                    patterns["allowed_count"] += 1
        else:
            patterns = None

        return {
            "success": True,
            "ip_address": ip_address,
            "log_type": log_type,
            "total_entries": len(log_entries),
            "patterns": patterns,
            "log_entries": log_entries,
            "links": client.extract_links(logs),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to search logs by IP: {e}")
        return {"success": False, "error": str(e)}
