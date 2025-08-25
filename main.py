#!/usr/bin/env python3
"""VirusTotal MCP Server - VirusTotal Model Context Protocol server."""

import asyncio
import base64
import os
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP

load_dotenv()

# Configuration
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable is required")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Initialize FastMCP server
mcp = FastMCP("VirusTotal MCP Server")

# HTTP client for VirusTotal API
client = httpx.AsyncClient(
    base_url=VT_BASE_URL, headers={"x-apikey": API_KEY}, timeout=30.0
)


def encode_url_for_vt(url: str) -> str:
    """Encode URL for VirusTotal API."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def query_virustotal(
    endpoint: str, method: str = "GET", data: Optional[Dict] = None
) -> Dict[str, Any]:
    """Query VirusTotal API."""
    try:
        if method.upper() == "POST":
            response = await client.post(endpoint, data=data)
        else:
            response = await client.get(endpoint)

        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as exc:
        raise ValueError(f"VirusTotal API error: {str(exc)}") from exc


def format_scan_results(data: Dict[str, Any], scan_type: str) -> str:
    """Format scan results for display."""
    output = [f"# {scan_type.title()} Analysis Report\n"]

    # Basic info
    if "attributes" in data:
        attrs = data["attributes"]
        if "last_analysis_stats" in attrs:
            stats = attrs["last_analysis_stats"]
            output.append("**Detection Summary:**")
            output.append(f"- Malicious: {stats.get('malicious', 0)}")
            output.append(f"- Suspicious: {stats.get('suspicious', 0)}")
            output.append(f"- Clean: {stats.get('harmless', 0)}")
            output.append(f"- Undetected: {stats.get('undetected', 0)}")
            output.append("")

    # Relationships
    if "relationships" in data:
        output.append("**Relationship Data:**")
        for rel_type, rel_data in data["relationships"].items():
            if "data" in rel_data:
                items = rel_data["data"]
                if isinstance(items, list) and len(items) > 0:
                    output.append(
                        f"- {rel_type.replace('_', ' ').title()}: {len(items)} items"
                    )
                elif items:
                    output.append(f"- {rel_type.replace('_', ' ').title()}: 1 item")
        output.append("")

    return "\n".join(output)


@mcp.tool()
async def get_url_report(url: str) -> str:
    """Get comprehensive URL analysis report with security results and relationships.

    Args:
        url: The URL to analyze

    Returns:
        str: Formatted analysis report with detection summary and relationships
    """
    encoded_url = encode_url_for_vt(url)

    # Submit URL for scanning
    scan_data = await query_virustotal("/urls", "POST", {"url": url})
    analysis_id = scan_data["data"]["id"]

    # Wait for analysis
    await asyncio.sleep(3)

    # Get analysis results
    analysis = await query_virustotal(f"/analyses/{analysis_id}")

    # Fetch key relationships
    relationships = {}
    default_rels = [
        "communicating_files",
        "contacted_domains",
        "contacted_ips",
        "downloaded_files",
        "redirects_to",
        "related_threat_actors",
    ]

    for rel_type in default_rels:
        try:
            rel_data = await query_virustotal(f"/urls/{encoded_url}/{rel_type}")
            relationships[rel_type] = rel_data
        except (httpx.HTTPError, KeyError, ValueError):
            continue

    result_data = {
        "attributes": analysis["data"]["attributes"],
        "relationships": relationships,
        "url": url,
    }

    return format_scan_results(result_data, "URL")


@mcp.tool()
async def get_file_report(file_hash: str) -> str:
    """Get a comprehensive file analysis report using its hash.

    Args:
        file_hash: MD5, SHA-1 or SHA-256 hash of the file

    Returns:
        str: Formatted analysis report with detection summary and relationships
    """

    # Get file report
    file_data = await query_virustotal(f"/files/{file_hash}")

    # Fetch key relationships
    relationships = {}
    default_rels = [
        "behaviours",
        "dropped_files",
        "contacted_domains",
        "contacted_ips",
        "embedded_urls",
        "related_threat_actors",
    ]

    for rel_type in default_rels:
        try:
            rel_data = await query_virustotal(f"/files/{file_hash}/{rel_type}")
            relationships[rel_type] = rel_data
        except (httpx.HTTPError, KeyError, ValueError):
            continue

    result_data = {
        "attributes": file_data["data"]["attributes"],
        "relationships": relationships,
        "hash": file_hash,
    }

    return format_scan_results(result_data, "File")


@mcp.tool()
async def get_ip_report(ip: str) -> str:
    """Get a comprehensive IP address analysis report.

    Args:
        ip: IP address to analyze

    Returns:
        str: Formatted analysis report with detection summary and relationships
    """

    # Get IP report
    ip_data = await query_virustotal(f"/ip_addresses/{ip}")

    # Fetch key relationships
    relationships = {}
    default_rels = [
        "communicating_files",
        "historical_ssl_certificates",
        "resolutions",
        "related_threat_actors",
    ]

    for rel_type in default_rels:
        try:
            rel_data = await query_virustotal(f"/ip_addresses/{ip}/{rel_type}")
            relationships[rel_type] = rel_data
        except (httpx.HTTPError, KeyError, ValueError):
            continue

    result_data = {
        "attributes": ip_data["data"]["attributes"],
        "relationships": relationships,
        "ip": ip,
    }

    return format_scan_results(result_data, "IP")


@mcp.tool()
async def get_domain_report(
    domain: str, relationships: Optional[List[str]] = None
) -> str:
    """Get a comprehensive domain analysis report.

    Args:
        domain: Domain name to analyze
        relationships: Optional list of specific relationships to include

    Returns:
        str: Formatted analysis report with detection summary and relationships
    """

    # Get domain report
    domain_data = await query_virustotal(f"/domains/{domain}")

    # Fetch key relationships
    rel_data = {}
    default_rels = relationships or [
        "subdomains",
        "historical_ssl_certificates",
        "resolutions",
        "related_threat_actors",
    ]

    for rel_type in default_rels:
        try:
            rel_response = await query_virustotal(f"/domains/{domain}/{rel_type}")
            rel_data[rel_type] = rel_response
        except (httpx.HTTPError, KeyError, ValueError):
            continue

    result_data = {
        "attributes": domain_data["data"]["attributes"],
        "relationships": rel_data,
        "domain": domain,
    }

    return format_scan_results(result_data, "Domain")


@mcp.tool()
async def get_url_relationship(
    url: str, relationship: str, limit: int = 10, cursor: Optional[str] = None
) -> str:
    """Query a specific relationship type for a URL with pagination support.

    Args:
        url: The URL to get relationships for
        relationship: Type of relationship to query
        limit: Maximum number of related objects to retrieve (1-40)
        cursor: Continuation cursor for pagination

    Returns:
        str: Formatted relationship data
    """
    encoded_url = encode_url_for_vt(url)

    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    endpoint = f"/urls/{encoded_url}/{relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {relationship: rel_data}, "url": url}

    return format_scan_results(result_data, f"URL {relationship}")


@mcp.tool()
async def get_file_relationship(
    file_hash: str, relationship: str, limit: int = 10, cursor: Optional[str] = None
) -> str:
    """Query a specific relationship type for a file with pagination support.

    Args:
        file_hash: MD5, SHA-1 or SHA-256 hash of the file
        relationship: Type of relationship to query
        limit: Maximum number of related objects to retrieve (1-40)
        cursor: Continuation cursor for pagination

    Returns:
        str: Formatted relationship data
    """

    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    endpoint = f"/files/{file_hash}/{relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {relationship: rel_data}, "hash": file_hash}

    return format_scan_results(result_data, f"File {relationship}")


@mcp.tool()
async def get_ip_relationship(
    ip: str, relationship: str, limit: int = 10, cursor: Optional[str] = None
) -> str:
    """Query a specific relationship type for an IP address with pagination support.

    Args:
        ip: IP address to analyze
        relationship: Type of relationship to query
        limit: Maximum number of related objects to retrieve (1-40)
        cursor: Continuation cursor for pagination

    Returns:
        str: Formatted relationship data
    """

    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    endpoint = f"/ip_addresses/{ip}/{relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {relationship: rel_data}, "ip": ip}

    return format_scan_results(result_data, f"IP {relationship}")


@mcp.tool()
async def get_domain_relationship(
    domain: str, relationship: str, limit: int = 10, cursor: Optional[str] = None
) -> str:
    """Query a specific relationship type for a domain with pagination support.

    Args:
        domain: Domain name to analyze
        relationship: Type of relationship to query
        limit: Maximum number of related objects to retrieve (1-40)
        cursor: Continuation cursor for pagination

    Returns:
        str: Formatted relationship data
    """

    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    endpoint = f"/domains/{domain}/{relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {relationship: rel_data}, "domain": domain}

    return format_scan_results(result_data, f"Domain {relationship}")


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse")
    mcp.run(transport=transport, host="0.0.0.0", port=8000)
