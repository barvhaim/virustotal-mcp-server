#!/usr/bin/env python3
"""VirusTotal MCP Server - VirusTotal Model Context Protocol server."""

import asyncio
import base64
import os
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

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


class UrlReportRequest(BaseModel):
    """Request model for URL analysis."""

    url: str = Field(description="The URL to analyze")


class FileReportRequest(BaseModel):
    """Request model for file analysis."""

    hash: str = Field(description="MD5, SHA-1 or SHA-256 hash of the file")


class IpReportRequest(BaseModel):
    """Request model for IP analysis."""

    ip: str = Field(description="IP address to analyze")


class DomainReportRequest(BaseModel):
    """Request model for domain analysis."""

    domain: str = Field(description="Domain name to analyze")
    relationships: Optional[List[str]] = Field(
        default=None, description="Array of specific relationships to include"
    )


class RelationshipRequest(BaseModel):
    """Base model for relationship queries."""

    relationship: str = Field(description="Type of relationship to query")
    limit: int = Field(
        default=10,
        ge=1,
        le=40,
        description="Maximum number of related objects to retrieve",
    )
    cursor: Optional[str] = Field(
        default=None, description="Continuation cursor for pagination"
    )


class UrlRelationshipRequest(RelationshipRequest):
    """Request model for URL relationship queries."""

    url: str = Field(description="The URL to get relationships for")


class FileRelationshipRequest(RelationshipRequest):
    """Request model for file relationship queries."""

    hash: str = Field(description="MD5, SHA-1 or SHA-256 hash of the file")


class IpRelationshipRequest(RelationshipRequest):
    """Request model for IP relationship queries."""

    ip: str = Field(description="IP address to analyze")


class DomainRelationshipRequest(RelationshipRequest):
    """Request model for domain relationship queries."""

    domain: str = Field(description="Domain name to analyze")


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
async def get_url_report(request: UrlReportRequest) -> str:
    """Get comprehensive URL analysis report with security results and relationships."""
    url = request.url
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
async def get_file_report(request: FileReportRequest) -> str:
    """Get a comprehensive file analysis report using its hash."""
    file_hash = request.hash

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
async def get_ip_report(request: IpReportRequest) -> str:
    """Get a comprehensive IP address analysis report."""
    ip = request.ip

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
async def get_domain_report(request: DomainReportRequest) -> str:
    """Get a comprehensive domain analysis report."""
    domain = request.domain

    # Get domain report
    domain_data = await query_virustotal(f"/domains/{domain}")

    # Fetch key relationships
    relationships = {}
    default_rels = request.relationships or [
        "subdomains",
        "historical_ssl_certificates",
        "resolutions",
        "related_threat_actors",
    ]

    for rel_type in default_rels:
        try:
            rel_data = await query_virustotal(f"/domains/{domain}/{rel_type}")
            relationships[rel_type] = rel_data
        except (httpx.HTTPError, KeyError, ValueError):
            continue

    result_data = {
        "attributes": domain_data["data"]["attributes"],
        "relationships": relationships,
        "domain": domain,
    }

    return format_scan_results(result_data, "Domain")


@mcp.tool()
async def get_url_relationship(request: UrlRelationshipRequest) -> str:
    """Query a specific relationship type for a URL with pagination support."""
    url = request.url
    encoded_url = encode_url_for_vt(url)

    params = {"limit": request.limit}
    if request.cursor:
        params["cursor"] = request.cursor

    endpoint = f"/urls/{encoded_url}/{request.relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {request.relationship: rel_data}, "url": url}

    return format_scan_results(result_data, f"URL {request.relationship}")


@mcp.tool()
async def get_file_relationship(request: FileRelationshipRequest) -> str:
    """Query a specific relationship type for a file with pagination support."""
    file_hash = request.hash

    params = {"limit": request.limit}
    if request.cursor:
        params["cursor"] = request.cursor

    endpoint = f"/files/{file_hash}/{request.relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {request.relationship: rel_data}, "hash": file_hash}

    return format_scan_results(result_data, f"File {request.relationship}")


@mcp.tool()
async def get_ip_relationship(request: IpRelationshipRequest) -> str:
    """Query a specific relationship type for an IP address with pagination support."""
    ip = request.ip

    params = {"limit": request.limit}
    if request.cursor:
        params["cursor"] = request.cursor

    endpoint = f"/ip_addresses/{ip}/{request.relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {request.relationship: rel_data}, "ip": ip}

    return format_scan_results(result_data, f"IP {request.relationship}")


@mcp.tool()
async def get_domain_relationship(request: DomainRelationshipRequest) -> str:
    """Query a specific relationship type for a domain with pagination support."""
    domain = request.domain

    params = {"limit": request.limit}
    if request.cursor:
        params["cursor"] = request.cursor

    endpoint = f"/domains/{domain}/{request.relationship}"
    if params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()])
        endpoint = f"{endpoint}?{param_str}"

    rel_data = await query_virustotal(endpoint)

    result_data = {"relationships": {request.relationship: rel_data}, "domain": domain}

    return format_scan_results(result_data, f"Domain {request.relationship}")


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
