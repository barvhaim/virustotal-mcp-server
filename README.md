# VirusTotal MCP Server

A Model Context Protocol (MCP) server for comprehensive security analysis using the [VirusTotal API](https://www.virustotal.com/). Built with FastMCP and Python, this server provides AI assistants like Claude with powerful malware detection and threat intelligence capabilities.

## Overview

This MCP server integrates VirusTotal's extensive security database, allowing AI assistants to perform comprehensive security analysis on URLs, files, IP addresses, and domains. The server automatically fetches relationship data to provide complete security context in a single request.

## Features

- **Comprehensive Security Analysis**: Complete threat analysis with automatic relationship fetching
- **URL Analysis**: Security reports with contacted domains, downloaded files, and threat actors
- **File Analysis**: Detailed file hash analysis including behaviors, dropped files, and network connections
- **IP Analysis**: Geolocation, reputation data, and historical information
- **Domain Analysis**: DNS records, WHOIS data, SSL certificates, and subdomains
- **Detailed Relationship Queries**: Paginated access to specific relationship types for deep investigation
- **Rate Limit Aware**: Respects VirusTotal API limitations
- **Multiple Transport Support**: SSE and STDIO transports for different integration needs

## Quick Start

### Prerequisites

- Python 3.8+ or Docker
- [uv](https://astral.sh/uv) package manager (for local development)
- VirusTotal API key ([Get one here](https://www.virustotal.com/gui/my-apikey))

### Installation

#### Option 1: Docker (Recommended)

1. **Clone and setup:**
   ```bash
   git clone https://github.com/barvhaim/virustotal-mcp-server.git
   cd virustotal-mcp-server
   ```

2. **Configure API key:**
   ```bash
   echo "VIRUSTOTAL_API_KEY=your_api_key_here" > .env
   ```

3. **Run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

4. **Or run with Docker directly:**
   ```bash
   docker build -t virustotal-mcp .
   docker run -d --name virustotal-mcp -p 8000:8000 --env-file .env virustotal-mcp
   ```

#### Option 2: Local Development

1. **Clone and setup:**
   ```bash
   git clone https://github.com/barvhaim/virustotal-mcp-server.git
   cd virustotal-mcp-server
   uv sync
   ```

2. **Configure API key:**
   ```bash
   echo "VIRUSTOTAL_API_KEY=your_api_key_here" > .env
   ```

3. **Run the server:**
   ```bash
   # SSE transport (web-friendly)
   uv run main.py
   
   # STDIO transport (for Claude Desktop)
   MCP_TRANSPORT=stdio uv run main.py
   ```

## Tools Available

### Report Tools (with Automatic Relationship Fetching)

#### 1. URL Report Tool
- **Name**: `get_url_report`
- **Description**: Get comprehensive URL analysis including security scan results and key relationships
- **Parameters**:
  - `url` (required): The URL to analyze
- **Auto-fetched relationships**: communicating files, contacted domains/IPs, downloaded files, redirects, threat actors

#### 2. File Report Tool
- **Name**: `get_file_report` 
- **Description**: Get comprehensive file analysis using hash (MD5/SHA-1/SHA-256)
- **Parameters**:
  - `hash` (required): File hash to analyze
- **Auto-fetched relationships**: behaviors, dropped files, contacted domains/IPs, embedded URLs, threat actors

#### 3. IP Report Tool
- **Name**: `get_ip_report`
- **Description**: Get comprehensive IP address analysis including geolocation and reputation
- **Parameters**:
  - `ip` (required): IP address to analyze  
- **Auto-fetched relationships**: communicating files, historical SSL certificates, resolutions, threat actors

#### 4. Domain Report Tool
- **Name**: `get_domain_report`
- **Description**: Get comprehensive domain analysis including DNS and WHOIS data
- **Parameters**:
  - `domain` (required): Domain name to analyze
  - `relationships` (optional): Specific relationships to include
- **Auto-fetched relationships**: subdomains, historical SSL certificates, resolutions, threat actors

### Relationship Tools (for Detailed Analysis)

#### 1. URL Relationship Tool
- **Name**: `get_url_relationship`
- **Description**: Query specific relationship types for URLs with pagination
- **Parameters**:
  - `url` (required): The URL to analyze
  - `relationship` (required): Relationship type (analyses, communicating_files, contacted_domains, etc.)
  - `limit` (optional, 1-40, default: 10): Number of results
  - `cursor` (optional): Pagination cursor

#### 2. File Relationship Tool  
- **Name**: `get_file_relationship`
- **Description**: Query specific relationship types for files with pagination
- **Parameters**:
  - `hash` (required): File hash
  - `relationship` (required): Relationship type (behaviours, dropped_files, contacted_domains, etc.)
  - `limit` (optional, 1-40, default: 10): Number of results
  - `cursor` (optional): Pagination cursor

#### 3. IP Relationship Tool
- **Name**: `get_ip_relationship`  
- **Description**: Query specific relationship types for IPs with pagination
- **Parameters**:
  - `ip` (required): IP address
  - `relationship` (required): Relationship type (communicating_files, resolutions, etc.)
  - `limit` (optional, 1-40, default: 10): Number of results
  - `cursor` (optional): Pagination cursor

#### 4. Domain Relationship Tool
- **Name**: `get_domain_relationship`
- **Description**: Query specific relationship types for domains with pagination  
- **Parameters**:
  - `domain` (required): Domain name
  - `relationship` (required): Relationship type (subdomains, historical_ssl_certificates, etc.)
  - `limit` (optional, 1-40, default: 10): Number of results
  - `cursor` (optional): Pagination cursor

## Claude Desktop Integration

To connect this server to Claude Desktop, add the following to your `claude_desktop_config.json`:

**Configuration file locations:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/claude_desktop_config.json`  
- **Windows**: `%APPDATA%\\Claude\\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/virustotal-mcp-server",
        "run",
        "main.py"
      ],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_api_key_here",
      }
    }
  }
}
```

## Resources

- **FastMCP Documentation**: [github.com/jlowin/fastmcp](https://github.com/jlowin/fastmcp)
- **MCP Specification**: [modelcontextprotocol.io](https://modelcontextprotocol.io)
- **VirusTotal API**: [developers.virustotal.com](https://developers.virustotal.com)
- **uv Package Manager**: [astral.sh/uv](https://astral.sh/uv)
- **Claude Desktop**: [claude.ai](https://claude.ai)

## Version History

- **v1.0.0**: Initial release with comprehensive VirusTotal integration
  - 8 security analysis tools
  - Automatic relationship fetching
  - SSE and STDIO transport support
  - Rate limiting awareness
  - Complete error handling
