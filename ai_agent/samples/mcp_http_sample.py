#!/usr/bin/env python3
"""
MCP Server using Streamable HTTP Transport
This example demonstrates the latest MCP Streamable HTTP protocol implementation
using FastMCP, which is the preferred transport over SSE for production deployments.
"""

import asyncio
from typing import Dict, Any, List
from fastmcp import FastMCP
from pydantic import BaseModel


# Optional: Define structured output models
class WeatherData(BaseModel):
    temperature: float
    humidity: float
    condition: str
    location: str


class DatabaseQuery(BaseModel):
    query: str
    results: List[Dict[str, Any]]


# Initialize FastMCP server with Streamable HTTP support
mcp = FastMCP(
    name="StreamableHTTPServer",
    version="1.0.0",
    description="Example MCP server using Streamable HTTP transport"
)


@mcp.tool()
def get_weather(city: str, units: str = "celsius") -> WeatherData:
    """
    Get current weather for a city.

    Args:
        city: Name of the city
        units: Temperature units (celsius or fahrenheit)

    Returns:
        WeatherData: Current weather information
    """
    # Simulate weather data - in real implementation, call actual weather API
    temp = 22.5 if units == "celsius" else 72.5

    return WeatherData(
        temperature=temp,
        humidity=65.0,
        condition="Partly cloudy",
        location=city
    )


@mcp.tool()
def calculate(expression: str) -> float:
    """
    Safely evaluate mathematical expressions.

    Args:
        expression: Mathematical expression to evaluate

    Returns:
        float: Result of the calculation
    """
    try:
        # Simple safe evaluation - in production, use safer alternatives
        allowed_chars = set('0123456789+-*/.() ')
        if not all(c in allowed_chars for c in expression):
            raise ValueError("Invalid characters in expression")

        result = eval(expression)
        return float(result)
    except Exception as e:
        raise ValueError(f"Calculation error: {str(e)}")


@mcp.tool()
def search_database(table: str, condition: str = "") -> DatabaseQuery:
    """
    Simulate database search functionality.

    Args:
        table: Table name to search
        condition: Optional WHERE condition

    Returns:
        DatabaseQuery: Query results
    """
    # Simulate database query
    query = f"SELECT * FROM {table}"
    if condition:
        query += f" WHERE {condition}"

    # Mock results
    results = [
        {"id": 1, "name": "Alice", "email": "alice@example.com"},
        {"id": 2, "name": "Bob", "email": "bob@example.com"}
    ]

    return DatabaseQuery(query=query, results=results)


@mcp.resource("config://server")
async def get_server_config() -> str:
    """
    Provide server configuration information.

    Returns:
        str: Server configuration as text
    """
    return """Server Configuration:
- Transport: Streamable HTTP
- Version: 1.0.0
- Features: Tools, Resources, Prompts
- Authentication: None (for demo)
"""


@mcp.resource("logs://recent")
async def get_recent_logs() -> str:
    """
    Get recent server logs.

    Returns:
        str: Recent log entries
    """
    return """Recent Logs:
[2025-08-13 10:30:15] Server started with Streamable HTTP transport
[2025-08-13 10:30:16] Registered 3 tools and 2 resources
[2025-08-13 10:30:17] Server ready to accept connections
"""


@mcp.prompt("weather-report")
async def weather_report_prompt(city: str = "New York") -> str:
    """
    Generate a weather report prompt template.

    Args:
        city: City for weather report

    Returns:
        str: Formatted prompt
    """
    return f"""Generate a detailed weather report for {city}. Include:
1. Current temperature and conditions
2. Humidity levels
3. Weather forecast for next 24 hours
4. Any weather advisories or warnings
5. Recommended clothing/activities

Use the get_weather tool to fetch current data and provide a comprehensive analysis."""


# Run server with Streamable HTTP transport
if __name__ == "__main__":
    print("Starting MCP Server with Streamable HTTP transport...")
    print("Server will be available at: http://127.0.0.1:8000/mcp")
    print("\nTo connect with Claude Desktop, use mcp-remote:")
    print('Add this to your claude_desktop_config.json:')
    print("""
{
  "streamable-http-server": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "http://127.0.0.1:8000/mcp"],
    "env": {
      "MCP_TRANSPORT_STRATEGY": "http-only"
    }
  }
}
""")

    # Start server with Streamable HTTP transport
    mcp.run(
        transport="http",  # "http" defaults to Streamable HTTP in FastMCP 2.3+
        host="127.0.0.1",
        port=8000,
        path="/mcp",  # Standard MCP endpoint path
        log_level="info"
    )


# Alternative ways to run the server:

# 1. Using FastMCP CLI (recommended for development):
# fastmcp run server.py --transport http --port 8000

# 2. Using explicit streamable-http transport:
# mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)

# 3. Integration with FastAPI/Starlette:
"""
from starlette.applications import Starlette
from starlette.routing import Mount

app = Starlette(
    routes=[
        Mount('/mcp', app=mcp.create_app())
    ]
)

# Then run with: uvicorn server:app --port 8000
"""

# 4. For production deployment with authentication:
"""
mcp = FastMCP(
    name="ProductionServer",
    auth_strategy="oauth",  # Enable OAuth authentication
    cors_enabled=True,      # Enable CORS for web clients
    rate_limit=100          # Rate limiting
)
"""