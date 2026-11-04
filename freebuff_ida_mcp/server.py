"""
freebuff-ida-mcp / server.py

Entry point for the freebuff-ida-mcp command-line tool.

    freebuff-ida-mcp

This launches the MCP server on stdio (the default transport) or on
SSE (when MCP_TRANSPORT=sse). See README.md for details.
"""

from freebuff_ida_mcp import ida_mcp_server as mcp_server

# The MCPServer instance is already created at module import time
# in ida_mcp_server.py. We simply delegate to its `run` method.
def main():
    mcp_server.mcp.run(transport=mcp_server.conf.mcp_transport)


if __name__ == "__main__":
    main()
