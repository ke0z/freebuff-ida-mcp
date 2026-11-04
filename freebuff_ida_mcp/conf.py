"""
freebuff-ida-mcp / conf.py

Centralized configuration for the Freebuff IDA Pro MCP server.

Environment variables (see .env.example for the full list):
    IDA_PRO_PATH       /opt/ida-free/ida64   Path to the IDA Pro binary
    IDA_SDK_PATH       (required)            Path to the Hex-Rays C++ SDK
    IDA_DB_PATH        (none)                Optional default .idb/.i64
    IDA_IDB_NAME       (none)                Optional database name
    MCP_TRANSPORT      stdio                 stdio or sse
    MCP_HOST           127.0.0.1
    MCP_PORT           8080
"""

import os
import sys

# ---------------------------------------------------------------------------
# IDA Pro binary
# ---------------------------------------------------------------------------
IDA_PRO_PATH = os.getenv("IDA_PRO_PATH", "/opt/ida-free/ida64")

# ---------------------------------------------------------------------------
# Hex-Rays C++ SDK
# ---------------------------------------------------------------------------
# The SDK directory must contain (at minimum):
#   include/pro.h, include/ida.hpp, include/loader.hpp, include/bytes.hpp,
#   include/funcs.hpp, include/xref.hpp, include/name.hpp, include/segment.hpp
#
# This development machine has the open-source Hex-Rays SDK here:
ida_sdk_path = "/home/ke0z/Downloads/ida-sdk/src/"

# Fallback: if the user has set IDA_SDK_PATH via environment, prefer that.
if os.getenv("IDA_SDK_PATH"):
    ida_sdk_path = os.getenv("IDA_SDK_PATH")

# ---------------------------------------------------------------------------
# Optional defaults
# ---------------------------------------------------------------------------
ida_db_path = os.getenv("IDA_DB_PATH")
ida_idb_name = os.getenv("IDA_IDB_NAME")

# ---------------------------------------------------------------------------
# MCP transport / server
# ---------------------------------------------------------------------------
mcp_transport = os.getenv("MCP_TRANSPORT", "stdio")
mcp_host = os.getenv("MCP_HOST", "127.0.0.1")
mcp_port = int(os.getenv("MCP_PORT", "8080"))

# ---------------------------------------------------------------------------
# Debug / verbosity
# ---------------------------------------------------------------------------
verbose = os.getenv("VERBOSE", "0").lower() in {"1", "true", "yes", "on"}
