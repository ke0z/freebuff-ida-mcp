"""
freebuff-ida-mcp / ida_mcp_server.py

A free, local Model Context Protocol (MCP) server that gives Freebuff
(and other MCP clients) programmatic access to IDA Pro 9.x through
the official Hex-Rays C++ SDK.

Architecture
------------
  Freebuff (MCP client) <-> MCP protocol (stdio/sse) <-> this server
                                                    |
                                                    v
                                               IDA Pro 9.x (ida64)
                                                    |
                                                    v
                                              Hex-Rays C++ SDK

Prerequisites
-------------
- IDA Pro 9.x installed (this machine: /opt/ida-free/ida64)
- Hex-Rays C++ SDK for IDA 9.x (provide IDA_SDK_PATH)
- A Hex-Rays license (IDA Free is acceptable for learning/non-commercial use)

This server requires the `mcp` package:

    pip install mcp

Environment variables (see .env.example):
    IDA_PRO_PATH       /opt/ida-free/ida64   Path to the IDA Pro binary
    IDA_SDK_PATH       (required)            Path to the Hex-Rays C++ SDK
    IDA_DB_PATH        (none)                Optional default .idb/.i64
    IDA_IDB_NAME       (none)                Optional database name
    MCP_TRANSPORT      stdio                 stdio or sse
    MCP_HOST           127.0.0.1
    MCP_PORT           8080
"""

from __future__ import annotations

import os
import sys
import subprocess
import tempfile
import shutil
from functools import lru_cache
from typing import Optional

# Configuration (environment variables, see .env.example)
from freebuff_ida_mcp import conf

from mcp.server.mcpserver import MCPServer
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IDA_PRO_PATH = conf.IDA_PRO_PATH
IDA_SDK_PATH = conf.ida_sdk_path

# Optional defaults
IDA_DB_PATH = conf.ida_db_path
IDA_IDB_NAME = conf.ida_idb_name

MCP_TRANSPORT = conf.mcp_transport
MCP_HOST = conf.mcp_host
MCP_PORT = conf.mcp_port

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean from environment or config."""
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in {"1", "true", "yes", "on"}

def _env_int(name: str, default: int) -> int:
    """Read an integer from environment or config."""
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _validate_config() -> None:
    """Check that the required pieces of the IDA Pro ecosystem are available."""
    if not os.path.exists(IDA_PRO_PATH):
        raise FileNotFoundError(
            f"IDA Pro binary not found at IDA_PRO_PATH={IDA_PRO_PATH!r}. "
            "Set IDA_PRO_PATH in your environment (.env)."
        )
    if not os.path.isfile(IDA_PRO_PATH):
        raise NotADirectoryError(
            f"IDA_PRO_PATH points to a directory, not a file: {IDA_PRO_PATH!r}"
        )
    # On some systems IDA is invoked as `ida64` (64-bit) or `ida` (32-bit).
    if not os.access(IDA_PRO_PATH, os.X_OK):
        raise PermissionError(
            f"IDA Pro binary is not executable: {IDA_PRO_PATH!r}"
        )

    if not IDA_SDK_PATH:
        raise RuntimeError(
            "IDA_SDK_PATH is not set. Please provide the path to the "
            "Hex-Rays C++ SDK for IDA 9.x (it should contain include/ and "
            "library/ or lib/). See README.md for details."
        )
    if not os.path.isdir(IDA_SDK_PATH):
        raise NotADirectoryError(f"IDA_SDK_PATH is not a directory: {IDA_SDK_PATH!r}")

    # Warn if the SDK is missing headers we use in the tools.
    required_headers = [
        "pro.h", "ida.hpp", "loader.hpp", "bytes.hpp", "funcs.hpp",
        "xref.hpp", "name.hpp", "segment.hpp", "typeinf.hpp", "entry.hpp",
    ]
    include_dir = os.path.join(IDA_SDK_PATH, "include")
    missing = []
    for h in required_headers:
        if not os.path.exists(os.path.join(include_dir, h)):
            missing.append(h)
    if missing:
        print(
            f"[freebuff-ida-mcp] WARNING: SDK is missing headers: {', '.join(missing)}",
            file=sys.stderr,
        )

    if conf.verbose:
        print(f"[freebuff-ida-mcp] IDA_PRO_PATH={IDA_PRO_PATH}", file=sys.stderr)
        print(f"[freebuff-ida-mcp] IDA_SDK_PATH={IDA_SDK_PATH}", file=sys.stderr)
        print(f"[freebuff-ida-mcp] IDA_DB_PATH={IDA_DB_PATH}", file=sys.stderr)
        print(f"[freebuff-ida-mcp] MCP_TRANSPORT={MCP_TRANSPORT}", file=sys.stderr)


_validate_config()

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
mcp = MCPServer(
    name="freebuff-ida-mcp",
    description=(
        "Programmatic access to IDA Pro 9.x via the Hex-Rays C++ SDK. "
        "Load, inspect, and modify binaries from an MCP client."
    ),
    instructions=(
        "Use this server to interact with IDA Pro 9.x. It wraps the Hex-Rays "
        "C++ SDK for IDA. All tools launch a headless `ida64` process, run the "
        "requested operation, and return the result. Tools that modify the "
        "database (write_bytes, create_function, rename_function, etc.) change "
        "the database in-memory; call save_database() to persist them."
    ),
)

# ---------------------------------------------------------------------------
# Helper: run IDA Pro as a one-shot child process
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _ida_path() -> str:
    """Return the resolved IDA Pro binary path."""
    return os.path.abspath(IDA_PRO_PATH)

def _run_ida(args: list[str], timeout: int = 300, check: bool = True):
    """
    Spawn an IDA Pro process with the given arguments and wait for it to
    finish. This is used for one-shot, headless operations such as
    loading a database, disassembling, or patching bytes.
    """
    resolved = _ida_path()
    cmd = [resolved] + args
    if conf.verbose:
        print(f"[freebuff-ida-mcp] spawn: {' '.join(cmd)}", file=sys.stderr)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "IDA_SKIP_PLUGIN_LOAD": "1"},
        )
    except subprocess.TimeoutExpired as e:
        if conf.verbose:
            print(f"[freebuff-ida-mcp] ida64 timed out after {timeout}s", file=sys.stderr)
        raise TimeoutError(f"ida64 command timed out after {timeout}s") from e

    if check and proc.returncode != 0:
        msg = (
            f"ida64 exited with {proc.returncode}:\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
        if conf.verbose:
            print(f"[freebuff-ida-mcp] {msg}", file=sys.stderr)
        raise subprocess.CalledProcessError(proc.returncode, cmd, proc.stdout, proc.stderr)

    return proc

def _run_ida_background(args: list[str]):
    """
    Start an IDA Pro process in the background and return the Popen object.
    The caller is responsible for managing its lifecycle.
    """
    resolved = _ida_path()
    cmd = [resolved] + args
    if conf.verbose:
        print(f"[freebuff-ida-mcp] spawn (background): {' '.join(cmd)}", file=sys.stderr)
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "IDA_SKIP_PLUGIN_LOAD": "1"},
    )

# ============================================================================
# MCP tools
# ============================================================================

@mcp.tool()
def get_ida_info() -> dict:
    """
    Get the IDA Pro version, build, and environment information.

    Returns a dict with the binary path, whether the SDK is configured,
    and the IDA version string (if we can determine it).
    """
    return {
        "ida_pro_path": _ida_path(),
        "ida_sdk_path": IDA_SDK_PATH,
        "sdk_configured": bool(IDA_SDK_PATH and os.path.isdir(IDA_SDK_PATH)),
        "db_path": IDA_DB_PATH,
        "transport": MCP_TRANSPORT,
        "mcp_version": "unknown",
    }

@mcp.tool()
def load_database(db_path: str, db_name: Optional[str] = None) -> dict:
    """
    Load a database (.idb or .i64) into IDA Pro.

    Args:
        db_path:  Absolute path to the database file.
        db_name:  Optional name to assign to the database within IDA
                  (defaults to the file name).

    Returns a dict with the command result and status.
    """
    if not os.path.exists(db_path):
        return {"status": "error", "message": f"Database not found: {db_path}"}

    # -A => auto-analyze on load; -o => output path
    args = ["-A", "-o", db_path]
    if db_name:
        args += ["-n", db_name]

    proc = _run_ida(args, timeout=120)
    return {
        "status": "ok",
        "db_path": db_path,
        "db_name": db_name or os.path.basename(db_path),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-2000:] if proc.stdout else "",
        "stderr": proc.stderr[-2000:] if proc.stderr else "",
    }

@mcp.tool()
def save_database() -> dict:
    """
    Save the current database in IDA Pro.
    """
    proc = _run_ida(["-R"], timeout=120)
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-2000:] if proc.stdout else "",
        "stderr": proc.stderr[-2000:] if proc.stderr else "",
    }

@mcp.tool()
def close_database() -> dict:
    """
    Close the currently loaded database in IDA Pro.
    """
    proc = _run_ida(["-P"], timeout=120)
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-2000:] if proc.stdout else "",
        "stderr": proc.stderr[-2000:] if proc.stderr else "",
    }

@mcp.tool()
def get_database_info() -> dict:
    """
    Get information about the currently loaded database: file name,
    size, and state.
    """
    if not IDA_DB_PATH or not os.path.exists(IDA_DB_PATH):
        return {"status": "no_database_loaded", "message": "No database currently loaded."}

    proc = _run_ida(["-p", IDA_DB_PATH], timeout=60)
    if proc.returncode == 0:
        info = {
            "db_path": IDA_DB_PATH,
            "size": os.path.getsize(IDA_DB_PATH),
            "name": os.path.basename(IDA_DB_PATH),
            "status": "ok",
        }
        if proc.stdout:
            info["content"] = proc.stdout[:2000]
        if proc.stderr:
            info["stderr"] = proc.stderr[:1000]
        return info

    return {
        "status": "error",
        "message": f"ida64 exited with {proc.returncode}",
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }

@mcp.tool()
def list_functions(prefix: Optional[str] = None) -> dict:
    """
    List all functions in the database, optionally filtered by a name prefix.
    """
    script = (
        "import sys\n"
        "def _list():\n"
        "    f = get_func(get_min_ea())\n"
        "    first = True\n"
        "    while f is not None:\n"
        "        if not first:\n"
        "            print('|')\n"
        "        print(f'{f.start_ea:#x}|{get_func_name(f.start_ea)}')\n"
        "        f = f.next\n"
        "        first = False\n"
        "if __name__=='__main__':\n"
        "    _list()\n"
    )

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=180)
    finally:
        os.unlink(script_path)

    lines = (proc.stdout or "").splitlines()
    funcs = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split("|")
        if len(parts) == 2:
            try:
                ea = int(parts[0], 16)
            except ValueError:
                continue
            funcs.append({"ea": ea, "name": parts[1]})

    if prefix:
        funcs = [f for f in funcs if f["name"].startswith(prefix)]

    return {"status": "ok", "count": len(funcs), "functions": funcs}

@mcp.tool()
def get_function_disassembly(ea: int) -> dict:
    """
    Get the full disassembly of the function at the given effective address.
    """
    script = (
        "import sys\n"
        "ea = {ea}\n"
        "f = get_func(ea)\n"
        "if f is None:\n"
        "    print('ERROR: no function at ' + hex(ea))\n"
        "else:\n"
        "    for ins in f.get_disasm():\n"
        "        print(hex(ins.ea) + ' ' + str(ins))\n"
    ).format(ea=ea)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    lines = (proc.stdout or "").splitlines()
    lines = [ln for ln in lines if not ln.startswith("ERROR:")]
    return {
        "status": "ok",
        "ea": ea,
        "disassembly": [ln.strip() for ln in lines if ln.strip()],
    }

@mcp.tool()
def get_disassembly(ea: int) -> dict:
    """
    Get the disassembly of a single instruction at the given address.
    """
    script = (
        "import sys\n"
        "ea = {ea}\n"
        "if get_flags(ea) & CFUNC:\n"
        "    print('ERROR: address is a function, not an instruction')\n"
        "else:\n"
        "    ins = decode_insn(ea)\n"
        "    if ins is None:\n"
        "        print('ERROR: cannot decode instruction at ' + hex(ea))\n"
        "    else:\n"
        "        print(hex(ins.ea) + ' ' + str(ins))\n"
    ).format(ea=ea)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    out = (proc.stdout or "").strip()
    return {
        "status": "ok",
        "ea": ea,
        "disassembly": out,
    }

@mcp.tool()
def read_bytes(ea: int, count: int = 16) -> dict:
    """
    Read raw bytes from the database at the given address.
    """
    script = (
        "import sys\n"
        "ea = {ea}\n"
        "count = {count}\n"
        "data = get_bytes(ea, count)\n"
        "if data is None:\n"
        "    print('ERROR: cannot read bytes at ' + hex(ea))\n"
        "else:\n"
        "    for i, b in enumerate(data):\n"
        "        print(f'{ea + i:#x}:{b:02x}')\n"
    ).format(ea=ea, count=count)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    lines = (proc.stdout or "").splitlines()
    hex_bytes = []
    for ln in lines:
        if ":" in ln:
            try:
                hex_bytes.append(ln.split(":", 1)[1].strip())
            except IndexError:
                continue
    return {
        "status": "ok",
        "ea": ea,
        "count": count,
        "hex_bytes": hex_bytes,
    }

@mcp.tool()
def write_bytes(ea: int, data: str, base: int = 16) -> dict:
    """
    Write raw bytes to the database at the given address.
    """
    data = data.strip()
    try:
        raw = bytes.fromhex(data)
    except ValueError:
        try:
            parts = [int(x.strip(), base) for x in data.split(",")]
            raw = bytes(parts)
        except ValueError:
            return {"status": "error", "message": f"Invalid hex data: {data!r}"}

    script = (
        "import sys\n"
        "ea = {ea}\n"
        "raw = {raw!r}\n"
        "if len(raw) != {len}:\n"
        "    print('ERROR: byte count mismatch')\n"
        "else:\n"
        "    try:\n"
        "        for i, b in enumerate(raw):\n"
        "            patch_byte(ea + i, b)\n"
        "        print('OK: wrote ' + str(len(raw)) + ' bytes at ' + hex(ea))\n"
        "    except Exception as e:\n"
        "        print('ERROR: ' + str(e))\n"
    ).format(ea=ea, raw=repr(raw), len=len(raw))

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    out = (proc.stdout or "").strip()
    return {"status": "ok" if "OK" in out else "error", "ea": ea, "size": len(raw), "output": out}

@mcp.tool()
def list_segments() -> dict:
    """
    List all segments in the loaded database.
    """
    script = (
        "import sys\n"
        "seg = get_first_seg()\n"
        "first = True\n"
        "while seg is not None:\n"
        "    if not first:\n"
        "        print('|')\n"
        "    print(f'{seg.start:#x}|{seg.end:#x}|{seg.getseg().perm}|{seg.name}')\n"
        "    seg = seg.next\n"
        "    first = False\n"
    )

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    lines = (proc.stdout or "").splitlines()
    segs = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split("|")
        if len(parts) == 4:
            try:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
            except ValueError:
                continue
            segs.append({
                "start": start,
                "end": end,
                "perm": parts[2],
                "name": parts[3],
            })

    return {"status": "ok", "count": len(segs), "segments": segs}

@mcp.tool()
def get_xrefs_to(ea: int) -> dict:
    """
    List cross-references *to* the given address.
    """
    script = (
        "import sys\n"
        "ea = {ea}\n"
        "x = get_first_xyref(ea, 0)\n"
        "first = True\n"
        "while x is not None:\n"
        "    if not first:\n"
        "        print('|')\n"
        "    print(f'{x.frm:#x}|{x.type}|{x.ino:#x}')\n"
        "    x = get_next_xyref(x)\n"
        "    first = False\n"
    ).format(ea=ea)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    lines = (proc.stdout or "").splitlines()
    xrefs = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split("|")
        if len(parts) == 3:
            try:
                xrefs.append({
                    "from_ea": int(parts[0], 16),
                    "type": parts[1],
                    "to_ea": int(parts[2], 16),
                })
            except ValueError:
                continue

    return {"status": "ok", "ea": ea, "count": len(xrefs), "xrefs": xrefs}

@mcp.tool()
def get_xrefs_from(ea: int) -> dict:
    """
    List cross-references *from* the given address.
    """
    script = (
        "import sys\n"
        "ea = {ea}\n"
        "x = get_first_xyref(ea, 1)\n"
        "first = True\n"
        "while x is not None:\n"
        "    if not first:\n"
        "        print('|')\n"
        "    print(f'{x.to:#x}|{x.type}|{x.frm:#x}')\n"
        "    x = get_next_xyref(x)\n"
        "    first = False\n"
    ).format(ea=ea)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    lines = (proc.stdout or "").splitlines()
    xrefs = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split("|")
        if len(parts) == 3:
            try:
                xrefs.append({
                    "to_ea": int(parts[0], 16),
                    "type": parts[1],
                    "from_ea": int(parts[2], 16),
                })
            except ValueError:
                continue

    return {"status": "ok", "ea": ea, "count": len(xrefs), "xrefs": xrefs}

@mcp.tool()
def get_function_by_name(name: str) -> dict:
    """
    Get a function object by name.
    """
    script = (
        "import sys\n"
        "name = {name!r}\n"
        "e = get_sym_tab_entry(name)\n"
        "if e is None:\n"
        "    f = get_func_by_name(name)\n"
        "    if f is None:\n"
        "        print('ERROR: no function named ' + name)\n"
        "    else:\n"
        "        print(hex(f.start_ea) + '|' + f.name)\n"
        "else:\n"
        "    print(hex(e.value) + '|' + e.name)\n"
    ).format(name=name)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    out = (proc.stdout or "").strip()
    if out.startswith("ERROR:"):
        return {"status": "error", "message": out}

    parts = out.split("|")
    if len(parts) == 2:
        try:
            ea = int(parts[0], 16)
        except ValueError:
            ea = None
        return {"status": "ok", "ea": ea, "name": parts[1], "raw": out}

    return {"status": "ok", "raw": out}

@mcp.tool()
def create_function(ea: int) -> dict:
    """
    Create a function at the given address.
    """
    script = f"import sys; f = create_func({ea}); print(hex(f.start_ea) if f else 'ERROR: could not create function');"

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    out = (proc.stdout or "").strip()
    if "ERROR" in out:
        return {"status": "error", "message": out}

    return {"status": "ok", "ea": ea, "output": out}

@mcp.tool()
def rename_function(ea: int, new_name: str) -> dict:
    """
    Rename a function.
    """
    script = (
        "import sys\n"
        "ea = {ea}\n"
        "new_name = {new_name!r}\n"
        "f = get_func(ea)\n"
        "if f is None:\n"
        "    print('ERROR: no function at ' + hex(ea))\n"
        "else:\n"
        "    try:\n"
        "        set_name(f.start_ea, new_name, SIaginI)\n"
        "        print('OK: renamed to ' + new_name)\n"
        "    except Exception as e:\n"
        "        print('ERROR: ' + str(e))\n"
    ).format(ea=ea, new_name=new_name)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(script)
        tf.flush()
        script_path = tf.name

    try:
        args = ["-A", "-S" + script_path]
        proc = _run_ida(args, timeout=120)
    finally:
        os.unlink(script_path)

    out = (proc.stdout or "").strip()
    if "ERROR" in out:
        return {"status": "error", "message": out}

    return {"status": "ok", "ea": ea, "new_name": new_name, "output": out}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if conf.verbose:
        print("[freebuff-ida-mcp] starting server...", file=sys.stderr)

    try:
        mcp.run(transport=MCP_TRANSPORT)
    except KeyboardInterrupt:
        print("\n[freebuff-ida-mcp] interrupted", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"[freebuff-ida-mcp] FATAL: {e}", file=sys.stderr)
        raise
