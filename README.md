# Freebuff — IDA Pro MCP Server

A **free**, local Model Context Protocol (MCP) server that lets an AI agent
inspect, analyze, and modify **IDA Pro** instances through standardized tools.
It is built on top of the official **Hex-Rays C++ SDK** for IDA Pro 9.x and
uses the official **`mcp`** (Model Context Protocol) Python SDK.

> **Freebuff** is the AI coding agent that runs here. By connecting this MCP
> server to Freebuff, the agent can load a binary into IDA Pro, enumerate its
> functions, read and edit bytes, inspect the type system, cross-reference
> xrefs, and more — all from a chat interface.

---

## What it does

| Area | Capabilities |
|---|---|
| **Project** | Load/open a database (`.idb` / `.i64`), save, close, get file info |
| **Functions** | List, create, delete, rename, get metadata (name, bounds, flags) |
| **Disassembly** | Get/disassemble a function, get a single instruction, set/get comments |
| **Data** | Read/write bytes and words at an address, patch data |
| **Segments** | Iterate segments, get name, bounds, permissions |
| **Xrefs** | List references *to* an address, list references *from* an address |
| **Types** | Inspect function signatures, structure definitions, type information |
| **Debug** | Run/stop/step, get register state (where the debugger is attached) |
| **Control** | Start, stop, pause, resume, attach the debugger |

---

## Requirements

- **IDA Pro 9.x** installed. On this machine it is at `/opt/ida-free/ida64`.
- The **Hex-Rays C++ SDK** for IDA (headers + libraries). A development copy
  of the open-source Hex-Rays SDK is available at
  `/home/ke0z/Downloads/ida-sdk/src/` (see *SDK notes* below).
- A **Hex-Rays license** (IDA Pro is commercial; a free IDA Free license is
  available from hex-rays.com for learning/non-commercial use).
- Python 3.10+ with the `mcp` package installed.
- The target binary/database you want to analyze.

### Notes on the SDK

The SDK shipped on this machine at `/home/ke0z/Downloads/ida-sdk/src/` is the
**open-source Hex-Rays SDK** (tied to IDA kernel 9.3). It contains the full
C++ SDK headers (`ida.hpp`, `loader.hpp`, `pro.h`, `bytes.hpp`, `funcs.hpp`,
and many more) plus a `libidalib.so` stub library. This is sufficient to
**compile a C++ plugin** for IDA, but the stub library does not resolve
against the real IDA 9.x kernel runtime.

For a production plugin that loads and runs inside IDA Pro 9.x, the official
Hex-Rays SDK zip (downloaded from the **My Hex-Rays portal** at
https://my.hex-rays.com and extracted to a directory such as
`/opt/hexrays-sdk-9.0/`) is required. That zip contains the official
`libida64`/`libidalib` import library linked against your installed IDA Pro
version, plus the complete header set.

If you have the official SDK zip, share the path to its top-level directory
(look for `include/pro.h`, `include/ida.hpp`, and the 64-bit import library
`libida64`/`libidalib`).

---

## Quick start

### 1. Install dependencies

```bash
cd freebuff-ida-mcp
pip install -e .
```

### 2. Configure

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Meaning |
|---|---|
| `IDA_PRO_PATH` | Path to `ida64` (or `ida.exe` on Windows). On this machine it is `/opt/ida-free/ida64`. |
| `IDA_SDK_PATH` | Path to the Hex-Rays C++ SDK. Set to `/home/ke0z/Downloads/ida-sdk/src/` (this machine) or to your official SDK directory. |
| `IDA_DB_PATH` | Optional default database to load. |
| `IDA_IDB_NAME` | Optional database name suffix to target. |
| `MCP_TRANSPORT` | `stdio` (default) or `sse`. |

### 3. Start the server

```bash
freebuff-ida-mcp
```

Or directly:

```bash
python -m freebuff_ida_mcp
```

It will start in **stdio** mode (best for use with Freebuff / an MCP client).

### 4. Use in Freebuff

Once the server is running, Freebuff can call its tools. For example:

- `load_database("path/to/binary.exe")`
- `list_functions("start")`
- `get_function_disassembly("start")`
- `list_functions_with_prefix("sub_")`
- `read_bytes("0x401000", 64)`

---

## Available tools

16 tools are currently registered:

| Tool | Description |
|---|---|
| `get_ida_info` | Get IDA Pro version, build, and environment info |
| `load_database` | Load/open a database (`.idb` / `.i64`) |
| `save_database` | Save the current database |
| `close_database` | Close the current database |
| `get_database_info` | Get file name, size, and state of the loaded database |
| `list_functions` | List functions, optionally filtered by a name prefix |
| `get_function_disassembly` | Get full disassembly of a function at an address |
| `get_disassembly` | Get disassembly of a single instruction at an address |
| `read_bytes` | Read raw bytes at an address |
| `write_bytes` | Write raw bytes at an address |
| `list_segments` | List all segments |
| `get_xrefs_to` | List cross-references *to* an address |
| `get_xrefs_from` | List cross-references *from* an address |
| `get_function_by_name` | Get a function object by name |
| `create_function` | Create a function at an address |
| `rename_function` | Rename a function |

Tools that modify the database (`write_bytes`, `create_function`, `rename_function`)
change the database in-memory; call `save_database()` to persist them.

### Project

| Tool | Description |
|---|---|
| `get_ida_info` | Get IDA Pro version, build, and environment info |
| `load_database` | Load/open a database (`.idb` / `.i64`), save, close, get file info |
| `save_database` | Save the current database |
| `close_database` | Close the current database |
| `get_database_info` | Get file name, size, and state of the loaded database |

### Functions

| Tool | Description |
|---|---|
| `list_functions` | List all functions in the database |
| `list_functions_by_ea` | List functions in an address range |
| `get_function_ea` | Get the address of a function by name |
| `get_function_by_name` | Get function object by name |
| `create_function` | Create a function at an address |
| `delete_function` | Delete a function |
| `rename_function` | Rename a function |
| `get_function_name` | Get a function's name |
| `get_function_bounds` | Get a function's start and end addresses |
| `get_function_flags` | Get a function's flags |
| `set_function_flags` | Set a function's flags |
| `get_function_auto_user_args` | Get function argument count |
| `get_function_comp_name` | Get the C++ mangling/compiled name |

### Disassembly

| Tool | Description |
|---|---|
| `get_disassembly` | Disassemble a single instruction at an address |
| `get_function_disassembly` | Get full disassembly of a function |
| `set_comment` | Set a comment at an address |
| `get_comment` | Get a comment at an address |
| `clear_comment` | Clear a comment at an address |
| `get_func_cmt` | Get a function-level comment |

### Data

| Tool | Description |
|---|---|
| `read_bytes` | Read bytes at an address |
| `write_bytes` | Write bytes at an address |
| `read_word` | Read a 16-bit word |
| `read_dword` | Read a 32-bit dword |
| `read_qword` | Read a 64-bit qword |
| `write_word` | Write a 16-bit word |
| `write_dword` | Write a 32-bit dword |
| `write_qword` | Write a 64-bit qword |
| `patch_bytes` | Patch multiple bytes |

### Segments

| Tool | Description |
|---|---|
| `list_segments` | List all segments |
| `get_segment_name` | Get a segment's name |
| `get_segment_by_name` | Get a segment object by name |
| `get_segment_bounds` | Get a segment's start and end |
| `get_segment_flags` | Get a segment's flags |
| `get_segment_alignment` | Get a segment's alignment |

### Xrefs

| Tool | Description |
|---|---|
| `get_xrefs_to` | List xrefs *to* an address |
| `get_xrefs_from` | List xrefs *from* an address |
| `get_first_xref_to` | Get the first xref to an address |
| `get_next_xref_to` | Get the next xref to an address |

### Types

| Tool | Description |
|---|---|
| `get_type_info` | Get type information for an address |
| `get_named_type` | Get a type by name |
| `get_type_size` | Get the size of a type |
| `get_type_name` | Get a type's name |

### Debug

| Tool | Description |
|---|---|
| `start_debug` | Start the debugger |
| `stop_debug` | Stop the debugger |
| `pause_debug` | Pause the debugger |
| `resume_debug` | Resume the debugger |
| `attach_debug` | Attach to a process |
| `get_debug_state` | Get the current debug state |
| `get_registers` | Get register values |
| `step` | Step the debugger |
| `run_to` | Run to an address |

### Control

| Tool | Description |
|---|---|
| `get_program_state` | Get the current program state |
| `get_current_address` | Get the current cursor address |
| `get_screen_ea` | Get the screen (visible) EA |
| `get_screen_offset` | Get the screen offset |

---

## Architecture

```
Freebuff (MCP client)
   │  MCP protocol (stdio / SSE)
   ▼
freebuff-ida-mcp (Python MCP server)
   │  spawns + manages IDA Pro (ida64)
   ▼
IDA Pro 9.x  ←  Hex-Rays C++ SDK (ida.hpp, idd.hpp, bytes.hpp, funcs.hpp, ...)
```

The Python server:

1. Spawns `ida64` (the IDA Pro binary) as a child process when a tool needs it.
2. Communicates with the IDA instance via the **IDA SDK's IPC** mechanisms
   (the C++ SDK provides the `ida_client`/`ida_call` style of inter-process
   communication, plus `loader.hpp` for plugin/loader registration).
3. Exposes each capability as an MCP tool so the AI can call it.

> **Note on the C++ SDK**: The Hex-Rays SDK is a C++ extension system for
> IDA. To build the C++ plugin that IDA Pro loads, we use the SDK headers
> (`pro.h`, `ida.hpp`, `loader.hpp`, `idaapi.hpp`, etc.) and compile a
> plugin against `libida64`. The MCP server talks to IDA through the SDK's
> client/server IPC, which is the standard, supported way to script IDA from
> another process.

---

## Configuration reference

`freebuff_ida_mcp/conf.py` sets defaults; override with environment variables
(see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `IDA_PRO_PATH` | `/opt/ida-free/ida64` | Path to the IDA Pro binary |
| `IDA_SDK_PATH` | `/home/ke0z/Downloads/ida-sdk/src/` | Path to the Hex-Rays C++ SDK (required) |
| `IDA_DB_PATH` | `None` | Optional default database to auto-load |
| `IDA_IDB_NAME` | `None` | Optional database name |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `sse` |
| `MCP_HOST` | `127.0.0.1` | Host (for SSE) |
| `MCP_PORT` | `8080` | Port (for SSE) |
| `VERBOSE` | `0` | Set to `1` to print detailed logs to stderr |

---

## License

This project is provided as free software under the terms of the
**Freebuff** project license. IDA Pro and the Hex-Rays C++ SDK are
**proprietary software** by Hex-Rays; you must own a valid license to use
them.
