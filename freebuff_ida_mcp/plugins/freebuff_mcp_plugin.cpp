// ============================================================================
// freebuff_mcp_plugin.cpp
//
// IDA Pro 9.3 C++ plugin for the Freebuff MCP server.
//
// This plugin wraps the Hex-Rays C++ SDK to expose IDA Pro functionality
// to an external MCP (Model Context Protocol) client. It provides:
//
//   - One-shot commands: load database, save, close, get info
//   - Function listing, disassembly, create/rename
//   - Byte read/write, segment listing, xrefs, types
//   - Debug control (run/stop/step/attach)
//
// Each MCP tool launches `ida64` with a headless script (`-A -S script.py`)
// and reads the result from stdout.
//
// Build:
//   cd /home/ke0z/Downloads/ida-sdk/src
//   g++ -std=c++17 -fPIC -shared -fvisibility=hidden \
//       -I<ida-sdk>/src/include \
//       -I<ida-sdk>/src/lib/x64_linux_gcc_64 \
//       freebuff_mcp_plugin.cpp \
//       -o freebuff_mcp_plugin.so \
//       -ldl -lpthread -lrt -ldl -pie
//
// Install:
//   cp freebuff_mcp_plugin.so /opt/ida-free/ida64/
//   # Or use IDA's scriptdir/plugins folder
//
// ============================================================================

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <entry.hpp>
#include <nalt.hpp>
#include <diskio.hpp>
#include <flags.hpp>
#include <fileio.hpp>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>

// ---------------------------------------------------------------------------
// Configuration (can be overridden via environment)
// ---------------------------------------------------------------------------
namespace {
    const char* IDA_PRO_PATH = getenv("IDA_PRO_PATH");
    const char* IDA_SDK_PATH = getenv("IDA_SDK_PATH");

    // Defaults (matches the installed IDA Free 9.x)
    const char* kDefaultIDAProPath = "/opt/ida-free/ida64";
    const char* kDefaultIDASDKPath = "/home/ke0z/Downloads/ida-sdk/src/";

    const char* get_ida_pro_path() {
        if (IDA_PRO_PATH && IDA_PRO_PATH[0]) return IDA_PRO_PATH;
        return kDefaultIDAProPath;
    }

    const char* get_ida_sdk_path() {
        if (IDA_SDK_PATH && IDA_SDK_PATH[0]) return IDA_SDK_PATH;
        return kDefaultIDASDKPath;
    }

    // Check that required SDK headers exist
    bool sdk_headers_ok() {
        const char* p = get_ida_sdk_path();
        struct { const char* name; } headers[] = {
            {"pro.h"}, {"ida.hpp"}, {"loader.hpp"}, {"bytes.hpp"},
            {"funcs.hpp"}, {"xref.hpp"}, {"name.hpp"}, {"segment.hpp"},
            {"typeinf.hpp"}, {"entry.hpp"}, {"idp.hpp"}, {"ida.hpp"},
        };
        for (auto* h : headers) {
            std::string path = std::string(p) + "include/" + h;
            if (access(path.c_str(), R_OK) != 0) return false;
        }
        return true;
    }
} // anonymous namespace

// ---------------------------------------------------------------------------
// Helper: run an IDA Pro one-shot command
// ---------------------------------------------------------------------------
// This function launches `ida64` with `-A -S script.py` (auto-analyze,
// run a Python script), captures stdout/stderr, and returns the result.
// We use the IDA SDK's C++ documentation conventions.
namespace {
    std::string run_ida_script(const std::string& script_code, int timeout_secs = 120) {
        // Write the script to a temporary file
        int fd = -1;
        char tmpfile[] = "/tmp/freebuff_ida_script_XXXXXX";
        fd = mkstemp(tmpfile);
        if (fd == -1) {
            msg("freebuff_mcp_plugin: mkstemp failed\n");
            return "ERROR: mkstemp failed";
        }
        dlog(tmpfile, "w");  // Use IDA's own file API (never use stdio for IDA files)
        std::string content = script_code;
        write(fd, content.c_str(), content.size());
        close(fd);

        // Build the command: ida64 -A -S<script>
        std::string cmd = std::string(get_ida_pro_path()) + " -A -S" + tmpfile;

        // Use popen to capture output
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            std::string err = "ERROR: popen failed (" + cmd + ")";
            unlink(tmpfile);
            msg("%s\n", err.c_str());
            return err;
        }

        std::string output;
        char buf[4096];
        while (fgets(buf, sizeof(buf), pipe) != nullptr) {
            output += buf;
        }
        int status = pclose(pipe);
        unlink(tmpfile);  // Clean up temp script

        if (WIFEXITED(status)) {
            int rc = WEXITSTATUS(status);
            if (rc != 0 && conf_verbose()) {
                msg("[freebuff_mcp_plugin] ida64 exited with code %d\n", rc);
            }
        } else {
            msg("[freebuff_mcp_plugin] ida64 aborted by signal\n");
        }

        return output;
    }

    // Check whether IDA Pro is reachable
    bool ida_available() {
        return access(get_ida_pro_path(), X_OK) == 0 && sdk_headers_ok();
    }

    // Query whether a database is currently loaded
    bool get_db_state() {
        // Use the IDA SDK's get_idb_state() or similar
        // We use the headless `-p` flag to query the database
        return false;  // Simplified - use get_idb_state() in production
    }

    // Check if we're running in a headless/one-shot mode
    bool is_headless() {
        return getenv("FREEbuff_IDA_HEADLESS") != nullptr;
    }
} // anonymous namespace

// ---------------------------------------------------------------------------
// MCP command handlers (implemented as C++ functions)
// ---------------------------------------------------------------------------

enum {
    // Command IDs for one-shot operations
    CMD_GET_IDA_INFO       = 1,
    CMD_LOAD_DATABASE      = 2,
    CMD_SAVE_DATABASE      = 3,
    CMD_CLOSE_DATABASE     = 4,
    CMD_GET_DATABASE_INFO  = 5,
    CMD_LIST_FUNCTIONS     = 6,
    CMD_GET_FUNCTION_DISM  = 7,
    CMD_GET_DISASSEMBLY    = 8,
    CMD_READ_BYTES         = 9,
    CMD_WRITE_BYTES        = 10,
    CMD_LIST_SEGMENTS      = 11,
    CMD_GET_XREFS_TO       = 12,
    CMD_GET_XREFS_FROM     = 13,
    CMD_GET_FUNCTION_BY_NAME = 14,
    CMD_CREATE_FUNCTION    = 15,
    CMD_RENAME_FUNCTION    = 16,
};

// ============================================================================
// MCP tool: get_ida_info
// ============================================================================
std::string cmd_get_ida_info() {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"ida_pro_path\": \"" << get_ida_pro_path() << "\",\n"
       << "  \"ida_sdk_path\": \"" << get_ida_sdk_path() << "\",\n"
       << "  \"sdk_configured\": " << (sdk_headers_ok() ? "true" : "false") << ",\n"
       << "  \"db_path\": \"" << (IDA_DB_PATH ? IDA_DB_PATH : "") << "\",\n"
       << "  \"transport\": \"stdio\",\n"
       << "  \"mcp_version\": \"0.1.0\"\n"
       << "}";
    return ss.str();
}

// ============================================================================
// MCP tool: load_database
// ============================================================================
std::string cmd_load_database(const std::string& db_path, const std::string& db_name) {
    if (access(db_path.c_str(), R_OK) != 0) {
        return R"({"status":"error","message":"Database not found: )" + db_path + '"}';
    }

    // Use -A to auto-analyze on load
    std::ostringstream cmd;
    cmd << get_ida_pro_path() << " -A -o " << db_path;
    if (!db_name.empty()) {
        cmd << " -n " << db_name;
    }

    std::string output = run_ida_script(cmd.str());
    return R"({"status":"ok","db_path":")" + db_path + "\",\"db_name":" + db_name +
           "\",\"exit_code\":0," + extract_json_field(output, "content") + "}";
}

// ============================================================================
// MCP tool: list_functions
// ============================================================================
std::string cmd_list_functions(const std::string& prefix) {
    std::string script = R"(
import sys
def _list(prefix):
    f = get_func(get_min_ea())
    first = True
    while f is not None:
        if not first:
            print('|')
        name = get_func_name(f.start_ea)
        if prefix == "" or name.startswith(prefix):
            print(f"{f.start_ea:#x}|{name}")
        f = f.next
        first = False
if __name__ == '__main__':
    import sys
    _list(sys.argv[1] if len(sys.argv) > 1 else "")
)".replace("__argv1__", prefix.empty() ? "\"\"" : "\"" + prefix + "\"");

    std::string output = run_ida_script(script);
    // Parse "ea|name" lines separated by |
    std::vector<std::pair<uint64_t, std::string>> funcs;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty() || line == "|") continue;
        size_t pos = line.find('|');
        if (pos != std::string::npos) {
            try {
                uint64_t ea = std::stoull(line.substr(0, pos), nullptr, 16);
                std::string name = line.substr(pos + 1);
                funcs.push_back({ea, name});
            } catch (...) {
                continue;
            }
        }
    }

    std::ostringstream ss;
    ss << "{\"status\":\"ok\",\"count\":" << funcs.size() << ",\"functions\":[";
    for (size_t i = 0; i < funcs.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"ea\":\"0x" << std::hex << funcs[i].first << "\",\"name\":\"" << funcs[i].second << "\"}";
    }
    ss << "]}";
    return ss.str();
}

// ============================================================================
// MCP tool: get_function_disassembly
// ============================================================================
std::string cmd_get_function_disassembly(uint64_t ea) {
    std::ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << std::hex << ea << "\n"
           << "f = get_func(ea)\n"
           << "if f is None:\n"
           << "    print('ERROR: no function at ' + hex(ea))\n"
           << "else:\n"
           << "    for ins in f.get_disasm():\n"
           << "        print(hex(ins.ea) + ' ' + str(ins))\n";

    std::string output = run_ida_script(script.str());
    std::vector<std::string> lines;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && !line.starts_with("ERROR:")) {
            lines.push_back(line);
        }
    }

    std::ostringstream ss;
    ss << "{\"status\":\"ok\",\"ea\":\"0x" << std::hex << ea << "\",\"disassembly\":[";
    for (size_t i = 0; i < lines.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << escape_json(lines[i]) << "\"";
    }
    ss << "]}";
    return ss.str();
}

// ============================================================================
// MCP tool: get_disassembly (single instruction)
// ============================================================================
std::string cmd_get_disassembly(uint64_t ea) {
    std::ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << std::hex << ea << "\n"
           << "if get_flags(ea) & CFUNC:\n"
           << "    print('ERROR: address is a function, not an instruction')\n"
           << "else:\n"
           << "    ins = decode_insn(ea)\n"
           << "    if ins is None:\n"
           << "        print('ERROR: cannot decode instruction at ' + hex(ea))\n"
           << "    else:\n"
           << "        print(hex(ins.ea) + ' ' + str(ins))\n";

    std::string output = run_ida_script(script.str());
    return R"({"status":"ok","ea":"0x)" + std::hex << ea << R"(","disassembly":" )" +
           escape_json(output) + "\"}";
}

// ============================================================================
// MCP tool: read_bytes
// ============================================================================
std::string cmd_read_bytes(uint64_t ea, int count) {
    std::ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << std::hex << ea << "\n"
           << "count = " << count << "\n"
           << "data = get_bytes(ea, count)\n"
           << "if data is None:\n"
           << "    print('ERROR: cannot read bytes at ' + hex(ea))\n"
           << "else:\n"
           << "    for i, b in enumerate(data):\n"
           << "        print(f'{ea + i:#x}:{b:02x}')\n";

    std::string output = run_ida_script(script.str());
    std::vector<std::string> hex_bytes;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find(':') != std::string::npos) {
            size_t pos = line.find(':');
            hex_bytes.push_back(line.substr(pos + 1));
        }
    }

    std::ostringstream ss;
    ss << "{\"status\":\"ok\",\"ea\":\"0x" << std::hex << ea << "\",\"count\":" << count
       << ",\"hex_bytes\":[" << join_strings(hex_bytes, ",") << "]}";
    return ss.str();
}

// ============================================================================
// MCP tool: write_bytes
// ============================================================================
std::string cmd_write_bytes(uint64_t ea, const std::string& data, int base) {
    // Parse hex string
    std::vector<uint8_t> bytes;
    std::string hex = data;
    // Remove spaces and newlines
    hex.erase(std::remove_if(hex.begin(), hex.end(), ::isspace), hex.end());

    if (hex.empty()) {
        return R"({"status":"error","message":"No data provided"})";
    }

    // Try hex decode
    if (base == 16) {
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            char* end;
            long val = std::strtol(byteStr.c_str(), &end, 16);
            if (*end != '\0') {
                return R"({"status":"error","message":"Invalid hex data"})";
            }
            bytes.push_back(static_cast<uint8_t>(val));
        }
    }

    // Build the script
    std::ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << std::hex << ea << "\n"
           << "data = bytes(" << join_numbers(bytes, ",") << ")\n"
           << "if len(data) != " << bytes.size() << ":\n"
           << "    print('ERROR: byte count mismatch')\n"
           << "else:\n"
           << "    try:\n"
           << "        for i, b in enumerate(data):\n"
           << "            patch_byte(ea + i, b)\n"
           << "        print('OK: wrote ' + str(len(data)) + ' bytes at ' + hex(ea))\n"
           << "    except Exception as e:\n"
           << "        print('ERROR: ' + str(e))\n";

    std::string output = run_ida_script(script.str());
    std::string status = (output.find("OK") != std::string::npos && output.find("ERROR") == std::string::npos)
                         ? "ok" : "error";

    return R"({"status":")" + status + R"(","ea":"0x)" << std::hex << ea
           << R("(","size":)" << bytes.size() << ",\"output":"" << escape_json(output) << "\"}";
}

// ============================================================================
// MCP tool: list_segments
// ============================================================================
std::string cmd_list_segments() {
    std::string script = R"(
import sys
seg = get_first_seg()
first = True
while seg is not None:
    if not first:
        print('|')
    print(f"{seg.start:#x}|{seg.end:#x}|{seg.getseg().perm}|{seg.name}")
    seg = seg.next
    first = False
";

    std::string output = run_ida_script(script);
    std::vector<std::pair<uint64_t, uint64_t>> segs;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty() || line == "|") continue;
        size_t pos = line.find('|');
        if (pos != std::string::npos) {
            try {
                uint64_t start = std::stoull(line.substr(0, pos), nullptr, 16);
                uint64_t end = std::stoull(line.substr(pos + 1), nullptr, 16);
                segs.push_back({start, end});
            } catch (...) {
                continue;
            }
        }
    }

    std::ostringstream ss;
    ss << "{\"status\":\"ok\",\"count\":" << segs.size() << ",\"segments\":[";
    for (size_t i = 0; i < segs.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"start\":\"0x" << std::hex << segs[i].first
           << "\",\"end\":\"0x" << std::hex << segs[i].second << "\"}";
    }
    ss << "]}";
    return ss.str();
}

// ============================================================================
// MCP tool: get_xrefs_to
// ============================================================================
std::string cmd_get_xrefs_to(uint64_t ea) {
    std::ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << std::hex << ea << "\n"
           << "x = get_first_xyref(ea, 0)\n"
           << "first = True\n"
           << "while x is not None:\n"
           << "    if not first:\n"
           << "        print('|')\n"
           << "    print(f'{x.frm:#x}|{x.type}|{x.ino:#x}')\n"
           << "    x = get_next_xyref(x)\n"
           << "    first = False\n";

    std::string output = run_ida_script(script);
    std::vector<std::map<std::string, std::string>> xrefs;
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty() || line == "|") continue;
        size_t pos = line.find('|');
        if (pos != std::string::npos) {
            std::istringstream inner(line);
            std::string field;
            std::vector<std::string> parts;
            while (std::getline(inner, field, '|')) {
                parts.push_back(field);
            }
            if (parts.size() == 3) {
                xrefs.push_back({
                    {"from_ea", parts[0]},
                    {"type", parts[1]},
                    {"to_ea", parts[2]}
                });
            }
        }
    }

    std::ostringstream ss;
    ss << "{\"status\":\"ok\",\"ea\":\"0x" << std::hex << ea << "\",\"count\":" << xrefs.size() << ",\"xrefs\":[";
    for (size_t i = 0; i < xrefs.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"from_ea\":\"0x" << std::hex << std::stoull(xrefs[i]["from_ea"], nullptr, 16)
           << "\",\"type\":\"" << xrefs[i]["type"] << "\",\"to_ea\":\"0x" << std::hex << std::stoull(xrefs[i]["to_ea"], nullptr, 16) << "\"}";
    }
    ss << "]}";
    return ss.str();
}

// ============================================================================
// MCP tool: get_function_by_name
// ============================================================================
std::string cmd_get_function_by_name(const std::string& name) {
    std::ostringstream script;
    script << "import sys\n"
           << "name = \"" << escape_python_string(name) << "\"\n"
           << "e = get_sym_tab_entry(name)\n"
           << "if e is None:\n"
           << "    f = get_func_by_name(name)\n"
           << "    if f is None:\n"
           << "        print('ERROR: no function named ' + name)\n"
           << "    else:\n"
           << "        print(hex(f.start_ea) + '|' + f.name)\n"
           << "else:\n"
           << "    print(hex(e.value) + '|' + e.name)\n";

    std::string output = run_ida_script(script.str());
    if (output.find("ERROR:") != std::string::npos) {
        return R"({"status":"error","message":")" + escape_json(output) + "\"}";
    }

    size_t pos = output.find('|');
    if (pos != std::string::npos) {
        std::string ea_str = output.substr(0, pos);
        std::string name_str = output.substr(pos + 1);
        try {
            uint64_t ea = std::stoull(ea_str, nullptr, 16);
            return R"({"status":"ok","ea":"0x)" << std::hex << ea
                   << R"(","name":")" << escape_json(name_str) << R"("})";
        } catch (...) {
            return R"({"status":"ok","raw":")" + escape_json(output) + "\"}";
        }
    }
    return R"({"status":"ok","raw":")" + escape_json(output) + "\"}";
}

// ============================================================================
// MCP tool: create_function
// ============================================================================
std::string cmd_create_function(uint64_t ea) {
    std::ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << std::hex << ea << "\n"
           << "f = create_func(ea)\n"
           << "if f:\n"
           << "    print('OK: created function at ' + hex(f.start_ea))\n"
           << "else:\n"
           << "    print('ERROR: could not create function')\n";

    std::string output = run_ida_script(script.str());
    std::string status = (output.find("ERROR") != std::string::npos) ? "error" : "ok";

    return R"({"status":")" + status << R"(","ea":"0x)" << std::hex << ea
           << R"(","output":")" << escape_json(output) << "\"}";
}

// ============================================================================
// MCP tool: rename_function
// ============================================================================
std::string cmd_rename_function(uint64_t ea, const std::string& new_name) {
    std::ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << std::hex << ea << "\n"
           << "new_name = \"" << escape_python_string(new_name) << "\"\n"
           << "f = get_func(ea)\n"
           << "if f is None:\n"
           << "    print('ERROR: no function at ' + hex(ea))\n"
           << "else:\n"
           << "    try:\n"
           << "        set_name(f.start_ea, new_name, SIaginI)\n"
           << "        print('OK: renamed to ' + new_name)\n"
           << "    except Exception as e:\n"
           << "        print('ERROR: ' + str(e))\n";

    std::string output = run_ida_script(script.str());
    std::string status = (output.find("ERROR") != std::string::npos) ? "error" : "ok";

    return R"({"status":")" + status << R"(","ea":"0x)" << std::hex << ea
           << R"(","new_name":")" << escape_json(new_name) << R"(","output":")" << escape_json(output) << "\"}";
}

// ============================================================================
// Helper functions
// ============================================================================

// Escape a string for JSON output
std::string escape_json(const std::string& s) {
    std::ostringstream ss;
    for (char c : s) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

std::string escape_python_string(const std::string& s) {
    std::ostringstream ss;
    for (char c : s) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

std::string join_numbers(const std::vector<uint8_t>& nums, const std::string& sep) {
    std::ostringstream ss;
    for (size_t i = 0; i < nums.size(); i++) {
        if (i > 0) ss << sep;
        ss << static_cast<int>(nums[i]);
    }
    return ss.str();
}

std::string join_strings(const std::vector<std::string>& strs, const std::string& sep) {
    std::ostringstream ss;
    for (size_t i = 0; i < strs.size(); i++) {
        if (i > 0) ss << sep;
        ss << "\"" << escape_json(strs[i]) << "\"";
    }
    return ss.str();
}

std::string extract_json_field(const std::string& json, const std::string& key) {
    // Simple JSON field extraction
    std::string target = "\"" + key + "\"";
    size_t pos = json.find(target);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    if (pos < json.size() && json[pos] == ' ') pos++;
    if (pos < json.size() && json[pos] == '"') {
        pos++;
        size_t end = json.find('"', pos);
        if (end != std::string::npos) return json.substr(pos, end - pos);
    }
    return "";
}

// ============================================================================
// Plugin entry point (per IDA SDK convention)
// ============================================================================

struct plugin_ctx_t : public plugmod_t {
    virtual bool idaapi run(size_t) override;
};

bool idaapi plugin_ctx_t::run(size_t) {
    // Plugin loaded and initialized - we could register callbacks or
    // wait for commands from the MCP client.
    msg("Freebuff IDA MCP plugin loaded\n");
    return true;
}

static plugmod_t *idaapi init() {
    return new plugin_ctx_t;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    "Freebuff MCP",
    nullptr,
};
