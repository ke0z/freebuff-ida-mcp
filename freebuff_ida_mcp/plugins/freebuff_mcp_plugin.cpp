// ============================================================================
// freebuff_mcp_plugin.cpp
// IDA Pro 9.3 C++ plugin for Freebuff MCP server (Linux x64)
// ============================================================================
// Build:
//   g++ -std=c++17 -fPIC -shared -fvisibility=hidden \
//       -I$HOME/Downloads/ida-sdk/src/include \
//       -I$HOME/Downloads/ida-sdk/src/lib/x64_linux_gcc_64 \
//       freebuff_mcp_plugin.cpp -o plugins_freebuff_mcp_plugin.so \
//       -ldl -lpthread -lrt -w -pie
// Install:
//   cp plugins_freebuff_mcp_plugin.so /opt/ida-free/ida64/plugins/
// ============================================================================
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <entry.hpp>
#include <nalt.hpp>
#include <diskio.hpp>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <iomanip>

using namespace std;

const char* g_ida_pro_path = "/opt/ida-free/ida64";
const char* g_ida_sdk_path = "/home/ke0z/Downloads/ida-sdk/src/";

// Read an environment variable using the SDK's qgetenv API.
// Returns true and fills buf if the variable exists, false otherwise.
static bool get_env_var(const char* name, string& value) {
    qstring buf;
    if (qgetenv(name, &buf)) {
        value = buf.c_str();
        return true;
    }
    return false;
}

void init_config(void) {
    string v;
    if (get_env_var("IDA_PRO_PATH", v)) g_ida_pro_path = v.c_str();
    if (get_env_var("IDA_SDK_PATH", v)) g_ida_sdk_path = v.c_str();
}

// Run an ida64 Python script and return its stdout.
string run_ida_script(const string& script_code) {
    char tmpfile[] = "/tmp/freebuff_ida_script_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd == -1) {
        msg("plugin: mkstemp failed\n");
        return "ERROR: mkstemp failed";
    }
    write(fd, script_code.c_str(), script_code.size());
    close(fd);

    string cmd = string(g_ida_pro_path) + " -A -S" + tmpfile;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        string err = "ERROR: popen failed";
        unlink(tmpfile);
        msg("%s\n", err.c_str());
        return err;
    }

    string output;
    char buf[4096];
    while (qfgets(buf, sizeof(buf), pipe) != nullptr) {
        output += buf;
    }
    int status = pclose(pipe);
    unlink(tmpfile);

    if (WIFEXITED(status)) {
        int rc = WEXITSTATUS(status);
        if (rc != 0) msg("[plugin] ida64 exited with code %d\n", rc);
    }
    return output;
}

string escape_json(const string& s) {
    ostringstream ss;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    ss << "\\u" << hex << setw(4) << setfill('0') << (int)c;
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

vector<pair<uint64_t, string>> parse_func_list(const string& output) {
    vector<pair<uint64_t, string>> funcs;
    istringstream iss(output);
    string line;
    while (getline(iss, line)) {
        if (line.empty() || line == "|") continue;
        size_t pos = line.find('|');
        if (pos != string::npos) {
            try {
                uint64_t ea = stoull(line.substr(0, pos), nullptr, 16);
                funcs.push_back(make_pair(ea, line.substr(pos + 1)));
            } catch (...) {}
        }
    }
    return funcs;
}

vector<pair<uint64_t, uint64_t>> parse_seg_list(const string& output) {
    vector<pair<uint64_t, uint64_t>> segs;
    istringstream iss(output);
    string line;
    while (getline(iss, line)) {
        if (line.empty() || line == "|") continue;
        size_t pos = line.find('|');
        if (pos != string::npos) {
            try {
                segs.push_back(make_pair(
                    stoull(line.substr(0, pos), nullptr, 16),
                    stoull(line.substr(pos + 1), nullptr, 16)));
            } catch (...) {}
        }
    }
    return segs;
}

// Tool implementations (JSON return values)

// --- get_ida_info ---
string cmd_get_ida_info() {
    ostringstream ss;
    ss << "{\"ida_pro_path\":\"" << g_ida_pro_path
       << "\",\"ida_sdk_path\":\"" << g_ida_sdk_path
       << "\",\"sdk_configured\":true,\"transport\":\"stdio\",\"mcp_version\":\"0.1.0\"}";
    return ss.str();
}

// --- load_database ---
string cmd_load_database(const string& db_path, const string& db_name) {
    string cmd = string(g_ida_pro_path) + " -A -o " + db_path + " -n " + db_name;
    string output = run_ida_script(cmd);
    ostringstream ss;
    ss << "{\"status\":\"ok\",\"db_path\":\"" << db_path
       << "\",\"db_name\":\"" << db_name
       << "\",\"exit_code\":0,\"content\":\"" << escape_json(output) << "\"}";
    return ss.str();
}

// --- list_functions ---
string cmd_list_functions(const string& prefix) {
    ostringstream script;
    script << "import sys\n"
           << "def _list(pfx):\n"
           << "    f = get_func(get_min_ea())\n"
           << "    first = True\n"
           << "    while f is not None:\n"
           << "        if not first: print('|')\n"
           << "        name = get_func_name(f.start_ea)\n"
           << "        if pfx == \"\" or name.startswith(pfx):\n"
           << "            print(\"%#x|%s\" % (f.start_ea, name))\n"
           << "        f = f.next\n"
           << "        first = False\n"
           << "if __name__ == '__main__':\n"
           << "    _list(sys.argv[1] if len(sys.argv) > 1 else \"\")\n";
    string output = run_ida_script(script.str());
    auto funcs = parse_func_list(output);
    ostringstream ss;
    ss << "{\"status\":\"ok\",\"count\":" << funcs.size() << ",\"functions\":[";
    for (size_t i = 0; i < funcs.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"ea\":\"0x" << hex << funcs[i].first
           << "\",\"name\":\"" << escape_json(funcs[i].second) << "\"}";
    }
    ss << "]}";
    return ss.str();
}

// --- get_disassembly ---
string cmd_get_disassembly(uint64_t ea) {
    ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << hex << ea << "\n"
           << "ins = decode_insn(ea)\n"
           << "if ins:\n"
           << "    print(\"%#x %s\" % (ins.ea, ins))\n";
    string output = run_ida_script(script.str());
    ostringstream ss;
    ss << "{\"status\":\"ok\",\"ea\":\"0x" << hex << ea
       << "\",\"disassembly\":\"" << escape_json(output) << "\"}";
    return ss.str();
}

// --- read_bytes ---
string cmd_read_bytes(uint64_t ea, int count) {
    ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << hex << ea << "\n"
           << "count = " << dec << count << "\n"
           << "data = get_bytes(ea, count)\n"
           << "if data:\n"
           << "    for i, b in enumerate(data):\n"
           << "        print(\"%#x:%02x\" % (ea + i, b))\n";
    string output = run_ida_script(script.str());
    vector<string> hex_bytes;
    istringstream iss(output);
    string line;
    while (getline(iss, line)) {
        if (line.find(':') != string::npos) {
            hex_bytes.push_back(line.substr(line.find(':') + 1));
        }
    }
    ostringstream ss;
    ss << "{\"status\":\"ok\",\"ea\":\"0x" << hex << ea
       << "\",\"count\":" << count << ",\"hex_bytes\":[";
    for (size_t i = 0; i < hex_bytes.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << hex_bytes[i] << "\"";
    }
    ss << "]}";
    return ss.str();
}

// --- list_segments ---
string cmd_list_segments() {
    ostringstream script;
    script << "import sys\n"
           << "seg = get_first_seg()\n"
           << "first = True\n"
           << "while seg is not None:\n"
           << "    if not first: print('|')\n"
           << "    print(\"%#x|%#x\" % (seg.start, seg.end))\n"
           << "    seg = seg.next\n"
           << "    first = False\n";
    string output = run_ida_script(script.str());
    auto segs = parse_seg_list(output);
    ostringstream ss;
    ss << "{\"status\":\"ok\",\"count\":" << segs.size() << ",\"segments\":[";
    for (size_t i = 0; i < segs.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"start\":\"0x" << hex << segs[i].first
           << "\",\"end\":\"0x" << hex << segs[i].second << "\"}";
    }
    ss << "]}";
    return ss.str();
}

// --- get_function_by_name ---
string cmd_get_function_by_name(const string& name) {
    ostringstream script;
    script << "import sys\n"
           << "name = \"" << name << "\"\n"
           << "e = get_sym_tab_entry(name)\n"
           << "if e is None:\n"
           << "    f = get_func_by_name(name)\n"
           << "    if f is None:\n"
           << "        print(\"ERROR: no function named \" + name)\n"
           << "    else:\n"
           << "        print(\"%#x|%s\" % (f.start_ea, f.name))\n"
           << "else:\n"
           << "    print(\"%#x|%s\" % (e.value, e.name))\n";
    string output = run_ida_script(script.str());
    size_t pos = output.find('|');
    if (pos != string::npos) {
        try {
            uint64_t ea = stoull(output.substr(0, pos), nullptr, 16);
            ostringstream ss;
            ss << "{\"status\":\"ok\",\"ea\":\"0x" << hex << ea
               << "\",\"name\":\"" << escape_json(output.substr(pos + 1)) << "\"}";
            return ss.str();
        } catch (...) {}
    }
    return "{\"status\":\"ok\",\"raw\":\"" + escape_json(output) + "\"}";
}

// --- create_function ---
string cmd_create_function(uint64_t ea) {
    ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << hex << ea << "\n"
           << "f = create_func(ea)\n"
           << "if f:\n"
           << "    print(\"OK created\")\n"
           << "else:\n"
           << "    print(\"ERROR\")\n";
    string output = run_ida_script(script.str());
    string status = (output.find("ERROR") != string::npos) ? "error" : "ok";
    ostringstream ss;
    ss << "{\"status\":\"" << status << "\",\"ea\":\"0x" << hex << ea << "\"}";
    return ss.str();
}

// --- rename_function ---
string cmd_rename_function(uint64_t ea, const string& new_name) {
    ostringstream script;
    script << "import sys\n"
           << "ea = 0x" << hex << ea << "\n"
           << "new_name = \"" << new_name << "\"\n"
           << "f = get_func(ea)\n"
           << "if f is None:\n"
           << "    print(\"ERROR: no function\")\n"
           << "else:\n"
           << "    set_name(f.start_ea, new_name, SIaginI)\n"
           << "    print(\"OK\")\n";
    string output = run_ida_script(script.str());
    string status = (output.find("ERROR") != string::npos) ? "error" : "ok";
    ostringstream ss;
    ss << "{\"status\":\"" << status << "\",\"ea\":\"0x" << hex << ea
       << "\",\"new_name\":\"" << escape_json(new_name) << "\"}";
    return ss.str();
}

// --- plugin_ctx_t / plugmod_t ---
struct plugin_ctx_t : public plugmod_t {
    virtual bool idaapi run(size_t) override {
        msg("Freebuff MCP plugin loaded\n");
        return true;
    }
};

// Plugin entry point (PLUGIN_MULTI — init() returns a plugmod_t object).
static plugmod_t* idaapi init() {
    init_config();
    return new plugin_ctx_t;
}

// plugin_t struct — 9 fields from loader.hpp:
// version, flags, init, term, run, comment, help, wanted_name, wanted_hotkey
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL | PLUGIN_MULTI,
    init,
    nullptr, nullptr, nullptr,
    "Freebuff MCP",
    nullptr,
    nullptr,
};
