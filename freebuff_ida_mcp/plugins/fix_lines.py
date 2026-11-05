#!/usr/bin/env python3
"""Fix the escaping issues in the C++ file."""

with open('/home/ke0z/freebuff-ida-mcp/freebuff_ida_mcp/plugins/freebuff_mcp_plugin.cpp', 'r') as f:
    lines = f.readlines()

# Fix specific lines that have the escaping issues
# Lines 657, 734, 938: << "    \"function_ea\": std::hex << function_ea << ",\n"
# The current (wrong) content: << "    \"function_ea\": std::hex << function_ea << ",\n
# This should be: << "    \"function_ea\": std::hex << function_ea << ",\n
# Actually wait, I need to understand what the correct format is.
# The Python script needs to output:     "function_ea": 0x12345678,

# The C++ code generates the Python script. So the C++ string should contain:
#     "function_ea": 0x12345678,
# Which in C++ is:     \"function_ea\": std::hex << function_ea << \",

# So the C++ source should have: \\" for the quote and \\n for the newline
# Wait, no: 
# - " in C++ source = \"
# - \n in C++ string literal = \n (escape sequence)
# - \\ in C++ source = \\
# - \\n in C++ source = \n (literal backslash + n)

# The Python script needs to output:     "function_ea": 0x12345678,
# So the C++ string needs to contain:     "function_ea": 0x12345678,
# Which is:     \"function_ea\": std::hex << function_ea << \",
# So the C++ source should have: \\" ... \\"

# Current (wrong): << "    \"function_ea\": std::hex << function_ea << ",\n"
# The \" is correct for C++ (produces " in string)
# The , is correct
# The \n is correct for C++ (produces newline in string)  
# Wait, but the error says \n is wrong. Let me check...

# Actually, I think the issue is that the original code used hex(ea) not hex(function_ea)
# And the original might have had a different format. Let me try to match the original.

# The original line 657 might have been:
# << "    \"function_ea\": hex(ea),\n"
# Where ea was a C++ variable that didn't exist...

# Or maybe the original was:
# << "    \"function_ea\": hex(function_ea),\n"
# Which is what I have now.

# The issue might be that the string ends with \", not \n
# Let me try without the closing quote.

print("Fix script ready")
