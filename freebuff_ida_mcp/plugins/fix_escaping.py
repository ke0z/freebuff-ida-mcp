#!/usr/bin/env python3
"""Fix the escaping in the C++ file."""

with open('/home/ke0z/freebuff-ida-mcp/freebuff_ida_mcp/plugins/freebuff_mcp_plugin.cpp', 'r') as f:
    lines = f.readlines()

# Fix line 657 (0-indexed: 656)
# The current line is:
#            << "    \"function_ea\": std::hex << function_ea << ",\n"
# It should be:
#            << "    \"function_ea\": std::hex << function_ea << ",\n"

# The issue is that \" in C++ string should be \\" in the file
# And \n at end of C++ string should be \\n in the file
# But we need to be careful about what we're replacing

# For line 657:
# Old: << "    \"function_ea\": std::hex << function_ea << ",\n"
# New: << "    \"function_ea\": std::hex << function_ea << ",\n"

# In the file, the sequence is:
# - \" (backslash + quote) - this is correct for C++
# - ,\n (comma + newline) - this is correct

# Wait, but the build error says there's an issue. Let me check what's actually wrong.
# The error says: stray '\' at position 66
# Position 66 is the \ before n in ,"\n"

# Actually, looking at the hex dump again:
# 2c5c 5c6e 220a
# , \ \ n " \n
# This is , \\ n " \n
# In C++, this is: comma, escaped backslash (\\), n, closing quote, newline
# The string would be: ",\n" (comma followed by \n)
# This should be fine...

# Let me just try building again to see if the error persists
print("File content checked")
