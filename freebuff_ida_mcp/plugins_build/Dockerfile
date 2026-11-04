# IDA Pro 9.3 C++ Plugin Build Environment
# Builds freebuff_mcp_plugin.so for Linux x64

FROM ubuntu:24.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    cmake \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install SDK (copy into container)
WORKDIR /ida-sdk
COPY . .

# Set up environment for IDA 9.3 Linux x64 build
ENV __LINUX__=1 \
    __X64__=1 \
    __EA64__=1 \
    COMPILER_NAME=gcc \
    IDA=ida-sdk/ \
    INCLUDE=ida-sdk/include/ \
    IDABIN=ida-sdk/bin/ \
    LIBDIR=ida-sdk/lib/x64_linux_gcc_64/ \
    OBJDIR=ida-sdk/obj/freebsd_gcc_64 \
    R=ida-sdk/bin/ \
    L=ida-sdk/lib/x64_linux_gcc_64/ \
    F=ida-sdk/obj/freebsd_gcc_64/ \
    DLLEXT=so \
    IDAVER_MAJOR=9 \
    IDAVER_MINOR=3 \
    IDAVER_PATCH=0

# Copy our plugin source
COPY freebuff_mcp_plugin.cpp /ida-sdk/plugins/freebuff_mcp_plugin/

# Build the plugin
WORKDIR /ida-sdk/plugins/freebuff_mcp_plugin
RUN gcc -std=c++17 -fPIC -shared -fvisibility=hidden \
    -I$IDA/include/ \
    -I$IDA/lib/x64_linux_gcc_64/ \
    freebuff_mcp_plugin.cpp \
    -o freebuff_mcp_plugin.so \
    -ldl -lpthread -lrt -ldl -pie

# Verify the build
RUN file freebuff_mcp_plugin.so && ldd freebuff_mcp_plugin.so

# Default command
CMD ["bash"]
