# ============================================================================
# Freebuff MCP Plugin Makefile
# ============================================================================
# Build:
#   make
# Install:
#   make install
# ============================================================================
IDA_SDK := /home/ke0z/Downloads/ida-sdk/src
IDA_LIB := $(IDA_SDK)/lib/x64_linux_gcc_64
IDA_PLUGINS := /opt/ida-free/plugins

CXX := g++
CXXFLAGS := -std=c++17 -fPIC -fvisibility=hidden \
            -I$(IDA_SDK)/include \
            -I$(IDA_LIB)
LDFLAGS := -L$(IDA_LIB) -lidalib -lida -ldl -lpthread -lrt -w -Wl,--no-as-needed
LDLIBS := -L$(IDA_PLUGINS) -lidalib -lida

SRC := freebuff_mcp_plugin.cpp
TARGET := plugins_freebuff_mcp_plugin.so
INSTALL := $(IDA_PLUGINS)/$(TARGET)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -shared $(SRC) -o $(TARGET) $(LDFLAGS) $(LDLIBS)
	@echo "Built: $(TARGET)"

install: $(TARGET)
	@if [ -d $(IDA_PLUGINS) ]; then \
		cp $(TARGET) $(IDA_PLUGINS)/; \
		echo "Installed: $(IDA_PLUGINS)/$(TARGET)"; \
	else \
		echo "Error: IDA plugins directory not found: $(IDA_PLUGINS)"; \
		exit 1; \
	fi

clean:
	rm -f $(TARGET)
	@echo "Cleaned"
