PLUGIN_NAME=func_trace

# Include the PANDA Makefile rules
include ../panda.mak

QEMU_CFLAGS+=-std=c++11

# Include files and lib from LLVM
CXXFLAGS+=$(LLVM_CXXFLAGS)

QEMU_CXXFLAGS+= -std=c++11
QEMU_CXXFLAGS+= -Wno-unused-variable

$(PLUGIN_TARGET_DIR)/pwnda_funcs.o: $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/pwnda_funcs.cpp $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/pwnda_funcs.h

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o \
    $(PLUGIN_TARGET_DIR)/pwnda_funcs.o  \

	$(call quiet-command,$(CXX) $(CXXFLAGS) $(QEMU_CXXFLAGS) \
            -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

ifdef CONFIG_LLVM
all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so
endif

