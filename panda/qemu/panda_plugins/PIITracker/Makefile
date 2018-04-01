# Don't forget to add your plugin to config.panda!

# Set your plugin name here. It does not have to correspond to the name
# of the directory in which your plugin resides.
PLUGIN_NAME=PIITracker

# Include the PANDA Makefile rules
include ../panda.mak

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+=-std=c11 -O2 -g
#CFLAGS+=$(LLVM_CFLAGS)
CXXFLAGS+=-std=c++11 -O2 -g
#CXXFLAGS+=$(LLVM_CXXFLAGS)

# If you need custom CFLAGS or LIBS, set them up here
# CFLAGS+=
LIBS+=-lpthread

# The main rule for your plugin. Please stick with the panda_ naming
# convention.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o $(PLUGIN_TARGET_DIR)/pwnda_funcs.o
	$(call quiet-command,$(CC) $(QEMU_CFLAGS) -shared -o $@ $^ $(LIBS),"  PLUGIN  $@")

all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so


