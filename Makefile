# proctrace - eBPF process/open tracer with Perfetto output
#
# Layout:
#   src/proctrace.bpf.c   -> compiled to BPF, turned into a libbpf skeleton
#   src/*.cpp             -> userspace loader linked against libbpf
#
ARCH        ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/')
CLANG       ?= clang
CXX         = clang++
BPFTOOL     ?= bpftool

SRC         := src
BUILD       := build
BIN         := proctrace

BPF_SRC     := $(SRC)/proctrace.bpf.c
BPF_OBJ     := $(BUILD)/proctrace.bpf.o
SKEL        := $(SRC)/proctrace.skel.h
VMLINUX     := $(SRC)/vmlinux.h

CXX_SRC     := $(SRC)/main.cpp $(SRC)/perfetto_trace.cpp
CXXFLAGS    := -O2 -g -std=c++23 -Wall -Wextra -I$(SRC)
LDLIBS      := -lbpf -lelf -lz

# ignore more than usual because of vmlinux.h
BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(SRC) \
               -Wall -Wno-unused-function -Wno-c23-extensions -Wno-missing-declarations \
	       -mcpu=v3

.PHONY: all clean vmlinux
all: $(BIN)

# Regenerate the kernel type header from the running kernel's BTF.
vmlinux $(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name proctrace_bpf > $@

$(BIN): $(SKEL) $(CXX_SRC)
	$(CXX) $(CXXFLAGS) $(CXX_SRC) -o $@ $(LDLIBS)

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD) $(SKEL) $(BIN)
