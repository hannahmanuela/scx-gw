

BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
BPF_CFLAGS ?= -O2 -g -target bpf -Iinclude
# CFLAGS += -I.include

BPFSRC := scx_h.bpf.c
BPFELF := scx_h.bpf.o
BPF_SKEL_HDR := scx_h.bpf.skel.h
USER_SRC := scx_h.c
USER_BIN := scx_h

# LIBBPF_OBJ ?= -lbpf
# PKGS ?= libbpf

.PHONY: bpf test clean

all: bpf test

bpf: $(USER_BIN)

$(BPFELF): $(BPFSRC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

$(BPF_SKEL_HDR): $(BPFELF)
	bpftool gen skeleton $< name scx_h > $@

$(USER_BIN): $(USER_SRC) $(BPF_SKEL_HDR)
	$(CC) -g -O2 -Wall -I. -Iinclude -Ilibbpf/include -o $@ $(USER_SRC) -Llibbpf/lib64 -Wl,-rpath,libbpf/lib64 -lbpf

test:
	g++ -std=c++17 -o test_policy/test test_policy/test.cpp
	g++ -std=c++17 -o test_policy/test-2core test_policy/test-2core.cpp

clean:
	rm -f $(BPFELF) $(BPF_SKEL_HDR) $(USER_BIN)

