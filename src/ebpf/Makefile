CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := x86
OUTPUT := ttl_editor.o
SRC := ttl_editor.c

INCLUDES := -I/usr/include -I/usr/include/$(ARCH)-linux-gnu

CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall

.PHONY: all clean install uninstall check-deps

all: check-deps $(OUTPUT)

check-deps:
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "Error: clang not found. Install with: sudo apt install clang llvm" >&2; exit 1; }
	@command -v $(LLVM_STRIP) >/dev/null 2>&1 || { echo "Error: llvm-strip not found. Install with: sudo apt install llvm" >&2; exit 1; }
	@command -v tc >/dev/null 2>&1 || { echo "Error: tc not found. Install with: sudo apt install iproute2" >&2; exit 1; }
	@test -f /usr/include/bpf/bpf_helpers.h || { echo "Error: libbpf headers not found. Install with: sudo apt install libbpf-dev" >&2; exit 1; }
	@test -f /usr/include/linux/bpf.h || { echo "Error: kernel headers not found. Install with: sudo apt install linux-headers-$$(uname -r)" >&2; exit 1; }

$(OUTPUT): $(SRC)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(OUTPUT)

install: $(OUTPUT)
	@echo "Attach qdisc with:"
	@echo "  sudo tc qdisc add dev <interface> clsact"
	@echo "Install tc filter with:"
	@echo "  sudo tc filter add dev <interface> egress bpf da obj $(OUTPUT) sec classifier"

uninstall:
	@echo "Remove with:"
	@echo "  sudo tc filter del dev <interface> egress"
	@echo "  sudo tc qdisc del dev <interface> clsact"

deps-install:
	@echo "Installing build dependencies..."
	@echo "Run: sudo apt update && sudo apt install -y clang llvm libbpf-dev linux-headers-$$(uname -r) iproute2"