CC = gcc
OUTPUT := .output
CLANG := clang
LLVM_STRIP := llvm-strip
BPFTOOL := bin/bpftool
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT)
CFLAGS := -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
APP_NAME := bpfstats

.PHONY: all
all: $(APP_NAME)

.PHONY: clean

clean:
	rm -rf $(OUTPUT) $(APP_NAME)

#create executable file
$(APP_NAME): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
		$(CC) $(CFLAGS) $^ -lelf -lz -o $@

#generate .output folder
$(OUTPUT) $(OUTPUT)/libbpf:
	mkdir -p $@

$(patsubst %,$(OUTPUT)/%.o,bpfstats): %.o: %.skel.h

#create user object file
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

#create bpf skeleton
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

#build bpf elf via clang
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) -c $(filter %.c,$^) -o $@ &&		      \
	$(LLVM_STRIP) -g $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install
