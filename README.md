# bpfstats
## Build
To build the program just run `make`. 
In this project it has been used bpftools and libbpf.
`vmlinux.h` file contains every kernel function and type for a specific version, so this file should be generated from the current version of the Linux kernel. 

## Known problem
File `bpf_struct.h` is required because libbpf `set_attach_target` function doesn't permit to attach a bpf program to a kernel function dynamicaly with fentry/fexit. So it was necessary to change the vmlinux_btf variable of a bpf program, in order to do that was required to define the bpf_program and bpf_object structure like they're defined in libbpf.c.
