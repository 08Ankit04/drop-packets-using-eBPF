## Counting Packets recieved

# https://ebpf-go.dev/guides/getting-started/#compile-ebpf-c-and-generate-scaffolding-using-bpf2go : reference link

1. First generate counter.c file and gen.go for generating bpfeb.go, bpfel.go, and .o files
2. go generate
3. create main.go file
4. go build && sudo ./counter for running function

Always need to generate and rebuild files if any changes in .c file.

"ip a" for finding interface of a machine

"sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm" as asm is renames as asm-generic
