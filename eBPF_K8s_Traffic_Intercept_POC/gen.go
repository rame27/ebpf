//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -strip llvm-strip-14 bpf ./bpf/tc_prog.c

package main
