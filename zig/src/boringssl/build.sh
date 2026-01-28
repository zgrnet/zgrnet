#!/bin/bash
set -e

# Compile C wrapper
clang -c chacha20_poly1305_wrapper.c -O3 -Wall -o wrapper.o -I.

# Compile ASM
clang -c chacha20_poly1305.S -o asm.o

# Create static library
ar rcs libchacha.a wrapper.o asm.o
ranlib libchacha.a

# Build Zig benchmark
zig build-obj bench.zig -OReleaseFast -femit-bin=bench_zig.o

# Link
clang bench_zig.o wrapper.o asm.o -o bench -lc

# Run
./bench

# Clean
rm -f wrapper.o asm.o bench_zig.o libchacha.a
