#!/bin/bash -eu
# OSS-Fuzz build script for openhitls-rs
# Builds all fuzz targets from the fuzz/ directory.

cd $SRC/openhitls-rs/fuzz

# Build each fuzz target
for target in fuzz_targets/fuzz_*.rs; do
    name=$(basename "$target" .rs)
    cargo +nightly fuzz build "$name" -- -C passes=sancov-module \
        -C llvm-args=-sanitizer-coverage-level=edge \
        -C llvm-args=-sanitizer-coverage-trace-compares \
        -C llvm-args=-sanitizer-coverage-inline-8bit-counters \
        -C llvm-args=-sanitizer-coverage-pc-table

    # Copy built binary to $OUT
    cp ../target/*/release/"$name" "$OUT/" 2>/dev/null || true
done

# Copy corpus seeds
for target_dir in corpus/fuzz_*; do
    name=$(basename "$target_dir")
    if [ -d "$target_dir" ]; then
        zip -j "$OUT/${name}_seed_corpus.zip" "$target_dir"/* 2>/dev/null || true
    fi
done

# Copy dictionary
if [ -f dictionary/common.dict ]; then
    for target in fuzz_targets/fuzz_*.rs; do
        name=$(basename "$target" .rs)
        cp dictionary/common.dict "$OUT/${name}.dict" 2>/dev/null || true
    done
fi
