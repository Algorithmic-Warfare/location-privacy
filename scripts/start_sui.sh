#!/usr/bin/env bash
# Run SUI localnet
# Make sure you have SUI installed and available in your PATH
RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis --epoch-duration-ms 10000
