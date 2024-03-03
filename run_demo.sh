#!/bin/bash
clear
pushd MP-SPDZ
./do_mpc.sh
popd
RUST_LOG="trace" cargo run --bin crunch
RISC0_DEV_MODE=1 RUST_LOG="[executor]=info" cargo run --bin uncrunch
