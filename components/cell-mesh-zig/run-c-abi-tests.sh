#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

zig build

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

run_test() {
  name="$1"
  src="../cell-mesh/test/${name}.c"
  exe="$tmpdir/$name"

  printf '==> %s\n' "$name"
  zig cc -I ../cell-mesh/include "$src" zig-out/lib/libcell_mesh_zig.a -o "$exe"
  "$exe"
}

run_test test_cell_wire
run_test test_cell_meter
run_test test_cell_ring
run_test test_cell_channel
run_test test_cell_forward
run_test test_cell_forward_v1
run_test test_cell_forward_v2
run_test test_cell_frame
run_test test_cell_capability
run_test test_cell_rules
run_test test_mnca_incentive
