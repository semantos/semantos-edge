# Smart-City Throughput Notes

The smart-city question is not whether one microcontroller can produce tens of
thousands of transactions per second. It cannot, and it should not try.

The Semantos edge split is:

- **Device:** verify local policy, meter use, actuate, and emit signed cells.
- **Gateway / broadcaster:** aggregate cells, batch work, and settle on BSV.
- **BSV L1:** carry the durable payment / audit / custody trail.

## 60k TPS Requirement

A 60k TPS smart-city target should be treated as a system-level throughput
requirement. The edge kit addresses the device side: cheap local verification
and physical consequences without giving devices spending keys. The settlement
side is a horizontally scaled broadcaster problem.

## Current Evidence

The broader Semantos broadcaster work has produced a short laptop burst of
about **14.7k tx/s** into GorillaPool ARC. That run is useful evidence that the
bottleneck can sit on the client/broadcaster machine rather than the network,
but it is not a formal capacity claim and should not be presented as a stable
benchmark without a reproducible harness and run log.

For public claims, use this phrasing:

> In short local bursts, Semantos broadcaster tooling has pushed roughly 14.7k
> tx/s into GorillaPool ARC before the laptop became the limiting factor. The
> edge-kit architecture is designed to scale that path horizontally: many
> devices verify locally, while gateway broadcasters parallelize settlement.

## What A Real Benchmark Needs

- Reproducible broadcaster command and version.
- Machine specs and network link.
- ARC endpoint and date.
- Number of streams / workers / UTXO lanes.
- Accepted tx count, rejected tx count, duration, p50/p95/p99 latency.
- Wallet/funding strategy and fee policy.
- Clear distinction between raw tx/s, cell-anchoring tx/s, and durable
  confirmation/finality.

## Design Implication

Do not put high-throughput chain work on the MCU. Use the MCU as the
policy-enforcing edge actor, and let gateways compete on batching,
parallelization, and relay quality.
