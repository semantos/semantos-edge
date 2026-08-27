# Vendored conformance vector

`cross-impl-derivation.golden.json` is copied verbatim from the Plexus SDK. It is
the oracle: where this Zig port disagrees with it, this port is wrong.

| | |
|---|---|
| source | `plexus-sdk-ts/src/tests/vectors/cross-impl-derivation.golden.json` |
| generator | `plexus-sdk-ts/tools/gen-derivation-vector.mjs` |
| schemaVersion | 1 |
| sha256 | `12455c0bc0cfe43ceb5601b928ea9d95effe66b45fb31c7beebea69af2c7f012` |
| vendored | 2026-08-27 |

To re-sync after the SDK regenerates it:

```bash
cp "$PLEXUS_SDK_REPO/src/tests/vectors/cross-impl-derivation.golden.json" .
shasum -a 256 cross-impl-derivation.golden.json    # update the row above
zig build test
```

Vendored rather than read from a sibling checkout so `zig build test` cannot pass
by silently failing to find the file — it is `@embedFile`'d, so a missing vector
is a compile error rather than a skipped assertion.
