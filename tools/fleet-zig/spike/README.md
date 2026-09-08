# Conformance spike — does bsvz reproduce Plexus derivation?

A ~40-line answer to the question the whole Zig control plane rests on. Run it:

```bash
zig build run          # needs zig 0.15.2
```

```
  root priv (PBKDF2)     MATCH    fe99e571a1efe336bae65e3c18ceeca686333fcbcfff5b08ecf5fed42d0f8398
  root pub               MATCH    028abd82d22850c0bff781e9a47e7d4f7bd6bf58102baad9baf5f8fa17d0c2cfa4
  child priv (BRC-42)    MATCH    a944d24511981a2277967f3a5dd7d27e8fb417cd4d7c8d8650a06076df816e1e
  child pub              MATCH    02237e12d171edde88f1c6980db9e289788dc418ed251cdecc9683e6186a702ede

*** bsvz reproduces Plexus derivation exactly ***
```

Values are from the SDK's own pinned golden vector,
`plexus-sdk-ts/src/tests/vectors/cross-impl-derivation.golden.json`.

Two things are proven here and nothing else:

1. **PBKDF2 agrees.** Zig's `std.crypto.pwhash.pbkdf2` with `HmacSha512`,
   100,000 iterations, 32 bytes out, is byte-identical to the SDK's root.
2. **BRC-42 agrees.** `bsvz.primitives.ec.deriveChild(self_pub, "inbox:2:0")`
   is byte-identical to `plexus-kdf-v1`. Note the two things that make Plexus's
   use of it unusual and which the spike deliberately exercises: the counterparty
   is the parent's OWN public key (self-derivation), and the invoice is an ASCII
   string, not the 24-byte binary `protocol_hash || index_le` that semantos-core's
   `host.deriveLeaf` uses. Same primitive, different derivation — `deriveLeaf`
   cannot be reused.

This is a spike, not the port. It has no store, no cert encoding, no signing,
and no canonical JSON.
