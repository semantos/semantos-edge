# bitpiggy_mesh

BitPiggy chore-claim demo on the existing Semantos ESP32 cell-mesh substrate.

This example is intentionally scaffolded from `esp32-hackkit/examples/mesh_demo`, not from the older `piggybank` sketch. It preserves the proven substrate:

- canonical 1024-byte cells;
- signed ESP-NOW frame fragmentation/reassembly;
- wallet-signed embedded cell deck;
- multicast/gossip;
- ring/rules/capability/channel/MNCA plumbing;
- LED feedback on accepted local actions.

## BitPiggy additions

- Adds `bitpiggy.chore_claim.v0` type hash.
- Adds deck kind `32` for pre-signed BitPiggy chore claims.
- Adds a `broadcast_bitpiggy_chore_claim()` cadence path.
- Emits `TX *** BITPIGGY CHORE CLAIM #N ***` logs and a 1200 ms LED confirmation blink.
- Uses `esp32-hackkit/tools/sign-bitpiggy-cell-deck.ts` to generate the embedded `main/embed/cell_deck.bin`.

## Generate deck

```sh
bun esp32-hackkit/tools/sign-bitpiggy-cell-deck.ts \
  esp32-hackkit/examples/bitpiggy_mesh/main/embed/cell_deck.bin
```

## Build/flash

Use the same ESP-IDF flow as `mesh_demo`, from this example directory:

```sh
cd esp32-hackkit/examples/bitpiggy_mesh
idf.py build
idf.py -p /dev/cu.usbmodemXXX flash monitor
```

Expected early logs include:

```text
deck: ... bitpiggy_claim=N
TX *** BITPIGGY CHORE CLAIM #1 *** (deck, broadcasting) cell_id=...
```
