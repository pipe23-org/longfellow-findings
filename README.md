# longfellow-findings

longfellow-findings records observed behaviour differences between implementations of the
Longfellow proof scheme (draft-google-cfrg-libzk). Each finding is one test file that
demonstrates the behaviour by running it. A file's module docstring states the observed
behaviour and cites the source locations in each implementation.

The implementations are reached through `pylongfellow`, which exposes google/longfellow-zk
as the `google-cpp` backend and abetterinternet/zk-cred-longfellow as the `isrg-rust`
backend. Inputs come from the `longfellow-vectors` collection. Both are released packages,
so a finding runs without a source checkout of either implementation.

Findings are run against pylongfellow 0.6.0, which vendors google/longfellow-zk at
`fe83ec6` (v0.9) and abetterinternet/zk-cred-longfellow at `b22d84e`, with inputs from
longfellow-vectors 0.1.0. Source locations cited in a finding are locations in those two
checkouts.

This is a record of observations, not a conformance suite. A finding is not a claim that
one implementation is wrong; where no published document states which behaviour is
required, the file says so.

## Running

```
uv sync
uv run pytest
```

Both backends ship in the `pylongfellow` wheel. The full set runs in about ten seconds.

## Findings

- `test_device_namespaces.py` — google-cpp refuses a presentation whose device signed a
  non-empty `DeviceNameSpaces` map, failing as prover with
  `MDOC_PROVER_DEVICE_SIGNATURE_FAILURE` and rejecting a valid isrg-rust proof as verifier
  with `MDOC_VERIFIER_GENERAL_FAILURE`. isrg-rust proves and verifies the same
  presentation. google assembles `DeviceAuthentication` over a constant empty map;
  isrg-rust takes the value as a parameter. Over the empty map the two interoperate.
- `test_embedded_circuit_id.py` — google-cpp checks a serialized circuit's embedded id
  against the structure it recomputes and refuses to parse a circuit whose embedded id
  does not match. isrg-rust reads the field without checking it, loads the tampered
  circuit, and completes a prove and verify round trip over it.

## Specimens

`specimens/` holds constructed inputs that are not yet in `longfellow-vectors`. These specimens
are candidates for admission to the vectors repository.

## Recorded, not demonstrated

Observations written up elsewhere that have no file here yet.

- A `doctype` of 256 bytes or more is silently replaced with a default in the C library
  (`lib/circuits/mdoc/mdoc_witness.h:415`), and the proof verifies against the wrong scope
  with no error. `pylongfellow` raises before the call, so demonstrating this reaches past
  the binding's public API.
- A `circuit_hash` longer than 64 bytes is an out-of-bounds heap write in the C library,
  silent between 66 and 80 bytes.
- The claim's namespace is not bound by the proof: matching is by element identifier and
  CBOR value, and the namespace string is ignored. Observed on google-cpp only; whether
  the two implementations agree here is untested.
