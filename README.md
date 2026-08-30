# longfellow-findings

longfellow-findings records observed behaviour of implementations of Longfellow
zero-knowledge proofs (draft-google-cfrg-libzk). Each finding is one test file that
demonstrates the behaviour by running it. A file's module docstring states the observed
behaviour and cites the source locations in each implementation.

The implementations are reached through `pylongfellow`, which exposes google/longfellow-zk
as the `google-cpp` backend and abetterinternet/zk-cred-longfellow as the `isrg-rust`
backend. Inputs come from the `longfellow-vectors` collection. Both are released packages,
so a finding runs without a source checkout of either implementation.

Findings are run against pylongfellow 0.7.0, which vendors google/longfellow-zk at
`fe83ec6` (v0.9) and abetterinternet/zk-cred-longfellow at `b22d84e`, with inputs from
longfellow-vectors 0.1.0. Source locations cited in a finding are locations in those two
checkouts.

This is a record of observations, not a conformance suite. A finding is not a claim that
an implementation is wrong.

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
- `test_zeroed_circuit_id.py` — a circuit whose embedded id has been zeroed loads, proves,
  and verifies on both backends. The embedded id is not read on the proving or verifying
  path. google-cpp's standalone `circuit_id` function rejects the circuit.

## Specimens

`specimens/` holds constructed inputs that are not yet in `longfellow-vectors`. These specimens
are candidates for admission to the vectors repository.

## License

Apache-2.0.
