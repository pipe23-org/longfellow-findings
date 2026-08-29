"""A serialized circuit carries an embedded id. google-cpp checks it against the
structure it recomputes and refuses to parse a circuit whose embedded id does not match.
isrg-rust reads the field without checking it, loads the tampered circuit, and completes
a prove and verify round trip over it.

google parses with enforce_circuit_id=true and compares the embedded id against the
recomputed one at lib/circuits/mdoc/mdoc_circuit_id.cc:55 and :65; load_circuit recomputes
circuit_id against the spec before use, so the same check gates load.
abetterinternet/zk-cred-longfellow's codec reads the embedded id without checking it at
src/circuit.rs:71; the check exists only in the test-only check_invariants
(src/circuit.rs:459-465), kept out of decode as too expensive per its comment.

Both implementations derive the id from the structure and would compute the same value.
The difference is whether the embedded field is consulted on load.

specimens/embedded-id-zeroed.circuit is the corpus vector google-v6-1attr with the last
32 bytes of its decompressed serialization -- the second circuit's embedded id -- zeroed
and the stream recompressed. No published standard states which behaviour is required.
"""

import hashlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import zstandard
from longfellow_vectors import LongfellowVectors
from pylongfellow import Pylongfellow, mdoc
from pylongfellow.backends import google_cpp

VECTORS = LongfellowVectors().mdoc

CIRCUIT = VECTORS.circuit("google-v6-1attr")
PRESENTATION = VECTORS.presentation("av-over-18-device-namespaces-empty")

SPECIMEN = Path(__file__).parent / "specimens" / "embedded-id-zeroed.circuit"
SIDECAR = json.loads(SPECIMEN.with_suffix(".json").read_text())
TAMPERED = SPECIMEN.read_bytes()

CLAIMS = [
    mdoc.RequestedAttribute(c.namespace, c.id, c.cbor_value) for c in PRESENTATION.claims()
]
ISSUER_PK = mdoc.PublicKey(
    PRESENTATION.issuer_public_key.x, PRESENTATION.issuer_public_key.y
)
# Inside the av-over-18 credential's MSO validity window, 2026-01-01 to 2028-01-01.
TIMESTAMP = datetime(2026, 7, 2, tzinfo=UTC)


def decompressed(circuit):
    return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(circuit)).read()


def test_the_specimen_differs_from_the_corpus_circuit_only_in_the_embedded_id():
    assert hashlib.sha256(TAMPERED).hexdigest() == SIDECAR["byte_sha256"]
    original, tampered = decompressed(CIRCUIT.bytes), decompressed(TAMPERED)
    assert tampered[:-32] == original[:-32]
    assert tampered[-32:] == bytes(32)
    assert original[-32:] != bytes(32)


def test_google_cpp_circuit_id_reads_the_corpus_circuit():
    assert google_cpp.circuit_id(CIRCUIT.bytes)


def test_google_cpp_circuit_id_rejects_the_tampered_circuit():
    with pytest.raises(mdoc.Error):
        google_cpp.circuit_id(TAMPERED)


def test_google_cpp_load_rejects_the_tampered_circuit():
    with pytest.raises(mdoc.Error):
        Pylongfellow(backend="google-cpp").load_circuit(
            TAMPERED, CIRCUIT.version, CIRCUIT.num_attributes
        )


def test_isrg_rust_proves_and_verifies_over_the_tampered_circuit():
    longfellow = Pylongfellow(backend="isrg-rust")
    longfellow.load_circuit(TAMPERED, CIRCUIT.version, CIRCUIT.num_attributes)
    proof = longfellow.prove(
        PRESENTATION.mdoc, ISSUER_PK, PRESENTATION.transcript, CLAIMS, TIMESTAMP
    )
    longfellow.verify(
        ISSUER_PK,
        PRESENTATION.transcript,
        CLAIMS,
        TIMESTAMP,
        proof,
        PRESENTATION.doctype,
        device_namespaces=PRESENTATION.device_namespaces,
    )
