"""A circuit whose embedded id has been zeroed loads, proves, and verifies on both
backends. The embedded id is not read on the proving or verifying path.

google/longfellow-zk parses the circuit with enforce_circuit_id set false in both
run_mdoc_prover and run_mdoc_verifier (lib/circuits/mdoc/mdoc_zk.cc:111-112, :437, :443,
:591, :598). The comment above those constants states that the application is expected to
check the circuit id once after download and keep the checked circuit in trusted storage;
the standalone circuit_id function (lib/circuits/mdoc/mdoc_circuit_id.cc:55, :65) is the
check. abetterinternet/zk-cred-longfellow's codec reads the embedded id without checking
it (src/circuit.rs:71); the check exists only in the test-only check_invariants
(src/circuit.rs:459-465).

specimens/embedded-id-zeroed.circuit is the corpus vector google-v6-1attr with the last
32 bytes of its decompressed serialization, the second circuit's embedded id, zeroed and
the stream recompressed. The circuit's structure is unchanged; the proof produced over it
is a proof over the same circuit.
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


def round_trip(backend):
    longfellow = Pylongfellow(backend=backend)
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


def test_the_specimen_differs_from_the_corpus_circuit_only_in_the_embedded_id():
    assert hashlib.sha256(TAMPERED).hexdigest() == SIDECAR["byte_sha256"]
    original, tampered = decompressed(CIRCUIT.bytes), decompressed(TAMPERED)
    assert tampered[:-32] == original[:-32]
    assert tampered[-32:] == bytes(32)
    assert original[-32:] != bytes(32)


def test_google_cpp_circuit_id_rejects_the_zeroed_circuit():
    with pytest.raises(mdoc.Error):
        google_cpp.circuit_id(TAMPERED)


def test_google_cpp_proves_and_verifies_over_the_zeroed_circuit():
    round_trip("google-cpp")


def test_isrg_rust_proves_and_verifies_over_the_zeroed_circuit():
    round_trip("isrg-rust")
