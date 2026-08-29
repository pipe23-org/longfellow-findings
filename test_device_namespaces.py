"""google-cpp refuses a presentation whose device signed a non-empty DeviceNameSpaces
map. isrg-rust proves and verifies the same presentation. Over the empty map the two
implementations agree and interoperate.

DeviceNameSpacesBytes is not a circuit input. Both implementations hash the four-element
DeviceAuthentication structure outside the circuit and bind the digest as a public input.
google/longfellow-zk assembles it over the constant D8 18 41 A0, tag 24 wrapping an empty
map, at lib/circuits/mdoc/mdoc_witness.h:413. abetterinternet/zk-cred-longfellow takes the
value as a prove and verify parameter at src/mdoc_zk/mod.rs:676.

The constant is unchanged at upstream HEAD 3dfaac7 (mdoc_witness.h:466) and carried into
the Rust implementation at 598816b
(rust/applications/mdoc_zk/circuits/src/cbor/mdoc.rs:354); neither is run here.

Deployed wallets emit the empty map, so the constant is consistent with a restriction to
the deployed profile. The non-empty vector here carries a pseudonym:
{"eu.europa.ec.av.1": {"nym": "nym-01"}}.
"""

import pytest
from longfellow_vectors import LongfellowVectors
from pylongfellow import Pylongfellow, mdoc

VECTORS = LongfellowVectors().mdoc

CIRCUIT = VECTORS.circuit("google-v6-1attr")
NONEMPTY = VECTORS.presentation("av-over-18-device-namespaces-nonempty")
EMPTY = VECTORS.presentation("av-over-18-device-namespaces-empty")
ISRG_PROOF = VECTORS.proof("isrg-rust-av-over-18-device-namespaces-nonempty-v6-1attr")

STATEMENT = ISRG_PROOF.statement()
CLAIMS = [mdoc.RequestedAttribute(c.namespace, c.id, c.cbor_value) for c in STATEMENT.claims]
ISSUER_PK = mdoc.PublicKey(STATEMENT.issuer_public_key.x, STATEMENT.issuer_public_key.y)
TIMESTAMP = STATEMENT.timestamp


def loaded(backend):
    longfellow = Pylongfellow(backend=backend)
    longfellow.load_circuit(CIRCUIT.bytes, CIRCUIT.version, CIRCUIT.num_attributes)
    return longfellow


def test_isrg_rust_proves_over_nonempty_device_namespaces():
    proof = loaded("isrg-rust").prove(
        NONEMPTY.mdoc, ISSUER_PK, NONEMPTY.transcript, CLAIMS, TIMESTAMP
    )
    assert proof


def test_isrg_rust_verifies_the_committed_proof_over_nonempty_device_namespaces():
    loaded("isrg-rust").verify(
        ISSUER_PK,
        STATEMENT.transcript,
        CLAIMS,
        TIMESTAMP,
        ISRG_PROOF.bytes,
        STATEMENT.doctype,
        device_namespaces=STATEMENT.device_namespaces,
    )


def test_google_cpp_prove_fails_with_device_signature_failure():
    with pytest.raises(mdoc.ProverError) as raised:
        loaded("google-cpp").prove(
            NONEMPTY.mdoc, ISSUER_PK, NONEMPTY.transcript, CLAIMS, TIMESTAMP
        )
    assert raised.value.code is mdoc.ProverErrorCode.MDOC_PROVER_DEVICE_SIGNATURE_FAILURE


def test_google_cpp_verify_of_the_isrg_rust_proof_fails_with_general_failure():
    with pytest.raises(mdoc.VerifierError) as raised:
        loaded("google-cpp").verify(
            ISSUER_PK,
            STATEMENT.transcript,
            CLAIMS,
            TIMESTAMP,
            ISRG_PROOF.bytes,
            STATEMENT.doctype,
            device_namespaces=STATEMENT.device_namespaces,
        )
    assert raised.value.code is mdoc.VerifierErrorCode.MDOC_VERIFIER_GENERAL_FAILURE


def test_the_backends_interoperate_over_empty_device_namespaces():
    proof = loaded("google-cpp").prove(EMPTY.mdoc, ISSUER_PK, EMPTY.transcript, CLAIMS, TIMESTAMP)
    loaded("isrg-rust").verify(
        ISSUER_PK,
        EMPTY.transcript,
        CLAIMS,
        TIMESTAMP,
        proof,
        EMPTY.doctype,
        device_namespaces=EMPTY.device_namespaces,
    )
