"""Tests for core crypto and DID functionality."""
import pytest
from sentinel_atl.core import (
    generate_keypair,
    sign,
    verify,
    sha256_hash,
    bytes_to_did,
    did_to_public_key,
    create_identity,
)


def test_generate_keypair():
    kp = generate_keypair()
    assert len(kp.private_key) == 32
    assert len(kp.public_key) == 32


def test_sign_and_verify():
    kp = generate_keypair()
    message = b"hello sentinel"
    signature = sign(message, kp.private_key)
    assert len(signature) == 64
    assert verify(signature, message, kp.public_key)


def test_verify_wrong_key():
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    message = b"hello sentinel"
    signature = sign(message, kp1.private_key)
    assert not verify(signature, message, kp2.public_key)


def test_verify_wrong_message():
    kp = generate_keypair()
    sig = sign(b"original", kp.private_key)
    assert not verify(sig, b"tampered", kp.public_key)


def test_sha256_hash():
    h = sha256_hash(b"test")
    assert len(h) == 32


def test_did_roundtrip():
    kp = generate_keypair()
    did = bytes_to_did(kp.public_key)
    assert did.startswith("did:key:z")
    recovered = did_to_public_key(did)
    assert recovered == kp.public_key


def test_create_identity():
    identity = create_identity("test-agent")
    assert identity.did.startswith("did:key:z")
    assert identity.key_id.startswith(identity.did)
    assert len(identity.public_key) == 32
    assert len(identity.private_key) == 32
