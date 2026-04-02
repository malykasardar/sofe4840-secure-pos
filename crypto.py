"""
crypto.py - Cryptography Module
Secure Purchase Order System - SOFE4840U Group 5
Author: Malyka Sardar (100752640)

This module handles all cryptographic operations for the system:
  - SHA-256 hashing of order content + timestamp
  - RSA+AES hybrid encryption (encrypt for a recipient)
  - RSA+AES hybrid decryption
  - Digital signature creation (sign with private key)
  - Digital signature verification (verify with public key)
  - Private key decryption from encrypted storage (used on login)

All functions are stateless - they take keys/data as arguments and return results.
They do NOT touch the database or Flask session directly.
"""

import os
import base64
import json
import hashlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256


# ---------------------------------------------------------------------------
# 1. HASHING
# ---------------------------------------------------------------------------

def hash_order(order_data: dict, timestamp: str) -> str:
    """
    Compute a SHA-256 hash of the order content combined with a timestamp.

    The order_data dict is serialized to JSON with sorted keys so the hash
    is deterministic regardless of insertion order.  The timestamp is
    appended before hashing so it is covered by the hash.

    Args:
        order_data: dict containing the purchase order fields
        timestamp:  ISO-8601 UTC string, e.g. '2024-11-01T14:23:00.000000'

    Returns:
        Lowercase hex string of the 256-bit digest, e.g. 'a3f1...'
    """
    content = json.dumps(order_data, sort_keys=True) + timestamp
    h = SHA256.new(content.encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 2. DIGITAL SIGNATURES
# ---------------------------------------------------------------------------

def sign_data(private_key_pem: str, order_hash: str, timestamp: str) -> str:
    """
    Sign the combination of an order hash and a timestamp using RSA-PSS
    with SHA-256.

    Signing process:
      1. Concatenate order_hash + timestamp into a single byte string
      2. Hash that with SHA-256
      3. Sign the hash with the signer's RSA private key using PSS padding

    Including the timestamp in what is signed means the signature
    cryptographically commits to WHEN the approval happened, preventing
    repudiation of the timing.

    Args:
        private_key_pem: PEM string of the signer's RSA-2048 private key
        order_hash:      hex digest from hash_order()
        timestamp:       ISO-8601 UTC string at the moment of signing

    Returns:
        Base64-encoded signature string (safe to store in SQLite TEXT column)
    """
    key = RSA.import_key(private_key_pem)
    content = (order_hash + timestamp).encode("utf-8")
    h = SHA256.new(content)
    signature_bytes = pss.new(key).sign(h)
    return base64.b64encode(signature_bytes).decode("utf-8")


def verify_signature(
    public_key_pem: str,
    signature_b64: str,
    order_hash: str,
    timestamp: str
) -> bool:
    """
    Verify an RSA-PSS signature created by sign_data().

    Verification process:
      1. Reconstruct the signed content: order_hash + timestamp
      2. Hash it with SHA-256
      3. Verify the signature against that hash using the signer's public key

    Returns True if the signature is valid, False if it is invalid or if
    anything goes wrong (tampered data, wrong key, corrupt signature, etc.).

    This function NEVER raises an exception to callers - all errors are
    caught internally and return False.

    Args:
        public_key_pem:  PEM string of the signer's RSA-2048 public key
        signature_b64:   Base64 signature string from sign_data()
        order_hash:      hex digest from hash_order() - must match original
        timestamp:       timestamp string that was included when signing

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        key = RSA.import_key(public_key_pem)
        content = (order_hash + timestamp).encode("utf-8")
        h = SHA256.new(content)
        pss.new(key).verify(h, base64.b64decode(signature_b64))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 3. HYBRID ENCRYPTION (RSA + AES-GCM)
# ---------------------------------------------------------------------------
#
# Why hybrid?  RSA-2048 with OAEP-SHA256 can only encrypt ~190 bytes of
# plaintext directly.  Purchase order JSON is larger than that.  The
# standard solution (also used by TLS/HTTPS) is:
#   - Generate a random 256-bit AES key for this message only
#   - Encrypt the actual data with AES-GCM (fast, handles any size)
#   - Encrypt the AES key with the recipient's RSA public key (OAEP)
#   - Bundle both together
# The recipient reverses this: RSA-decrypt the AES key, then AES-decrypt
# the data.
#
# AES-GCM is used (not AES-CBC) because GCM is authenticated encryption:
# it produces an authentication tag that detects any tampering with the
# ciphertext, providing both confidentiality AND integrity.

def encrypt_for_recipient(public_key_pem: str, plaintext: str) -> str:
    """
    Hybrid-encrypt a plaintext string for a specific recipient.

    Encryption steps:
      1. Generate a random 256-bit AES session key
      2. Encrypt the plaintext with AES-256-GCM -> produces ciphertext + tag
      3. Encrypt the AES session key with the recipient's RSA-2048 public
         key using OAEP-SHA256 padding
      4. Bundle {enc_key, nonce, tag, ciphertext} as JSON, base64-encode it

    Only the recipient who holds the corresponding RSA private key can
    decrypt this bundle.

    Args:
        public_key_pem: PEM string of the RECIPIENT's RSA-2048 public key
        plaintext:      The string to encrypt (e.g. JSON order data)

    Returns:
        Base64-encoded JSON bundle string, safe to store in SQLite
    """
    # Step 1: random AES-256 session key (used once, discarded after)
    aes_key = os.urandom(32)

    # Step 2: encrypt plaintext with AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode("utf-8"))

    # Step 3: encrypt the AES key with RSA-OAEP
    rsa_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Step 4: bundle everything together
    bundle = {
        "enc_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "nonce":   base64.b64encode(cipher_aes.nonce).decode("utf-8"),
        "tag":     base64.b64encode(tag).decode("utf-8"),
        "ct":      base64.b64encode(ciphertext).decode("utf-8"),
    }
    bundle_json = json.dumps(bundle)
    return base64.b64encode(bundle_json.encode("utf-8")).decode("utf-8")


def decrypt_payload(private_key_pem: str, encrypted_bundle: str) -> str:
    """
    Decrypt a bundle created by encrypt_for_recipient().

    Decryption steps:
      1. Base64-decode and JSON-parse the bundle
      2. RSA-OAEP decrypt the encrypted AES key using the recipient's
         RSA private key
      3. AES-GCM decrypt the ciphertext using the recovered AES key,
         verifying the authentication tag (raises ValueError if tampered)

    Args:
        private_key_pem:   PEM string of the RECIPIENT's RSA-2048 private key
        encrypted_bundle:  Base64 bundle string from encrypt_for_recipient()

    Returns:
        The original plaintext string

    Raises:
        ValueError: if the AES-GCM authentication tag does not match
                    (meaning the ciphertext was tampered with)
        Exception:  if the RSA decryption fails (wrong private key, etc.)
    """
    # Step 1: unpack the bundle
    bundle = json.loads(base64.b64decode(encrypted_bundle).decode("utf-8"))

    # Step 2: RSA-OAEP decrypt the AES session key
    rsa_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    aes_key = cipher_rsa.decrypt(base64.b64decode(bundle["enc_key"]))

    # Step 3: AES-GCM decrypt and verify integrity tag
    cipher_aes = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=base64.b64decode(bundle["nonce"])
    )
    plaintext_bytes = cipher_aes.decrypt_and_verify(
        base64.b64decode(bundle["ct"]),
        base64.b64decode(bundle["tag"])
    )
    return plaintext_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# 4. PRIVATE KEY DECRYPTION FROM STORAGE
# ---------------------------------------------------------------------------
#
# Abdallah's registration code encrypts each user's private key with a key
# derived from their password before storing it in the database (NFR-04:
# private keys must never be stored in plaintext).
#
# The storage format Abdallah uses is:
#   base64( salt[16] || nonce[16] || tag[16] || ciphertext )
#
# This function mirrors that format exactly so you can recover the private
# key PEM after a user logs in.

def decrypt_private_key(encrypted_priv_b64: str, password: str) -> str:
    """
    Recover a user's RSA private key PEM from its encrypted form in the DB.

    The encrypted form was produced by Abdallah's register_user() function
    using PBKDF2-HMAC-SHA256 key derivation + AES-256-GCM encryption.

    Decryption steps:
      1. Base64-decode to get raw bytes
      2. Split into: salt (16), nonce (16), tag (16), ciphertext (rest)
      3. Re-derive the AES key from the password using PBKDF2
      4. AES-GCM decrypt and verify

    Args:
        encrypted_priv_b64: base64 string from the users.encrypted_private_key
                            column in the database
        password:           the user's plaintext password (from login form)

    Returns:
        PEM string of the user's RSA-2048 private key

    Raises:
        ValueError: if the password is wrong or the stored key is corrupted
    """
    raw = base64.b64decode(encrypted_priv_b64)

    # unpack the four parts stored by Abdallah
    salt       = raw[0:16]
    nonce      = raw[16:32]
    tag        = raw[32:48]
    ciphertext = raw[48:]

    # re-derive the same AES key using the same parameters
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000,   # iterations - must match what Abdallah used
        dklen=32   # 256-bit AES key
    )

    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    private_key_pem_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return private_key_pem_bytes.decode("utf-8")
