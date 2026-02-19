#!/usr/bin/env python3
"""
Example: Generate an SD-JWT Trust Proof email header (Mode 2).

This demonstrates the sending-side flow for the TPM-Trust-Proof header
from draft-drake-email-tpm-attestation-00, Section 5.

An SD-JWT (Selective Disclosure JWT) allows the sender to selectively
reveal claims about their hardware attestation without exposing the
full certificate chain or hardware fingerprint in every message.

Requirements:
    pip install pyjwt cryptography
"""

import base64
import hashlib
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


def create_sd_jwt_trust_proof(
  issuer_private_key,
  issuer_kid: str,
  subject_email: str,
  trust_tier: str,
  hardware_fingerprint: str,
  manufacturer_code: str,
  holder_binding_key_jwk: dict,
  disclosed_claims: list[str] | None = None,
  issuer_url: str = "https://1id.com",
) -> str:
  """Create an SD-JWT trust proof.

  The trust registry (issuer) signs a JWT containing hardware attestation
  claims. The holder (email sender) can then selectively disclose claims
  to the verifier (receiving MTA).

  Args:
      issuer_private_key: EC private key of the trust registry.
      issuer_kid: Key ID of the issuer's signing key.
      subject_email: The email address of the attested sender.
      trust_tier: Trust tier (e.g., "sovereign", "sovereign-portable").
      hardware_fingerprint: SHA-256 of EK/AIK public key.
      manufacturer_code: TPM/PIV manufacturer code.
      holder_binding_key_jwk: The holder's public key in JWK format.
      disclosed_claims: Which claims to include as disclosures.
      issuer_url: URL of the trust registry.

  Returns:
      The SD-JWT string (issuer-signed JWT ~ disclosure1 ~ disclosure2 ~).
  """

  # Build the full claims set
  now = int(time.time())
  full_claims = {
    "iss": issuer_url,
    "sub": subject_email,
    "iat": now,
    "exp": now + 86400,
    "cnf": {"jwk": holder_binding_key_jwk},
    "trust_tier": trust_tier,
    "hw_fingerprint": hardware_fingerprint,
    "hw_manufacturer": manufacturer_code,
    "hw_type": "tpm2.0",
    "anti_sybil": True,
    "_sd_alg": "sha-256",
  }

  # Create selective disclosures
  # Each disclosure is: base64url(json([salt, claim_name, claim_value]))
  disclosable_claim_names = ["hw_fingerprint", "hw_manufacturer", "hw_type", "trust_tier"]
  if disclosed_claims is None:
    disclosed_claims = ["trust_tier", "anti_sybil"]

  sd_disclosure_list = []
  sd_digest_list = []

  for claim_name in disclosable_claim_names:
    salt = base64.urlsafe_b64encode(hashlib.sha256(
      f"{claim_name}{now}".encode()
    ).digest()[:16]).decode("ascii").rstrip("=")

    disclosure_array = [salt, claim_name, full_claims[claim_name]]
    disclosure_json = json.dumps(disclosure_array, separators=(",", ":"))
    disclosure_b64 = base64.urlsafe_b64encode(disclosure_json.encode()).decode("ascii").rstrip("=")

    digest = base64.urlsafe_b64encode(
      hashlib.sha256(disclosure_b64.encode()).digest()
    ).decode("ascii").rstrip("=")

    sd_disclosure_list.append((claim_name, disclosure_b64))
    sd_digest_list.append(digest)

    del full_claims[claim_name]

  full_claims["_sd"] = sd_digest_list

  # Sign the JWT
  issuer_signed_jwt = jwt.encode(
    full_claims,
    issuer_private_key,
    algorithm="ES256",
    headers={"kid": issuer_kid, "typ": "sd+jwt"},
  )

  # Assemble SD-JWT: include only the disclosed claims
  selected_disclosures = [
    disclosure_b64
    for claim_name, disclosure_b64 in sd_disclosure_list
    if claim_name in disclosed_claims
  ]
  sd_jwt = issuer_signed_jwt + "~" + "~".join(selected_disclosures) + "~"

  return sd_jwt


def generate_trust_proof_header(
  sd_jwt: str,
  email_body: bytes,
) -> str:
  """Generate the TPM-Trust-Proof header value.

  Per Section 5.2 of the draft:
      TPM-Trust-Proof: v=1; bh=<base64url>; sd-jwt=<sd_jwt>

  Args:
      sd_jwt: The SD-JWT trust proof string.
      email_body: The canonicalised email body.

  Returns:
      The header value string.
  """
  body_hash = base64.urlsafe_b64encode(
    hashlib.sha256(email_body).digest()
  ).decode("ascii").rstrip("=")

  return f"v=1; bh={body_hash}; sd-jwt={sd_jwt}"


if __name__ == "__main__":
  print("=" * 60)
  print("SD-JWT Trust Proof Generation Example")
  print("draft-drake-email-tpm-attestation-00, Section 5")
  print("=" * 60)
  print()

  # Generate issuer key (trust registry signing key)
  issuer_key = ec.generate_private_key(ec.SECP256R1())
  holder_key = ec.generate_private_key(ec.SECP256R1())

  # Create a minimal JWK for holder binding
  holder_public_numbers = holder_key.public_key().public_numbers()
  holder_jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": base64.urlsafe_b64encode(
      holder_public_numbers.x.to_bytes(32, "big")
    ).decode("ascii").rstrip("="),
    "y": base64.urlsafe_b64encode(
      holder_public_numbers.y.to_bytes(32, "big")
    ).decode("ascii").rstrip("="),
  }

  # Create SD-JWT with selective disclosure
  sd_jwt = create_sd_jwt_trust_proof(
    issuer_private_key=issuer_key,
    issuer_kid="1id-com-signing-key-001",
    subject_email="agent@example.com",
    trust_tier="sovereign",
    hardware_fingerprint="sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    manufacturer_code="INTC",
    holder_binding_key_jwk=holder_jwk,
    disclosed_claims=["trust_tier"],
  )

  email_body = b"This message was sent by a hardware-attested agent.\r\n"
  header_value = generate_trust_proof_header(sd_jwt, email_body)

  print(f"Email body: {email_body}")
  print(f"\nTPM-Trust-Proof header ({len(header_value)} chars):")
  print(f"  {header_value[:120]}...")
  print(f"\nSD-JWT components:")

  jwt_parts = sd_jwt.split("~")
  print(f"  Issuer-signed JWT: {jwt_parts[0][:60]}...")
  print(f"  Disclosures: {len(jwt_parts) - 2} selective disclosure(s)")

  # Decode the JWT (no verification, just inspect)
  decoded_header = jwt.get_unverified_header(jwt_parts[0])
  decoded_payload = jwt.decode(jwt_parts[0], issuer_key, algorithms=["ES256"])
  print(f"\n  JWT header: {json.dumps(decoded_header, indent=2)}")
  print(f"  JWT payload (visible claims): {json.dumps(decoded_payload, indent=2)}")

