#!/usr/bin/env python3
"""
Example: Verify an SD-JWT Trust Proof email header (Mode 2).

This implements the verification algorithm from Section 5.4 of
draft-drake-email-tpm-attestation-00.

Requirements:
    pip install pyjwt cryptography
"""

import base64
import hashlib
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


def verify_sd_jwt_trust_proof(
  header_value: str,
  email_body: bytes,
  trust_registry_public_keys: dict,
  max_timestamp_drift_seconds: int = 300,
) -> dict:
  """Verify a TPM-Trust-Proof header per Section 5.4 of the draft.

  Args:
      header_value: The raw TPM-Trust-Proof header value.
      email_body: The canonicalised email body bytes.
      trust_registry_public_keys: Dict mapping kid -> public key objects.
      max_timestamp_drift_seconds: Maximum clock skew tolerance.

  Returns:
      dict with result, reason, disclosed claims, and trust tier.
  """

  # Step 1: Parse header fields
  fields = {}
  for field_part in header_value.split(";"):
    field_part = field_part.strip()
    if "=" not in field_part:
      continue
    field_key, field_value = field_part.split("=", 1)
    fields[field_key.strip()] = field_value.strip()

  if "sd-jwt" not in fields:
    return {"result": "none", "reason": "missing sd-jwt field"}

  # Step 2: Verify body hash
  expected_body_hash = base64.urlsafe_b64encode(
    hashlib.sha256(email_body).digest()
  ).decode("ascii").rstrip("=")

  if fields.get("bh") != expected_body_hash:
    return {"result": "fail", "reason": "body hash mismatch"}

  # Step 3: Parse SD-JWT
  sd_jwt_string = fields["sd-jwt"]
  sd_jwt_parts = sd_jwt_string.split("~")
  issuer_signed_jwt = sd_jwt_parts[0]
  disclosures = [part for part in sd_jwt_parts[1:] if part]

  # Step 4: Verify JWT header to find the kid
  unverified_header = jwt.get_unverified_header(issuer_signed_jwt)
  kid = unverified_header.get("kid")

  if kid not in trust_registry_public_keys:
    return {
      "result": "fail",
      "reason": f"trust registry key {kid} not in local trust store",
    }

  # Step 5: Verify JWT signature
  try:
    jwt_payload = jwt.decode(
      issuer_signed_jwt,
      trust_registry_public_keys[kid],
      algorithms=["ES256", "RS256"],
      options={"verify_exp": True},
    )
  except jwt.ExpiredSignatureError:
    return {"result": "fail", "reason": "trust proof has expired"}
  except jwt.InvalidSignatureError:
    return {"result": "fail", "reason": "invalid issuer signature"}
  except jwt.DecodeError as decode_error:
    return {"result": "fail", "reason": f"JWT decode error: {decode_error}"}

  # Step 6: Verify timestamp freshness
  issued_at = jwt_payload.get("iat", 0)
  now = int(time.time())
  if abs(now - issued_at) > max_timestamp_drift_seconds:
    return {"result": "fail", "reason": "trust proof is stale"}

  # Step 7: Process selective disclosures
  disclosed_claims = {}
  for disclosure_b64 in disclosures:
    try:
      pad = 4 - len(disclosure_b64) % 4
      if pad != 4:
        disclosure_b64 += "=" * pad
      decoded = json.loads(base64.urlsafe_b64decode(disclosure_b64))
      if isinstance(decoded, list) and len(decoded) == 3:
        _salt, claim_name, claim_value = decoded
        disclosed_claims[claim_name] = claim_value
    except (json.JSONDecodeError, ValueError):
      continue

  # Step 8: Verify disclosure digests match _sd array
  sd_digests_in_jwt = jwt_payload.get("_sd", [])
  for disclosure_b64 in disclosures:
    if not disclosure_b64:
      continue
    digest = base64.urlsafe_b64encode(
      hashlib.sha256(disclosure_b64.encode()).digest()
    ).decode("ascii").rstrip("=")
    if digest not in sd_digests_in_jwt:
      return {"result": "fail", "reason": "disclosure digest not found in JWT _sd array"}

  # Step 9: Build result
  trust_tier = disclosed_claims.get("trust_tier", jwt_payload.get("trust_tier", "unknown"))

  return {
    "result": "pass",
    "reason": "SD-JWT trust proof verified",
    "issuer": jwt_payload.get("iss"),
    "subject": jwt_payload.get("sub"),
    "trust_tier": trust_tier,
    "disclosed_claims": disclosed_claims,
    "anti_sybil": jwt_payload.get("anti_sybil", False),
  }


def format_authentication_results(
  receiving_domain: str,
  verification_result: dict,
) -> str:
  """Format the result as an Authentication-Results header.

  Per Section 5.5 of the draft.
  """
  result_code = verification_result["result"]
  lines = [f"Authentication-Results: {receiving_domain};"]
  lines.append(f"  tpm-trust={result_code}")

  if result_code == "pass":
    if "issuer" in verification_result:
      lines.append(f"    header.iss={verification_result['issuer']}")
    if "trust_tier" in verification_result:
      lines.append(f"    header.tier={verification_result['trust_tier']}")
    if "subject" in verification_result:
      lines.append(f"    header.sub={verification_result['subject']}")

  return "\n".join(lines)


if __name__ == "__main__":
  from generate_sd_jwt_trust_proof import (
    create_sd_jwt_trust_proof,
    generate_trust_proof_header,
  )

  print("=" * 60)
  print("SD-JWT Trust Proof Verification Example")
  print("draft-drake-email-tpm-attestation-00, Section 5.4")
  print("=" * 60)
  print()

  # Set up issuer and holder keys
  issuer_key = ec.generate_private_key(ec.SECP256R1())
  holder_key = ec.generate_private_key(ec.SECP256R1())
  issuer_kid = "1id-com-signing-key-001"

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

  # Create trust proof
  sd_jwt = create_sd_jwt_trust_proof(
    issuer_private_key=issuer_key,
    issuer_kid=issuer_kid,
    subject_email="agent@example.com",
    trust_tier="sovereign",
    hardware_fingerprint="sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    manufacturer_code="INTC",
    holder_binding_key_jwk=holder_jwk,
    disclosed_claims=["trust_tier"],
  )

  email_body = b"This message was sent by a hardware-attested agent.\r\n"
  header_value = generate_trust_proof_header(sd_jwt, email_body)

  # Verify it
  trust_registry_keys = {issuer_kid: issuer_key.public_key()}
  result = verify_sd_jwt_trust_proof(
    header_value=header_value,
    email_body=email_body,
    trust_registry_public_keys=trust_registry_keys,
  )

  print(f"Verification result: {result['result']}")
  print(f"Reason: {result['reason']}")
  if result["result"] == "pass":
    print(f"Issuer: {result['issuer']}")
    print(f"Subject: {result['subject']}")
    print(f"Trust tier: {result['trust_tier']}")
    print(f"Disclosed claims: {result['disclosed_claims']}")
    print(f"Anti-Sybil: {result['anti_sybil']}")
  print()

  auth_results = format_authentication_results("mx.example.com", result)
  print("Authentication-Results header:")
  print(auth_results)

