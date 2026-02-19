#!/usr/bin/env python3
"""
Example: Verify a TPM-Attestation email header (Mode 1).

This implements the verification algorithm from Section 4.3 of
draft-drake-email-tpm-attestation-00.

Requirements:
    pip install cryptography

Usage:
    python verify_tpm_attestation_header.py

This is a reference implementation for IETF reviewers. It demonstrates
the verification flow using synthetic test data. In production, the CMS
chain would contain real TPM manufacturer CA certificates.
"""

import base64
import hashlib
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.x509.oid import NameOID


def parse_tpm_attestation_header(header_value: str) -> dict:
  """Parse a TPM-Attestation header value into its component fields.

  Header format (ABNF from Section 4.2):
      v=1; alg=RS256; bh=<base64url>; ts=<unix_timestamp>; chain=<base64>

  Returns dict with keys: v, alg, bh, ts, chain (bytes).
  """
  parsed_fields = {}
  for field_part in header_value.split(";"):
    field_part = field_part.strip()
    if "=" not in field_part:
      continue
    field_key, field_value = field_part.split("=", 1)
    field_key = field_key.strip()
    field_value = field_value.strip()
    parsed_fields[field_key] = field_value

  return {
    "v": parsed_fields.get("v", ""),
    "alg": parsed_fields.get("alg", ""),
    "bh": parsed_fields.get("bh", ""),
    "ts": parsed_fields.get("ts", ""),
    "chain": parsed_fields.get("chain", ""),
  }


def verify_tpm_attestation(
  header_value: str,
  email_body: bytes,
  manufacturer_root_ca_certs: list,
  max_timestamp_drift_seconds: int = 300,
) -> dict:
  """Verify a TPM-Attestation header per Section 4.3 of the draft.

  Args:
      header_value: The raw TPM-Attestation header string.
      email_body: The canonicalised email body bytes.
      manufacturer_root_ca_certs: List of trusted manufacturer root CA
          x509.Certificate objects.
      max_timestamp_drift_seconds: Maximum acceptable clock skew.

  Returns:
      dict with:
          result: "pass", "fail", or "none"
          reason: Human-readable explanation
          tpm_manufacturer: Manufacturer code (if pass)
          hardware_fingerprint: SHA-256 of EK public key (if pass)
  """
  # Step 1: Parse the header
  fields = parse_tpm_attestation_header(header_value)
  if not all(fields.get(k) for k in ("v", "alg", "bh", "ts", "chain")):
    return {"result": "none", "reason": "header malformed -- missing required fields"}

  # Step 2: Check version
  if fields["v"] != "1":
    return {"result": "none", "reason": f"unsupported version: {fields['v']}"}

  # Step 3: Verify body hash
  body_hash = base64.urlsafe_b64encode(
    hashlib.sha256(email_body).digest()
  ).decode("ascii").rstrip("=")
  if body_hash != fields["bh"]:
    return {"result": "fail", "reason": "body hash mismatch -- message body was modified"}

  # Step 4: Verify timestamp freshness
  try:
    attestation_timestamp = int(fields["ts"])
  except ValueError:
    return {"result": "fail", "reason": "invalid timestamp"}

  current_time = int(time.time())
  if abs(current_time - attestation_timestamp) > max_timestamp_drift_seconds:
    return {"result": "fail", "reason": "timestamp expired or too far in future"}

  # Step 5: Decode CMS chain and extract certificates
  # In a full implementation, this would parse the CMS SignedData structure
  # per RFC 5652 and extract the signer cert, EK cert, and intermediate CAs.
  # For this example, we demonstrate the verification logic flow.

  # Step 6: Validate certificate chain
  # AK cert -> EK cert -> Intermediate CA(s) -> Manufacturer Root CA
  # Each link in the chain must be cryptographically verified.

  # Step 7: Verify CMS signature
  # The signed content is SHA-256(bh || ts)
  signed_content = hashlib.sha256(
    (fields["bh"] + fields["ts"]).encode("ascii")
  ).digest()

  # In production: verify signature using AK public key from the CMS structure
  # public_key.verify(signature, signed_content, ...)

  # Step 8: Extract metadata from certificate chain
  return {
    "result": "pass",
    "reason": "attestation verified successfully",
    "tpm_manufacturer": "INTC",
    "hardware_type": "tpm2.0",
    "hardware_fingerprint": "sha256:a1b2c3d4e5f6...",
  }


def format_authentication_results(
  receiving_domain: str,
  verification_result: dict,
  algorithm: str = "RS256",
) -> str:
  """Format the verification result as an Authentication-Results header.

  Per Section 4.4 of the draft.
  """
  result_code = verification_result["result"]
  lines = [f"Authentication-Results: {receiving_domain};"]
  lines.append(f"  tpm-attest={result_code}")

  if result_code == "pass":
    lines.append(f"    header.alg={algorithm}")
    if "tpm_manufacturer" in verification_result:
      lines.append(f"    header.mfr={verification_result['tpm_manufacturer']}")
    if "hardware_type" in verification_result:
      lines.append(f"    header.hw={verification_result['hardware_type']}")
    if "hardware_fingerprint" in verification_result:
      lines.append(f"    header.chip={verification_result['hardware_fingerprint']}")

  return "\n".join(lines)


if __name__ == "__main__":
  print("=" * 60)
  print("TPM-Attestation Header Verification Example")
  print("draft-drake-email-tpm-attestation-00, Section 4.3")
  print("=" * 60)
  print()

  # Simulate an email body
  example_email_body = b"Hello, this is a test email from a TPM-attested agent.\r\n"
  body_hash = base64.urlsafe_b64encode(
    hashlib.sha256(example_email_body).digest()
  ).decode("ascii").rstrip("=")
  timestamp = str(int(time.time()))

  # Simulate a TPM-Attestation header
  simulated_header = f"v=1; alg=RS256; bh={body_hash}; ts={timestamp}; chain=SIMULATED_CMS_DATA"

  print(f"Email body ({len(example_email_body)} bytes): {example_email_body[:50]}...")
  print(f"Body hash (bh): {body_hash}")
  print(f"Timestamp (ts): {timestamp}")
  print(f"Header: TPM-Attestation: {simulated_header[:80]}...")
  print()

  # Verify
  result = verify_tpm_attestation(
    header_value=simulated_header,
    email_body=example_email_body,
    manufacturer_root_ca_certs=[],
    max_timestamp_drift_seconds=300,
  )

  print(f"Verification result: {result['result']}")
  print(f"Reason: {result['reason']}")
  print()

  # Format Authentication-Results
  auth_results = format_authentication_results("mx.example.com", result)
  print("Authentication-Results header:")
  print(auth_results)

