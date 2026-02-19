#!/usr/bin/env python3
"""
Example: Generate a TPM-Attestation email header (Mode 1).

This demonstrates the sending-side flow from
draft-drake-email-tpm-attestation-00, Section 4.

In production, the AK private key lives inside the TPM and signing
is performed via TPM2_Sign. This example uses software keys to
illustrate the data flow.

Requirements:
    pip install cryptography
"""

import base64
import hashlib
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_tpm_attestation_header(
  email_body: bytes,
  ak_private_key,
  ak_certificate_pem: bytes,
  ek_certificate_pem: bytes,
  intermediate_ca_pems: list[bytes] | None = None,
  algorithm: str = "RS256",
) -> str:
  """Generate a TPM-Attestation header value.

  In production, the ak_private_key parameter would be replaced by
  a TPM handle, and the signing would be done via TPM2_Sign.

  Args:
      email_body: The canonicalised email body.
      ak_private_key: The AK private key (software stand-in for TPM).
      ak_certificate_pem: PEM-encoded AK certificate.
      ek_certificate_pem: PEM-encoded EK certificate.
      intermediate_ca_pems: Optional list of intermediate CA cert PEMs.
      algorithm: Signing algorithm (RS256, ES256, PS256).

  Returns:
      The TPM-Attestation header value string.
  """
  # Step 1: Compute body hash (DKIM simple body canonicalisation)
  body_hash_bytes = hashlib.sha256(email_body).digest()
  body_hash_b64url = base64.urlsafe_b64encode(body_hash_bytes).decode("ascii").rstrip("=")

  # Step 2: Generate timestamp
  timestamp_string = str(int(time.time()))

  # Step 3: Compute the signed content: SHA-256(bh || ts)
  signed_content = hashlib.sha256(
    (body_hash_b64url + timestamp_string).encode("ascii")
  ).digest()

  # Step 4: Sign with AK (in production: TPM2_Sign)
  if algorithm == "RS256":
    signature = ak_private_key.sign(
      signed_content,
      padding.PKCS1v15(),
      hashes.SHA256(),
    )
  else:
    raise ValueError(f"Algorithm {algorithm} not implemented in this example")

  # Step 5: Build CMS SignedData structure
  # In production, this would be a proper CMS SignedData (RFC 5652)
  # containing the signature, AK cert, EK cert, and intermediate CAs.
  # For this example, we concatenate them as a simplified demonstration.
  cms_payload = {
    "signature": base64.b64encode(signature).decode("ascii"),
    "ak_cert": ak_certificate_pem.decode("ascii"),
    "ek_cert": ek_certificate_pem.decode("ascii"),
  }
  import json
  cms_b64 = base64.b64encode(json.dumps(cms_payload).encode()).decode("ascii")

  # Step 6: Assemble header value
  return f"v=1; alg={algorithm}; bh={body_hash_b64url}; ts={timestamp_string}; chain={cms_b64}"


if __name__ == "__main__":
  print("=" * 60)
  print("TPM-Attestation Header Generation Example")
  print("draft-drake-email-tpm-attestation-00, Section 4")
  print("=" * 60)
  print()

  # Generate a demo RSA key pair (stand-in for TPM AK)
  print("Generating demo RSA-2048 key pair (stand-in for TPM AK)...")
  ak_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
  )

  # Self-signed certs for demonstration (in production: real TPM certs)
  from cryptography import x509
  from cryptography.x509.oid import NameOID
  import datetime

  ak_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo AK")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo EK")]))
    .public_key(ak_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .sign(ak_private_key, hashes.SHA256())
  )

  ak_cert_pem = ak_cert.public_bytes(Encoding.PEM)
  ek_cert_pem = ak_cert_pem  # Same for demo purposes

  # Generate the header
  email_body = b"Hello, this is a TPM-attested email from an AI agent.\r\n"
  header_value = generate_tpm_attestation_header(
    email_body=email_body,
    ak_private_key=ak_private_key,
    ak_certificate_pem=ak_cert_pem,
    ek_certificate_pem=ek_cert_pem,
  )

  print(f"\nEmail body: {email_body}")
  print(f"\nTPM-Attestation: {header_value[:120]}...")
  print(f"\n(Full header is {len(header_value)} characters)")

