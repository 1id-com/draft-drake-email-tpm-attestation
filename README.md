# draft-drake-email-tpm-attestation

**Hardware Attestation for Email Sender Verification**

This is the companion repository for the IETF Internet-Draft
[draft-drake-email-tpm-attestation-00](https://datatracker.ietf.org/doc/draft-drake-email-tpm-attestation/).

## Abstract

This document defines a mechanism for email senders to include hardware
attestation evidence in message headers, enabling receiving mail servers
to cryptographically verify that an email was composed on a machine
containing a genuine Trusted Platform Module (TPM) from a known
manufacturer (Intel, AMD, Infineon, or similar).

Two complementary modes are defined:

1. **Direct TPM Attestation** (Mode 1): A CMS signed-data structure
   containing the attestation signature and full certificate chain,
   verifiable directly against manufacturer root CAs.

2. **SD-JWT Trust Proof** (Mode 2): A Selective Disclosure JWT issued by
   a trust registry, where the sender selects which claims to reveal.
   Optimised for privacy.

Together, these mechanisms provide Sybil-resistant email authentication:
each sender requires a unique physical security chip, making large-scale
automated spam economically infeasible regardless of advances in
artificial intelligence.

## Repository Contents

```
draft-drake-email-tpm-attestation-00.xml   # I-D source (xml2rfc v3 format)
examples/
  generate_tpm_attestation_header.py       # Mode 1: generate TPM-Attestation header
  verify_tpm_attestation_header.py         # Mode 1: verify TPM-Attestation header
  generate_sd_jwt_trust_proof.py           # Mode 2: generate TPM-Trust-Proof header
  verify_sd_jwt_trust_proof.py             # Mode 2: verify TPM-Trust-Proof header
test-vectors/
  test_vector_01_mode1_rs256.json          # Mode 1 test vector (RS256, Intel TPM)
  test_vector_02_mode2_sd_jwt.json         # Mode 2 test vector (SD-JWT trust proof)
```

## Building the Draft

The XML source uses [xml2rfc](https://xml2rfc.tools.ietf.org/) v3 format:

```bash
pip install xml2rfc
xml2rfc draft-drake-email-tpm-attestation-00.xml --html
xml2rfc draft-drake-email-tpm-attestation-00.xml --text
```

## Related Resources

| Resource | URL |
|----------|-----|
| **1id.com** (reference Trust Registry implementation) | https://1id.com |
| **Python SDK** (`pip install oneid`) | https://github.com/1id-com/oneid-sdk |
| **Node.js SDK** (`npm install 1id`) | https://github.com/1id-com/oneid-node |
| **Go binary** (TPM/PIV operations) | https://github.com/1id-com/oneid-enroll |
| **TPM Manufacturer CA Trust Store** | https://github.com/1id-com/tpm-manufacturer-cas |
| **IETF Datatracker** | https://datatracker.ietf.org/doc/draft-drake-email-tpm-attestation/ |

## Implementation Status

Per [RFC 7942](https://www.rfc-editor.org/rfc/rfc7942.html), a working
implementation of the attestation and enrollment flows described in this
draft exists at [1id.com](https://1id.com). The implementation includes:

- **Server-side verification** of TPM EK certificate chains against
  manufacturer root CAs (Intel, AMD, Infineon, STMicroelectronics,
  Nuvoton, Qualcomm), with anti-Sybil enforcement via a one-EK-per-identity
  registry.
- **Client-side attestation** via a Go binary (`oneid-enroll`) that
  handles cross-platform TPM access (Windows TBS, Linux /dev/tpmrm0),
  privilege elevation (UAC/sudo), and AK provisioning.
- **SD-JWT trust proof issuance** via the 1id.com enrollment API, which
  issues SD-JWTs with selectively disclosable claims matching the
  structure defined in Section 5 of the draft.

## License

The Internet-Draft XML source is subject to the IETF Trust Legal
Provisions (TLP). See https://trustee.ietf.org/license-info for details.

Example code and test vectors are provided under the Apache License 2.0.

## Author

Christopher Drake <cnd@1id.com>
https://1id.com

