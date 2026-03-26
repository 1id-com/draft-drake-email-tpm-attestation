# draft-drake-email-hardware-attestation

**Hardware Attestation for Email Sender Verification**

This is the companion repository for the IETF Internet-Draft
[draft-drake-email-hardware-attestation-00](https://datatracker.ietf.org/doc/draft-drake-email-hardware-attestation/).

## Abstract

This document defines a mechanism for email senders to include
hardware attestation evidence in message headers, enabling receiving
mail servers to cryptographically verify that an email was composed
on a device containing genuine, tamper-resistant hardware security --
whether a discrete TPM, firmware TPM, PIV smart card (e.g. YubiKey),
hardware enclave (e.g. Apple Secure Enclave), or virtual TPM.

Two complementary modes are defined:

1. **Direct Hardware Attestation** (Mode 1): A CMS SignedData
   structure (RFC 5652) containing a per-message attestation signature
   and full Issuer-certified certificate chain, embedded in the
   `Hardware-Attestation` email header.

2. **SD-JWT Trust Proof** (Mode 2): A Selective Disclosure JWT
   (RFC 9901) issued by a trust registry, embedded in the
   `Hardware-Trust-Proof` email header.  The sender selects which
   claims to reveal, enabling privacy-preserving attestation.

Together, these mechanisms provide Sybil-resistant email authentication:
each sender identity requires distinct hardware, making large-scale
automated spam economically infeasible regardless of advances in
artificial intelligence.

## Repository Contents

```
draft-drake-email-hardware-attestation-00.xml   # I-D source (xml2rfc v3)
examples/
  rfc_example_1_sovereign_tpm_nodejs_mode12-72.eml  # Sovereign TPM, Node.js, Mode 1+2
  rfc_example_2_portable_piv_python_mode2-72.eml    # Portable PIV, Python, Mode 2
  rfc_example_3_enclave_python_mode12-72.eml        # Enclave (Apple SE), Python, Mode 1+2
  rfc_example_4_virtual_vtpm_python_mode12-72.eml   # Virtual vTPM, Python, Mode 1+2
  rfc_example_5_declared_python_mode2-72.eml        # Declared (software), Python, Mode 2
  rfc_example_6_sovereign_tpm_python_mode1-72.eml   # Sovereign TPM, Python, Mode 1 only
```

The `.eml` files are real emails sent through production infrastructure
(Stalwart SMTP with DKIM signing) and verified by the `hw-attest-verify`
tool.  They are the same emails reproduced in Appendix A of the draft.

## Building the Draft

The XML source uses [xml2rfc](https://xml2rfc.tools.ietf.org/) v3 format:

```bash
pip install xml2rfc
xml2rfc draft-drake-email-hardware-attestation-00.xml --html
xml2rfc draft-drake-email-hardware-attestation-00.xml --text
```

## Verifying the Example Emails

Install the reference verification tool:

```bash
pip install hw-attest-verify
```

Verify any example email (use `--no-time-check` since the attestation
timestamps will be in the past):

```bash
hw-attest-verify --auth-results --no-time-check examples/rfc_example_1_sovereign_tpm_nodejs_mode12-72.eml
```

## Trust Tiers

The specification defines five trust tiers grouped into three
compatibility classes:

| Group | Tiers | Hardware | Anti-Sybil |
|-------|-------|----------|------------|
| (a) | sovereign, portable | Discrete TPM, PIV smart card | Yes -- manufacturer-attested, persistent identity |
| (b) | virtual, enclave | vTPM, Apple Secure Enclave | No -- re-keyable at will |
| (c) | declared | Software-only key | No -- no hardware backing |

Devices within the same group may back the same identity.  Cross-group
mixing is forbidden.  Upgrading from a lower group to a higher group
requires permanent burning of all former-group devices and a
co-presence cryptographic ceremony.

## Related Resources

| Resource | URL |
|----------|-----|
| **1id.com** (reference Issuer implementation) | https://1id.com |
| **Attestation verifier** (`pip install hw-attest-verify`) | https://github.com/1id-com/hw-attest-verify |
| **Python SDK** (`pip install oneid`) | https://github.com/1id-com/oneid-sdk |
| **Node.js SDK** (`npm install 1id`) | https://github.com/1id-com/oneid-node |
| **Go binary** (TPM/PIV/Enclave operations) | https://github.com/1id-com/oneid-enroll |
| **TPM Manufacturer CA Trust Store** | https://github.com/1id-com/tpm-manufacturer-cas |
| **IETF Datatracker** | https://datatracker.ietf.org/doc/draft-drake-email-hardware-attestation/ |

## Implementation Status

Per [RFC 7942](https://www.rfc-editor.org/rfc/rfc7942.html), a working
implementation exists at [1id.com](https://1id.com).  The implementation
includes:

- **Server-side verification** of hardware identity certificate chains
  with anti-Sybil enforcement (one device per identity per Issuer).
- **Client-side attestation** via Python SDK, Node.js SDK, and a
  cross-platform Go binary (`oneid-enroll`) supporting Windows TBS,
  Linux /dev/tpmrm0, macOS Secure Enclave (via Swift helper), and
  PIV smart cards.
- **SD-JWT trust proof issuance** via the 1id.com enrollment API,
  with selective disclosure per RFC 9901.
- **Direct hardware attestation** (Mode 1) with CMS SignedData per
  RFC 5652, including full Issuer-certified certificate chains.
- **Production email delivery** through Stalwart SMTP with DKIM,
  verified end-to-end across all five trust tiers using the
  `hw-attest-verify` reference tool.

## License

The Internet-Draft XML source is subject to the IETF Trust Legal
Provisions (TLP).  See https://trustee.ietf.org/license-info for
details.

Example emails are provided under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Author

Christopher Drake <cnd@1id.com>
https://1id.com
