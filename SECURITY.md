# Security

This shard is a Crystal port of ruby-saml. Versions before 0.2.0 carried ruby-saml's
sign-in bypass (CVE-2024-45409) and must not be used.

## How a Response is verified

- **Strict parsing.** XML is parsed by libxml2 with network access off and without
  RECOVER, DTD loading or entity substitution. A DOCTYPE, an entity, a namespace error or
  any parser warning rejects the message. The same parser reads messages, decrypted
  elements and metadata.
- **One signature at a time.** Every lookup (SignedInfo, Reference, DigestValue,
  SignatureValue, KeyInfo) is relative to the signature being checked. A signature must be
  a direct child of the element it signs, and must have:
  - one Reference to that element's ID, or `""` for the root;
  - at most an enveloped transform plus one canonicalization transform;
  - supported algorithms only.

  The referenced ID must appear exactly once in the document.
- **Configured certificates only.** Signatures are checked against `idp_cert`, or the
  `idp_cert_multi` signing certificates (two are allowed during a rollover). A KeyInfo
  certificate that differs from them rejects the message. The document's own certificate
  is used only in legacy fingerprint mode (`idp_cert_fingerprint`), and only once its
  fingerprint matches, compared in constant time.
- **Data from signed bytes.** NameID, attributes, conditions and SessionIndex are read
  from a fresh parse of the canonical bytes the digest covers, never from the received
  tree. When a certificate or fingerprint is configured, the getters return nothing from a
  signature that doesn't verify.
- **Every signature checked.** The Response-level signature and the Assertion signature
  (after decryption) are both checked when present. One of them is required, and
  `want_assertions_signed` requires the Assertion's.
- **Digests compared in constant time.** An empty canonical form is an error.
- **Size limits.** Messages over `message_max_bytesize` (250,000 bytes by default) are
  refused before any regexp or base64 work, and inflation stops at the same limit.
- **Schema validation.** Responses and logout messages are validated against the SAML
  2.0 XSDs shipped in `src/schemas`, with libxml2's schema validator.
- **Decryption.** AES-GCM tags are always checked. Decryption errors are reported with
  one generic message.

## ruby-saml advisories

| Advisory | Status |
|---|---|
| CVE-2024-45409: XPath selected the wrong DigestValue/signature | Fixed: all lookups are relative to their signature (tests in `spec/security_test.cr`) |
| CVE-2025-25291, CVE-2025-25292: parser differential (REXML vs Nokogiri) | Not applicable, since only libxml2 parses. DOCTYPE/ATTLIST tricks are refused anyway |
| CVE-2025-25293: compressed message DoS | Fixed: inflation is capped at `message_max_bytesize` |
| CVE-2025-54572: large message DoS before the size check | Fixed: the size check runs before any regexp or decoding |
| CVE-2025-66567: incomplete fix for CVE-2025-25292 | Not applicable (single parser); DOCTYPEs are refused |
| CVE-2025-66568: libxml2 canonicalization returning an empty string | Fixed: empty canonical output is an error |
| CVE-2017-11428: comments splitting node text | Fixed: text joins every text and CDATA child |

## Known limits

- **Fetching remote metadata.** `IdpMetadataParser#parse_remote` fetches any http(s) URL
  it is given. When the URL comes from a user, check it first (scheme, host, no internal
  addresses). Redirects are not followed, there is a 10-second timeout and a 10 MB cap
  (`:max_bytesize`), and TLS is verified unless `validate_cert` is false.
- **Older encryption algorithms.** AES-CBC and RSA-1.5 key transport remain supported
  for compatibility and are open to padding-oracle attacks in principle. OpenSSL 3.2 and
  later use implicit rejection for RSA-1.5. Prefer IdPs that use AES-GCM with RSA-OAEP.
- **Logout messages.** As in ruby-saml, a LogoutRequest or LogoutResponse signature is
  only checked when the HTTP-Redirect `Signature` parameter is present (`:get_params`).
- **Crystal version.** Only Crystal 1.21 has been tested.

## Reporting

Please report vulnerabilities privately to the maintainer rather than in a public issue.
