# Changelog

## 0.2.0

Security release; every user of 0.1.x should upgrade. See SECURITY.md.

- Fix CVE-2024-45409 and port the later ruby-saml advisories (CVE-2025-25293,
  CVE-2025-54572, CVE-2025-66568); signature wrapping (XSW1-XSW8) and duplicate IDs are refused.
- Verify signatures only with the configured IdP certificates; read assertion data from the
  signed bytes only.
- Strict XML parsing: no RECOVER, DOCTYPE, DTD loading or entities.
- Real XSD schema validation with libxml2.
- Capped inflate and message size checks before decoding.
- AES-GCM decryption checks the authentication tag.
- `Attributes#to_h : Hash(String, Array(String))`, `XMLSecurity::Document.parse`,
  `IdpMetadataParser` remote fetch with timeout and size cap (`:max_bytesize`).
- Logging goes through `Saml::Log` (`::Log.for("saml")`).
- Builds on Crystal 1.21 (`-Duse_pcre2 -Dwithout_mt`); openssl_ext ~> 2.8.
- The test suite compiles and runs (minitest.cr); it never did before.
