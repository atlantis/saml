# saml

SAML 2.0 Service Provider library for Crystal, ported from
[ruby-saml](https://github.com/SAML-Toolkits/ruby-saml) 1.18 and kept close to its API.
It covers SP-initiated sign-in (HTTP-Redirect AuthnRequest, HTTP-POST Response),
encrypted assertions, single logout, and IdP and SP metadata.

See [SECURITY.md](SECURITY.md) for the ruby-saml advisories this port handles and
how it verifies signatures.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     saml:
       github: atlantis/saml
   ```

2. Run `shards install`

Requires Crystal 1.21 (the only version tested), libxml2 and OpenSSL 3. Build with
`-Duse_pcre2 -Dwithout_mt`.

## Usage

Build a `Saml::Settings` for each request from your stored configuration; nothing is global.

```crystal
require "saml"

settings = Saml::IdpMetadataParser.new.parse_remote("https://idp.example.com/metadata")
# or, from pasted XML: Saml::IdpMetadataParser.new.parse(xml)
settings.sp_entity_id = "https://sp.example.com/saml/metadata"
settings.assertion_consumer_service_url = "https://sp.example.com/saml/acs"
settings.idp_sso_service_binding = :redirect
```

### Sign-in request (HTTP-Redirect)

```crystal
request = Saml::Authrequest.new
url = request.create(settings, {"RelayState" => "/dashboard"})
# keep request.request_id to check InResponseTo, then redirect to url
```

To sign the redirect with SHA-256, set the SP key and certificate:

```crystal
settings.private_key = File.read("sp.key")
settings.certificate = File.read("sp.crt")
settings.security[:authn_requests_signed] = true
settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
settings.security[:digest_method] = XMLSecurity::Document::SHA256
```

### Response (HTTP-POST)

```crystal
response = Saml::Response.new(params["SAMLResponse"], {
  :settings            => settings,
  :matches_request_id  => request_id,
  :allowed_clock_drift => 3.minutes,
})

if response.is_valid?
  response.name_id         # => "user@example.com"
  response.name_id_format
  response.sessionindex
  response.attributes.to_h # => {"groups" => ["admins"]}
else
  response.errors          # plain messages
end
```

`is_valid?` checks the signature against the configured IdP certificates (`idp_cert`,
or up to two signing certificates in `idp_cert_multi` during a rollover), plus the issuer,
audience, destination, recipient, InResponseTo, NotBefore/NotOnOrAfter (with the clock
drift), and `security[:want_assertions_signed]`. Encrypted assertions are decrypted
with `settings.private_key`. Assertion values are read only from the bytes the signature
covers. When an IdP certificate or fingerprint is configured, nothing is returned from an
assertion whose signature doesn't verify.

### SP metadata

```crystal
xml = Saml::Metadata.new.generate(settings)
```

## Development

```sh
shards install
make spec      # every spec file in one binary
make check     # crystal tool format --check
```

The suite uses [minitest.cr](https://github.com/ysbaddaden/minitest.cr). Spec files are
`spec/*_test.cr`; `spec/security_test.cr` holds the attack cases (CVE-2024-45409,
XSW1-XSW8, DOCTYPE/XXE, compressed bombs, GCM tampering and more).

## Contributing

1. Fork it (<https://github.com/atlantis/saml/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [atlantisnova](https://github.com/atlantisnova) - creator and maintainer
