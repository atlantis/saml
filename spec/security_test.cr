require "./spec_helper"

# Attacks on the sign-in path, each against a response freshly signed with the
# test key so the unmodified document is known to be valid.
module SecurityFixtures
  PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
  ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
  DSIG      = "http://www.w3.org/2000/09/xmldsig#"
  IDP       = "https://idp.example.com/metadata"
  SP        = "https://sp.example.com/metadata"
  ACS       = "https://sp.example.com/saml/acs"
  REQUEST   = "_request-1"
  USER      = "user@example.com"
  EVIL      = "evil@attacker.example"

  def self.stamp(offset : Time::Span = Time::Span.zero) : String
    (Time.utc + offset).to_s("%Y-%m-%dT%H:%M:%SZ")
  end

  def self.assertion(id = "_assertion-1", name_id = USER, not_before = -5.minutes, not_on_or_after = 5.minutes,
                     audience = SP, issuer = IDP) : String
    <<-XML.gsub(/\n\s*/, "")
      <saml:Assertion xmlns:samlp="#{PROTOCOL}" xmlns:saml="#{ASSERTION}" ID="#{id}" Version="2.0" IssueInstant="#{stamp}">
        <saml:Issuer>#{issuer}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{name_id}</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="#{stamp(not_on_or_after)}" Recipient="#{ACS}" InResponseTo="#{REQUEST}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="#{stamp(not_before)}" NotOnOrAfter="#{stamp(not_on_or_after)}">
          <saml:AudienceRestriction><saml:Audience>#{audience}</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="#{stamp}" SessionIndex="_session-1">
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
          <saml:Attribute Name="groups">
            <saml:AttributeValue>admins</saml:AttributeValue>
            <saml:AttributeValue>ops</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    XML
  end

  def self.response(assertions : String, id = "_response-1", extensions = "", destination = ACS) : String
    %(<samlp:Response xmlns:samlp="#{PROTOCOL}" xmlns:saml="#{ASSERTION}" ID="#{id}" Version="2.0" IssueInstant="#{stamp}" ) +
      %(Destination="#{destination}" InResponseTo="#{REQUEST}"><saml:Issuer>#{IDP}</saml:Issuer>#{extensions}) +
      %(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>#{assertions}</samlp:Response>)
  end

  def self.key : OpenSSL::PKey::RSA
    OpenSSL::PKey::RSA.new(File.read(File.join(__DIR__, "certificates", "crystal-saml.key")))
  end

  def self.cert_text : String
    File.read(File.join(__DIR__, "certificates", "crystal-saml.crt"))
  end

  def self.other_cert_text : String
    File.read(File.join(__DIR__, "certificates", "crystal-saml-2.crt"))
  end

  # The root element signed (SHA-256), serialised without reformatting.
  def self.sign(xml : String, key = self.key, cert : String? = cert_text) : String
    doc = XMLSecurity::Document.parse(xml)
    doc.sign_document(key, cert, XMLSecurity::Document::RSA_SHA256, XMLSecurity::Document::SHA256)
    doc.root.not_nil!.to_xml(options: XML::SaveOptions::NO_DECL | XML::SaveOptions::AS_XML)
  end

  def self.strip_signature(xml : String) : String
    xml.sub(/<ds:Signature\b.*?<\/ds:Signature>/m, "")
  end

  def self.signed_assertion : String
    sign(assertion)
  end

  # An unsigned look-alike carrying the attacker's NameID.
  def self.evil_assertion(id = "_evil") : String
    strip_signature(assertion(id, EVIL))
  end

  def self.settings : Saml::Settings
    settings = Saml::Settings.new
    settings.idp_entity_id = IDP
    settings.sp_entity_id = SP
    settings.assertion_consumer_service_url = ACS
    settings.idp_cert = cert_text
    settings
  end

  def self.parse(xml : String, settings = self.settings, extra = {} of Symbol => Saml::Response::OptionValue) : Saml::Response
    options = {:settings => settings, :matches_request_id => REQUEST} of Symbol => Saml::Response::OptionValue
    Saml::Response.new(Base64.strict_encode(xml), options.merge(extra))
  end
end

describe "Security" do
  describe "a well-formed signed response" do
    it "is valid with the assertion signed" do
      response = SecurityFixtures.parse(SecurityFixtures.response(SecurityFixtures.signed_assertion))
      assert response.is_valid?(true), response.errors.inspect
      assert_equal SecurityFixtures::USER, response.name_id
      assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", response.name_id_format
      assert_equal "_session-1", response.sessionindex
      assert_equal({"groups" => ["admins", "ops"]}, response.attributes.to_h)
    end

    it "is valid with the response and the assertion signed" do
      xml = SecurityFixtures.sign(SecurityFixtures.response(SecurityFixtures.signed_assertion))
      response = SecurityFixtures.parse(xml)
      assert response.is_valid?(true), response.errors.inspect
      assert_equal SecurityFixtures::USER, response.name_id
    end

    it "is valid with only the response signed, reading the assertion from the signed bytes" do
      xml = SecurityFixtures.sign(SecurityFixtures.response(SecurityFixtures.assertion))
      response = SecurityFixtures.parse(xml)
      assert response.is_valid?(true), response.errors.inspect
      assert_equal SecurityFixtures::USER, response.name_id
    end

    it "rejects a response-only signature when want_assertions_signed is set" do
      settings = SecurityFixtures.settings
      settings.security[:want_assertions_signed] = true
      response = SecurityFixtures.parse(SecurityFixtures.sign(SecurityFixtures.response(SecurityFixtures.assertion)), settings)
      refute response.is_valid?(true)
      assert_includes response.errors, "The Assertion of the Response is not signed and the SP requires it"
    end

    it "rejects an unsigned response" do
      response = SecurityFixtures.parse(SecurityFixtures.response(SecurityFixtures.assertion))
      refute response.is_valid?(true)
    end
  end

  describe "CVE-2024-45409" do
    # The forged digest sits earlier in document order than the real one, so a
    # document-wide //ds:DigestValue lookup would find it first.
    it "rejects a modified assertion whose digest is planted in Extensions" do
      signed = SecurityFixtures.signed_assertion
      forged = signed.sub(SecurityFixtures::USER, SecurityFixtures::EVIL)

      doc = Saml::XMLUtil.safe_parse(SecurityFixtures.response(forged))
      assertion = doc.xpath_node("//saml:Assertion", TEST_NAMESPACES).not_nil!
      signature = assertion.xpath_node("ds:Signature", TEST_NAMESPACES).not_nil!
      canonical = XMLSecurity::Canonicalizer.canonicalize(assertion, XML::C14N::Mode::C14N_EXCLUSIVE_1_0,
        XMLSecurity::Document::INC_PREFIX_LIST.split(" "), exclude: signature)
      digest = OpenSSL::Digest.new("SHA256")
      digest << canonical
      planted = %(<samlp:Extensions><ds:DigestValue xmlns:ds="#{SecurityFixtures::DSIG}">#{Base64.strict_encode(digest.final)}</ds:DigestValue></samlp:Extensions>)

      response = SecurityFixtures.parse(SecurityFixtures.response(forged, extensions: planted))
      refute response.is_valid?(true)
      assert_includes response.errors, "Digest mismatch"
      refute_equal SecurityFixtures::EVIL, response.name_id
    end

    it "rejects a planted SignatureValue and SignedInfo outside the signature" do
      signed = SecurityFixtures.signed_assertion
      signed_info = signed[/<ds:SignedInfo>.*<\/ds:SignedInfo>/m]
      forged = signed.sub(SecurityFixtures::USER, SecurityFixtures::EVIL)
      planted = %(<samlp:Extensions><ds:Signature xmlns:ds="#{SecurityFixtures::DSIG}">#{signed_info}</ds:Signature></samlp:Extensions>)

      response = SecurityFixtures.parse(SecurityFixtures.response(forged, extensions: planted))
      refute response.is_valid?(true)
      refute_equal SecurityFixtures::EVIL, response.name_id
    end
  end

  describe "signature wrapping" do
    def signed_response : String
      SecurityFixtures.sign(SecurityFixtures.response(SecurityFixtures.assertion))
    end

    it "XSW1 original response inside the signature of an evil response" do
      original = signed_response
      evil = original.sub(%(ID="_response-1"), %(ID="_evil-response")).sub(SecurityFixtures::USER, SecurityFixtures::EVIL)
      xml = evil.sub("</ds:Signature>", "<ds:Object>#{original}</ds:Object></ds:Signature>")
      assert_rejected SecurityFixtures.parse(xml)
    end

    it "XSW2 original response before the signature of an evil response" do
      original = signed_response
      evil = original.sub(%(ID="_response-1"), %(ID="_evil-response")).sub(SecurityFixtures::USER, SecurityFixtures::EVIL)
      xml = evil.sub("<ds:Signature ", "#{original}<ds:Signature ")
      assert_rejected SecurityFixtures.parse(xml)
    end

    it "XSW3 evil assertion before the signed one" do
      xml = SecurityFixtures.response(SecurityFixtures.evil_assertion + SecurityFixtures.signed_assertion)
      assert_rejected SecurityFixtures.parse(xml)
    end

    it "XSW4 signed assertion inside the evil one" do
      evil = SecurityFixtures.evil_assertion.sub("</saml:Assertion>", SecurityFixtures.signed_assertion + "</saml:Assertion>")
      assert_rejected SecurityFixtures.parse(SecurityFixtures.response(evil))
    end

    it "XSW5 modified signed assertion plus an unsigned copy of the original" do
      signed = SecurityFixtures.signed_assertion
      evil = signed.sub(SecurityFixtures::USER, SecurityFixtures::EVIL)
      assert_rejected SecurityFixtures.parse(SecurityFixtures.response(evil + SecurityFixtures.strip_signature(signed)))
    end

    it "XSW6 original assertion inside the signature of a modified one" do
      signed = SecurityFixtures.signed_assertion
      evil = signed.sub(SecurityFixtures::USER, SecurityFixtures::EVIL)
        .sub("</ds:Signature>", "<ds:Object>#{SecurityFixtures.strip_signature(signed)}</ds:Object></ds:Signature>")
      assert_rejected SecurityFixtures.parse(SecurityFixtures.response(evil))
    end

    it "XSW7 signed assertion hidden in Extensions, evil one in its place" do
      extensions = "<samlp:Extensions>#{SecurityFixtures.signed_assertion}</samlp:Extensions>"
      xml = SecurityFixtures.response(SecurityFixtures.evil_assertion, extensions: extensions)
      assert_rejected SecurityFixtures.parse(xml)
    end

    it "XSW8 evil assertion carries the signature with the original in an Object" do
      signed = SecurityFixtures.signed_assertion
      signature = signed[/<ds:Signature\b.*<\/ds:Signature>/m]
      original = SecurityFixtures.strip_signature(signed)
      evil = SecurityFixtures.strip_signature(signed).sub(SecurityFixtures::USER, SecurityFixtures::EVIL)
        .sub("</saml:Issuer>", "</saml:Issuer>" + signature.sub("</ds:Signature>", "<ds:Object>#{original}</ds:Object></ds:Signature>"))
      assert_rejected SecurityFixtures.parse(SecurityFixtures.response(evil))
    end

    it "rejects a second signature on the assertion" do
      signed = SecurityFixtures.signed_assertion
      signature = signed[/<ds:Signature\b.*<\/ds:Signature>/m]
      doubled = signed.sub("</saml:Issuer>", "</saml:Issuer>" + signature)
      assert_rejected SecurityFixtures.parse(SecurityFixtures.response(doubled))
    end

    it "rejects another element reusing the signed ID" do
      extensions = %(<samlp:Extensions><x:Decoy xmlns:x="urn:example:decoy" ID="_assertion-1"/></samlp:Extensions>)
      response = SecurityFixtures.parse(SecurityFixtures.response(SecurityFixtures.signed_assertion, extensions: extensions))
      refute response.is_valid?(true)
    end

    it "rejects a signature referencing an XPointer" do
      xml = SecurityFixtures.signed_assertion.sub(%(URI="#_assertion-1"), %(URI="#xpointer(id('_assertion-1'))"))
      assert_rejected SecurityFixtures.parse(SecurityFixtures.response(xml))
    end
  end

  describe "comments in signed text" do
    # Exclusive c14n drops comments, so one can be added without breaking the digest.
    it "reads the whole NameID, not the text before an inserted comment" do
      signed = SecurityFixtures.sign(SecurityFixtures.assertion(name_id: "user@example.com.evil.example"))
      xml = SecurityFixtures.response(signed.sub("user@example.com.evil.example", "user@example.com<!---->.evil.example"))
      response = SecurityFixtures.parse(xml)
      assert response.is_valid?(true), response.errors.inspect
      assert_equal "user@example.com.evil.example", response.name_id
    end
  end

  describe "certificates" do
    it "ignores the KeyInfo certificate when the configured one differs" do
      settings = SecurityFixtures.settings
      settings.idp_cert = SecurityFixtures.other_cert_text
      response = SecurityFixtures.parse(SecurityFixtures.response(SecurityFixtures.signed_assertion), settings)
      refute response.is_valid?(true)
      assert_includes response.errors, "Certificate of the Signature element does not match provided certificate"
    end

    it "rejects an attacker key even when KeyInfo carries the IdP certificate" do
      attacker = OpenSSL::PKey::RSA.new(2048)
      signed = SecurityFixtures.sign(SecurityFixtures.assertion(name_id: SecurityFixtures::EVIL), attacker)
      response = SecurityFixtures.parse(SecurityFixtures.response(signed))
      refute response.is_valid?(true)
      assert_includes response.errors, "Key validation error"
    end

    it "rejects an attacker key with no KeyInfo" do
      attacker = OpenSSL::PKey::RSA.new(2048)
      signed = SecurityFixtures.sign(SecurityFixtures.assertion(name_id: SecurityFixtures::EVIL), attacker, nil)
      refute SecurityFixtures.parse(SecurityFixtures.response(signed)).is_valid?(true)
    end

    it "accepts either of two configured signing certificates" do
      settings = SecurityFixtures.settings
      settings.idp_cert = nil
      settings.idp_cert_multi = {:signing => [SecurityFixtures.other_cert_text, SecurityFixtures.cert_text], :encryption => [] of String}
      response = SecurityFixtures.parse(SecurityFixtures.response(SecurityFixtures.signed_assertion), settings)
      assert response.is_valid?(true), response.errors.inspect
    end

    it "accepts the document certificate only when its fingerprint matches" do
      settings = SecurityFixtures.settings
      settings.idp_cert = nil
      settings.idp_cert_fingerprint = crystal_saml_cert_fingerprint
      xml = SecurityFixtures.response(SecurityFixtures.signed_assertion)
      assert SecurityFixtures.parse(xml, settings).is_valid?(true)

      settings.idp_cert_fingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33"
      response = SecurityFixtures.parse(xml, settings)
      refute response.is_valid?(true)
      assert_includes response.errors, "Fingerprint mismatch"
    end
  end

  describe "XML parsing" do
    it "rejects a DOCTYPE in front of a validly signed response" do
      xml = %(<!DOCTYPE samlp:Response [<!ENTITY x "y">]>) + SecurityFixtures.response(SecurityFixtures.signed_assertion)
      response = SecurityFixtures.parse(xml)
      refute response.is_valid?(true)
      assert_nil response.name_id
    end

    it "rejects external entities" do
      response = Saml::Response.new(fixture("attackxee"), {:settings => SecurityFixtures.settings})
      refute response.is_valid?(true)
      refute response.document.loaded?
    end

    it "rejects entity expansion quickly" do
      lol = %(<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">) +
            %(<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>)
      refute SecurityFixtures.parse(lol).is_valid?(true)
    end

    it "rejects malformed XML instead of repairing it" do
      xml = SecurityFixtures.response(SecurityFixtures.signed_assertion) + "<trailing"
      refute SecurityFixtures.parse(xml).is_valid?(true)
    end

    it "rejects an unbound namespace prefix" do
      xml = SecurityFixtures.response(SecurityFixtures.signed_assertion).sub("<saml:Issuer>", "<bad:Issuer>").sub("</saml:Issuer><samlp:Status>", "</bad:Issuer><samlp:Status>")
      response = SecurityFixtures.parse(xml)
      refute response.is_valid?(true)
      refute response.document.loaded?
    end

    it "refuses an empty canonical form" do
      doc = Saml::XMLUtil.safe_parse("<a/>")
      root = doc.root.not_nil!
      assert_raises(XMLSecurity::CanonicalizationError) do
        XMLSecurity::Canonicalizer.canonicalize(root, XML::C14N::Mode::C14N_EXCLUSIVE_1_0, exclude: root)
      end
    end
  end

  describe "message size" do
    it "rejects an oversized message before decoding it" do
      error = assert_raises(Saml::ValidationError) do
        Saml::Response.new("A" * 250_001, {:settings => SecurityFixtures.settings})
      end
      assert_match(/exceeds 250000 bytes/, error.message.to_s)
    end

    it "stops inflating a compressed bomb at the limit" do
      bomb = Base64.strict_encode(deflate("<samlp:Response>" + " " * 20_000_000 + "</samlp:Response>"))
      assert bomb.bytesize < 250_000
      assert_raises(Saml::ValidationError) do
        Saml::Response.new(bomb, {:settings => SecurityFixtures.settings})
      end
      assert_raises(Saml::ValidationError) do
        Saml::SloLogoutrequest.new(bomb, {:settings => SecurityFixtures.settings})
      end
    end

    it "honours a configured limit" do
      settings = SecurityFixtures.settings
      settings.message_max_bytesize = 1000
      assert_raises(Saml::ValidationError) do
        SecurityFixtures.parse(SecurityFixtures.response(SecurityFixtures.signed_assertion), settings)
      end
    end
  end

  describe "AES-GCM" do
    let(:encrypted) { Base64.decode_string(read_response("unsigned_message_aes128gcm_encrypted_signed_assertion.xml.base64")) }

    @encrypted : String?

    def gcm_settings : Saml::Settings
      settings = Saml::Settings.new
      settings.private_key = read_certificate("crystal-saml.key")
      settings.idp_cert = read_certificate("crystal-saml.crt")
      settings
    end

    # Flips one bit in the data CipherValue (the last one), at *index* from its end.
    def tamper(xml : String, index : Int32) : String
      values = xml.scan(/<(?:\w+:)?CipherValue>([^<]+)<\/(?:\w+:)?CipherValue>/m)
      original = values.last[1]
      bytes = Base64.decode(original.gsub(/\s/, ""))
      bytes[bytes.size - index] ^= 0x01
      xml.sub(original, Base64.strict_encode(bytes))
    end

    it "decrypts the untouched message" do
      response = Saml::Response.new(Base64.strict_encode(encrypted), {:settings => gcm_settings})
      refute_nil response.decrypted_document
    end

    it "rejects a modified authentication tag" do
      assert_raises(Saml::ValidationError) do
        Saml::Response.new(Base64.strict_encode(tamper(encrypted, 1)), {:settings => gcm_settings})
      end
    end

    it "rejects modified ciphertext" do
      assert_raises(Saml::ValidationError) do
        Saml::Response.new(Base64.strict_encode(tamper(encrypted, 20)), {:settings => gcm_settings})
      end
    end
  end

  describe "conditions" do
    it "rejects another audience" do
      xml = SecurityFixtures.response(SecurityFixtures.sign(SecurityFixtures.assertion(audience: "https://other.example")))
      refute SecurityFixtures.parse(xml).is_valid?(true)
    end

    it "rejects another issuer" do
      xml = SecurityFixtures.response(SecurityFixtures.sign(SecurityFixtures.assertion(issuer: "https://other-idp.example")))
      refute SecurityFixtures.parse(xml).is_valid?(true)
    end

    it "rejects another destination" do
      xml = SecurityFixtures.response(SecurityFixtures.signed_assertion, destination: "https://other.example/acs")
      refute SecurityFixtures.parse(xml).is_valid?(true)
    end

    it "rejects another InResponseTo" do
      xml = SecurityFixtures.response(SecurityFixtures.signed_assertion)
      response = SecurityFixtures.parse(xml, extra: {:matches_request_id => "_another-request"} of Symbol => Saml::Response::OptionValue)
      refute response.is_valid?(true)
    end

    it "rejects an expired assertion" do
      xml = SecurityFixtures.response(SecurityFixtures.sign(SecurityFixtures.assertion(not_before: -20.minutes, not_on_or_after: -10.minutes)))
      refute SecurityFixtures.parse(xml).is_valid?(true)
    end

    it "allows the configured clock skew and no more" do
      xml = SecurityFixtures.response(SecurityFixtures.sign(SecurityFixtures.assertion(not_before: 2.minutes, not_on_or_after: 10.minutes)))
      refute SecurityFixtures.parse(xml).is_valid?(true)
      skew = {:allowed_clock_drift => 3.minutes} of Symbol => Saml::Response::OptionValue
      assert SecurityFixtures.parse(xml, extra: skew).is_valid?(true)
    end

    it "rejects an invalid time instead of ignoring it" do
      xml = SecurityFixtures.sign(SecurityFixtures.assertion).sub(/NotOnOrAfter="[^"]+"/, %(NotOnOrAfter="soon"))
      refute SecurityFixtures.parse(SecurityFixtures.response(xml)).is_valid?(true)
    end
  end

  def assert_rejected(response : Saml::Response)
    refute response.is_valid?(true), "accepted a wrapped response"
    refute_equal SecurityFixtures::EVIL, response.name_id
    refute_includes response.attributes.to_h.keys, "evil"
  end
end
