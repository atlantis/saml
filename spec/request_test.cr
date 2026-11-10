require "./spec_helper"

describe "Authrequest" do
  let(:settings) { Saml::Settings.new }
  let(:cert) { OpenSSL::X509::Certificate.new(crystal_saml_cert_text) }

  before do
    settings.idp_sso_service_url = "http://example.com"
  end

  it "create the deflated SAMLRequest URL parameter" do
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)

    inflated = decode_saml_request_payload(auth_url)
    assert_match(/<samlp:AuthnRequest/, inflated)
  end

  it "create the deflated SAMLRequest URL parameter including the Destination" do
    auth_url = Saml::Authrequest.new.create(settings)
    inflated = decode_saml_request_payload(auth_url)

    assert_match(/<samlp:AuthnRequest[^<]* Destination="http:\/\/example.com"/, inflated)
  end

  it "create the SAMLRequest URL parameter without deflating" do
    settings.compress_request = false
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
    payload = URI.decode_www_form(auth_url.split("=").last)
    decoded = Base64.decode_string(payload)

    assert_match(/<samlp:AuthnRequest/, decoded)
  end

  it "create the SAMLRequest URL parameter with IsPassive" do
    settings.passive = true
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
    inflated = decode_saml_request_payload(auth_url)

    assert_match(/<samlp:AuthnRequest[^<]* IsPassive="true"/, inflated)
  end

  it "create the SAMLRequest URL parameter with ProtocolBinding" do
    settings.protocol_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
    inflated = decode_saml_request_payload(auth_url)

    assert_match(/<samlp:AuthnRequest[^<]* ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/, inflated)
  end

  it "create the SAMLRequest URL parameter with AttributeConsumingServiceIndex" do
    settings.attributes_index = 30
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
    inflated = decode_saml_request_payload(auth_url)

    assert_match(/<samlp:AuthnRequest[^<]* AttributeConsumingServiceIndex="30"/, inflated)
  end

  it "create the SAMLRequest URL parameter with ForceAuthn" do
    settings.force_authn = true
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
    inflated = decode_saml_request_payload(auth_url)

    assert_match(/<samlp:AuthnRequest[^<]* ForceAuthn="true"/, inflated)
  end

  it "create the SAMLRequest URL parameter with NameID Format" do
    settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
    inflated = decode_saml_request_payload(auth_url)

    assert_match(/<samlp:NameIDPolicy[^<]* AllowCreate="true"/, inflated)
    assert_match(/<samlp:NameIDPolicy[^<]* Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/, inflated)
  end

  it "create the SAMLRequest URL parameter with Subject" do
    settings.name_identifier_value_requested = "testuser@example.com"
    settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    auth_url = Saml::Authrequest.new.create(settings)
    assert_match(/^http:\/\/example\.com\?SAMLRequest=/, auth_url)
    inflated = decode_saml_request_payload(auth_url)

    assert inflated.includes?("<saml:Subject>")
    assert inflated.includes?(%(<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>))
    assert inflated.includes?(%(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>))
  end

  it "creates a request that matches the protocol schema" do
    settings.sp_entity_id = "http://sp.example.com/metadata"
    settings.assertion_consumer_service_url = "http://sp.example.com/acs"
    settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    xml = decode_saml_request_payload(Saml::Authrequest.new.create(settings))

    assert validate_xml!(xml, Saml::Schema::PROTOCOL)
  end

  it "accept extra parameters" do
    auth_url = Saml::Authrequest.new.create(settings, {"hello" => "there"})
    assert_match(/&hello=there$/, auth_url)
  end

  it "accept extra parameters with nil values" do
    auth_url = Saml::Authrequest.new.create(settings, {"hello" => nil})
    assert_match(/&hello=$/, auth_url)
  end

  it "RelayState cases" do
    auth_url = Saml::Authrequest.new.create(settings, {:RelayState => nil})
    assert !auth_url.includes?("RelayState")

    auth_url = Saml::Authrequest.new.create(settings, {:RelayState => "http://example.com"})
    assert auth_url.includes?("&RelayState=http%3A%2F%2Fexample.com")

    auth_url = Saml::Authrequest.new.create(settings, {"RelayState" => nil})
    assert !auth_url.includes?("RelayState")

    auth_url = Saml::Authrequest.new.create(settings, {"RelayState" => "http://example.com"})
    assert auth_url.includes?("&RelayState=http%3A%2F%2Fexample.com")
  end

  it "keeps RelayState with reserved characters intact" do
    relay_state = "/dashboard?tab=a b&next=/x"
    auth_url = Saml::Authrequest.new.create(settings, {"RelayState" => relay_state})
    raw = auth_url.split("&RelayState=").last.split("&").first

    assert_equal relay_state, URI.decode_www_form(raw)
  end

  it "creates request with ID prefixed with default '_'" do
    request = Saml::Authrequest.new

    assert_match(/^_/, request.uuid)
  end

  it "creates request with ID is prefixed, when id_prefix is passed" do
    Saml::Utils.set_prefix("test")
    begin
      request = Saml::Authrequest.new
      assert_match(/^test/, request.uuid)
    ensure
      Saml::Utils.set_prefix("_")
    end
  end

  describe "when the target url is not set" do
    before do
      settings.idp_sso_service_url = nil
    end

    it "raises an error with a descriptive message" do
      err = assert_raises(Saml::SettingError) do
        Saml::Authrequest.new.create(settings)
      end
      assert_match(/idp_sso_service_url is not set/, err.message.to_s)
    end
  end

  describe "when the target url doesn't contain a query string" do
    it "create the SAMLRequest parameter correctly" do
      auth_url = Saml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example.com\?SAMLRequest/, auth_url)
    end
  end

  describe "when the target url contains a query string" do
    it "create the SAMLRequest parameter correctly" do
      settings.idp_sso_service_url = "http://example.com?field=value"

      auth_url = Saml::Authrequest.new.create(settings)
      assert_match(/^http:\/\/example.com\?field=value&SAMLRequest/, auth_url)
    end
  end

  it "create the saml_AuthnContextClassRef element correctly" do
    settings.authn_context = "secure/name/password/uri"
    auth_doc = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
  end

  it "create multiple saml_AuthnContextClassRef elements correctly" do
    settings.authn_context = ["secure/name/password/uri", "secure/email/password/uri"]
    auth_doc = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
    assert_match(/<saml:AuthnContextClassRef>secure\/email\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
  end

  it "create the saml_AuthnContextClassRef with comparison exact" do
    settings.authn_context = "secure/name/password/uri"
    auth_doc = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    assert_match(/<samlp:RequestedAuthnContext[\S ]+Comparison="exact"/, auth_doc.to_s)
    assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
  end

  it "create the saml_AuthnContextClassRef with comparison minimun" do
    settings.authn_context = "secure/name/password/uri"
    settings.authn_context_comparison = "minimun"
    auth_doc = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    assert_match(/<samlp:RequestedAuthnContext[\S ]+Comparison="minimun"/, auth_doc.to_s)
    assert_match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/, auth_doc.to_s)
  end

  it "create the saml_AuthnContextDeclRef element correctly" do
    settings.authn_context_decl_ref = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    auth_doc = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    assert_match(/<saml:AuthnContextDeclRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport<\/saml:AuthnContextDeclRef>/, auth_doc.to_s)
  end

  it "create multiple saml_AuthnContextDeclRef elements correctly" do
    settings.authn_context_decl_ref = ["name/password/uri", "example/decl/ref"]
    auth_doc = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    assert_match(/<saml:AuthnContextDeclRef>name\/password\/uri<\/saml:AuthnContextDeclRef>/, auth_doc.to_s)
    assert_match(/<saml:AuthnContextDeclRef>example\/decl\/ref<\/saml:AuthnContextDeclRef>/, auth_doc.to_s)
  end

  describe "#create_params signing with HTTP-POST binding" do
    before do
      settings.compress_request = false
      settings.idp_sso_service_url = "http://example.com?field=value"
      settings.idp_sso_service_binding = :post
      settings.security[:authn_requests_signed] = true
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
    end

    it "create a signed request" do
      params = Saml::Authrequest.new.create_params(settings)
      request_xml = Base64.decode_string(params["SAMLRequest"])
      assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], request_xml
      assert_match %r[<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>], request_xml
      refute params.has_key?("Signature")
      refute params.has_key?("SigAlg")
    end

    it "create a signed request with 256 digest and signature methods" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.security[:digest_method] = XMLSecurity::Document::SHA512

      params = Saml::Authrequest.new.create_params(settings)

      request_xml = Base64.decode_string(params["SAMLRequest"])
      assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], request_xml
      assert_match %r[<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>], request_xml
      assert_match %r[<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>], request_xml
    end

    it "create a signed request with SHA-256 that verifies against the SP certificate" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.security[:digest_method] = XMLSecurity::Document::SHA256
      settings.idp_cert = crystal_saml_cert_text

      params = Saml::Authrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      request_xml = Base64.decode_string(params["SAMLRequest"])
      assert_match %r[<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>], request_xml
      assert_equal "http://example.com", params["RelayState"]

      document = XMLSecurity::SignedDocument.new(request_xml)
      assert document.validate_document_with_cert(cert, true)
    end
  end

  describe "#create_params signing with HTTP-Redirect binding" do
    before do
      settings.compress_request = false
      settings.idp_sso_service_url = "http://example.com?field=value"
      settings.idp_sso_service_binding = :redirect
      settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
      settings.security[:authn_requests_signed] = true
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
    end

    it "create a signature parameter with RSA_SHA1 and validate it" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

      params = Saml::Authrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      assert params["SAMLRequest"]
      assert params["RelayState"]
      assert params["Signature"]
      assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA1

      query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
      query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
      query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

      signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
      assert_equal "SHA1", signature_algorithm.name

      assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
    end

    it "create a signature parameter with RSA_SHA256 and validate it" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256

      params = Saml::Authrequest.new.create_params(settings, {"RelayState" => "http://example.com"})
      assert params["Signature"]
      assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA256

      query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
      query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
      query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

      signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
      assert_equal "SHA256", signature_algorithm.name
      assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
    end

    it "round-trips an RSA_SHA256 signature with RelayState through Utils.verify_signature" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      relay_state = "https://sp.example.com/after?x=1&y=two words"

      params = Saml::Authrequest.new.create_params(settings, {"RelayState" => relay_state})
      assert_equal relay_state, params["RelayState"]

      query_string = Saml::Utils.build_query({
        type:        "SAMLRequest",
        data:        params["SAMLRequest"],
        relay_state: params["RelayState"],
        sig_alg:     params["SigAlg"],
      })
      assert Saml::Utils.verify_signature({cert: cert, sig_alg: params["SigAlg"], signature: params["Signature"], query_string: query_string})

      tampered = Saml::Utils.build_query({
        type:        "SAMLRequest",
        data:        params["SAMLRequest"],
        relay_state: "https://evil.example.com",
        sig_alg:     params["SigAlg"],
      })
      refute Saml::Utils.verify_signature({cert: cert, sig_alg: params["SigAlg"], signature: params["Signature"], query_string: tampered})
    end

    it "signs the URL create builds, RelayState included" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.compress_request = true

      auth_url = Saml::Authrequest.new.create(settings, {"RelayState" => "http://example.com/a?b=c"})
      query = auth_url.split("?field=value&").last
      raw = {} of String => String
      query.split("&").each do |pair|
        key, value = pair.split("=", 2)
        raw[key] = value
      end

      assert_equal XMLSecurity::Document::RSA_SHA256, URI.decode_www_form(raw["SigAlg"])
      query_string = Saml::Utils.build_query_from_raw_parts({
        type:            "SAMLRequest",
        raw_data:        raw["SAMLRequest"],
        raw_relay_state: raw["RelayState"],
        raw_sig_alg:     raw["SigAlg"],
      })
      assert Saml::Utils.verify_signature({cert: cert, sig_alg: URI.decode_www_form(raw["SigAlg"]),
                                           signature: URI.decode_www_form(raw["Signature"]), query_string: query_string})
      assert_match(/<samlp:AuthnRequest/, decode_saml_request_payload(auth_url))
    end

    it "accepts the binding as a URN" do
      settings.idp_sso_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      assert_equal Saml::Utils::BINDINGS[:redirect], settings.idp_sso_service_binding
      assert Saml::Authrequest.new.create_params(settings).has_key?("Signature")

      settings.idp_sso_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      params = Saml::Authrequest.new.create_params(settings)
      refute params.has_key?("Signature")
      assert_match(/<ds:SignatureValue>/, Base64.decode_string(params["SAMLRequest"]))
    end

    it "refuses a tampered POST-signed request" do
      settings.idp_sso_service_binding = :post
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
      settings.security[:digest_method] = XMLSecurity::Document::SHA256
      xml = Base64.decode_string(Saml::Authrequest.new.create_params(settings)["SAMLRequest"])
      tampered = xml.sub(%(Version="2.0"), %(Version="2.0" ForceAuthn="true"))
      refute_equal xml, tampered

      refute XMLSecurity::SignedDocument.new(tampered).validate_document_with_cert(cert, true)
    end

    it "does not embed a signature in the document" do
      params = Saml::Authrequest.new.create_params(settings)
      refute_match(/<ds:Signature/, Base64.decode_string(params["SAMLRequest"]))
    end
  end

  describe "DEPRECATED #create_params signing with HTTP-POST binding via embed_sign" do
    before do
      settings.compress_request = false
      settings.idp_sso_service_url = "http://example.com?field=value"
      settings.security[:authn_requests_signed] = true
      settings.security[:embed_sign] = true
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
    end

    it "create a signed request" do
      params = Saml::Authrequest.new.create_params(settings)
      request_xml = Base64.decode_string(params["SAMLRequest"])
      assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], request_xml
      assert_match %r[<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>], request_xml
    end
  end

  describe "DEPRECATED #create_params signing with HTTP-Redirect binding via embed_sign" do
    before do
      settings.compress_request = false
      settings.idp_sso_service_url = "http://example.com?field=value"
      settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
      settings.security[:authn_requests_signed] = true
      settings.security[:embed_sign] = false
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
    end

    it "create a signature parameter with RSA_SHA1 and validate it" do
      settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

      params = Saml::Authrequest.new.create_params(settings, {:RelayState => "http://example.com"})
      assert params["SAMLRequest"]
      assert params["RelayState"]
      assert params["Signature"]
      assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA1

      query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
      query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
      query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

      signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
      assert_equal "SHA1", signature_algorithm.name

      assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
    end
  end

  describe "#manipulate request_id" do
    it "be able to modify the request id" do
      authnrequest = Saml::Authrequest.new
      request_id = authnrequest.request_id
      assert_equal request_id, authnrequest.uuid
      authnrequest.uuid = "new_uuid"
      assert_equal authnrequest.request_id, authnrequest.uuid
      assert_equal "new_uuid", authnrequest.request_id
    end
  end
end
