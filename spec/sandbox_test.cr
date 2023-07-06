require "./spec_helper"

describe "XmlSecurity" do
  @base64cert : String?
  @document : XMLSecurity::SignedDocument?

  let(:decoded_response) { Base64.decode_string(response_document_without_recipient) }
  let(:document) { XMLSecurity::SignedDocument.new(decoded_response) }
  let(:settings) { Saml::Settings.new }

  before do
    @base64cert = document.xpath_node("//ds:X509Certificate", {"ds" => XMLSecurity::BaseDocument::DSIG}).try(&.text)
  end

  describe "XMLSecurity::DSIG" do
    before do
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.protocol_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      settings.idp_slo_service_url = "https://idp.example.com/slo"
      settings.sp_entity_id = "https://sp.example.com/saml2"
      settings.assertion_consumer_service_url = "https://sp.example.com/acs"
      settings.single_logout_service_url = "https://sp.example.com/sls"
    end

    # it "sign an AuthNRequest" do
    #   request = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    #   request.sign_document(crystal_saml_key, crystal_saml_cert)
    #   # verify our signature
    #   signed_doc = XMLSecurity::SignedDocument.new(request.to_s)
    #   assert signed_doc.validate_document(crystal_saml_cert_fingerprint, false)

    #   request2 = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    #   request2.sign_document(crystal_saml_key, crystal_saml_cert_text)
    #   # verify our signature
    #   signed_doc2 = XMLSecurity::SignedDocument.new(request2.to_s)
    #   assert signed_doc2.validate_document(crystal_saml_cert_fingerprint, false)
    # end

    # it "sign an AuthNRequest with certificate as text" do
    #   request = Saml::Authrequest.new.create_authentication_xml_doc(settings)
    #   request.sign_document(crystal_saml_key, crystal_saml_cert_text)

    #   # verify our signature
    #   signed_doc = XMLSecurity::SignedDocument.new(request.to_s)
    #   assert signed_doc.validate_document(crystal_saml_cert_fingerprint, false)
    # end

    it "sign a LogoutRequest" do
      logout_request = Saml::Logoutrequest.new.create_logout_request_xml_doc(settings)
      logout_request.sign_document(crystal_saml_key, crystal_saml_cert)

#puts "LOGOUT REQUEST: #{logout_request.to_s}"

      #verify our signature
      signed_doc = XMLSecurity::SignedDocument.new(logout_request.to_s)
      assert signed_doc.validate_document(crystal_saml_cert_fingerprint, false)

      logout_request2 = Saml::Logoutrequest.new.create_logout_request_xml_doc(settings)
      logout_request2.sign_document(crystal_saml_key, crystal_saml_cert_text)
      # verify our signature
      signed_doc2 = XMLSecurity::SignedDocument.new(logout_request2.to_s)
      signed_doc2.validate_document(crystal_saml_cert_fingerprint, false)
      assert signed_doc2.validate_document(crystal_saml_cert_fingerprint, false)
    end
  end
end