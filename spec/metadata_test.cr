require "./spec_helper"

# Adds an IdP descriptor before and an Organization after the SP descriptor.
class MetadataSpecWithExtras < Saml::Metadata
  protected def add_extras(root, _settings)
    sp = Saml::XMLUtil.element_children(root).first

    idp = root.add_element("md:IDPSSODescriptor", {"protocolSupportEnumeration" => "urn:oasis:names:tc:SAML:2.0:protocol"})
    idp.add_element("md:NameIDFormat").text = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    idp.add_element("md:SingleSignOnService", {
      "Binding"  => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "Location" => "https://foobar.com/sso",
    })
    sp.add_prev_sibling(idp)

    org = root.add_element("md:Organization")
    org.add_element("md:OrganizationName", {"xml:lang" => "en-US"}).text = "ACME Inc."
    org.add_element("md:OrganizationDisplayName", {"xml:lang" => "en-US"}).text = "ACME"
    org.add_element("md:OrganizationURL", {"xml:lang" => "en-US"}).text = "https://www.acme.com"
    root
  end
end

describe "Metadata" do
  @settings : Saml::Settings?
  @xml_text : String?
  @xml_doc : XML::Node?
  @spsso_descriptor : XML::Node?
  @acs : XML::Node?
  @key_descriptors : XML::NodeSet?
  @cert_nodes : XML::NodeSet?
  @cert : OpenSSL::X509::Certificate?
  @attr_svc : XML::Node?
  @req_attr : XML::Node?

  let(:settings) { Saml::Settings.new }
  let(:xml_text) { Saml::Metadata.new.generate(settings, false) }
  let(:xml_doc) { Saml::XMLUtil.safe_parse(xml_text) }
  let(:spsso_descriptor) { xml_doc.xpath_node("//md:SPSSODescriptor", TEST_NAMESPACES).not_nil! }
  let(:acs) { xml_doc.xpath_node("//md:AssertionConsumerService", TEST_NAMESPACES).not_nil! }

  def node(doc : XML::Node, path : String) : XML::Node
    doc.xpath_node(path, TEST_NAMESPACES).not_nil!
  end

  before do
    settings.sp_entity_id = "https://example.com"
    settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    settings.assertion_consumer_service_url = "https://foo.example/saml/consume"
  end

  it "generates Pretty Print Service Provider Metadata" do
    xml_text = Saml::Metadata.new.generate(settings, true)
    # assert correct xml declaration
    start = "<?xml version='1.0' encoding='UTF-8'?>\n<md:EntityDescriptor"
    assert_equal xml_text[0..start.size - 1], start

    assert_equal "https://example.com", node(xml_doc, "//md:EntityDescriptor")["entityID"]

    assert_equal "urn:oasis:names:tc:SAML:2.0:protocol", spsso_descriptor["protocolSupportEnumeration"]
    assert_equal "false", spsso_descriptor["AuthnRequestsSigned"]
    assert_equal "false", spsso_descriptor["WantAssertionsSigned"]

    assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", node(xml_doc, "//md:NameIDFormat").content.strip

    assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs["Binding"]
    assert_equal "https://foo.example/saml/consume", acs["Location"]

    assert validate_xml!(xml_text, Saml::Schema::METADATA)
  end

  it "generates Service Provider Metadata" do
    settings.single_logout_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    settings.single_logout_service_url = "https://foo.example/saml/sls"
    xml_metadata = Saml::Metadata.new.generate(settings, false)

    start = "<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor"
    assert_equal xml_metadata[0..start.size - 1], start

    doc_metadata = Saml::XMLUtil.safe_parse(xml_metadata)
    sls = node(doc_metadata, "//md:SingleLogoutService")

    assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", sls["Binding"]
    assert_equal "https://foo.example/saml/sls", sls["Location"]
    assert_equal "https://foo.example/saml/sls", sls["ResponseLocation"]
    assert_nil sls["isDefault"]?
    assert_nil sls["index"]?

    assert validate_xml!(xml_metadata, Saml::Schema::METADATA)
  end

  it "generates Service Provider Metadata with single logout service" do
    start = "<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor"
    assert_equal xml_text[0..start.size - 1], start

    assert_equal "https://example.com", node(xml_doc, "//md:EntityDescriptor")["entityID"]

    assert_equal "urn:oasis:names:tc:SAML:2.0:protocol", spsso_descriptor["protocolSupportEnumeration"]
    assert_equal "false", spsso_descriptor["AuthnRequestsSigned"]
    assert_equal "false", spsso_descriptor["WantAssertionsSigned"]

    assert_equal "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", node(xml_doc, "//md:NameIDFormat").content.strip

    assert_equal "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs["Binding"]
    assert_equal "https://foo.example/saml/consume", acs["Location"]

    assert validate_xml!(xml_text, Saml::Schema::METADATA)
  end

  it "generates Service Provider Metadata with ValidUntil and CacheDuration" do
    valid_until = Time.utc + 172800.seconds
    cache_duration = 604800
    xml_metadata = Saml::Metadata.new.generate(settings, false, valid_until, cache_duration)
    start = "<?xml version='1.0' encoding='UTF-8'?><md:EntityDescriptor"
    assert_equal xml_metadata[0..start.size - 1], start

    doc_metadata = Saml::XMLUtil.safe_parse(xml_metadata)
    assert_equal valid_until.to_s("%Y-%m-%dT%H:%M:%SZ"), node(doc_metadata, "//md:EntityDescriptor")["validUntil"]
    assert_equal "PT604800S", node(doc_metadata, "//md:EntityDescriptor")["cacheDuration"]
  end

  describe "WantAssertionsSigned" do
    it "generates Service Provider Metadata with WantAssertionsSigned = false" do
      settings.security[:want_assertions_signed] = false
      assert_equal "false", spsso_descriptor["WantAssertionsSigned"]
      assert validate_xml!(xml_text, Saml::Schema::METADATA)
    end

    it "generates Service Provider Metadata with WantAssertionsSigned = true" do
      settings.security[:want_assertions_signed] = true
      assert_equal "true", spsso_descriptor["WantAssertionsSigned"]
      assert validate_xml!(xml_text, Saml::Schema::METADATA)
    end
  end

  describe "with a sign/encrypt certificate" do
    let(:key_descriptors) { xml_doc.xpath_nodes("//md:KeyDescriptor", TEST_NAMESPACES) }
    let(:cert_nodes) { xml_doc.xpath_nodes("//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", TEST_NAMESPACES) }
    let(:cert) { OpenSSL::X509::Certificate.from_der(Base64.decode(cert_nodes[0].content)) }

    before do
      settings.certificate = crystal_saml_cert_text
    end

    it "generates Service Provider Metadata with X509Certificate for sign" do
      assert_equal 1, key_descriptors.size
      assert_equal "signing", key_descriptors[0]["use"]

      assert_equal 1, cert_nodes.size
      assert_equal crystal_saml_cert.to_der, cert.to_der

      assert validate_xml!(xml_text, Saml::Schema::METADATA)
    end

    describe "and signed authentication requests" do
      before do
        settings.security[:authn_requests_signed] = true
      end

      it "generates Service Provider Metadata with AuthnRequestsSigned" do
        assert_equal "true", spsso_descriptor["AuthnRequestsSigned"]
        assert validate_xml!(xml_text, Saml::Schema::METADATA)
      end
    end

    describe "and encrypted assertions" do
      before do
        settings.security[:want_assertions_encrypted] = true
      end

      it "generates Service Provider Metadata with X509Certificate for encrypt" do
        assert_equal 2, key_descriptors.size

        assert_equal "encryption", key_descriptors[1]["use"]

        assert_equal 2, cert_nodes.size
        assert_equal cert_nodes[0].content, cert_nodes[1].content
        assert validate_xml!(xml_text, Saml::Schema::METADATA)
      end
    end
  end

  describe "with a future SP certificate" do
    let(:key_descriptors) { xml_doc.xpath_nodes("//md:KeyDescriptor", TEST_NAMESPACES) }
    let(:cert_nodes) { xml_doc.xpath_nodes("//md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", TEST_NAMESPACES) }

    before do
      settings.certificate = crystal_saml_cert_text
      settings.certificate_new = crystal_saml_cert_text2
    end

    it "generates Service Provider Metadata with 2 X509Certificate for sign" do
      assert_equal 2, key_descriptors.size
      assert_equal "signing", key_descriptors[0]["use"]
      assert_equal "signing", key_descriptors[1]["use"]

      cert = OpenSSL::X509::Certificate.from_der(Base64.decode(cert_nodes[0].content))
      cert_new = OpenSSL::X509::Certificate.from_der(Base64.decode(cert_nodes[1].content))

      assert_equal 2, cert_nodes.size
      assert_equal crystal_saml_cert.to_der, cert.to_der
      assert_equal crystal_saml_cert2.to_der, cert_new.to_der

      assert validate_xml!(xml_text, Saml::Schema::METADATA)
    end

    describe "and signed authentication requests" do
      before do
        settings.security[:authn_requests_signed] = true
      end

      it "generates Service Provider Metadata with AuthnRequestsSigned" do
        assert_equal "true", spsso_descriptor["AuthnRequestsSigned"]
        assert validate_xml!(xml_text, Saml::Schema::METADATA)
      end
    end

    describe "and encrypted assertions" do
      before do
        settings.security[:want_assertions_encrypted] = true
      end

      it "generates Service Provider Metadata with X509Certificate for encrypt" do
        assert_equal 4, key_descriptors.size
        assert_equal "signing", key_descriptors[0]["use"]
        assert_equal "encryption", key_descriptors[1]["use"]
        assert_equal "signing", key_descriptors[2]["use"]
        assert_equal "encryption", key_descriptors[3]["use"]

        assert_equal 4, cert_nodes.size
        assert_equal cert_nodes[0].content, cert_nodes[1].content
        assert_equal cert_nodes[2].content, cert_nodes[3].content
        assert validate_xml!(xml_text, Saml::Schema::METADATA)
      end
    end
  end

  describe "when attribute service is configured with multiple attribute values" do
    let(:attr_svc) { node(xml_doc, "//md:AttributeConsumingService") }
    let(:req_attr) { node(xml_doc, "//md:RequestedAttribute") }

    before do
      settings.attribute_consuming_service.configure do
        service_name "Test Service"
        add_attribute({:name => "Name", :name_format => "Name Format", :friendly_name => "Friendly Name", :attribute_value => ["Attribute Value One", false]})
      end
    end

    it "generates attribute service" do
      assert_equal "true", attr_svc["isDefault"]
      assert_equal "1", attr_svc["index"]
      assert_equal node(xml_doc, "//md:ServiceName").content.strip, "Test Service"

      assert_equal "Name", req_attr["Name"]
      assert_equal "Name Format", req_attr["NameFormat"]
      assert_equal "Friendly Name", req_attr["FriendlyName"]

      attribute_values = xml_doc.xpath_nodes("//saml:AttributeValue", TEST_NAMESPACES).map(&.content)
      assert_equal "Attribute Value One", attribute_values[0]
      assert_equal "false", attribute_values[1]

      assert validate_xml!(xml_text, Saml::Schema::METADATA)
    end
  end

  describe "when attribute service is configured" do
    let(:attr_svc) { node(xml_doc, "//md:AttributeConsumingService") }
    let(:req_attr) { node(xml_doc, "//md:RequestedAttribute") }

    before do
      settings.attribute_consuming_service.configure do
        service_name "Test Service"
        add_attribute({:name => "active", :name_format => "format", :friendly_name => "Active", :attribute_value => true})
      end
    end

    it "generates attribute service" do
      assert_equal "true", attr_svc["isDefault"]
      assert_equal "1", attr_svc["index"]
      assert_equal node(xml_doc, "//md:ServiceName").content.strip, "Test Service"

      assert_equal "active", req_attr["Name"]
      assert_equal "format", req_attr["NameFormat"]
      assert_equal "Active", req_attr["FriendlyName"]
      assert_equal "true", node(xml_doc, "//saml:AttributeValue").content.strip

      assert validate_xml!(xml_text, Saml::Schema::METADATA)
    end

    describe "#service_name" do
      before do
        settings.attribute_consuming_service.service_name("Test2 Service")
      end

      it "change service name" do
        assert_equal node(xml_doc, "//md:ServiceName").content.strip, "Test2 Service"
      end
    end

    describe "#service_index" do
      before do
        settings.attribute_consuming_service.service_index(2)
      end

      it "change service index" do
        assert_equal "2", attr_svc["index"]
      end
    end
  end

  describe "when the settings indicate to sign (embedded) metadata" do
    before do
      settings.security[:metadata_signed] = true
      settings.certificate = crystal_saml_cert_text
      settings.private_key = crystal_saml_key_text
    end

    it "creates a signed metadata" do
      assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>]m, xml_text
      assert_match %r[<ds:SignatureMethod Algorithm=['"]http://www.w3.org/2000/09/xmldsig#rsa-sha1['"]/>], xml_text
      assert_match %r[<ds:DigestMethod Algorithm=['"]http://www.w3.org/2000/09/xmldsig#sha1['"]/>], xml_text

      signed_metadata = XMLSecurity::SignedDocument.new(xml_text)
      assert signed_metadata.validate_document(crystal_saml_cert_fingerprint, false)

      assert validate_xml!(xml_text, Saml::Schema::METADATA)
    end

    describe "when digest and signature methods are specified" do
      before do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        settings.security[:digest_method] = XMLSecurity::Document::SHA512
      end

      it "creates a signed metadata with specified digest and signature methods" do
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>]m, xml_text
        assert_match %r[<ds:SignatureMethod Algorithm=['"]http://www.w3.org/2001/04/xmldsig-more#rsa-sha256['"]/>], xml_text
        assert_match %r[<ds:DigestMethod Algorithm=['"]http://www.w3.org/2001/04/xmlenc#sha512['"]/>], xml_text

        signed_metadata = XMLSecurity::SignedDocument.new(xml_text)
        assert signed_metadata.validate_document(crystal_saml_cert_fingerprint, false)

        assert validate_xml!(xml_text, Saml::Schema::METADATA)
      end
    end

    describe "when custom metadata elements have been inserted" do
      let(:xml_text) { MetadataSpecWithExtras.new.generate(settings, false) }

      it "inserts signature as the first child of root element" do
        first_child = Saml::XMLUtil.element_children(xml_doc.root.not_nil!)[0]
        assert_equal first_child.namespace.try(&.prefix), "ds"
        assert_equal first_child.name, "Signature"

        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>]m, xml_text
        assert_match %r[<ds:SignatureMethod Algorithm=['"]http://www.w3.org/2000/09/xmldsig#rsa-sha1['"]/>], xml_text
        assert_match %r[<ds:DigestMethod Algorithm=['"]http://www.w3.org/2000/09/xmldsig#sha1['"]/>], xml_text

        signed_metadata = XMLSecurity::SignedDocument.new(xml_text)
        assert signed_metadata.validate_document(crystal_saml_cert_fingerprint, false)

        assert validate_xml!(xml_text, Saml::Schema::METADATA)
      end
    end
  end
end
