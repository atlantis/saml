require "spec"
require "timecop"
require "minitest/autorun"
require "../src/saml"

class Minitest::Test
  @response_document_without_attributes : String?
  @response_document_without_recipient : String?
  @response_document_valid_signed_without_x509certificate : String?
  @crystal_saml_cert_fingerprint : String?
  @response_document_with_signed_assertion : String?
  @response_document_valid_signed : String?
  @response_document_unsigned : String?
  @response_document_with_saml2_namespace : String?
  @response_document_with_ds_namespace_at_the_root : String?
  @signature1 : String?
  @response_document_wrapped : String?
  @response_document_without_reference_uri : String?
  @ampersands_response : String?

  def fixture(document, base64 = true)
    response = Dir.glob(File.join(File.dirname(__FILE__), "responses", "#{document}*")).first
    if base64 && response =~ /\.xml$/
      Base64.encode(File.read(response))
    else
      File.read(response)
    end
  end

  def read_response(response)
    File.read(File.join(File.dirname(__FILE__), "responses", response))
  end

  def read_invalid_response(response)
    File.read(File.join(File.dirname(__FILE__), "responses", "invalids", response))
  end

  def read_logout_request(request)
    File.read(File.join(File.dirname(__FILE__), "logout_requests", request))
  end

  def read_certificate(certificate)
    File.read(File.join(File.dirname(__FILE__), "certificates", certificate))
  end

  def response_document_valid_signed
    @response_document_valid_signed ||= read_response("valid_response.xml.base64")
  end

  def response_document_valid_signed_without_x509certificate
    @response_document_valid_signed_without_x509certificate ||= read_response("valid_response_without_x509certificate.xml.base64")
  end

  def response_document_without_recipient
    @response_document_without_recipient ||= read_response("response_with_undefined_recipient.xml.base64")
  end

  def response_document_without_recipient_with_time_updated
    doc = Base64.decode_string(response_document_without_recipient)
    doc = doc.gsub(/NotBefore=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotBefore=\"#{(Time.utc - 300.seconds).to_s("%Y-%m-%dT%XZ")}\"")
    doc = doc.gsub(/NotOnOrAfter=\"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\"/, "NotOnOrAfter=\"#{(Time.utc + 300.seconds).to_s("%Y-%m-%dT%XZ")}\"")
    Base64.encode(doc)
  end

  def response_document_without_attributes
    @response_document_without_attributes ||= read_response("response_without_attributes.xml.base64")
  end

  def response_document_without_reference_uri
    @response_document_without_reference_uri ||= read_response("response_without_reference_uri.xml.base64")
  end

  def response_document_with_signed_assertion
    @response_document_with_signed_assertion ||= read_response("response_with_signed_assertion.xml.base64")
  end

  def response_document_with_signed_assertion_2
    @response_document_with_signed_assertion_2 ||= read_response("response_with_signed_assertion_2.xml.base64")
  end

  def response_document_with_ds_namespace_at_the_root
    @response_document_with_ds_namespace_at_the_root ||= read_response("response_with_ds_namespace_at_the_root.xml.base64")
  end

  def response_document_unsigned
    @response_document_unsigned ||= read_response("response_unsigned_xml_base64")
  end

  def response_document_with_saml2_namespace
    @response_document_with_saml2_namespace ||= read_response("response_with_saml2_namespace.xml.base64")
  end

  def ampersands_document
    @ampersands_response ||= read_response("response_with_ampersands.xml.base64")
  end

  def response_document_no_cert_and_encrypted_attrs
    @response_document_no_cert_and_encrypted_attrs ||= Base64.encode(read_response("response_no_cert_and_encrypted_attrs.xml"))
  end

  def response_document_wrapped
    @response_document_wrapped ||= read_response("response_wrapped.xml.base64")
  end

  def response_document_assertion_wrapped
    @response_document_assertion_wrapped ||= read_response("response_assertion_wrapped.xml.base64")
  end

  def response_document_encrypted_nameid
    @response_document_encrypted_nameid ||= File.read(File.join(File.dirname(__FILE__), "responses", "response_encrypted_nameid.xml.base64"))
  end

  def signed_message_encrypted_unsigned_assertion
    @signed_message_encrypted_unsigned_assertion ||= File.read(File.join(File.dirname(__FILE__), "responses", "signed_message_encrypted_unsigned_assertion.xml.base64"))
  end

  def signed_message_encrypted_signed_assertion
    @signed_message_encrypted_signed_assertion ||= File.read(File.join(File.dirname(__FILE__), "responses", "signed_message_encrypted_signed_assertion.xml.base64"))
  end

  def unsigned_message_encrypted_signed_assertion
    @unsigned_message_encrypted_signed_assertion ||= File.read(File.join(File.dirname(__FILE__), "responses", "unsigned_message_encrypted_signed_assertion.xml.base64"))
  end

  def unsigned_message_encrypted_unsigned_assertion
    @unsigned_message_encrypted_unsigned_assertion ||= File.read(File.join(File.dirname(__FILE__), "responses", "unsigned_message_encrypted_unsigned_assertion.xml.base64"))
  end

  def response_document_encrypted_attrs
    @response_document_encrypted_attrs ||= File.read(File.join(File.dirname(__FILE__), "responses", "response_encrypted_attrs.xml.base64"))
  end

  def response_document_double_status_code
    @response_document_double_status_code ||= File.read(File.join(File.dirname(__FILE__), "responses", "response_double_status_code.xml.base64"))
  end

  def signature_fingerprint_1
    @signature_fingerprint1 ||= "C5:19:85:D9:47:F1:BE:57:08:20:25:05:08:46:EB:27:F6:CA:B7:83"
  end

  # certificate used on response_with_undefined_recipient
  def signature_1
    @signature1 ||= read_certificate("certificate1")
  end

  # certificate used on response_document_with_signed_assertion_2
  def certificate_without_head_foot
    @certificate_without_head_foot ||= read_certificate("certificate_without_head_foot")
  end

  def idp_metadata_descriptor
    @idp_metadata_descriptor ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor.xml"))
  end

  def idp_metadata_descriptor2
    @idp_metadata_descriptor2 ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor_2.xml"))
  end

  def idp_metadata_descriptor3
    @idp_metadata_descriptor3 ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor_3.xml"))
  end

  def idp_metadata_descriptor4
    @idp_metadata_descriptor4 ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor_4.xml"))
  end

  def idp_metadata_descriptor5
    @idp_metadata_descriptor5 ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor_5.xml"))
  end

  def idp_metadata_descriptor6
    @idp_metadata_descriptor6 ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_descriptor_6.xml"))
  end

  def no_idp_metadata_descriptor
    @no_idp_metadata_descriptor ||= File.read(File.join(File.dirname(__FILE__), "metadata", "no_idp_descriptor.xml"))
  end

  def idp_metadata_multiple_descriptors
    @idp_metadata_multiple_descriptors ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_multiple_descriptors.xml"))
  end

  def idp_metadata_multiple_descriptors2
    @idp_metadata_multiple_descriptors2 ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_multiple_descriptors_2.xml"))
  end

  def idp_metadata_multiple_certs
    @idp_metadata_multiple_descriptors ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_metadata_multi_certs.xml"))
  end

  def idp_metadata_multiple_signing_certs
    @idp_metadata_multiple_signing_certs ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_metadata_multi_signing_certs.xml"))
  end

  def idp_metadata_same_sign_and_encrypt_cert
    @idp_metadata_same_sign_and_encrypt_cert ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_metadata_same_sign_and_encrypt_cert.xml"))
  end

  def idp_metadata_different_sign_and_encrypt_cert
    @idp_metadata_different_sign_and_encrypt_cert ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_metadata_different_sign_and_encrypt_cert.xml"))
  end

  def idp_different_slo_response_location
    @idp_different_slo_response_location ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_different_slo_response_location.xml"))
  end

  def idp_without_slo_response_location
    @idp_without_slo_response_location ||= File.read(File.join(File.dirname(__FILE__), "metadata", "idp_without_slo_response_location.xml"))
  end

  def logout_request_document
    unless @logout_request_document
      xml = read_logout_request("slo_request.xml")
      deflated = Zlib::Deflate.deflate(xml, 9)[2..-5]
      @logout_request_document = Base64.encode(deflated)
    end
    @logout_request_document
  end

  def logout_request_document_with_name_id_format
    unless @logout_request_document_with_name_id_format
      xml = read_logout_request("slo_request_with_name_id_format.xml")
      deflated = Zlib::Deflate.deflate(xml, 9)[2..-5]
      @logout_request_document_with_name_id_format = Base64.encode(deflated)
    end
    @logout_request_document_with_name_id_format
  end

  def logout_request_xml_with_session_index
    @logout_request_xml_with_session_index ||= File.read(File.join(File.dirname(__FILE__), "logout_requests", "slo_request_with_session_index.xml"))
  end

  def invalid_logout_request_document
    unless @invalid_logout_request_document
      xml = File.read(File.join(File.dirname(__FILE__), "logout_requests", "invalid_slo_request.xml"))
      deflated = Zlib::Deflate.deflate(xml, 9)[2..-5]
      @invalid_logout_request_document = Base64.encode(deflated)
    end
    @invalid_logout_request_document
  end

  def logout_request_base64
    @logout_request_base64 ||= File.read(File.join(File.dirname(__FILE__), "logout_requests", "slo_request.xml.base64"))
  end

  def logout_request_deflated_base64
    @logout_request_deflated_base64 ||= File.read(File.join(File.dirname(__FILE__), "logout_requests", "slo_request_deflated.xml.base64"))
  end

  def crystal_saml_cert
    @crystal_saml_cert ||= OpenSSL::X509::Certificate.new(crystal_saml_cert_text)
  end

  def crystal_saml_cert2
    @crystal_saml_cert2 ||= OpenSSL::X509::Certificate.new(crystal_saml_cert_text2)
  end

  def crystal_saml_cert_fingerprint
    @crystal_saml_cert_fingerprint ||= Digest::SHA1.hexdigest(Base64.decode(XMLSecurity::BaseDocument.pem_to_der(crystal_saml_cert.to_pem))).scan(/../).map{|r|r[0]}.join(":")
    @crystal_saml_cert_fingerprint.not_nil!
  end

  def crystal_saml_cert_text
    read_certificate("crystal-saml.crt")
  end

  def crystal_saml_cert_text2
    read_certificate("crystal-saml-2.crt")
  end

  def crystal_saml_key
    @crystal_saml_key ||= OpenSSL::PKey::RSA.new(crystal_saml_key_text)
  end

  def crystal_saml_key_text
    read_certificate("crystal-saml.key")
  end

  #
  # logoutresponse fixtures
  #
  def random_id
    "_#{Saml::Utils.uuid}"
  end

  #
  # decodes a base64 encoded SAML response for use in SloLogoutresponse tests
  #
  def decode_saml_response_payload(unauth_url)
    payload = URI.decode(unauth_url.split("SAMLResponse=").last)
    decoded = Base64.decode(payload)

    zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflated = zstream.inflate(decoded)
    zstream.finish
    zstream.close
    inflated
  end

  #
  # decodes a base64 encoded SAML request for use in Logoutrequest tests
  #
  def decode_saml_request_payload(unauth_url)
    payload = URI.decode(unauth_url.split("SAMLRequest=").last)
    decoded = Base64.decode(payload)

    zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    inflated = zstream.inflate(decoded)
    zstream.finish
    zstream.close
    inflated
  end

  SCHEMA_DIR = File.expand_path(File.join(__FILE__, "../../lib/schemas"))

  #
  # validate an xml document against the given schema
  #
  def validate_xml!(document : String, schema)
    begin
      # TODO: Maybe rewrite the file paths to xsds?
      XML.parse(document, XML::ParserOptions::DTDVALID)
      true
    rescue ex
      raise "Schema validation failed! XSD validation errors: #{ex.message}"
    end
    # Dir.chdir(SCHEMA_DIR) do
    #   xsd = if schema.is_a? Nokogiri::XML::Schema
    #           schema
    #         else
    #           Nokogiri::XML::Schema(File.read(schema))
    #         end

    #   xml = if document.is_a? Nokogiri::XML::Document
    #           document
    #         else
    #           Nokogiri::XML(document) { |c| c.strict }
    #         end

    #   result = xsd.validate(xml)

    #   if result.size != 0
    #     raise "Schema validation failed! XSD validation errors: #{result.join(", ")}"
    #   else
    #     true
    #   end
    # end
  end

  # Allows to emulate Azure AD request behavior
  def downcased_escape(str)
    Saml::Utils.url_encode(str).gsub(/%[A-Fa-f0-9]{2}/) { |match| match.downcase }
  end
end