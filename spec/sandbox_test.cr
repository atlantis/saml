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

  it "correctly obtain the digest method with alternate namespace declaration" do
    adfs_document = XMLSecurity::SignedDocument.new(fixture(:adfs_response_xmlns, false))
    base64cert = adfs_document.xpath_node("//*[local-name()='X509Certificate']").try &.text
    assert adfs_document.validate_signature(base64cert, false)
  end
end