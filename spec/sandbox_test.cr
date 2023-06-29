require "./spec_helper"

describe "XmlSecurity" do
  @document : XMLSecurity::SignedDocument?
  @base64cert : String?

  let(:decoded_response) { Base64.decode_string(response_document_without_recipient) }
  let(:document) { XMLSecurity::SignedDocument.new(decoded_response) }
  let(:settings) { Saml::Settings.new() }

  before do
    @base64cert = document.xpath_node("//ds:X509Certificate", { "ds" => XMLSecurity::BaseDocument::DSIG }).not_nil!.text
  end

  it "should run validate without throwing NS related exceptions" do
    assert !document.validate_signature(@base64cert, true)
  end
end
