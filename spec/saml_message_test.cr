require "./spec_helper"

# Exposes SamlMessage's private codec helpers to the specs.
class SamlMessageSpecExposer < Saml::SamlMessage
  def call_decode_raw_saml(saml : String, settings = nil) : String
    decode_raw_saml(saml, settings)
  end

  def call_encode_raw_saml(saml : String, settings) : String
    encode_raw_saml(saml, settings)
  end

  def call_decode(string : String) : String
    decode(string)
  end

  def call_decode_bytes(string : String) : Bytes
    decode_bytes(string)
  end

  def call_encode(data : String | Bytes) : String
    encode(data)
  end

  def call_deflate(inflated : String) : Bytes
    deflate(inflated)
  end

  def call_inflate(deflated : Bytes) : String
    inflate(deflated)
  end
end

describe "SamlMessage" do
  let(:settings) { Saml::Settings.new }
  let(:saml_message) { SamlMessageSpecExposer.new }
  let(:response_document) { read_response("response_unsigned_xml_base64") }
  let(:response_document_xml) { read_response("adfs_response_xmlns.xml") }
  @logout_request_xml : String?
  @response_document : String?
  @response_document_xml : String?
  @saml_message : SamlMessageSpecExposer?
  @settings : Saml::Settings?

  let(:logout_request_xml) { Base64.decode_string(logout_request_base64) }

  # The ruby-saml originals used `assert a, b`, which always passes; these compare the values.
  it "return decoded raw saml" do
    assert_equal(logout_request_xml, saml_message.call_decode_raw_saml(logout_request_deflated_base64))
    assert_equal(logout_request_xml, saml_message.call_decode_raw_saml(logout_request_base64))
  end

  it "return encoded raw saml" do
    settings.compress_request = true
    encoded_raw = saml_message.call_encode_raw_saml(logout_request_xml, settings)
    assert_equal(logout_request_xml, saml_message.call_decode_raw_saml(URI.decode_www_form(encoded_raw)))

    settings.compress_request = false
    encoded_raw = saml_message.call_encode_raw_saml(logout_request_xml, settings)
    assert_equal(Saml::Utils.url_encode(Base64.strict_encode(logout_request_xml)), encoded_raw)
  end

  it "return decoded string" do
    # The fixture is deflated, so the decoded bytes are the raw-deflated Response.
    decoded = saml_message.call_decode_bytes(response_document)
    assert_includes(inflate(decoded), "<samlp:Response ")
    assert_equal(String.new(decoded), saml_message.call_decode(response_document))
    assert_equal(logout_request_xml, saml_message.call_decode(logout_request_base64))
  end

  it "return encoded string" do
    assert_equal(response_document_xml, Base64.decode_string(saml_message.call_encode(response_document_xml)))
    assert_equal(logout_request_base64.gsub(/\s/, ""), saml_message.call_encode(logout_request_xml))
  end

  it "return deflated string" do
    deflated = saml_message.call_deflate(logout_request_xml)
    assert_equal(logout_request_xml, inflate(deflated))
    assert_equal(logout_request_deflated_base64.gsub(/\s/, ""), saml_message.call_encode(deflated))
  end

  it "return inflated string" do
    decoded = saml_message.call_decode_bytes(logout_request_deflated_base64)
    assert_equal(logout_request_xml, saml_message.call_inflate(decoded))
  end

  describe "Prevent Zlib bomb attack" do
    @bomb : String?
    @bomb_data : String?
    @bomb_prefix : String?
    @bomb_suffix : String?

    let(:bomb) { Base64.encode(deflate(bomb_data)) }
    let(:bomb_data) { bomb_prefix + "A" * (200000 * 1024) + bomb_suffix }
    let(:bomb_prefix) {
      "<?xml version='1.0' encoding='UTF-8'?>
      <samlp:LogoutRequest xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d' Version='2.0' IssueInstant='2014-07-18T01:13:06Z' Destination='http://idp.example.com/SingleLogoutService.php'>
      <saml:Issuer>"
    }
    let(:bomb_suffix) {
      "</saml:Issuer>
      <saml:NameID SPNameQualifier='http://sp.example.com/demo1/metadata.php' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>
   </samlp:LogoutRequest>"
    }

    it "raises error when SAML Message exceed the allowed bytes" do
      error = assert_raises(Saml::ValidationError) do
        SamlMessageSpecExposer.new.call_decode_raw_saml(bomb)
      end
      assert_equal("Encoded SAML Message exceeds #{Saml::Settings::DEFAULTS[:message_max_bytesize]} bytes, so was rejected", error.message)
    end

    it "raises error when the inflated SAML Message exceeds the allowed bytes" do
      small_bomb = Base64.strict_encode(deflate(bomb_prefix + "A" * 300_000 + bomb_suffix))
      error = assert_raises(Saml::ValidationError) do
        SamlMessageSpecExposer.new.call_decode_raw_saml(small_bomb)
      end
      assert_equal("SAML Message exceeds #{Saml::Settings::DEFAULTS[:message_max_bytesize]} bytes, so was rejected", error.message)
    end

    describe "with a custom setting for message_max_bytesize" do
      @message_max_bytesize : Int32?
      @custom_settings : Saml::Settings?

      let(:message_max_bytesize) { 100_00 }
      let(:custom_settings) { Saml::Settings.new({:message_max_bytesize => message_max_bytesize}) }

      it "uses the custom setting" do
        error = assert_raises(Saml::ValidationError) do
          SamlMessageSpecExposer.new.call_decode_raw_saml(bomb, custom_settings)
        end
        assert_equal("Encoded SAML Message exceeds #{message_max_bytesize} bytes, so was rejected", error.message)
      end
    end
  end
end
