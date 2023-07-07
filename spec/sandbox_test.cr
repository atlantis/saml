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

  describe "Fingerprint Algorithms" do
    let(:response_fingerprint_test) { Saml::Response.new(fixture(:adfs_response_sha1, false)) }

    it "validate using SHA1" do
      sha1_fingerprint = "F1:3C:6B:80:90:5A:03:0E:6C:91:3E:5D:15:FA:DD:B0:16:45:48:72"
      sha1_fingerprint_downcase = "f13c6b80905a030e6c913e5d15faddb016454872"

      response_fingerprint_test.document.validate_document(sha1_fingerprint)

      assert response_fingerprint_test.document.validate_document(sha1_fingerprint)
      assert response_fingerprint_test.document.validate_document(sha1_fingerprint, true, {:fingerprint_alg => XMLSecurity::Document::SHA1})

      assert response_fingerprint_test.document.validate_document(sha1_fingerprint_downcase)
      assert response_fingerprint_test.document.validate_document(sha1_fingerprint_downcase, true, {:fingerprint_alg => XMLSecurity::Document::SHA1})
    end

    it "validate using SHA256" do
      sha256_fingerprint = "C4:C6:BD:41:EC:AD:57:97:CE:7B:7D:80:06:C3:E4:30:53:29:02:0B:DD:2D:47:02:9E:BD:85:AD:93:02:45:21"

      assert !response_fingerprint_test.document.validate_document(sha256_fingerprint)
      assert response_fingerprint_test.document.validate_document(sha256_fingerprint, true, {:fingerprint_alg => XMLSecurity::Document::SHA256})
    end

    # it "validate using SHA384" do
    #   sha384_fingerprint = "98:FE:17:90:31:E7:68:18:8A:65:4D:DA:F5:76:E2:09:97:BE:8B:E3:7E:AA:8D:63:64:7C:0C:38:23:9A:AC:A2:EC:CE:48:A6:74:4D:E0:4C:50:80:40:B4:8D:55:14:14"

    #   assert !response_fingerprint_test.document.validate_document(sha384_fingerprint)
    #   assert response_fingerprint_test.document.validate_document(sha384_fingerprint, true, {:fingerprint_alg => XMLSecurity::Document::SHA384})
    # end

    it "validate using SHA512" do
      sha512_fingerprint = "5A:AE:BA:D0:BA:9D:1E:25:05:01:1E:1A:C9:E9:FF:DB:ED:FA:6E:F7:52:EB:45:49:BD:DB:06:D8:A3:7E:CC:63:3A:04:A2:DD:DF:EE:61:05:D9:58:95:2A:77:17:30:4B:EB:4A:9F:48:4A:44:1C:D0:9E:0B:1E:04:77:FD:A3:D2"

      assert !response_fingerprint_test.document.validate_document(sha512_fingerprint)
      assert response_fingerprint_test.document.validate_document(sha512_fingerprint, true, {:fingerprint_alg => XMLSecurity::Document::SHA512})
    end
  end
end