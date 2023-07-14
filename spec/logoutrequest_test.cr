require "./spec_helper"

require "onelogin/ruby-saml/logoutrequest"

class RequestTest < Minitest::Test
  describe "Logoutrequest" do
    let(:settings) { Saml::Settings.new }

    before do
      settings.idp_slo_service_url = "http://unauth.com/logout"
      settings.name_identifier_value = "f00f00"
    end

    it "create the deflated SAMLRequest URL parameter" do
      unauth_url = Saml::Logoutrequest.new.create(settings)
      assert_match(/^http:\/\/unauth\.com\/logout\?SAMLRequest=/, unauth_url)

      inflated = decode_saml_request_payload(unauth_url)
      assert_match(/^<samlp:LogoutRequest/, inflated)
    end

    it "support additional params" do
      unauth_url = Saml::Logoutrequest.new.create(settings, { :hello => nil })
      assert_match(/&hello=$/, unauth_url)

      unauth_url = Saml::Logoutrequest.new.create(settings, { :foo => "bar" })
      assert_match(/&foo=bar$/, unauth_url)
    end

    it "RelayState cases" do
      unauth_url = Saml::Logoutrequest.new.create(settings, { :RelayState => nil })
      assert !unauth_url.includes?("RelayState")

      unauth_url = Saml::Logoutrequest.new.create(settings, { :RelayState => "http://example.com" })
      assert unauth_url.includes?("&RelayState=http%3A%2F%2Fexample.com")

      unauth_url = Saml::Logoutrequest.new.create(settings, { "RelayState" => nil })
      assert !unauth_url.includes?("RelayState")

      unauth_url = Saml::Logoutrequest.new.create(settings, { "RelayState" => "http://example.com" })
      assert unauth_url.includes?("&RelayState=http%3A%2F%2Fexample.com")
    end

    it "set sessionindex" do
      settings.idp_slo_service_url = "http://example.com"
      sessionidx = Saml::Utils.uuid
      settings.sessionindex = sessionidx

      unauth_url = Saml::Logoutrequest.new.create(settings, { :nameid => "there" })
      inflated = decode_saml_request_payload(unauth_url)

      assert_match(/<samlp:SessionIndex/, inflated)
      assert_match %r(#{sessionidx}</samlp:SessionIndex>), inflated
    end

    it "set name_identifier_value" do
      settings.name_identifier_format = "transient"
      name_identifier_value = "abc123"
      settings.name_identifier_value = name_identifier_value

      unauth_url = Saml::Logoutrequest.new.create(settings, { :nameid => "there" })
      inflated = decode_saml_request_payload(unauth_url)

      assert_match(/<saml:NameID/, inflated)
      assert_match %r(#{name_identifier_value}</saml:NameID>), inflated
    end

    describe "when the target url doesn't contain a query string" do
      it "create the SAMLRequest parameter correctly" do
        unauth_url = Saml::Logoutrequest.new.create(settings)
        assert_match(/^http:\/\/unauth.com\/logout\?SAMLRequest/, unauth_url)
      end
    end

    describe "when the target url contains a query string" do
      it "create the SAMLRequest parameter correctly" do
        settings.idp_slo_service_url = "http://example.com?field=value"

        unauth_url = Saml::Logoutrequest.new.create(settings)
        assert_match(/^http:\/\/example.com\?field=value&SAMLRequest/, unauth_url)
      end
    end

    describe "consumation of logout may need to track the transaction" do
      it "have access to the request uuid" do
        settings.idp_slo_service_url = "http://example.com?field=value"

        unauth_req = Saml::Logoutrequest.new
        unauth_url = unauth_req.create(settings)

        inflated = decode_saml_request_payload(unauth_url)
        assert_match %r[ID='#{unauth_req.uuid}'], inflated
      end
    end

    describe "playgin with preix" do
      it "creates request with ID prefixed with default '_'" do
        request = Saml::Logoutrequest.new

        assert_match(/^_/, request.uuid)
      end

      it "creates request with ID is prefixed, when :id_prefix is passed" do
        Saml::Utils::set_prefix("test")
        request = Saml::Logoutrequest.new
        assert_match(/^test/, request.uuid)
        Saml::Utils::set_prefix("_")
      end
    end

    describe "signing with HTTP-POST binding" do
      before do
        settings.security[:logout_requests_signed] = true
        settings.idp_slo_service_binding = :post
        settings.idp_sso_service_binding = :redirect
        settings.certificate = crystal_saml_cert_text
        settings.private_key = crystal_saml_key_text
      end

      it "doesn't sign through create_xml_document" do
        unauth_req = Saml::Logoutrequest.new
        inflated = unauth_req.create_xml_document(settings).to_s

        refute_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], inflated
        refute_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], inflated
        refute_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], inflated
      end

      it "sign unsigned request" do
        unauth_req = Saml::Logoutrequest.new
        unauth_req_doc = unauth_req.create_xml_document(settings)
        inflated = unauth_req_doc.to_s

        refute_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], inflated
        refute_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], inflated
        refute_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], inflated

        inflated = unauth_req.sign_document(unauth_req_doc, settings).to_s

        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], inflated
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], inflated
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], inflated
      end

      it "signs through create_logout_request_xml_doc" do
        unauth_req = Saml::Logoutrequest.new
        inflated = unauth_req.create_logout_request_xml_doc(settings).to_s

        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], inflated
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], inflated
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], inflated
      end

      it "created a signed logout request" do
        settings.compress_request = true

        unauth_req = Saml::Logoutrequest.new
        unauth_url = unauth_req.create(settings)

        inflated = decode_saml_request_payload(unauth_url)
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], inflated
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], inflated
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], inflated
      end

      it "create a signed logout request with 256 digest and signature method" do
        settings.compress_request = false
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        settings.security[:digest_method] = XMLSecurity::Document::SHA256

        params = Saml::Logoutrequest.new.create_params(settings)
        request_xml = Base64.decode(params["SAMLRequest"])

        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], request_xml
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/>], request_xml
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/>], request_xml
      end

      it "create a signed logout request with 512 digest and signature method RSA_SHA384" do
        settings.compress_request = false
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA384
        settings.security[:digest_method] = XMLSecurity::Document::SHA512

        params = Saml::Logoutrequest.new.create_params(settings)
        request_xml = Base64.decode(params["SAMLRequest"])

        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], request_xml
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'/>], request_xml
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha512'/>], request_xml
      end
    end

    describe "signing with HTTP-Redirect binding" do
      let(:cert) { OpenSSL::X509::Certificate.new(crystal_saml_cert_text) }

      before do
        settings.security[:logout_requests_signed] = true
        settings.idp_slo_service_binding = :redirect
        settings.idp_sso_service_binding = :post
        settings.certificate = crystal_saml_cert_text
        settings.private_key = crystal_saml_key_text
      end

      it "create a signature parameter with RSA_SHA1 / SHA1 and validate it" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

        params = Saml::Logoutrequest.new.create_params(settings, :RelayState => "http://example.com")
        assert params["SAMLRequest"]
        assert params["RelayState"]
        assert params["Signature"]
        assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA1

        query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
        query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
        query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

        signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
        assert_equal signature_algorithm, OpenSSL::Digest::SHA1
        assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
      end

      it "create a signature parameter with RSA_SHA256 / SHA256 and validate it" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256

        params = Saml::Logoutrequest.new.create_params(settings, :RelayState => "http://example.com")
        assert params["Signature"]
        assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA256

        query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
        query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
        query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

        signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
        assert_equal signature_algorithm, OpenSSL::Digest::SHA256
        assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
      end

      it "create a signature parameter with RSA_SHA384 / SHA384 and validate it" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA384

        params = Saml::Logoutrequest.new.create_params(settings, :RelayState => "http://example.com")
        assert params["Signature"]
        assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA384

        query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
        query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
        query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

        # signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
        # assert_equal signature_algorithm, OpenSSL::Digest::SHA384
        # assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
      end

      it "create a signature parameter with RSA_SHA512 / SHA512 and validate it" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA512

        params = Saml::Logoutrequest.new.create_params(settings, :RelayState => "http://example.com")
        assert params["Signature"]
        assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA512

        query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
        query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
        query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

        signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
        assert_equal signature_algorithm, OpenSSL::Digest::SHA512
        assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
      end
    end

    describe "DEPRECATED: signing with HTTP-POST binding via :embed_sign" do
      before do
        # sign the logout request
        settings.security[:logout_requests_signed] = true
        settings.security[:embed_sign] = true
        settings.certificate = crystal_saml_cert_text
        settings.private_key = crystal_saml_key_text
      end

      it "created a signed logout request" do
        settings.compress_request = true

        unauth_req = Saml::Logoutrequest.new
        unauth_url = unauth_req.create(settings)

        inflated = decode_saml_request_payload(unauth_url)
        assert_match %r[<ds:SignatureValue>([a-zA-Z0-9/+=]+)</ds:SignatureValue>], inflated
        assert_match %r[<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'/>], inflated
        assert_match %r[<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'/>], inflated
      end
    end

    describe "DEPRECATED: signing with HTTP-Redirect binding via :embed_sign" do
      let(:cert) { OpenSSL::X509::Certificate.new(crystal_saml_cert_text) }

      before do
        settings.security[:logout_requests_signed] = true
        settings.security[:embed_sign] = false
        settings.certificate = crystal_saml_cert_text
        settings.private_key = crystal_saml_key_text
      end

      it "create a signature parameter with RSA_SHA1 / SHA1 and validate it" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1

        params = Saml::Logoutrequest.new.create_params(settings, :RelayState => "http://example.com")
        assert params["SAMLRequest"]
        assert params["RelayState"]
        assert params["Signature"]
        assert_equal params["SigAlg"], XMLSecurity::Document::RSA_SHA1

        query_string = "SAMLRequest=#{Saml::Utils.url_encode(params["SAMLRequest"])}"
        query_string += "&RelayState=#{Saml::Utils.url_encode(params["RelayState"])}"
        query_string += "&SigAlg=#{Saml::Utils.url_encode(params["SigAlg"])}"

        signature_algorithm = XMLSecurity::BaseDocument.algorithm(params["SigAlg"])
        assert_equal signature_algorithm, OpenSSL::Digest::SHA1
        assert cert.public_key.verify(signature_algorithm, Base64.decode(params["Signature"]), query_string)
      end
    end

    describe "#manipulate request_id" do
      it "be able to modify the request id" do
        logoutrequest = Saml::Logoutrequest.new
        request_id = logoutrequest.request_id
        assert_equal request_id, logoutrequest.uuid
        logoutrequest.uuid = "new_uuid"
        assert_equal logoutrequest.request_id, logoutrequest.uuid
        assert_equal "new_uuid", logoutrequest.request_id
      end
    end
  end
end
