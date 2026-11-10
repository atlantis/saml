require "./spec_helper"
require "./logout_responses/logoutresponse_fixtures"

# Expose private validations to the specs.
class Saml::Logoutresponse
  def spec_validate_structure : Bool
    validate_structure
  end

  def spec_validate_signature : Bool
    validate_signature
  end
end

describe "Logoutresponse" do
  include LogoutresponseFixtures

  @params : Hash(String, String)?

  let(:valid_logout_response_without_settings) { Saml::Logoutresponse.new(valid_logout_response_document) }
  let(:valid_logout_response) { Saml::Logoutresponse.new(valid_logout_response_document, settings) }

  def signature_options(params : Hash(String, String)) : Hash(Symbol, Saml::RedirectSignature::OptionValue)
    options = {} of Symbol => Saml::RedirectSignature::OptionValue
    options[:get_params] = params
    options
  end

  describe "#new" do
    it "raise an exception when response is initialized with nil" do
      assert_raises(ArgumentError) { Saml::Logoutresponse.new(nil) }
    end

    it "default to empty settings" do
      assert_nil valid_logout_response_without_settings.settings
    end

    it "accept constructor-injected settings" do
      refute_nil valid_logout_response.settings
    end

    it "accept constructor-injected options" do
      logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document, nil, {:foo => "bar"})
      assert !logoutresponse.options.empty?
    end

    it "support base64 encoded responses" do
      generated_logout_response = valid_logout_response_document
      logoutresponse = Saml::Logoutresponse.new(Base64.encode(generated_logout_response), settings)
      assert_equal generated_logout_response, logoutresponse.response
    end

    it "support deflated base64 encoded responses" do
      generated_logout_response = valid_logout_response_document
      logoutresponse = Saml::Logoutresponse.new(Base64.strict_encode(deflate(generated_logout_response)), settings)
      assert_equal generated_logout_response, logoutresponse.response
    end

    it "rejects a response over message_max_bytesize" do
      settings.message_max_bytesize = 100
      assert_raises(Saml::ValidationError) do
        Saml::Logoutresponse.new(Base64.strict_encode(valid_logout_response_document), settings)
      end
    end
  end

  describe "#validate_structure" do
    it "invalidates when the logout response has an invalid xml" do
      settings.soft = true
      logoutresponse = Saml::Logoutresponse.new(invalid_xml_logout_response_document, settings)
      assert !logoutresponse.spec_validate_structure
      assert_includes logoutresponse.errors, "Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd"
    end

    it "raise when the logout response has an invalid xml" do
      settings.soft = false
      logoutresponse = Saml::Logoutresponse.new(invalid_xml_logout_response_document, settings)
      assert_raises(Saml::ValidationError) do
        logoutresponse.spec_validate_structure
      end
    end

    it "invalidates a malformed logout response without repairing it" do
      logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document.sub("</samlp:LogoutResponse>", ""), settings)
      assert !logoutresponse.validate
      refute_empty logoutresponse.errors
    end

    it "invalidates a logout response with a DOCTYPE" do
      xml = %(<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x "y">]>) + valid_logout_response_document
      logoutresponse = Saml::Logoutresponse.new(xml, settings)
      assert !logoutresponse.validate
      assert logoutresponse.errors.any?(&.includes?("Doctype"))
    end
  end

  describe "#validate" do
    describe "when soft=true" do
      before do
        settings.soft = true
      end

      it "validate the logout response" do
        in_relation_to_request_id = random_id
        opts = {:matches_request_id => in_relation_to_request_id}

        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings, opts)

        assert logoutresponse.validate

        assert_equal settings.sp_entity_id, logoutresponse.issuer
        assert_equal in_relation_to_request_id, logoutresponse.in_response_to

        assert logoutresponse.success?
        assert_empty logoutresponse.errors
      end

      it "validate the logout response extended" do
        in_relation_to_request_id = random_id
        settings.idp_entity_id = "http://app.muda.no"
        opts = {:matches_request_id => in_relation_to_request_id}

        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings, opts)
        assert logoutresponse.validate
        assert_equal in_relation_to_request_id, logoutresponse.in_response_to
        assert logoutresponse.success?
        assert_empty logoutresponse.errors
      end

      it "invalidate logout response when initiated with blank" do
        logoutresponse = Saml::Logoutresponse.new("", settings)
        assert !logoutresponse.validate
        assert_includes logoutresponse.errors, "Blank logout response"
      end

      it "invalidate logout response when initiated with no idp cert or fingerprint" do
        settings.idp_cert_fingerprint = nil
        settings.idp_cert = nil
        settings.idp_cert_multi = nil
        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document, settings)
        assert !logoutresponse.validate
        assert_includes logoutresponse.errors, "No fingerprint or certificate on settings of the logout response"
      end

      it "invalidate logout response with wrong id when given option matches_request_id" do
        expected_request_id = "_some_other_expected_uuid"
        opts = {:matches_request_id => expected_request_id}

        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document, settings, opts)

        assert !logoutresponse.validate
        refute_equal expected_request_id, logoutresponse.in_response_to
        assert_includes logoutresponse.errors, "The InResponseTo of the Logout Response: #{logoutresponse.in_response_to}, does not match the ID of the Logout Request sent by the SP: #{expected_request_id}"
      end

      it "invalidate logout response with unexpected request status" do
        logoutresponse = Saml::Logoutresponse.new(unsuccessful_logout_response_document, settings)

        assert !logoutresponse.success?
        assert !logoutresponse.validate
        assert_includes logoutresponse.errors, "The status code of the Logout Response was not Success, was Requester"
      end

      it "invalidate logout response with unexpected request status and status message" do
        logoutresponse = Saml::Logoutresponse.new(unsuccessful_logout_response_with_message_document, settings)

        assert !logoutresponse.success?
        assert !logoutresponse.validate
        assert_includes logoutresponse.errors, "The status code of the Logout Response was not Success, was Requester -> Logoutrequest expired"
      end

      it "invalidate logout response when in lack of sp_entity_id setting" do
        bad_settings = settings
        bad_settings.issuer = nil
        bad_settings.sp_entity_id = nil
        logoutresponse = Saml::Logoutresponse.new(unsuccessful_logout_response_document, bad_settings)
        assert !logoutresponse.validate
        assert_includes logoutresponse.errors, "No sp_entity_id in settings of the logout response"
      end

      it "invalidate logout response with wrong issuer" do
        in_relation_to_request_id = random_id
        settings.idp_entity_id = "http://invalid.issuer.example.com/"
        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)
        assert !logoutresponse.validate
        assert_includes logoutresponse.errors, "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <http://app.muda.no>"
      end

      it "collect errors when collect_errors=true" do
        settings.idp_entity_id = "http://invalid.issuer.example.com/"
        logoutresponse = Saml::Logoutresponse.new(unsuccessful_logout_response_document, settings)
        collect_errors = true
        assert !logoutresponse.validate(collect_errors)
        assert_includes logoutresponse.errors, "The status code of the Logout Response was not Success, was Requester"
        assert_includes logoutresponse.errors, "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <http://app.muda.no>"
      end
    end

    describe "when soft=false" do
      before do
        settings.soft = false
      end

      it "validates good logout response" do
        in_relation_to_request_id = random_id

        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)
        assert logoutresponse.validate
        assert_empty logoutresponse.errors
      end

      it "raises validation error when response initiated with blank" do
        logoutresponse = Saml::Logoutresponse.new("", settings)

        assert_raises(Saml::ValidationError) { logoutresponse.validate }
        assert_includes logoutresponse.errors, "Blank logout response"
      end

      it "raises validation error when initiated with no idp cert or fingerprint" do
        settings.idp_cert_fingerprint = nil
        settings.idp_cert = nil
        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document, settings)
        assert_raises(Saml::ValidationError) { logoutresponse.validate }
        assert_includes logoutresponse.errors, "No fingerprint or certificate on settings of the logout response"
      end

      it "raises validation error when matching for wrong request id" do
        expected_request_id = "_some_other_expected_id"
        opts = {:matches_request_id => expected_request_id}

        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document, settings, opts)
        assert_raises(Saml::ValidationError) { logoutresponse.validate }
        assert_includes logoutresponse.errors, "The InResponseTo of the Logout Response: #{logoutresponse.in_response_to}, does not match the ID of the Logout Request sent by the SP: #{expected_request_id}"
      end

      it "raise validation error for wrong request status" do
        logoutresponse = Saml::Logoutresponse.new(unsuccessful_logout_response_document, settings)

        assert_raises(Saml::ValidationError) { logoutresponse.validate }
        assert_includes logoutresponse.errors, "The status code of the Logout Response was not Success, was Requester"
      end

      it "raise validation error when in bad state" do
        logoutresponse = Saml::Logoutresponse.new(unsuccessful_logout_response_document, settings)
        assert_raises(Saml::ValidationError) { logoutresponse.validate }
        assert_includes logoutresponse.errors, "The status code of the Logout Response was not Success, was Requester"
      end

      it "raise validation error when in lack of sp_entity_id setting" do
        settings.issuer = nil
        settings.sp_entity_id = nil
        logoutresponse = Saml::Logoutresponse.new(unsuccessful_logout_response_document, settings)
        assert_raises(Saml::ValidationError) { logoutresponse.validate }
        assert_includes logoutresponse.errors, "No sp_entity_id in settings of the logout response"
      end

      it "raise validation error when logout response with wrong issuer" do
        in_relation_to_request_id = random_id
        settings.idp_entity_id = "http://invalid.issuer.example.com/"
        logoutresponse = Saml::Logoutresponse.new(valid_logout_response_document({:uuid => in_relation_to_request_id}), settings)
        assert_raises(Saml::ValidationError) { logoutresponse.validate }
        assert_includes logoutresponse.errors, "Doesn't match the issuer, expected: <#{settings.idp_entity_id}>, but was: <http://app.muda.no>"
      end
    end

    describe "#validate_signature" do
      let(:params) { Saml::SloLogoutresponse.new.create_params(settings, random_id, "Custom Logout Message", {"RelayState" => "http://example.com"}) }

      before do
        settings.soft = true
        settings.idp_slo_service_url = "http://example.com?field=value"
        settings.security[:logout_responses_signed] = true
        settings.certificate = crystal_saml_cert_text
        settings.private_key = crystal_saml_key_text
        settings.idp_cert = crystal_saml_cert_text
      end

      it "return true when no idp_cert is provided and option relax_signature_validation is present" do
        settings.idp_cert = nil
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        options = signature_options(params)
        options[:relax_signature_validation] = true
        logoutresponse_sign_test = Saml::Logoutresponse.new(params["SAMLResponse"], settings, options)
        assert logoutresponse_sign_test.spec_validate_signature
      end

      it "return false when no idp_cert is provided and no option relax_signature_validation is present" do
        settings.idp_cert = nil
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        logoutresponse_sign_test = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert !logoutresponse_sign_test.spec_validate_signature
      end

      it "return true when valid RSA_SHA1 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        logoutresponse_sign_test = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert logoutresponse_sign_test.spec_validate_signature
      end

      it "return true when valid RSA_SHA256 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        logoutresponse = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert logoutresponse.spec_validate_signature
      end

      it "validates a signed RSA_SHA256 response end to end" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        settings.sp_entity_id = "http://app.muda.no"
        request_id = random_id
        signed = Saml::SloLogoutresponse.new.create_params(settings, request_id, "Signed out", {"RelayState" => "http://example.com"})
        options = signature_options(signed)
        options[:matches_request_id] = request_id

        logoutresponse = Saml::Logoutresponse.new(signed["SAMLResponse"], settings, options)
        assert logoutresponse.validate, logoutresponse.errors.inspect
        assert_equal "Signed out", logoutresponse.status_message
      end

      it "return false when invalid RSA_SHA1 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        params["RelayState"] = "http://invalid.example.com"
        logoutresponse = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert !logoutresponse.spec_validate_signature
      end

      it "raise when invalid RSA_SHA1 Signature" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        settings.soft = false
        params["RelayState"] = "http://invalid.example.com"
        logoutresponse = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))

        assert_raises(Saml::ValidationError) { logoutresponse.spec_validate_signature }
        assert logoutresponse.errors.includes? "Invalid Signature on Logout Response"
      end

      it "raise when get_params encoding differs from what this library generates" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        settings.soft = false
        params["RelayState"] = "http://example.com"
        query = Saml::Utils.build_query({
          type:        "SAMLResponse",
          data:        params["SAMLResponse"],
          relay_state: params["RelayState"],
          sig_alg:     params["SigAlg"],
        })
        # Same values, different percent-encoding.
        original_query = query
        query = query.gsub("example", "ex%61mple")
        refute_equal(query, original_query)
        assert_equal(URI.decode(query), URI.decode(original_query))
        sign_algorithm = XMLSecurity::BaseDocument.algorithm(settings.security[:signature_method].as(String))
        signature = settings.get_sp_key.not_nil!.sign(sign_algorithm, query)
        params["Signature"] = Base64.strict_encode(signature)
        # Re-encoding the decoded get_params can't reproduce what the IdP signed.
        logoutresponse = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert_raises(Saml::ValidationError) do
          logoutresponse.spec_validate_signature
        end
      end

      it "return true even if raw_get_params encoding differs from what this library generates" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        settings.soft = false
        params["RelayState"] = "http://example.com"
        query = Saml::Utils.build_query({
          type:        "SAMLResponse",
          data:        params["SAMLResponse"],
          relay_state: params["RelayState"],
          sig_alg:     params["SigAlg"],
        })
        original_query = query
        query = query.gsub("example", "ex%61mple")
        refute_equal(query, original_query)
        assert_equal(URI.decode(query), URI.decode(original_query))
        sign_algorithm = XMLSecurity::BaseDocument.algorithm(settings.security[:signature_method].as(String))
        signature = settings.get_sp_key.not_nil!.sign(sign_algorithm, query)
        params["Signature"] = Base64.strict_encode(signature)
        # The raw form is what was signed, so no guessing at the encoding.
        params.delete("RelayState")
        options = signature_options(params)
        options[:raw_get_params] = {"RelayState" => "http%3A%2F%2Fex%61mple.com"}
        logoutresponse = Saml::Logoutresponse.new(params["SAMLResponse"], settings, options)
        assert logoutresponse.spec_validate_signature
      end

      it "verifies lowercase percent-encoding when lowercase_url_encoding is set" do
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
        settings.security[:lowercase_url_encoding] = true
        query = Saml::Utils.build_query({
          type:        "SAMLResponse",
          data:        params["SAMLResponse"],
          relay_state: params["RelayState"],
          sig_alg:     params["SigAlg"],
        }).gsub(/%[A-F0-9]{2}/) { |match| match.downcase }
        sign_algorithm = XMLSecurity::BaseDocument.algorithm(XMLSecurity::Document::RSA_SHA256)
        params["Signature"] = Base64.strict_encode(settings.get_sp_key.not_nil!.sign(sign_algorithm, query))

        logoutresponse = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert logoutresponse.spec_validate_signature
      end
    end

    describe "#validate_signature with idp_cert_multi" do
      let(:params) { Saml::SloLogoutresponse.new.create_params(settings, random_id, "Custom Logout Message", {"RelayState" => "http://example.com"}) }

      before do
        settings.soft = true
        settings.idp_slo_service_url = "http://example.com?field=value"
        settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA1
        settings.security[:logout_responses_signed] = true
        settings.certificate = crystal_saml_cert_text
        settings.private_key = crystal_saml_key_text
        settings.idp_cert = nil
      end

      it "return true when at least a idp_cert is valid" do
        settings.idp_cert_multi = {
          :signing    => [crystal_saml_cert_text2, crystal_saml_cert_text],
          :encryption => [] of String,
        }
        logoutresponse_sign_test = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert logoutresponse_sign_test.spec_validate_signature
      end

      it "return false when cert expired and check_idp_cert_expiration expired" do
        settings.security[:check_idp_cert_expiration] = true
        settings.idp_cert = nil
        settings.idp_cert_multi = {
          :signing    => [crystal_saml_cert_text],
          :encryption => [] of String,
        }
        logoutresponse_sign_test = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert !logoutresponse_sign_test.spec_validate_signature
        assert_includes logoutresponse_sign_test.errors, "IdP x509 certificate expired"
      end

      it "return false when none cert on idp_cert_multi is valid" do
        settings.idp_cert_multi = {
          :signing    => [crystal_saml_cert_text2, crystal_saml_cert_text2],
          :encryption => [] of String,
        }
        logoutresponse_sign_test = Saml::Logoutresponse.new(params["SAMLResponse"], settings, signature_options(params))
        assert !logoutresponse_sign_test.spec_validate_signature
        assert_includes logoutresponse_sign_test.errors, "Invalid Signature on Logout Response"
      end
    end
  end
end
